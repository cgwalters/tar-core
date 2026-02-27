//! Proof-of-concept: Using tar-core's sans-IO Parser with tokio async I/O.
//!
//! This example demonstrates the key insight of the sans-IO architecture:
//!
//! **The Parser itself does NO I/O** - it just processes byte slices and returns
//! events. The async/sync difference is ONLY in how you fill the buffer.
//!
//! This means:
//! - `tar-rs` can use `Parser` with `std::io::Read`
//! - `tokio-tar` can use the SAME `Parser` with `tokio::io::AsyncRead`
//! - Any other async runtime (async-std, smol) can also use the same Parser
//!
//! # Key Architecture Points
//!
//! 1. **Parser is runtime-agnostic**: It takes `&[u8]` and returns events
//! 2. **Buffer management is caller's responsibility**: Fill it however you want
//! 3. **No trait bounds on Parser**: No `Read`, no `AsyncRead`, just bytes
//! 4. **Same parsing logic everywhere**: GNU long names, PAX, checksums - all shared
//!
//! # Usage
//!
//! ```sh
//! cargo run -p tar-core --example tokio_parser
//! ```

// Disable strict lints for examples - they have different documentation needs
#![allow(missing_docs)]
#![allow(missing_debug_implementations)]

use std::borrow::Cow;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use tar_core::parse::{ParseEvent, ParsedEntry, Parser};
use tar_core::stream::Limits;
use tar_core::{EntryType, HEADER_SIZE};

// ============================================================================
// Async buffer management
// ============================================================================

/// Async read buffer - the ONLY difference from sync code is using AsyncRead.
///
/// Compare this to `ReadBuffer` in `tar_rs_compat.rs` - the buffer logic is
/// nearly identical. The only changes are:
/// - `reader: R` where `R: AsyncRead` instead of `R: Read`
/// - `fill()` is async and uses `read().await` instead of `read()`
///
/// The Parser doesn't care - it just sees `&[u8]`.
struct AsyncReadBuffer<R> {
    reader: R,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
}

impl<R: AsyncRead + Unpin> AsyncReadBuffer<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: vec![0u8; 64 * 1024],
            start: 0,
            end: 0,
            eof: false,
        }
    }

    fn data(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    fn compact(&mut self) {
        if self.start > 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
    }

    /// Fill the buffer with at least `min_bytes` of data.
    ///
    /// This is the ONLY async method - everything else is sync.
    /// The Parser doesn't know or care that this is async.
    async fn fill(&mut self, min_bytes: usize) -> io::Result<bool> {
        if self.end - self.start >= min_bytes {
            return Ok(true);
        }

        self.compact();

        if self.buffer.len() < min_bytes {
            self.buffer.resize(min_bytes, 0);
        }

        while !self.eof && self.end < min_bytes {
            // This is the ONLY async operation in the entire parsing flow!
            let n = self.reader.read(&mut self.buffer[self.end..]).await?;
            if n == 0 {
                self.eof = true;
            } else {
                self.end += n;
            }
        }

        Ok(self.end - self.start >= min_bytes)
    }

    async fn skip(&mut self, mut n: usize) -> io::Result<()> {
        while n > 0 {
            self.fill(n.min(self.buffer.len())).await?;
            let available = self.end - self.start;
            if available == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
            let to_skip = n.min(available);
            self.consume(to_skip);
            n -= to_skip;
        }
        Ok(())
    }
}

// ============================================================================
// Entry type (same as sync version)
// ============================================================================

/// Entry type - identical to the sync version.
///
/// This demonstrates that the data structures don't change at all
/// between sync and async usage.
#[derive(Debug)]
pub struct Entry {
    entry_type: EntryType,
    path: Vec<u8>,
    link_target: Option<Vec<u8>>,
    size: u64,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
}

impl Entry {
    fn from_parsed(parsed: &ParsedEntry<'_>) -> Self {
        Self {
            entry_type: parsed.entry_type,
            path: parsed.path.to_vec(),
            link_target: parsed.link_target.as_ref().map(|t| t.to_vec()),
            size: parsed.size,
            mode: parsed.mode,
            uid: parsed.uid,
            gid: parsed.gid,
            mtime: parsed.mtime,
        }
    }

    pub fn path_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.path)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn entry_type(&self) -> EntryType {
        self.entry_type
    }

    pub fn link_name_bytes(&self) -> Option<&[u8]> {
        self.link_target.as_deref()
    }

    pub fn is_file(&self) -> bool {
        self.entry_type.is_file()
    }

    pub fn is_dir(&self) -> bool {
        self.entry_type.is_dir()
    }

    pub fn is_symlink(&self) -> bool {
        self.entry_type.is_symlink()
    }

    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn mtime(&self) -> u64 {
        self.mtime
    }
}

// ============================================================================
// Async Archive
// ============================================================================

/// Async tar archive reader using tokio.
///
/// This uses the EXACT SAME `Parser` as the sync version - the only difference
/// is that `buffer` is an `AsyncReadBuffer` instead of `ReadBuffer`.
pub struct AsyncArchive<R> {
    buffer: AsyncReadBuffer<R>,
    // Same Parser type as sync! No AsyncParser needed.
    parser: Parser,
    finished: bool,
}

impl<R: AsyncRead + Unpin> AsyncArchive<R> {
    pub fn new(reader: R) -> Self {
        Self {
            buffer: AsyncReadBuffer::new(reader),
            // The Parser is completely runtime-agnostic
            parser: Parser::new(Limits::default()),
            finished: false,
        }
    }

    /// Read the next entry from the archive.
    ///
    /// This is an async method, but note that the Parser.parse() call inside
    /// is completely synchronous - only the buffer filling is async.
    pub async fn next_entry(&mut self) -> io::Result<Option<Entry>> {
        if self.finished {
            return Ok(None);
        }

        loop {
            // Async: fill the buffer
            self.buffer.fill(HEADER_SIZE).await?;

            // Handle clean EOF at header boundary
            if self.buffer.data().is_empty() {
                self.finished = true;
                return Ok(None);
            }

            // SYNC: Parse using the exact same Parser as sync code!
            // This is the key insight - parsing is completely synchronous.
            let parse_result = self.parser.parse(self.buffer.data());

            match parse_result {
                Ok((_, ParseEvent::NeedData { min_bytes })) => {
                    // Async: need more data
                    match self.buffer.fill(min_bytes).await {
                        Ok(true) => continue,
                        Ok(false) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!("need {} bytes but got EOF", min_bytes),
                            ));
                        }
                        Err(e) => return Err(e),
                    }
                }

                Ok((consumed, ParseEvent::Entry(parsed))) => {
                    let entry = Entry::from_parsed(&parsed);
                    let size = entry.size;

                    // Consume header bytes
                    self.buffer.consume(consumed);

                    // Async: skip content + padding
                    let padded = size.next_multiple_of(HEADER_SIZE as u64) as usize;
                    self.buffer.skip(padded).await?;

                    // SYNC: Update parser state
                    if let Err(e) = self.parser.advance_content(size) {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                    }

                    return Ok(Some(entry));
                }

                Ok((consumed, ParseEvent::End)) => {
                    self.buffer.consume(consumed);
                    self.finished = true;
                    return Ok(None);
                }

                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
            }
        }
    }
}

// ============================================================================
// Test archive creation (identical to sync version)
// ============================================================================

/// Create a minimal valid tar archive for testing.
///
/// This function is identical to the one in `tar_rs_compat.rs` - further
/// demonstrating that archive creation doesn't care about sync vs async.
fn create_test_archive() -> Vec<u8> {
    let mut archive = Vec::new();

    fn make_header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut header = [0u8; 512];

        let name_bytes = name.as_bytes();
        header[..name_bytes.len().min(100)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);

        header[100..107].copy_from_slice(b"0000644");
        header[108..115].copy_from_slice(b"0001750");
        header[116..123].copy_from_slice(b"0001750");

        let size_str = format!("{:011o}", size);
        header[124..135].copy_from_slice(size_str.as_bytes());

        header[136..147].copy_from_slice(b"14712345670");
        header[156] = typeflag;

        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        header[265..269].copy_from_slice(b"user");
        header[297..302].copy_from_slice(b"group");

        // Compute checksum
        let mut sum: u64 = 0;
        for (i, &byte) in header.iter().enumerate() {
            if (148..156).contains(&i) {
                sum += u64::from(b' ');
            } else {
                sum += u64::from(byte);
            }
        }
        let checksum_str = format!("{:06o}\0 ", sum);
        header[148..156].copy_from_slice(checksum_str.as_bytes());

        header
    }

    // Add a directory
    archive.extend_from_slice(&make_header("testdir/", 0, b'5'));

    // Add a file with content
    archive.extend_from_slice(&make_header("testdir/hello.txt", 13, b'0'));
    let mut content = [0u8; 512];
    content[..13].copy_from_slice(b"Hello, World!");
    archive.extend_from_slice(&content);

    // Add an empty file
    archive.extend_from_slice(&make_header("testdir/empty.txt", 0, b'0'));

    // Add a larger file
    archive.extend_from_slice(&make_header("testdir/data.bin", 1024, b'0'));
    archive.extend_from_slice(&[0xAA; 512]);
    archive.extend_from_slice(&[0xBB; 512]);

    // Add a symlink
    let mut symlink_header = make_header("testdir/link", 0, b'2');
    symlink_header[157..168].copy_from_slice(b"hello.txt\0\0");
    // Recompute checksum
    let mut sum: u64 = 0;
    for (i, &byte) in symlink_header.iter().enumerate() {
        if (148..156).contains(&i) {
            sum += u64::from(b' ');
        } else {
            sum += u64::from(byte);
        }
    }
    let checksum_str = format!("{:06o}\0 ", sum);
    symlink_header[148..156].copy_from_slice(checksum_str.as_bytes());
    archive.extend_from_slice(&symlink_header);

    // End of archive: two zero blocks
    archive.extend_from_slice(&[0u8; 1024]);

    archive
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("=== Tokio Async Parser Demo ===\n");
    println!("This demonstrates using tar-core's sans-IO Parser with tokio.\n");
    println!("KEY INSIGHT: The Parser is IDENTICAL to the sync version!");
    println!("Only the buffer-filling code is async.\n");
    println!("This means tokio-tar could share the exact same Parser as tar-rs.\n");
    println!("---\n");

    // Create a test archive in memory
    let archive_data = create_test_archive();
    println!("Created test archive: {} bytes\n", archive_data.len());

    // Parse using async I/O with the SAME Parser as sync code
    let cursor = std::io::Cursor::new(&archive_data);
    let mut archive = AsyncArchive::new(cursor);

    println!("Entries (parsed asynchronously):\n");
    println!(
        "{:<6} {:<30} {:>10} {:>8} {:>8}",
        "Type", "Path", "Size", "UID", "GID"
    );
    println!("{}", "-".repeat(70));

    while let Some(entry) = archive.next_entry().await? {
        let type_str = match entry.entry_type() {
            EntryType::Regular => "file",
            EntryType::Directory => "dir",
            EntryType::Symlink => "link",
            EntryType::Link => "hard",
            EntryType::Char => "char",
            EntryType::Block => "block",
            EntryType::Fifo => "fifo",
            _ => "other",
        };

        let path = entry.path_lossy();
        let display_path = if entry.is_symlink() {
            let target = entry
                .link_name_bytes()
                .map(String::from_utf8_lossy)
                .unwrap_or_default();
            format!("{} -> {}", path, target)
        } else {
            path.to_string()
        };

        println!(
            "{:<6} {:<30} {:>10} {:>8} {:>8}",
            type_str,
            display_path,
            entry.size(),
            entry.uid,
            entry.gid
        );
    }

    println!("\n---");
    println!("\nArchitecture summary:");
    println!("  1. Parser::new() - same as sync (no runtime dependency)");
    println!("  2. Parser::parse(&[u8]) - sync, just processes bytes");
    println!("  3. Parser::advance_content() - sync, just updates state");
    println!("  4. AsyncReadBuffer::fill() - the ONLY async code");
    println!("\nThis proves that tokio-tar can share Parser with tar-rs!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_archive_entries() {
        let archive_data = create_test_archive();
        let cursor = std::io::Cursor::new(&archive_data);
        let mut archive = AsyncArchive::new(cursor);

        let mut entries = Vec::new();
        while let Some(entry) = archive.next_entry().await.unwrap() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 5);

        // Check first entry (directory)
        assert_eq!(entries[0].path_lossy(), "testdir/");
        assert!(entries[0].is_dir());

        // Check second entry (file with content)
        assert_eq!(entries[1].path_lossy(), "testdir/hello.txt");
        assert!(entries[1].is_file());
        assert_eq!(entries[1].size(), 13);

        // Check third entry (empty file)
        assert_eq!(entries[2].path_lossy(), "testdir/empty.txt");
        assert!(entries[2].is_file());
        assert_eq!(entries[2].size(), 0);

        // Check fourth entry (larger file)
        assert_eq!(entries[3].path_lossy(), "testdir/data.bin");
        assert!(entries[3].is_file());
        assert_eq!(entries[3].size(), 1024);

        // Check fifth entry (symlink)
        assert_eq!(entries[4].path_lossy(), "testdir/link");
        assert!(entries[4].is_symlink());
        assert_eq!(
            entries[4].link_name_bytes(),
            Some(b"hello.txt".as_slice())
        );
    }

    #[tokio::test]
    async fn test_empty_archive() {
        // Just two zero blocks
        let archive_data = vec![0u8; 1024];
        let cursor = std::io::Cursor::new(&archive_data);
        let mut archive = AsyncArchive::new(cursor);

        let entry = archive.next_entry().await.unwrap();
        assert!(entry.is_none());
    }

    /// This test demonstrates that the same Parser works for both sync and async.
    #[tokio::test]
    async fn test_parser_is_sync() {
        // Create a simple archive with just end markers
        let data = vec![0u8; 1024];

        // The Parser itself is completely sync - no async traits needed
        let mut parser = Parser::new(Limits::default());

        // parse() is a normal sync method that takes &[u8]
        let result = parser.parse(&data);
        assert!(result.is_ok());

        let (consumed, event) = result.unwrap();
        assert_eq!(consumed, 1024);
        assert!(matches!(event, ParseEvent::End));
    }
}
