//! Proof-of-concept: tar-rs compatibility layer using tar-core
//!
//! This demonstrates how tar-rs could be rebased on tar-core's sans-IO parser.
//! The `Archive` and `Entry` types provide a familiar API for tar-rs users,
//! while using tar-core's `Parser` internally for all parsing logic.
//!
//! # Key Points
//!
//! 1. **API Compatibility**: The types feel familiar to tar-rs users
//! 2. **Sans-IO Core**: Under the hood, we use tar-core's `Parser`
//! 3. **Iterator Pattern**: The event-based parser is wrapped in an iterator
//!
//! # Usage
//!
//! ```sh
//! cargo run -p tar-core --example tar_rs_compat
//! ```

use std::borrow::Cow;
use std::io::{self, Read};

use tar_core::parse::{ParseEvent, ParsedEntry, Parser};
use tar_core::stream::Limits;
use tar_core::{EntryType, HEADER_SIZE};

// ============================================================================
// Buffer management
// ============================================================================

/// Internal buffer for managing I/O operations.
struct ReadBuffer<R> {
    reader: R,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
}

impl<R: Read> ReadBuffer<R> {
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

    fn fill(&mut self, min_bytes: usize) -> io::Result<bool> {
        if self.end - self.start >= min_bytes {
            return Ok(true);
        }

        self.compact();

        if self.buffer.len() < min_bytes {
            self.buffer.resize(min_bytes, 0);
        }

        while !self.eof && self.end < min_bytes {
            let n = self.reader.read(&mut self.buffer[self.end..])?;
            if n == 0 {
                self.eof = true;
            } else {
                self.end += n;
            }
        }

        Ok(self.end - self.start >= min_bytes)
    }

    fn skip(&mut self, mut n: usize) -> io::Result<()> {
        while n > 0 {
            self.fill(n.min(self.buffer.len()))?;
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
// Entry (tar-rs compatible)
// ============================================================================

/// Entry type similar to tar-rs's `Entry`.
///
/// This provides a familiar interface for accessing tar entry metadata,
/// with data backed by tar-core's `ParsedEntry`.
#[derive(Debug)]
pub struct Entry {
    /// The entry type
    entry_type: EntryType,
    /// The resolved file path (may be from PAX/GNU extensions)
    path: Vec<u8>,
    /// The resolved link target (for symlinks/hardlinks)
    link_target: Option<Vec<u8>>,
    /// Content size in bytes
    size: u64,
    /// File mode/permissions
    mode: u32,
    /// Owner UID
    uid: u64,
    /// Owner GID
    gid: u64,
    /// Modification time
    mtime: u64,
    /// User name
    uname: Option<Vec<u8>>,
    /// Group name
    gname: Option<Vec<u8>>,
}

impl Entry {
    /// Create an Entry from a ParsedEntry (copying data to own it).
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
            uname: parsed.uname.as_ref().map(|u| u.to_vec()),
            gname: parsed.gname.as_ref().map(|g| g.to_vec()),
        }
    }

    /// Returns the raw path bytes of this entry.
    ///
    /// This is the resolved path including any GNU long name or PAX path extensions.
    #[must_use]
    pub fn path_bytes(&self) -> &[u8] {
        &self.path
    }

    /// Returns the path as a lossy UTF-8 string.
    #[must_use]
    pub fn path_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.path)
    }

    /// Returns the content size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the entry type.
    #[must_use]
    pub fn entry_type(&self) -> EntryType {
        self.entry_type
    }

    /// Returns the link target bytes for symlinks/hardlinks.
    #[must_use]
    pub fn link_name_bytes(&self) -> Option<&[u8]> {
        self.link_target.as_deref()
    }

    /// Returns the file mode/permissions.
    #[must_use]
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns the owner UID.
    #[must_use]
    pub fn uid(&self) -> u64 {
        self.uid
    }

    /// Returns the owner GID.
    #[must_use]
    pub fn gid(&self) -> u64 {
        self.gid
    }

    /// Returns the modification time as Unix timestamp.
    #[must_use]
    pub fn mtime(&self) -> u64 {
        self.mtime
    }

    /// Returns the owner user name, if present.
    #[must_use]
    pub fn username(&self) -> Option<&[u8]> {
        self.uname.as_deref()
    }

    /// Returns the owner group name, if present.
    #[must_use]
    pub fn groupname(&self) -> Option<&[u8]> {
        self.gname.as_deref()
    }

    /// Returns true if this is a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.entry_type.is_file()
    }

    /// Returns true if this is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.entry_type.is_dir()
    }

    /// Returns true if this is a symbolic link.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.entry_type.is_symlink()
    }

    /// Returns true if this is a hard link.
    #[must_use]
    pub fn is_hard_link(&self) -> bool {
        self.entry_type.is_hard_link()
    }
}

// ============================================================================
// Archive (tar-rs compatible)
// ============================================================================

/// A compatibility wrapper providing tar-rs-like API over tar-core.
///
/// This demonstrates how tar-rs's `Archive` type could be implemented
/// using tar-core's sans-IO `Parser` internally.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use std::io::BufReader;
///
/// let file = File::open("archive.tar").unwrap();
/// let mut archive = Archive::new(BufReader::new(file));
///
/// for entry in archive.entries() {
///     let entry = entry.unwrap();
///     println!("{} ({} bytes)", entry.path_lossy(), entry.size());
/// }
/// ```
pub struct Archive<R> {
    buffer: ReadBuffer<R>,
    parser: Parser,
    finished: bool,
}

impl<R> std::fmt::Debug for Archive<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Archive<R> {
    /// Create a new Archive from a reader.
    pub fn new(reader: R) -> Self {
        Self {
            buffer: ReadBuffer::new(reader),
            parser: Parser::new(Limits::default()),
            finished: false,
        }
    }

    /// Create a new Archive with custom limits.
    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self {
            buffer: ReadBuffer::new(reader),
            parser: Parser::new(limits),
            finished: false,
        }
    }

    /// Returns an iterator over the entries in this archive.
    ///
    /// This is the main way to iterate over tar contents, similar to
    /// tar-rs's `Archive::entries()`.
    pub fn entries(&mut self) -> Entries<'_, R> {
        Entries { archive: self }
    }
}

// ============================================================================
// Entries iterator (tar-rs compatible)
// ============================================================================

/// Owned parse result to avoid borrow issues.
///
/// We extract what we need from the ParseEvent before releasing the borrow
/// on the buffer, allowing us to mutate the reader afterwards.
enum OwnedParseResult {
    NeedData { min_bytes: usize },
    Entry { consumed: usize, entry: Entry },
    End { consumed: usize },
    Error(io::Error),
}

/// Iterator over the entries in a tar archive.
///
/// This wraps tar-core's event-based parser in a familiar iterator interface.
pub struct Entries<'a, R> {
    archive: &'a mut Archive<R>,
}

impl<R> std::fmt::Debug for Entries<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entries").finish_non_exhaustive()
    }
}

impl<R: Read> Iterator for Entries<'_, R> {
    type Item = io::Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.archive.finished {
            return None;
        }

        loop {
            // Ensure we have enough data for at least a header
            if let Err(e) = self.archive.buffer.fill(HEADER_SIZE) {
                return Some(Err(e));
            }

            // Handle clean EOF at header boundary
            if self.archive.buffer.data().is_empty() {
                self.archive.finished = true;
                return None;
            }

            // Parse the next event and extract owned data to release the borrow
            let result = match self.archive.parser.parse(self.archive.buffer.data()) {
                Ok((_, ParseEvent::NeedData { min_bytes })) => {
                    OwnedParseResult::NeedData { min_bytes }
                }
                Ok((consumed, ParseEvent::Entry(parsed))) => OwnedParseResult::Entry {
                    consumed,
                    entry: Entry::from_parsed(&parsed),
                },
                Ok((consumed, ParseEvent::End)) => OwnedParseResult::End { consumed },
                Err(e) => OwnedParseResult::Error(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )),
            };

            match result {
                OwnedParseResult::NeedData { min_bytes } => {
                    // Need more data
                    match self.archive.buffer.fill(min_bytes) {
                        Ok(true) => continue,
                        Ok(false) => {
                            return Some(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!("need {} bytes but got EOF", min_bytes),
                            )));
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }

                OwnedParseResult::Entry { consumed, entry } => {
                    // Consume the header bytes
                    self.archive.buffer.consume(consumed);

                    let size = entry.size;

                    // Skip content + padding
                    let padded = size.next_multiple_of(HEADER_SIZE as u64) as usize;
                    if let Err(e) = self.archive.buffer.skip(padded) {
                        return Some(Err(e));
                    }

                    // Tell the parser we handled the content
                    if let Err(e) = self.archive.parser.advance_content(size) {
                        return Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }

                    return Some(Ok(entry));
                }

                OwnedParseResult::End { consumed } => {
                    self.archive.buffer.consume(consumed);
                    self.archive.finished = true;
                    return None;
                }

                OwnedParseResult::Error(e) => {
                    return Some(Err(e));
                }
            }
        }
    }
}

// ============================================================================
// Test archive creation (reused from async_parser.rs)
// ============================================================================

/// Create a minimal valid tar archive for testing.
fn create_test_archive() -> Vec<u8> {
    let mut archive = Vec::new();

    // Helper to create a simple header
    fn make_header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut header = [0u8; 512];

        // Name
        let name_bytes = name.as_bytes();
        header[..name_bytes.len().min(100)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);

        // Mode: 0644
        header[100..107].copy_from_slice(b"0000644");

        // UID/GID: 1000
        header[108..115].copy_from_slice(b"0001750");
        header[116..123].copy_from_slice(b"0001750");

        // Size
        let size_str = format!("{:011o}", size);
        header[124..135].copy_from_slice(size_str.as_bytes());

        // Mtime: arbitrary
        header[136..147].copy_from_slice(b"14712345670");

        // Typeflag
        header[156] = typeflag;

        // UStar magic
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        // Username/groupname
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

fn main() -> io::Result<()> {
    println!("=== tar-rs Compatibility Layer Demo ===\n");
    println!("This demonstrates how tar-rs could be rebased on tar-core.");
    println!("The Archive and Entry types provide a familiar API,");
    println!("while using tar-core's sans-IO Parser internally.\n");
    println!("---\n");

    // Create a test archive in memory
    let archive_data = create_test_archive();
    println!("Created test archive: {} bytes\n", archive_data.len());

    // Parse using tar-rs-like API
    let mut archive = Archive::new(std::io::Cursor::new(&archive_data));

    println!("Entries (tar-rs compatible API):\n");
    println!(
        "{:<6} {:<30} {:>10} {:>8} {:>8}",
        "Type", "Path", "Size", "UID", "GID"
    );
    println!("{}", "-".repeat(70));

    for entry in archive.entries() {
        let entry = entry?;

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
            entry.uid(),
            entry.gid()
        );
    }

    println!("\n---");
    println!("\nKey implementation insights:");
    println!("  1. Archive wraps a ReadBuffer + Parser (both from tar-core)");
    println!("  2. Entries iterator translates ParseEvents to Entry structs");
    println!("  3. All header parsing logic comes from tar-core");
    println!("  4. GNU long name/link and PAX extensions handled automatically");
    println!("  5. Same pattern works for tokio-tar with AsyncRead");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_entries() {
        let archive_data = create_test_archive();
        let mut archive = Archive::new(std::io::Cursor::new(&archive_data));

        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 5);

        // Check first entry (directory)
        let entry0 = entries[0].as_ref().unwrap();
        assert_eq!(entry0.path_bytes(), b"testdir/");
        assert!(entry0.is_dir());
        assert_eq!(entry0.size(), 0);

        // Check second entry (file with content)
        let entry1 = entries[1].as_ref().unwrap();
        assert_eq!(entry1.path_bytes(), b"testdir/hello.txt");
        assert!(entry1.is_file());
        assert_eq!(entry1.size(), 13);

        // Check third entry (empty file)
        let entry2 = entries[2].as_ref().unwrap();
        assert_eq!(entry2.path_bytes(), b"testdir/empty.txt");
        assert!(entry2.is_file());
        assert_eq!(entry2.size(), 0);

        // Check fourth entry (larger file)
        let entry3 = entries[3].as_ref().unwrap();
        assert_eq!(entry3.path_bytes(), b"testdir/data.bin");
        assert!(entry3.is_file());
        assert_eq!(entry3.size(), 1024);

        // Check fifth entry (symlink)
        let entry4 = entries[4].as_ref().unwrap();
        assert_eq!(entry4.path_bytes(), b"testdir/link");
        assert!(entry4.is_symlink());
        assert_eq!(entry4.link_name_bytes(), Some(b"hello.txt".as_slice()));
    }

    #[test]
    fn test_empty_archive() {
        // Just two zero blocks
        let archive_data = vec![0u8; 1024];
        let mut archive = Archive::new(std::io::Cursor::new(&archive_data));

        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_entry_metadata() {
        let archive_data = create_test_archive();
        let mut archive = Archive::new(std::io::Cursor::new(&archive_data));

        let entry = archive.entries().next().unwrap().unwrap();

        // Check metadata
        assert_eq!(entry.mode(), 0o644);
        assert_eq!(entry.uid(), 1000); // 01750 octal = 1000
        assert_eq!(entry.gid(), 1000);
        assert!(entry.mtime() > 0);
        assert_eq!(entry.username(), Some(b"user".as_slice()));
        assert_eq!(entry.groupname(), Some(b"group".as_slice()));
    }
}
