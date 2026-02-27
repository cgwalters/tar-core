//! Async tar parser example demonstrating sans-IO usage patterns.
//!
//! This shows how the same [`Parser`] can be used in an async context.
//! The key insight is that the parser itself does no I/O - it just processes
//! byte slices and returns events. This makes it trivial to adapt for async.
//!
//! This example compiles without any async runtime dependency by using a
//! simulated async pattern. In a real application, you would use tokio,
//! async-std, or another async runtime.
//!
//! # The Sans-IO Advantage
//!
//! The same `Parser` type works for both sync and async code because:
//!
//! 1. `Parser::parse(&[u8])` takes a slice and returns immediately
//! 2. `ParseEvent::NeedData` tells you to read more (sync or async)
//! 3. `ParseEvent::Entry` gives you metadata; you handle content I/O yourself
//! 4. `Parser::advance_content()` updates state after you've handled content
//!
//! This separation means tokio-tar could share the same parser core as tar-rs.

use std::task::Poll;

use tar_core::parse::{ParseEvent, ParsedEntry, Parser};
use tar_core::stream::Limits;
use tar_core::HEADER_SIZE;

/// A mock async reader that simulates reading from a byte slice.
///
/// In a real async application, this would be replaced with something like
/// `tokio::io::AsyncRead` or `futures::io::AsyncRead`.
struct MockAsyncReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MockAsyncReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Simulate an async read.
    ///
    /// In real async code, this would be:
    /// ```ignore
    /// async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>
    /// ```
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        let remaining = &self.data[self.pos..];
        if remaining.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Simulate partial reads (common in async I/O)
        let to_read = buf.len().min(remaining.len()).min(512);
        buf[..to_read].copy_from_slice(&remaining[..to_read]);
        self.pos += to_read;

        Poll::Ready(Ok(to_read))
    }
}

/// An async-compatible buffer that can be filled from a mock reader.
///
/// In a real async application, the fill method would be async.
struct AsyncBuffer<'a> {
    reader: MockAsyncReader<'a>,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

impl<'a> AsyncBuffer<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            reader: MockAsyncReader::new(data),
            buffer: vec![0u8; 8192],
            start: 0,
            end: 0,
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

    /// Fill buffer with at least `min_bytes`.
    ///
    /// In real async code, this would be:
    /// ```ignore
    /// async fn fill(&mut self, min_bytes: usize) -> io::Result<bool>
    /// ```
    fn fill(&mut self, min_bytes: usize) -> std::io::Result<bool> {
        if self.end - self.start >= min_bytes {
            return Ok(true);
        }

        self.compact();

        if self.buffer.len() < min_bytes {
            self.buffer.resize(min_bytes, 0);
        }

        // In real async code, this loop would use `.await`
        loop {
            if self.end - self.start >= min_bytes {
                return Ok(true);
            }

            match self.reader.poll_read(&mut self.buffer[self.end..]) {
                Poll::Ready(Ok(0)) => return Ok(self.end - self.start >= min_bytes),
                Poll::Ready(Ok(n)) => self.end += n,
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => {
                    // In real async, we'd yield here and be woken up later
                    // For this example, we just continue (simulating immediate data)
                    continue;
                }
            }
        }
    }

    /// Skip `n` bytes.
    fn skip(&mut self, mut n: usize) -> std::io::Result<()> {
        while n > 0 {
            self.fill(n.min(self.buffer.len()))?;
            let available = self.end - self.start;
            if available == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF in content",
                ));
            }
            let to_skip = n.min(available);
            self.consume(to_skip);
            n -= to_skip;
        }
        Ok(())
    }
}

/// Information extracted from a parsed entry (owned version).
struct EntryInfo {
    entry_type: tar_core::EntryType,
    size: u64,
    path: Vec<u8>,
    link_target: Option<Vec<u8>>,
}

impl EntryInfo {
    fn from_parsed(entry: &ParsedEntry<'_>) -> Self {
        Self {
            entry_type: entry.entry_type,
            size: entry.size,
            path: entry.path.to_vec(),
            link_target: entry.link_target.as_ref().map(|t| t.to_vec()),
        }
    }
}

/// Print entry information.
fn print_entry(info: &EntryInfo) {
    let type_str = match info.entry_type {
        tar_core::EntryType::Regular => "file",
        tar_core::EntryType::Directory => "dir ",
        tar_core::EntryType::Symlink => "link",
        tar_core::EntryType::Link => "hard",
        _ => "????",
    };

    println!(
        "  [{type_str}] {:>8} bytes: {}",
        info.size,
        String::from_utf8_lossy(&info.path)
    );

    if let Some(ref target) = info.link_target {
        println!("           -> {}", String::from_utf8_lossy(target));
    }
}

/// Process a tar archive asynchronously.
///
/// In real async code, this would be:
/// ```ignore
/// async fn process_archive(data: &[u8]) -> io::Result<()>
/// ```
fn process_archive(data: &[u8]) -> std::io::Result<()> {
    let mut buf = AsyncBuffer::new(data);
    let mut parser = Parser::new(Limits::default());
    let mut count = 0usize;

    println!("Parsing archive ({} bytes)...\n", data.len());

    loop {
        // Fill buffer - in async, this would `.await`
        buf.fill(HEADER_SIZE)?;

        // Parse the next event
        let event = parser
            .parse(buf.data())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match event {
            ParseEvent::NeedData { min_bytes } => {
                // Need more data - fill buffer and retry
                // In async, this is where we'd yield if data isn't ready
                if !buf.fill(min_bytes)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ));
                }
            }

            ParseEvent::Entry {
                consumed,
                ref entry,
            } => {
                let info = EntryInfo::from_parsed(entry);
                buf.consume(consumed);
                count += 1;
                print_entry(&info);

                // Handle content - in async, skip would `.await`
                let size = info.size;
                let padded = size.next_multiple_of(HEADER_SIZE as u64) as usize;
                buf.skip(padded)?;

                // Update parser state
                parser.advance_content(size).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
            }

            ParseEvent::End { consumed } => {
                buf.consume(consumed);
                println!("\nArchive complete: {count} entries");
                break;
            }
        }
    }

    Ok(())
}

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

        // UID/GID: 0
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");

        // Size
        let size_str = format!("{:011o}", size);
        header[124..135].copy_from_slice(size_str.as_bytes());

        // Mtime: 0
        header[136..147].copy_from_slice(b"00000000000");

        // Typeflag
        header[156] = typeflag;

        // UStar magic
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

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

fn main() {
    println!("=== Sans-IO Async Parser Demo ===\n");
    println!("This demonstrates how the same Parser type can be used");
    println!("for both synchronous and asynchronous tar parsing.\n");
    println!("Key insight: Parser::parse() is pure computation on byte slices.");
    println!("All I/O (sync or async) is handled by the wrapper.\n");
    println!("---\n");

    let archive = create_test_archive();
    if let Err(e) = process_archive(&archive) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
