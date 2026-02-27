//! Synchronous tar parser example using the sans-IO parser with std::io::Read.
//!
//! This demonstrates how the sans-IO [`Parser`] can be wrapped for synchronous I/O,
//! similar to how tar-rs would use it internally.
//!
//! # Usage
//!
//! ```sh
//! # Parse a tar file
//! cargo run -p tar-core --example sync_parser -- archive.tar
//!
//! # Or pipe from stdin
//! cat archive.tar | cargo run -p tar-core --example sync_parser
//! ```

use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};

use tar_core::parse::{ParseEvent, Parser};
use tar_core::stream::Limits;
use tar_core::HEADER_SIZE;

/// A buffer that can be filled from a reader.
///
/// This is separate from the parser to avoid borrow checker issues.
struct ReadBuffer<R> {
    reader: R,
    buffer: Vec<u8>,
    /// Start of unprocessed data in buffer
    start: usize,
    /// End of valid data in buffer
    end: usize,
    /// Whether we've hit EOF on the reader
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

    /// Get the current unprocessed data in the buffer.
    fn data(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    /// Compact the buffer by moving unprocessed data to the front.
    fn compact(&mut self) {
        if self.start > 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// Advance past `n` bytes in the buffer.
    fn consume(&mut self, n: usize) {
        self.start += n;
    }

    /// Ensure we have at least `min_bytes` in the buffer.
    /// Returns true if we have enough data, false on EOF.
    fn fill(&mut self, min_bytes: usize) -> io::Result<bool> {
        // Already have enough?
        if self.end - self.start >= min_bytes {
            return Ok(true);
        }

        // Compact to make room
        self.compact();

        // Grow buffer if needed
        if self.buffer.len() < min_bytes {
            self.buffer.resize(min_bytes, 0);
        }

        // Read until we have enough or hit EOF
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

    /// Skip `n` bytes, reading more data as needed.
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

    /// Read exactly `n` bytes into output.
    fn read_exact_to(&mut self, mut n: usize, output: &mut Vec<u8>) -> io::Result<()> {
        output.clear();
        output.reserve(n);

        while n > 0 {
            self.fill(n.min(self.buffer.len()))?;
            let available = self.end - self.start;
            if available == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
            let to_read = n.min(available);
            output.extend_from_slice(&self.buffer[self.start..self.start + to_read]);
            self.consume(to_read);
            n -= to_read;
        }
        Ok(())
    }
}

/// Information extracted from a parsed entry.
///
/// We extract what we need from [`ParsedEntry`] before releasing the borrow
/// on the buffer, allowing us to mutate the reader afterwards.
struct EntryInfo {
    entry_type: tar_core::EntryType,
    mode: u32,
    size: u64,
    path: Vec<u8>,
    link_target: Option<Vec<u8>>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl EntryInfo {
    fn from_parsed(entry: &tar_core::parse::ParsedEntry<'_>) -> Self {
        Self {
            entry_type: entry.entry_type,
            mode: entry.mode,
            size: entry.size,
            path: entry.path.to_vec(),
            link_target: entry.link_target.as_ref().map(|t| t.to_vec()),
            xattrs: entry
                .xattrs
                .iter()
                .map(|(k, v)| (k.to_vec(), v.to_vec()))
                .collect(),
        }
    }
}

/// Process a tar archive, printing information about each entry.
fn process_archive<R: Read>(reader: R) -> io::Result<()> {
    let mut buf = ReadBuffer::new(reader);
    let mut parser = Parser::new(Limits::default());
    let mut entry_count = 0u64;
    let mut total_size = 0u64;
    let mut content_buf = Vec::new();

    loop {
        // Ensure we have data for parsing
        if !buf.fill(HEADER_SIZE)? {
            // Clean EOF at header boundary - this is valid
            if buf.data().is_empty() {
                println!("\n(Clean EOF - no end-of-archive marker)");
                break;
            }
        }

        // Parse the next event from the buffer
        let event = parser
            .parse(buf.data())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        match event {
            ParseEvent::NeedData { min_bytes } => {
                // Need more data - try to fill
                if !buf.fill(min_bytes)? {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("need {} bytes but got EOF", min_bytes),
                    ));
                }
                // Loop around to parse again with more data
            }

            ParseEvent::Entry {
                consumed,
                ref entry,
            } => {
                let info = EntryInfo::from_parsed(entry);
                buf.consume(consumed);
                entry_count += 1;
                total_size += info.size;

                // Print entry information
                let type_char = match info.entry_type {
                    tar_core::EntryType::Regular => '-',
                    tar_core::EntryType::Directory => 'd',
                    tar_core::EntryType::Symlink => 'l',
                    tar_core::EntryType::Link => 'h',
                    tar_core::EntryType::Char => 'c',
                    tar_core::EntryType::Block => 'b',
                    tar_core::EntryType::Fifo => 'p',
                    _ => '?',
                };

                print!("{}{:04o} {:>8} ", type_char, info.mode & 0o7777, info.size);

                // Print path (handle non-UTF8 gracefully)
                io::stdout().write_all(&info.path)?;

                // Print link target for symlinks
                let is_link = matches!(
                    info.entry_type,
                    tar_core::EntryType::Symlink | tar_core::EntryType::Link
                );
                if is_link {
                    if let Some(ref target) = info.link_target {
                        print!(" -> ");
                        io::stdout().write_all(target)?;
                    }
                }

                println!();

                // Print extended attributes if present
                for (name, value) in &info.xattrs {
                    print!("  xattr: ");
                    io::stdout().write_all(name)?;
                    print!(" = ");
                    // Only print value if it's short and printable
                    if value.len() <= 64 && value.iter().all(|&b| (0x20..0x7f).contains(&b)) {
                        io::stdout().write_all(value)?;
                    } else {
                        print!("({} bytes)", value.len());
                    }
                    println!();
                }

                // Handle content
                let size = info.size;
                let padded = size.next_multiple_of(HEADER_SIZE as u64) as usize;
                if size > 0 {
                    // For demonstration: read small files, skip large ones
                    if size <= 1024 * 1024 {
                        buf.read_exact_to(size as usize, &mut content_buf)?;
                        // Skip padding
                        let padding = padded - size as usize;
                        if padding > 0 {
                            buf.skip(padding)?;
                        }
                        // Could process content_buf here...
                    } else {
                        // Large files: skip content + padding
                        buf.skip(padded)?;
                    }
                }

                // Tell the parser we handled the content
                parser
                    .advance_content(size)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            }

            ParseEvent::End { consumed } => {
                buf.consume(consumed);
                println!("\n--- Archive Summary ---");
                println!("Entries: {}", entry_count);
                println!("Total content size: {} bytes", total_size);
                break;
            }
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        // Read from file
        let path = &args[1];
        println!("Parsing tar archive: {}\n", path);
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        process_archive(reader)?;
    } else {
        // Read from stdin
        eprintln!("Reading tar archive from stdin...\n");
        let stdin = io::stdin().lock();
        let reader = BufReader::new(stdin);
        process_archive(reader)?;
    }

    Ok(())
}
