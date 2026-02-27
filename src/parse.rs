//! Sans-IO tar archive parser.
//!
//! This module provides a sans-IO state machine parser for tar archives.
//! It operates on `&[u8]` slices directly (no `Read` trait bound), making
//! it suitable for:
//!
//! - Async I/O (tokio, async-std)
//! - Custom buffering strategies
//! - Zero-copy parsing in memory-mapped archives
//! - Embedding in other parsers
//!
//! In addition to the parser itself, this module contains the configuration
//! and error types it uses: [`Limits`] for security limits and [`ParseError`]
//! for error reporting.
//!
//! # Design
//!
//! The parser is a state machine that processes bytes and emits [`ParseEvent`]s.
//! The caller is responsible for:
//!
//! 1. Providing input data via [`Parser::parse`]
//! 2. Handling events (headers, content markers, end-of-archive)
//! 3. Managing the buffer and reading more data when needed
//!
//! # Example
//!
//! ```
//! use tar_core::parse::{Parser, ParseEvent, Limits};
//!
//! let mut parser = Parser::new(Limits::default());
//!
//! // Simulated tar data (in practice, read from file/network)
//! let data = [0u8; 1024]; // Two zero blocks = end of archive
//!
//! match parser.parse(&data) {
//!     Ok(ParseEvent::End { consumed }) => {
//!         println!("End of archive after {} bytes", consumed);
//!     }
//!     Ok(event) => {
//!         println!("Got event {:?}", event);
//!     }
//!     Err(e) => {
//!         eprintln!("Parse error: {}", e);
//!     }
//! }
//! ```

use std::borrow::Cow;
use std::str::Utf8Error;

use thiserror::Error;

use crate::{
    EntryType, Header, HeaderError, PaxError, PaxExtensions, HEADER_SIZE, PAX_GID, PAX_GNAME,
    PAX_LINKPATH, PAX_MTIME, PAX_PATH, PAX_SCHILY_XATTR, PAX_SIZE, PAX_UID, PAX_UNAME,
};

// ============================================================================
// Limits
// ============================================================================

/// Configurable security limits for tar archive parsing.
///
/// These limits protect against malicious or malformed archives that could
/// exhaust memory or create excessively long paths.
///
/// # Example
///
/// ```
/// use tar_core::parse::Limits;
///
/// // Use defaults
/// let limits = Limits::default();
///
/// // Customize limits
/// let strict_limits = Limits {
///     max_path_len: 1024,
///     max_pax_size: 64 * 1024,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum path length in bytes.
    ///
    /// Applies to both file paths and link targets. Paths exceeding this
    /// limit will cause a [`ParseError::PathTooLong`] error.
    ///
    /// Default: 4096 bytes (Linux PATH_MAX).
    pub max_path_len: usize,

    /// Maximum size of PAX extended header data in bytes.
    ///
    /// This limits the total size of a single PAX 'x' entry's content.
    /// PAX headers larger than this will cause a [`ParseError::PaxTooLarge`] error.
    ///
    /// Default: 1 MiB (1,048,576 bytes).
    pub max_pax_size: u64,

    /// Maximum size of GNU long name/link data in bytes.
    ///
    /// GNU 'L' (long name) and 'K' (long link) entries should only contain
    /// a single path. Values exceeding this limit will cause a
    /// [`ParseError::GnuLongTooLarge`] error.
    ///
    /// Default: 4096 bytes.
    pub max_gnu_long_size: u64,

    /// Maximum number of consecutive metadata entries before an actual entry.
    ///
    /// Prevents infinite loops from malformed archives that contain only
    /// metadata entries (GNU long name, PAX headers) without actual file entries.
    /// Exceeding this limit will cause a [`ParseError::TooManyPendingEntries`] error.
    ///
    /// Default: 16 entries.
    pub max_pending_entries: usize,

    /// When true, PAX extension values that fail to parse (invalid UTF-8,
    /// invalid integer for numeric fields like `uid`, `gid`, `size`, `mtime`)
    /// cause errors instead of being silently ignored.
    ///
    /// Default: `true`.
    pub strict: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_path_len: 4096,
            max_pax_size: 1024 * 1024, // 1 MiB
            max_gnu_long_size: 4096,
            max_pending_entries: 16,
            strict: true,
        }
    }
}

impl Limits {
    /// Create a new `Limits` with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create permissive limits suitable for trusted archives.
    ///
    /// This sets very high limits that effectively disable most checks.
    /// Only use this for archives from trusted sources.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            max_path_len: usize::MAX,
            max_pax_size: u64::MAX,
            max_gnu_long_size: u64::MAX,
            max_pending_entries: usize::MAX,
            strict: false,
        }
    }

    /// Create strict limits suitable for untrusted archives.
    ///
    /// This sets conservative limits to minimize resource consumption
    /// from potentially malicious archives.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_path_len: 1024,
            max_pax_size: 64 * 1024, // 64 KiB
            max_gnu_long_size: 1024,
            max_pending_entries: 8,
            strict: true,
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during tar archive parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    /// I/O error from the underlying reader.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Header parsing error (checksum, invalid octal, etc.).
    #[error("header error: {0}")]
    Header(#[from] HeaderError),

    /// PAX extension parsing error.
    #[error("PAX error: {0}")]
    Pax(#[from] PaxError),

    /// Invalid UTF-8 in PAX key.
    #[error("invalid UTF-8 in PAX key: {0}")]
    InvalidUtf8(#[from] Utf8Error),

    /// Path exceeds configured maximum length.
    #[error("path exceeds limit: {len} bytes > {limit} bytes")]
    PathTooLong {
        /// Actual path length.
        len: usize,
        /// Configured limit.
        limit: usize,
    },

    /// PAX extended header exceeds configured maximum size.
    #[error("PAX header exceeds limit: {size} bytes > {limit} bytes")]
    PaxTooLarge {
        /// Actual PAX header size.
        size: u64,
        /// Configured limit.
        limit: u64,
    },

    /// GNU long name/link exceeds configured maximum size.
    #[error("GNU long name/link exceeds limit: {size} bytes > {limit} bytes")]
    GnuLongTooLarge {
        /// Actual GNU long name/link size.
        size: u64,
        /// Configured limit.
        limit: u64,
    },

    /// Duplicate GNU long name entry without an intervening actual entry.
    #[error("duplicate GNU long name entry")]
    DuplicateGnuLongName,

    /// Duplicate GNU long link entry without an intervening actual entry.
    #[error("duplicate GNU long link entry")]
    DuplicateGnuLongLink,

    /// Duplicate PAX extended header without an intervening actual entry.
    #[error("duplicate PAX extended header")]
    DuplicatePaxHeader,

    /// Metadata entries (GNU long name, PAX, etc.) found but no actual entry followed.
    #[error("metadata entries without a following actual entry")]
    OrphanedMetadata,

    /// Too many consecutive metadata entries (possible infinite loop or malicious archive).
    #[error("too many pending metadata entries: {count} > {limit}")]
    TooManyPendingEntries {
        /// Number of pending metadata entries.
        count: usize,
        /// Configured limit.
        limit: usize,
    },

    /// A PAX extension value failed to parse in strict mode.
    #[error("invalid PAX {key} value: {value:?}")]
    InvalidPaxValue {
        /// The PAX key (e.g. "uid", "size").
        key: &'static str,
        /// The raw value string.
        value: String,
    },

    /// Entry size in header is invalid (e.g., overflow when computing padded size).
    #[error("invalid entry size: {0}")]
    InvalidSize(u64),

    /// Unexpected EOF while reading entry content or padding.
    #[error("unexpected EOF at position {pos}")]
    UnexpectedEof {
        /// Position in the stream where EOF occurred.
        pos: u64,
    },
}

/// Result type for parsing operations.
pub type Result<T> = std::result::Result<T, ParseError>;

// ============================================================================
// Parser
// ============================================================================

/// Events emitted by the sans-IO parser.
#[derive(Debug)]
pub enum ParseEvent<'a> {
    /// Need more data to continue parsing.
    ///
    /// No bytes are consumed from the input when this event is returned.
    /// The caller should ensure at least `min_bytes` bytes are available
    /// before calling `parse` again with the same (or larger) buffer.
    NeedData {
        /// Minimum number of bytes needed to make progress.
        min_bytes: usize,
    },

    /// A complete entry header has been parsed.
    ///
    /// The entry contains resolved metadata (path, link target, etc.) with
    /// GNU long name/link and PAX extensions applied.
    ///
    /// After this event, the caller must:
    /// 1. Read/skip `entry.size` bytes of content from the input
    /// 2. Read/skip padding bytes to reach the next 512-byte boundary
    /// 3. Call `advance_content(entry.size)` to update parser state
    Entry {
        /// Number of bytes consumed from the input for this entry's header(s).
        consumed: usize,
        /// The parsed entry with resolved metadata.
        entry: ParsedEntry<'a>,
    },

    /// Archive end marker reached (two consecutive zero blocks, or clean EOF).
    End {
        /// Number of bytes consumed from the input.
        consumed: usize,
    },
}

impl<'a> ParseEvent<'a> {
    /// Add `n` to the consumed byte count in this event.
    ///
    /// Used when recursing through extension headers to accumulate the total
    /// bytes consumed. `NeedData` is unchanged because no bytes are committed
    /// when the parser needs more input (it will re-parse from the start).
    fn add_consumed(self, n: usize) -> Self {
        match self {
            ev @ ParseEvent::NeedData { .. } => ev,
            ParseEvent::Entry { consumed, entry } => ParseEvent::Entry {
                consumed: consumed + n,
                entry,
            },
            ParseEvent::End { consumed } => ParseEvent::End {
                consumed: consumed + n,
            },
        }
    }
}

/// A fully-resolved tar entry with all extensions applied.
///
/// Borrowed data comes from the input slice, so the entry is valid only
/// as long as the input buffer is live.
#[derive(Debug)]
pub struct ParsedEntry<'a> {
    /// The raw 512-byte header.
    pub header: &'a Header,

    /// The entry type (Regular, Directory, Symlink, etc.).
    pub entry_type: EntryType,

    /// The resolved file path.
    ///
    /// Priority: PAX `path` > GNU long name > header `name` (+ UStar `prefix`).
    pub path: Cow<'a, [u8]>,

    /// The resolved link target (for symlinks and hardlinks).
    ///
    /// Priority: PAX `linkpath` > GNU long link > header `linkname`.
    pub link_target: Option<Cow<'a, [u8]>>,

    /// File mode/permissions.
    pub mode: u32,

    /// Owner UID.
    pub uid: u64,

    /// Owner GID.
    pub gid: u64,

    /// Modification time as Unix timestamp.
    pub mtime: u64,

    /// Content size in bytes.
    pub size: u64,

    /// User name.
    pub uname: Option<Cow<'a, [u8]>>,

    /// Group name.
    pub gname: Option<Cow<'a, [u8]>>,

    /// Device major number (for block/char devices).
    pub dev_major: Option<u32>,

    /// Device minor number (for block/char devices).
    pub dev_minor: Option<u32>,

    /// Extended attributes from PAX `SCHILY.xattr.*` entries.
    #[allow(clippy::type_complexity)]
    pub xattrs: Vec<(Cow<'a, [u8]>, Cow<'a, [u8]>)>,
}

impl<'a> ParsedEntry<'a> {
    /// Get the path as a lossy UTF-8 string.
    #[must_use]
    pub fn path_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.path)
    }

    /// Get the link target as a lossy UTF-8 string, if present.
    #[must_use]
    pub fn link_target_lossy(&self) -> Option<Cow<'_, str>> {
        self.link_target
            .as_ref()
            .map(|t| String::from_utf8_lossy(t))
    }

    /// Check if this is a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.entry_type.is_file()
    }

    /// Check if this is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.entry_type.is_dir()
    }

    /// Check if this is a symbolic link.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.entry_type.is_symlink()
    }

    /// Check if this is a hard link.
    #[must_use]
    pub fn is_hard_link(&self) -> bool {
        self.entry_type.is_hard_link()
    }

    /// Get the padded size (rounded up to block boundary).
    #[must_use]
    pub fn padded_size(&self) -> u64 {
        self.size.next_multiple_of(HEADER_SIZE as u64)
    }
}

/// Internal parser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting to read a header.
    ReadHeader,
    /// Waiting to read content (after emitting Entry event).
    /// The u64 is the padded size we're waiting for.
    ReadContent { padded_size: u64 },
    /// Archive is complete.
    Done,
}

/// Pending metadata from GNU/PAX extension entries.
#[derive(Debug, Default)]
struct PendingMetadata {
    gnu_long_name: Option<Vec<u8>>,
    gnu_long_link: Option<Vec<u8>>,
    pax_extensions: Option<Vec<u8>>,
    count: usize,
}

impl PendingMetadata {
    fn is_empty(&self) -> bool {
        self.gnu_long_name.is_none()
            && self.gnu_long_link.is_none()
            && self.pax_extensions.is_none()
    }

    fn clear(&mut self) {
        self.gnu_long_name = None;
        self.gnu_long_link = None;
        self.pax_extensions = None;
        self.count = 0;
    }
}

/// Sans-IO tar archive parser.
///
/// This parser operates as a state machine on `&[u8]` input slices.
/// It does not perform any I/O itself - the caller is responsible for
/// providing data and handling the parsed events.
///
/// # State Machine
///
/// The parser cycles through states:
///
/// 1. **ReadHeader**: Waiting for a 512-byte header block
/// 2. **ReadContent**: Waiting for content + padding bytes
/// 3. **Done**: Archive complete
///
/// # Usage Pattern
///
/// ```ignore
/// let mut parser = Parser::new(Limits::default());
/// let mut buf = vec![0u8; 65536];
/// let mut filled = 0;
///
/// loop {
///     // Try to parse from current buffer
///     match parser.parse(&buf[..filled]) {
///         Ok(ParseEvent::NeedData { min_bytes }) => {
///             // Need more data - read into buffer
///             let n = read_more(&mut buf[filled..])?;
///             filled += n;
///             if n == 0 && filled < min_bytes {
///                 return Err("unexpected EOF");
///             }
///         }
///         Ok(ParseEvent::Entry { consumed, entry }) => {
///             process_entry(&entry);
///             let content_size = entry.size;
///             // ... handle content ...
///             parser.advance_content(content_size)?;
///         }
///         Ok(ParseEvent::End { .. }) => break,
///         Err(e) => return Err(e),
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Parser {
    limits: Limits,
    state: State,
    pending: PendingMetadata,
    /// Count of consecutive zero blocks seen.
    zero_blocks: u8,
}

impl Parser {
    /// Create a new parser with the given limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: State::ReadHeader,
            pending: PendingMetadata::default(),
            zero_blocks: 0,
        }
    }

    /// Create a new parser with default limits.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Limits::default())
    }

    /// Get the current limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Check if the parser is done (archive complete).
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Parse the next event from the input buffer.
    ///
    /// Returns a [`ParseEvent`] on success. `Entry` and `End` events include
    /// a `consumed` field indicating how many bytes were consumed from the
    /// input; the caller should advance past that many bytes in their buffer.
    ///
    /// # Events
    ///
    /// - `NeedData { min_bytes }`: Need at least `min_bytes` more data (nothing consumed)
    /// - `Entry { consumed, entry }`: A complete entry header; caller must handle content
    /// - `End { consumed }`: Archive is complete
    ///
    /// # Content Handling
    ///
    /// After receiving an `Entry` event, the caller is responsible for:
    /// 1. Processing `entry.size` bytes of content from their buffer
    /// 2. Skipping padding to reach the next 512-byte boundary
    /// 3. Calling `advance_content(entry.size)` to transition the parser
    ///
    /// The content bytes are NOT consumed by this method - they remain in
    /// the caller's buffer for processing.
    pub fn parse<'a>(&mut self, input: &'a [u8]) -> Result<ParseEvent<'a>> {
        match self.state {
            State::Done => Ok(ParseEvent::End { consumed: 0 }),

            State::ReadContent { padded_size } => {
                // Caller hasn't called advance_content yet
                // Return NeedData with the remaining content size
                Ok(ParseEvent::NeedData {
                    min_bytes: padded_size as usize,
                })
            }

            State::ReadHeader => self.parse_header(input),
        }
    }

    /// Advance past entry content after processing.
    ///
    /// Call this after handling an `Entry` event and consuming/skipping
    /// the entry's content and padding bytes.
    ///
    /// # Arguments
    ///
    /// * `content_size` - The `entry.size` from the Entry event
    ///
    /// # Errors
    ///
    /// Returns an error if the parser is not in the ReadContent state.
    pub fn advance_content(&mut self, content_size: u64) -> Result<()> {
        match self.state {
            State::ReadContent { padded_size } => {
                // Verify the caller is advancing the expected amount
                let expected_padded = content_size.next_multiple_of(HEADER_SIZE as u64);
                debug_assert_eq!(
                    expected_padded, padded_size,
                    "advance_content called with size {content_size} but parser expected padded size {padded_size}"
                );
                self.state = State::ReadHeader;
                Ok(())
            }
            State::ReadHeader | State::Done => {
                // Not in content state - this may happen if caller skips content
                // for empty entries, which is fine
                debug_assert!(
                    content_size == 0,
                    "advance_content called in {:?} state with non-zero size {content_size}",
                    self.state
                );
                Ok(())
            }
        }
    }

    /// Parse a header from the input.
    fn parse_header<'a>(&mut self, input: &'a [u8]) -> Result<ParseEvent<'a>> {
        // Need at least one header block
        if input.len() < HEADER_SIZE {
            return Ok(ParseEvent::NeedData {
                min_bytes: HEADER_SIZE,
            });
        }

        // Check for zero block (end of archive marker)
        let header_bytes = &input[..HEADER_SIZE];
        if header_bytes.iter().all(|&b| b == 0) {
            self.zero_blocks += 1;
            if self.zero_blocks >= 2 {
                self.state = State::Done;
                if !self.pending.is_empty() {
                    return Err(ParseError::OrphanedMetadata);
                }
                return Ok(ParseEvent::End {
                    consumed: HEADER_SIZE,
                });
            }
            // First zero block - need to check for second
            if input.len() < 2 * HEADER_SIZE {
                return Ok(ParseEvent::NeedData {
                    min_bytes: 2 * HEADER_SIZE,
                });
            }
            // Check second block
            let second_block = &input[HEADER_SIZE..2 * HEADER_SIZE];
            if second_block.iter().all(|&b| b == 0) {
                self.state = State::Done;
                if !self.pending.is_empty() {
                    return Err(ParseError::OrphanedMetadata);
                }
                return Ok(ParseEvent::End {
                    consumed: 2 * HEADER_SIZE,
                });
            }
            // Not end of archive - continue with second block as header
            // (this handles archives with single zero blocks mid-stream)
            self.zero_blocks = 0;
            return self
                .parse_header(&input[HEADER_SIZE..])
                .map(|e| e.add_consumed(HEADER_SIZE));
        }

        self.zero_blocks = 0;

        // Check pending entry limit
        if self.pending.count > self.limits.max_pending_entries {
            return Err(ParseError::TooManyPendingEntries {
                count: self.pending.count,
                limit: self.limits.max_pending_entries,
            });
        }

        // Parse header
        let header = Header::from_bytes(header_bytes)?;
        header.verify_checksum()?;

        let entry_type = header.entry_type();
        let size = header.entry_size()?;
        let padded_size = size
            .checked_next_multiple_of(HEADER_SIZE as u64)
            .ok_or(ParseError::InvalidSize(size))?;

        // Handle metadata entry types
        match entry_type {
            EntryType::GnuLongName => self.handle_gnu_long_name(input, size, padded_size),
            EntryType::GnuLongLink => self.handle_gnu_long_link(input, size, padded_size),
            EntryType::XHeader => self.handle_pax_header(input, size, padded_size),
            EntryType::XGlobalHeader => {
                // Skip global PAX headers
                let total_size = HEADER_SIZE as u64 + padded_size;
                if (input.len() as u64) < total_size {
                    return Ok(ParseEvent::NeedData {
                        min_bytes: total_size as usize,
                    });
                }
                // Recurse to parse next header
                self.parse_header(&input[total_size as usize..])
                    .map(|e| e.add_consumed(total_size as usize))
            }
            _ => {
                // Actual entry - resolve metadata and emit
                self.emit_entry(header, size)
            }
        }
    }

    fn handle_gnu_long_name<'a>(
        &mut self,
        input: &'a [u8],
        size: u64,
        padded_size: u64,
    ) -> Result<ParseEvent<'a>> {
        // Check for duplicate
        if self.pending.gnu_long_name.is_some() {
            return Err(ParseError::DuplicateGnuLongName);
        }

        // Check size limit
        if size > self.limits.max_gnu_long_size {
            return Err(ParseError::GnuLongTooLarge {
                size,
                limit: self.limits.max_gnu_long_size,
            });
        }

        let total_size = HEADER_SIZE as u64 + padded_size;
        if (input.len() as u64) < total_size {
            return Ok(ParseEvent::NeedData {
                min_bytes: total_size as usize,
            });
        }

        // Extract content
        let content_start = HEADER_SIZE;
        let content_end = content_start + size as usize;
        let mut data = input[content_start..content_end].to_vec();

        // Strip trailing null
        if data.last() == Some(&0) {
            data.pop();
        }

        // Check path length
        if data.len() > self.limits.max_path_len {
            return Err(ParseError::PathTooLong {
                len: data.len(),
                limit: self.limits.max_path_len,
            });
        }

        self.pending.gnu_long_name = Some(data);
        self.pending.count += 1;

        // Recurse to parse next header
        self.parse_header(&input[total_size as usize..])
            .map(|e| e.add_consumed(total_size as usize))
    }

    fn handle_gnu_long_link<'a>(
        &mut self,
        input: &'a [u8],
        size: u64,
        padded_size: u64,
    ) -> Result<ParseEvent<'a>> {
        // Check for duplicate
        if self.pending.gnu_long_link.is_some() {
            return Err(ParseError::DuplicateGnuLongLink);
        }

        // Check size limit
        if size > self.limits.max_gnu_long_size {
            return Err(ParseError::GnuLongTooLarge {
                size,
                limit: self.limits.max_gnu_long_size,
            });
        }

        let total_size = HEADER_SIZE as u64 + padded_size;
        if (input.len() as u64) < total_size {
            return Ok(ParseEvent::NeedData {
                min_bytes: total_size as usize,
            });
        }

        // Extract content
        let content_start = HEADER_SIZE;
        let content_end = content_start + size as usize;
        let mut data = input[content_start..content_end].to_vec();

        // Strip trailing null
        if data.last() == Some(&0) {
            data.pop();
        }

        // Check path length
        if data.len() > self.limits.max_path_len {
            return Err(ParseError::PathTooLong {
                len: data.len(),
                limit: self.limits.max_path_len,
            });
        }

        self.pending.gnu_long_link = Some(data);
        self.pending.count += 1;

        // Recurse to parse next header
        self.parse_header(&input[total_size as usize..])
            .map(|e| e.add_consumed(total_size as usize))
    }

    fn handle_pax_header<'a>(
        &mut self,
        input: &'a [u8],
        size: u64,
        padded_size: u64,
    ) -> Result<ParseEvent<'a>> {
        // Check for duplicate
        if self.pending.pax_extensions.is_some() {
            return Err(ParseError::DuplicatePaxHeader);
        }

        // Check size limit
        if size > self.limits.max_pax_size {
            return Err(ParseError::PaxTooLarge {
                size,
                limit: self.limits.max_pax_size,
            });
        }

        let total_size = HEADER_SIZE as u64 + padded_size;
        if (input.len() as u64) < total_size {
            return Ok(ParseEvent::NeedData {
                min_bytes: total_size as usize,
            });
        }

        // Extract content
        let content_start = HEADER_SIZE;
        let content_end = content_start + size as usize;
        let data = input[content_start..content_end].to_vec();

        self.pending.pax_extensions = Some(data);
        self.pending.count += 1;

        // Recurse to parse next header
        self.parse_header(&input[total_size as usize..])
            .map(|e| e.add_consumed(total_size as usize))
    }

    fn emit_entry<'a>(&mut self, header: &'a Header, size: u64) -> Result<ParseEvent<'a>> {
        // Start with header values
        let mut path: Cow<'a, [u8]> = Cow::Borrowed(header.path_bytes());
        let mut link_target: Option<Cow<'a, [u8]>> = None;
        let mut uid = header.uid()?;
        let mut gid = header.gid()?;
        let mut mtime = header.mtime()?;
        let mut entry_size = size;
        let mut xattrs = Vec::new();
        let mut uname: Option<Cow<'a, [u8]>> = header.username().map(Cow::Borrowed);
        let mut gname: Option<Cow<'a, [u8]>> = header.groupname().map(Cow::Borrowed);

        // Handle UStar prefix for path
        if let Some(prefix) = header.prefix() {
            if !prefix.is_empty() {
                let mut full_path = prefix.to_vec();
                full_path.push(b'/');
                full_path.extend_from_slice(header.path_bytes());
                path = Cow::Owned(full_path);
            }
        }

        // Apply GNU long name (overrides header + prefix)
        if let Some(long_name) = self.pending.gnu_long_name.take() {
            path = Cow::Owned(long_name);
        }

        // Apply GNU long link
        if let Some(long_link) = self.pending.gnu_long_link.take() {
            link_target = Some(Cow::Owned(long_link));
        } else {
            let header_link = header.link_name_bytes();
            if !header_link.is_empty() {
                link_target = Some(Cow::Borrowed(header_link));
            }
        }

        // Apply PAX extensions (highest priority)
        if let Some(ref pax) = self.pending.pax_extensions {
            let strict = self.limits.strict;
            let extensions = PaxExtensions::new(pax);

            // Helper: parse a PAX numeric value, returning Err in strict mode
            // or Ok(None) in lenient mode when the value is unparseable.
            let parse_pax_u64 =
                |ext: &crate::PaxExtension<'_>, key: &'static str| -> Result<Option<u64>> {
                    let s = match ext.value() {
                        Ok(s) => s,
                        Err(_) if !strict => return Ok(None),
                        Err(_) => {
                            return Err(ParseError::InvalidPaxValue {
                                key,
                                value: String::from_utf8_lossy(ext.value_bytes()).into(),
                            })
                        }
                    };
                    match s.parse::<u64>() {
                        Ok(v) => Ok(Some(v)),
                        Err(_) if !strict => Ok(None),
                        Err(_) => Err(ParseError::InvalidPaxValue {
                            key,
                            value: s.into(),
                        }),
                    }
                };

            for ext in extensions {
                let ext = ext?;
                let key = ext.key().map_err(ParseError::from)?;
                let value = ext.value_bytes();

                match key {
                    PAX_PATH => {
                        if value.len() > self.limits.max_path_len {
                            return Err(ParseError::PathTooLong {
                                len: value.len(),
                                limit: self.limits.max_path_len,
                            });
                        }
                        path = Cow::Owned(value.to_vec());
                    }
                    PAX_LINKPATH => {
                        if value.len() > self.limits.max_path_len {
                            return Err(ParseError::PathTooLong {
                                len: value.len(),
                                limit: self.limits.max_path_len,
                            });
                        }
                        link_target = Some(Cow::Owned(value.to_vec()));
                    }
                    PAX_SIZE => {
                        if let Some(v) = parse_pax_u64(&ext, PAX_SIZE)? {
                            entry_size = v;
                        }
                    }
                    PAX_UID => {
                        if let Some(v) = parse_pax_u64(&ext, PAX_UID)? {
                            uid = v;
                        }
                    }
                    PAX_GID => {
                        if let Some(v) = parse_pax_u64(&ext, PAX_GID)? {
                            gid = v;
                        }
                    }
                    PAX_MTIME => {
                        // mtime may have fractional seconds (e.g. "1234567890.5");
                        // parse only the integer part.
                        let s = match ext.value() {
                            Ok(s) => s,
                            Err(_) if !strict => continue,
                            Err(_) => {
                                return Err(ParseError::InvalidPaxValue {
                                    key: PAX_MTIME,
                                    value: String::from_utf8_lossy(value).into(),
                                })
                            }
                        };
                        let int_part = s.split('.').next().unwrap_or(s);
                        match int_part.parse::<u64>() {
                            Ok(v) => mtime = v,
                            Err(_) if !strict => {}
                            Err(_) => {
                                return Err(ParseError::InvalidPaxValue {
                                    key: PAX_MTIME,
                                    value: s.into(),
                                })
                            }
                        }
                    }
                    PAX_UNAME => {
                        uname = Some(Cow::Owned(value.to_vec()));
                    }
                    PAX_GNAME => {
                        gname = Some(Cow::Owned(value.to_vec()));
                    }
                    _ => {
                        if let Some(attr_name) = key.strip_prefix(PAX_SCHILY_XATTR) {
                            xattrs.push((
                                Cow::Owned(attr_name.as_bytes().to_vec()),
                                Cow::Owned(value.to_vec()),
                            ));
                        }
                    }
                }
            }
        }

        // Clear pending metadata
        self.pending.clear();

        // Validate final path length
        if path.len() > self.limits.max_path_len {
            return Err(ParseError::PathTooLong {
                len: path.len(),
                limit: self.limits.max_path_len,
            });
        }

        // Update state to expect content
        let content_padded = entry_size.next_multiple_of(HEADER_SIZE as u64);
        self.state = State::ReadContent {
            padded_size: content_padded,
        };

        let entry = ParsedEntry {
            header,
            entry_type: header.entry_type(),
            path,
            link_target,
            mode: header.mode()?,
            uid,
            gid,
            mtime,
            size: entry_size,
            uname,
            gname,
            dev_major: header.device_major()?,
            dev_minor: header.device_minor()?,
            xattrs,
        };

        // Only consume the header - content is left for caller
        Ok(ParseEvent::Entry {
            consumed: HEADER_SIZE,
            entry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{USTAR_MAGIC, USTAR_VERSION};

    #[test]
    fn test_default_limits() {
        let limits = Limits::default();
        assert_eq!(limits.max_path_len, 4096);
        assert_eq!(limits.max_pax_size, 1024 * 1024);
        assert_eq!(limits.max_gnu_long_size, 4096);
        assert_eq!(limits.max_pending_entries, 16);
    }

    #[test]
    fn test_permissive_limits() {
        let limits = Limits::permissive();
        assert_eq!(limits.max_path_len, usize::MAX);
        assert_eq!(limits.max_pax_size, u64::MAX);
    }

    #[test]
    fn test_strict_limits() {
        let limits = Limits::strict();
        assert!(limits.max_path_len < Limits::default().max_path_len);
        assert!(limits.max_pax_size < Limits::default().max_pax_size);
    }

    #[test]
    fn test_parser_empty_archive() {
        let mut parser = Parser::new(Limits::default());

        // Two zero blocks = end of archive
        let data = [0u8; 1024];

        let event = parser.parse(&data).unwrap();
        assert!(matches!(event, ParseEvent::End { consumed: 1024 }));
        assert!(parser.is_done());
    }

    #[test]
    fn test_parser_need_data() {
        let mut parser = Parser::new(Limits::default());

        // Not enough data for a header
        let data = [0u8; 256];

        let event = parser.parse(&data).unwrap();
        assert!(matches!(event, ParseEvent::NeedData { min_bytes: 512 }));
    }

    #[test]
    fn test_parser_need_more_for_end() {
        let mut parser = Parser::new(Limits::default());

        // One zero block - need second to confirm end
        let data = [0u8; 512];

        let event = parser.parse(&data).unwrap();
        assert!(matches!(event, ParseEvent::NeedData { min_bytes: 1024 }));
    }

    #[test]
    fn test_parser_with_real_header() {
        let mut parser = Parser::new(Limits::default());

        // Create a minimal valid tar header
        let mut data = vec![0u8; 2048];

        // Set up header at offset 0
        // name: "test.txt"
        data[0..8].copy_from_slice(b"test.txt");
        // mode: 0000644
        data[100..107].copy_from_slice(b"0000644");
        // uid: 0
        data[108..115].copy_from_slice(b"0000000");
        // gid: 0
        data[116..123].copy_from_slice(b"0000000");
        // size: 0 (empty file)
        data[124..135].copy_from_slice(b"00000000000");
        // mtime: 0
        data[136..147].copy_from_slice(b"00000000000");
        // typeflag: '0' (regular file)
        data[156] = b'0';
        // magic: "ustar\0"
        data[257..263].copy_from_slice(USTAR_MAGIC);
        // version: "00"
        data[263..265].copy_from_slice(USTAR_VERSION);

        // Compute and set checksum
        let header = Header::from_bytes(&data[..512]).unwrap();
        let checksum = header.compute_checksum();
        let checksum_str = format!("{checksum:06o}\0 ");
        data[148..156].copy_from_slice(checksum_str.as_bytes());

        // Two zero blocks at the end
        // data[512..1536] is already zeros

        let event = parser.parse(&data).unwrap();
        match event {
            ParseEvent::Entry { consumed, entry } => {
                assert_eq!(consumed, 512);
                assert_eq!(entry.path_lossy(), "test.txt");
                assert_eq!(entry.size, 0);
                assert!(entry.is_file());
            }
            other => panic!("Expected Entry, got {:?}", other),
        }

        // Advance past content (size 0, so padded_size is also 0)
        parser.advance_content(0).unwrap();

        // Now parse end
        let event = parser.parse(&data[512..]).unwrap();
        assert!(matches!(event, ParseEvent::End { consumed: 1024 }));
    }

    #[test]
    fn test_parser_entry_with_content() {
        let mut parser = Parser::new(Limits::default());

        // Create a tar with a file containing "hello"
        let mut data = vec![0u8; 2560]; // header + content block + 2 zero blocks

        // Header
        data[0..8].copy_from_slice(b"test.txt");
        data[100..107].copy_from_slice(b"0000644");
        data[108..115].copy_from_slice(b"0000000");
        data[116..123].copy_from_slice(b"0000000");
        data[124..135].copy_from_slice(b"00000000005"); // size = 5
        data[136..147].copy_from_slice(b"00000000000");
        data[156] = b'0';
        data[257..263].copy_from_slice(USTAR_MAGIC);
        data[263..265].copy_from_slice(USTAR_VERSION);

        // Checksum
        let header = Header::from_bytes(&data[..512]).unwrap();
        let checksum = header.compute_checksum();
        let checksum_str = format!("{checksum:06o}\0 ");
        data[148..156].copy_from_slice(checksum_str.as_bytes());

        // Content at 512..517
        data[512..517].copy_from_slice(b"hello");

        let event = parser.parse(&data).unwrap();
        match event {
            ParseEvent::Entry { consumed, entry } => {
                assert_eq!(consumed, 512);
                assert_eq!(entry.path_lossy(), "test.txt");
                assert_eq!(entry.size, 5);
                assert_eq!(entry.padded_size(), 512);
            }
            other => panic!("Expected Entry, got {:?}", other),
        }

        // Content starts at data[512], size 5, padded to 512
        // Caller would read data[512..517] for content
        // Then call advance_content(5) to move past
        parser.advance_content(5).unwrap();

        // Parse end (zero blocks at 1024..2048)
        let event = parser.parse(&data[1024..]).unwrap();
        assert!(matches!(event, ParseEvent::End { consumed: 1024 }));
    }

    // =========================================================================
    // Helper functions for building test tar archives
    // =========================================================================

    /// Create a valid tar header with computed checksum.
    ///
    /// # Arguments
    /// * `name` - File name (max 100 bytes)
    /// * `size` - Content size in bytes
    /// * `typeflag` - Entry type (b'0' for regular, b'L' for GNU long name, etc.)
    fn make_header(name: &[u8], size: u64, typeflag: u8) -> [u8; HEADER_SIZE] {
        let mut header = [0u8; HEADER_SIZE];

        // name (0..100)
        let name_len = name.len().min(100);
        header[0..name_len].copy_from_slice(&name[..name_len]);

        // mode (100..108): 0000644
        header[100..107].copy_from_slice(b"0000644");

        // uid (108..116): 0001750 (1000 in octal)
        header[108..115].copy_from_slice(b"0001750");

        // gid (116..124): 0001750 (1000 in octal)
        header[116..123].copy_from_slice(b"0001750");

        // size (124..136): 11-digit octal
        let size_str = format!("{size:011o}");
        header[124..135].copy_from_slice(size_str.as_bytes());

        // mtime (136..148): arbitrary timestamp
        header[136..147].copy_from_slice(b"14712345670");

        // typeflag (156)
        header[156] = typeflag;

        // magic (257..263): "ustar\0"
        header[257..263].copy_from_slice(USTAR_MAGIC);

        // version (263..265): "00"
        header[263..265].copy_from_slice(USTAR_VERSION);

        // Compute and set checksum
        let hdr = Header::from_bytes(&header).unwrap();
        let checksum = hdr.compute_checksum();
        let checksum_str = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_str.as_bytes());

        header
    }

    /// Create a tar header with a link target (for symlinks/hardlinks).
    fn make_link_header(name: &[u8], link_target: &[u8], typeflag: u8) -> [u8; HEADER_SIZE] {
        let mut header = make_header(name, 0, typeflag);

        // linkname (157..257)
        let link_len = link_target.len().min(100);
        header[157..157 + link_len].copy_from_slice(&link_target[..link_len]);

        // Recompute checksum
        let hdr = Header::from_bytes(&header).unwrap();
        let checksum = hdr.compute_checksum();
        let checksum_str = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_str.as_bytes());

        header
    }

    /// Create a GNU long name entry (type 'L') with the given long name.
    ///
    /// Returns the complete entry: header + padded content.
    fn make_gnu_long_name(name: &[u8]) -> Vec<u8> {
        // GNU long name: content is the name with a trailing null
        let content_size = name.len() + 1; // +1 for null terminator
        let padded = content_size.next_multiple_of(HEADER_SIZE);
        let header = make_header(b"././@LongLink", content_size as u64, b'L');

        let mut result = Vec::with_capacity(HEADER_SIZE + padded);
        result.extend_from_slice(&header);
        result.extend_from_slice(name);
        result.push(0); // null terminator
        result.extend(zeroes(padded - content_size));

        result
    }

    /// Create a GNU long link entry (type 'K') with the given long link target.
    ///
    /// Returns the complete entry: header + padded content.
    fn make_gnu_long_link(link: &[u8]) -> Vec<u8> {
        let content_size = link.len() + 1; // +1 for null terminator
        let padded = content_size.next_multiple_of(HEADER_SIZE);
        let header = make_header(b"././@LongLink", content_size as u64, b'K');

        let mut result = Vec::with_capacity(HEADER_SIZE + padded);
        result.extend_from_slice(&header);
        result.extend_from_slice(link);
        result.push(0); // null terminator
        result.extend(zeroes(padded - content_size));

        result
    }

    /// Create a PAX extended header (type 'x') with the given key-value pairs.
    ///
    /// Returns the complete entry: header + padded content.
    fn make_pax_header(entries: &[(&str, &[u8])]) -> Vec<u8> {
        // Build PAX content: each record is "<length> <key>=<value>\n"
        let mut content = Vec::new();
        for (key, value) in entries {
            // Format: <length> <key>=<value>\n
            // The length includes itself, the space, key, '=', value, and '\n'
            // We need to compute this iteratively since the length is part of the record

            // Start with an estimate
            let base_len = 1 + key.len() + 1 + value.len() + 1; // space + key + '=' + value + '\n'
            let mut total_len = base_len + 1; // +1 for at least one digit

            // Adjust for actual digit count
            loop {
                let digit_count = if total_len < 10 {
                    1
                } else if total_len < 100 {
                    2
                } else if total_len < 1000 {
                    3
                } else {
                    4
                };
                let new_len = base_len + digit_count;
                if new_len == total_len {
                    break;
                }
                total_len = new_len;
            }

            let record = format!("{total_len} {key}=");
            content.extend_from_slice(record.as_bytes());
            content.extend_from_slice(value);
            content.push(b'\n');
        }

        let content_size = content.len();
        let header = make_header(b"PaxHeader/file", content_size as u64, b'x');

        let padded = content_size.next_multiple_of(HEADER_SIZE);
        let mut result = Vec::with_capacity(HEADER_SIZE + padded);
        result.extend_from_slice(&header);
        result.extend_from_slice(&content);
        result.extend(zeroes(padded - content_size));

        result
    }

    /// Return `n` zero bytes (for end-of-archive markers, padding, etc.).
    fn zeroes(n: usize) -> impl Iterator<Item = u8> {
        std::iter::repeat(0u8).take(n)
    }

    // =========================================================================
    // GNU long name tests
    // =========================================================================

    #[test]
    fn test_parser_gnu_long_name() {
        // Create archive with GNU long name entry followed by actual file
        let long_name =
            "very/long/path/that/exceeds/one/hundred/bytes/".to_string() + &"x".repeat(60);
        assert!(long_name.len() > 100);

        let mut archive = Vec::new();
        archive.extend(make_gnu_long_name(long_name.as_bytes()));
        archive.extend_from_slice(&make_header(b"placeholder", 5, b'0'));
        // Content: "hello"
        let mut content_block = [0u8; 512];
        content_block[0..5].copy_from_slice(b"hello");
        archive.extend_from_slice(&content_block);
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        // Should consume GNU long name header + content + actual header
        let consumed = match &event {
            ParseEvent::Entry { consumed, entry } => {
                assert!(*consumed > 512);
                assert_eq!(entry.path.as_ref(), long_name.as_bytes());
                assert_eq!(entry.size, 5);
                assert!(entry.is_file());
                *consumed
            }
            other => panic!("Expected Entry, got {:?}", other),
        };

        parser.advance_content(5).unwrap();

        // Parse end
        let remaining = &archive[consumed + 512..];
        let event = parser.parse(remaining).unwrap();
        assert!(matches!(event, ParseEvent::End { .. }));
    }

    // =========================================================================
    // GNU long link tests
    // =========================================================================

    #[test]
    fn test_parser_gnu_long_link() {
        // Create archive with GNU long link entry followed by symlink
        let long_target = "/some/very/long/symlink/target/path/".to_string() + &"t".repeat(80);
        assert!(long_target.len() > 100);

        let mut archive = Vec::new();
        archive.extend(make_gnu_long_link(long_target.as_bytes()));
        // Symlink header with placeholder linkname
        archive.extend_from_slice(&make_link_header(b"mylink", b"placeholder", b'2'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        let consumed = match &event {
            ParseEvent::Entry { consumed, entry } => {
                assert_eq!(entry.path.as_ref(), b"mylink");
                assert!(entry.is_symlink());
                assert_eq!(
                    entry.link_target.as_ref().unwrap().as_ref(),
                    long_target.as_bytes()
                );
                *consumed
            }
            other => panic!("Expected Entry, got {:?}", other),
        };

        parser.advance_content(0).unwrap();

        let remaining = &archive[consumed..];
        let event = parser.parse(remaining).unwrap();
        assert!(matches!(event, ParseEvent::End { .. }));
    }

    // =========================================================================
    // PAX extension tests
    // =========================================================================

    #[test]
    fn test_parser_pax_path_override() {
        // PAX header should override the path in the actual header
        let pax_path = "pax/overridden/path/to/file.txt";

        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[("path", pax_path.as_bytes())]));
        archive.extend_from_slice(&make_header(b"original.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.path.as_ref(), pax_path.as_bytes());
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    #[test]
    fn test_parser_pax_size_override() {
        // PAX header should override the size in the actual header
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[("size", b"999")]));
        // Header says size=5, but PAX says 999
        archive.extend_from_slice(&make_header(b"file.txt", 5, b'0'));
        // We still need content padded to the PAX size for proper parsing
        archive.extend(zeroes(1024)); // More than enough

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.size, 999);
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    #[test]
    fn test_parser_pax_metadata() {
        // PAX header overriding uid, gid, and mtime
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[
            ("uid", b"65534"),
            ("gid", b"65535"),
            ("mtime", b"1700000000.123456789"),
        ]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.uid, 65534);
                assert_eq!(entry.gid, 65535);
                // mtime should be the integer part only
                assert_eq!(entry.mtime, 1700000000);
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    #[test]
    fn test_parser_pax_xattr() {
        // PAX SCHILY.xattr.* entries for extended attributes
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[
            ("SCHILY.xattr.user.test", b"test_value"),
            (
                "SCHILY.xattr.security.selinux",
                b"system_u:object_r:unlabeled_t:s0",
            ),
        ]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.xattrs.len(), 2);

                // Check xattrs (order should be preserved)
                assert_eq!(entry.xattrs[0].0.as_ref(), b"user.test");
                assert_eq!(entry.xattrs[0].1.as_ref(), b"test_value");

                assert_eq!(entry.xattrs[1].0.as_ref(), b"security.selinux");
                assert_eq!(
                    entry.xattrs[1].1.as_ref(),
                    b"system_u:object_r:unlabeled_t:s0"
                );
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    #[test]
    fn test_parser_pax_linkpath() {
        // PAX linkpath for symlink targets
        let pax_linkpath = "/a/very/long/symlink/target/from/pax";

        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[("linkpath", pax_linkpath.as_bytes())]));
        archive.extend_from_slice(&make_link_header(b"mylink", b"short", b'2'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                assert!(entry.is_symlink());
                assert_eq!(
                    entry.link_target.as_ref().unwrap().as_ref(),
                    pax_linkpath.as_bytes()
                );
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    // =========================================================================
    // Error case tests
    // =========================================================================

    #[test]
    fn test_parser_orphaned_metadata() {
        // GNU long name entry followed by end of archive (no actual entry)
        let mut archive = Vec::new();
        archive.extend(make_gnu_long_name(b"some/long/name/here"));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let result = parser.parse(&archive);

        assert!(matches!(result, Err(ParseError::OrphanedMetadata)));
    }

    #[test]
    fn test_parser_orphaned_pax_metadata() {
        // PAX header followed by end of archive
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[("path", b"test")]));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let result = parser.parse(&archive);

        assert!(matches!(result, Err(ParseError::OrphanedMetadata)));
    }

    #[test]
    fn test_parser_duplicate_gnu_long_name() {
        // Two GNU long name entries in a row should error
        let mut archive = Vec::new();
        archive.extend(make_gnu_long_name(b"first/long/name"));
        archive.extend(make_gnu_long_name(b"second/long/name"));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let result = parser.parse(&archive);

        assert!(matches!(result, Err(ParseError::DuplicateGnuLongName)));
    }

    #[test]
    fn test_parser_duplicate_gnu_long_link() {
        // Two GNU long link entries in a row should error
        let mut archive = Vec::new();
        archive.extend(make_gnu_long_link(b"first/long/target"));
        archive.extend(make_gnu_long_link(b"second/long/target"));
        archive.extend_from_slice(&make_link_header(b"link", b"x", b'2'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let result = parser.parse(&archive);

        assert!(matches!(result, Err(ParseError::DuplicateGnuLongLink)));
    }

    #[test]
    fn test_parser_duplicate_pax_header() {
        // Two PAX headers in a row should error
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[("path", b"first")]));
        archive.extend(make_pax_header(&[("path", b"second")]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let result = parser.parse(&archive);

        assert!(matches!(result, Err(ParseError::DuplicatePaxHeader)));
    }

    // =========================================================================
    // Combined GNU and PAX tests
    // =========================================================================

    #[test]
    fn test_parser_combined_gnu_pax() {
        // Both GNU long name and PAX path - PAX should win
        let gnu_name = "gnu/long/name/".to_string() + &"g".repeat(100);
        let pax_path = "pax/should/win/file.txt";

        let mut archive = Vec::new();
        archive.extend(make_gnu_long_name(gnu_name.as_bytes()));
        archive.extend(make_pax_header(&[("path", pax_path.as_bytes())]));
        archive.extend_from_slice(&make_header(b"header.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                // PAX path should override GNU long name
                assert_eq!(entry.path.as_ref(), pax_path.as_bytes());
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    #[test]
    fn test_parser_gnu_long_name_and_link_combined() {
        // Both GNU long name and long link for the same entry
        let long_name = "long/symlink/name/".to_string() + &"n".repeat(100);
        let long_target = "long/target/path/".to_string() + &"t".repeat(100);

        let mut archive = Vec::new();
        archive.extend(make_gnu_long_name(long_name.as_bytes()));
        archive.extend(make_gnu_long_link(long_target.as_bytes()));
        archive.extend_from_slice(&make_link_header(b"short", b"short", b'2'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.path.as_ref(), long_name.as_bytes());
                assert_eq!(
                    entry.link_target.as_ref().unwrap().as_ref(),
                    long_target.as_bytes()
                );
                assert!(entry.is_symlink());
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    #[test]
    fn test_parser_pax_multiple_entries() {
        // Multiple PAX entries for different files
        let mut archive = Vec::new();

        // First file with PAX
        archive.extend(make_pax_header(&[("path", b"first/file.txt")]));
        archive.extend_from_slice(&make_header(b"f1", 5, b'0'));
        let mut content1 = [0u8; 512];
        content1[0..5].copy_from_slice(b"hello");
        archive.extend_from_slice(&content1);

        // Second file with PAX
        archive.extend(make_pax_header(&[("path", b"second/file.txt")]));
        archive.extend_from_slice(&make_header(b"f2", 5, b'0'));
        let mut content2 = [0u8; 512];
        content2[0..5].copy_from_slice(b"world");
        archive.extend_from_slice(&content2);

        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());

        // Parse first entry
        let event1 = parser.parse(&archive).unwrap();
        let consumed1 = match &event1 {
            ParseEvent::Entry { consumed, entry } => {
                assert_eq!(entry.path.as_ref(), b"first/file.txt");
                assert_eq!(entry.size, 5);
                *consumed
            }
            other => panic!("Expected Entry, got {:?}", other),
        };
        parser.advance_content(5).unwrap();

        // Parse second entry
        let offset = consumed1 + 512;
        let event2 = parser.parse(&archive[offset..]).unwrap();
        let consumed2 = match &event2 {
            ParseEvent::Entry { consumed, entry } => {
                assert_eq!(entry.path.as_ref(), b"second/file.txt");
                assert_eq!(entry.size, 5);
                *consumed
            }
            other => panic!("Expected Entry, got {:?}", other),
        };
        parser.advance_content(5).unwrap();

        // Parse end
        let final_offset = offset + consumed2 + 512;
        let event3 = parser.parse(&archive[final_offset..]).unwrap();
        assert!(matches!(event3, ParseEvent::End { .. }));
    }

    #[test]
    fn test_parser_pax_uname_gname() {
        // PAX uname and gname override
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[
            ("uname", b"testuser"),
            ("gname", b"testgroup"),
        ]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.uname.as_ref().unwrap().as_ref(), b"testuser");
                assert_eq!(entry.gname.as_ref().unwrap().as_ref(), b"testgroup");
            }
            other => panic!("Expected Entry, got {:?}", other),
        }
    }

    // =========================================================================
    // Size limit tests
    // =========================================================================

    #[test]
    fn test_parser_gnu_long_too_large() {
        let long_name = "x".repeat(200);

        let mut archive = Vec::new();
        archive.extend(make_gnu_long_name(long_name.as_bytes()));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let limits = Limits {
            max_gnu_long_size: 100,
            ..Default::default()
        };
        let mut parser = Parser::new(limits);
        let result = parser.parse(&archive);

        assert!(matches!(result, Err(ParseError::GnuLongTooLarge { .. })));
    }

    #[test]
    fn test_parser_pax_path_too_long() {
        let long_path = "x".repeat(200);

        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[("path", long_path.as_bytes())]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let limits = Limits {
            max_path_len: 100,
            ..Default::default()
        };
        let mut parser = Parser::new(limits);
        let result = parser.parse(&archive);

        assert!(matches!(
            result,
            Err(ParseError::PathTooLong {
                len: 200,
                limit: 100
            })
        ));
    }

    #[test]
    fn test_parser_pax_too_large() {
        // Create a PAX header that exceeds the size limit
        let large_value = "x".repeat(1000);

        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[("path", large_value.as_bytes())]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let limits = Limits {
            max_pax_size: 100,
            ..Default::default()
        };
        let mut parser = Parser::new(limits);
        let result = parser.parse(&archive);

        assert!(matches!(result, Err(ParseError::PaxTooLarge { .. })));
    }

    // =========================================================================
    // Need data tests for extension entries
    // =========================================================================

    #[test]
    fn test_parser_need_data_for_gnu_long_content() {
        // Create a GNU long name header, but don't provide the content
        let header = make_header(b"././@LongLink", 200, b'L');

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&header).unwrap();

        // Need header (512) + padded content (512)
        match event {
            ParseEvent::NeedData { min_bytes } => {
                assert!(min_bytes > 512);
            }
            other => panic!("Expected NeedData, got {:?}", other),
        }
    }

    #[test]
    fn test_parser_need_data_for_pax_content() {
        // Create a PAX header, but don't provide the content
        let header = make_header(b"PaxHeader/file", 100, b'x');

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&header).unwrap();

        match event {
            ParseEvent::NeedData { min_bytes } => {
                assert!(min_bytes > 512);
            }
            other => panic!("Expected NeedData, got {:?}", other),
        }
    }

    /// Test for CVE-2025-62518 (TARmageddon): PAX size must override header size
    ///
    /// The vulnerability occurs when:
    /// 1. PAX header specifies size=X (e.g., 1024)
    /// 2. ustar header specifies size=0
    /// 3. Vulnerable parser uses header size (0) instead of PAX size (1024)
    /// 4. Parser advances 0 bytes, treating nested tar content as outer entries
    ///
    /// tar-core MUST use PAX size for content advancement to be secure.
    #[test]
    fn test_cve_2025_62518_pax_size_overrides_header() {
        // PAX header with size=1024
        let pax_entries: &[(&str, &[u8])] = &[("size", b"1024")];
        let pax_data = make_pax_header(pax_entries);

        // Actual file header with size=0 in ustar (the attack vector!)
        // A vulnerable parser would skip 0 bytes and see the "content" as headers
        let file_header = make_header(b"nested.tar", 0, b'0'); // size=0 in header!

        // The "content" - in an attack this would be a nested tar archive
        // with malicious files that get extracted
        let mut content = vec![0u8; 1024];
        // Put something that looks like a tar header to detect if parser is confused
        content[0..9].copy_from_slice(b"MALICIOUS");
        content[156] = b'0'; // Would be parsed as regular file if vulnerable

        // Build full archive: PAX header + actual header + content + padding + end markers
        let mut archive = Vec::new();
        archive.extend_from_slice(&pax_data);
        archive.extend_from_slice(&file_header);
        archive.extend_from_slice(&content);
        // Pad to 512 boundary (1024 is already aligned)
        archive.extend(zeroes(1024));

        // Parse
        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();

        let consumed = match &event {
            ParseEvent::Entry { consumed, entry } => {
                // CRITICAL: entry.size MUST be 1024 (from PAX), not 0 (from header)
                assert_eq!(
                    entry.size, 1024,
                    "CVE-2025-62518: Parser MUST use PAX size (1024), not header size (0)"
                );

                // padded_size should also be 1024
                assert_eq!(entry.padded_size(), 1024, "Padded size must match PAX size");

                // Path should be from header
                assert_eq!(entry.path_lossy(), "nested.tar");

                // Advance past content
                parser.advance_content(entry.size).unwrap();
                *consumed
            }
            other => panic!("Expected Entry, got {:?}", other),
        };

        // Continue parsing - should get End, NOT another entry
        let remaining = &archive[consumed + 1024..]; // consumed headers + 1024 bytes content
        let event = parser.parse(remaining).unwrap();

        match event {
            ParseEvent::End { .. } => {
                // Correct! Parser properly skipped the 1024-byte content
            }
            ParseEvent::Entry { entry, .. } => {
                panic!(
                    "CVE-2025-62518 VULNERABLE: Parser found unexpected entry '{}' \
                     because it used header size (0) instead of PAX size (1024)",
                    entry.path_lossy()
                );
            }
            other => panic!("Expected End, got {:?}", other),
        }
    }

    /// Additional test: ensure parser state tracks PAX-overridden size
    #[test]
    fn test_pax_size_affects_parser_state() {
        // PAX specifies 512 bytes, header says 0
        let pax_entries: &[(&str, &[u8])] = &[("size", b"512")];
        let pax_data = make_pax_header(pax_entries);
        let file_header = make_header(b"test.bin", 0, b'0');

        let content = vec![0u8; 512];
        let mut archive = Vec::new();
        archive.extend_from_slice(&pax_data);
        archive.extend_from_slice(&file_header);
        archive.extend_from_slice(&content);
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());

        // Parse entry
        let event = parser.parse(&archive).unwrap();
        let size = match event {
            ParseEvent::Entry { entry, .. } => entry.size,
            other => panic!("Expected Entry, got {:?}", other),
        };

        assert_eq!(size, 512, "Entry size must reflect PAX override");

        // Parser should now be in ReadContent state expecting 512 bytes
        // If we try to parse again without advancing, it should return NeedData
        let event = parser.parse(&[]).unwrap();
        match event {
            ParseEvent::NeedData { min_bytes } => {
                assert_eq!(min_bytes, 512, "Parser must expect PAX size bytes");
            }
            other => panic!("Expected NeedData, got {:?}", other),
        }
    }

    // =========================================================================
    // Strict mode tests
    // =========================================================================

    /// Build a minimal archive with a PAX header overriding `key` to `value`,
    /// followed by a regular file entry and end-of-archive.
    fn make_archive_with_pax(key: &str, value: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[(key, value)]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));
        archive
    }

    #[test]
    fn test_strict_rejects_invalid_pax_uid() {
        let archive = make_archive_with_pax("uid", b"notanumber");
        let mut parser = Parser::new(Limits::default());
        let err = parser.parse(&archive).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidPaxValue { key: "uid", .. }),
            "expected InvalidPaxValue for uid, got {err:?}"
        );
    }

    #[test]
    fn test_strict_rejects_invalid_pax_size() {
        let archive = make_archive_with_pax("size", b"xyz");
        let mut parser = Parser::new(Limits::default());
        let err = parser.parse(&archive).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidPaxValue { key: "size", .. }
        ));
    }

    #[test]
    fn test_strict_rejects_invalid_pax_gid() {
        let archive = make_archive_with_pax("gid", b"bad");
        let mut parser = Parser::new(Limits::default());
        let err = parser.parse(&archive).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidPaxValue { key: "gid", .. }
        ));
    }

    #[test]
    fn test_strict_rejects_invalid_pax_mtime() {
        let archive = make_archive_with_pax("mtime", b"nottime");
        let mut parser = Parser::new(Limits::default());
        let err = parser.parse(&archive).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidPaxValue { key: PAX_MTIME, .. }
        ));
    }

    #[test]
    fn test_lenient_ignores_invalid_pax_uid() {
        let archive = make_archive_with_pax("uid", b"notanumber");
        let limits = Limits {
            strict: false,
            ..Default::default()
        };
        let mut parser = Parser::new(limits);
        let event = parser.parse(&archive).unwrap();
        match event {
            ParseEvent::Entry { entry, .. } => {
                // Should fall back to header uid (1000 from make_header)
                assert_eq!(entry.uid, 1000);
            }
            other => panic!("Expected Entry, got {other:?}"),
        }
    }

    #[test]
    fn test_lenient_ignores_invalid_pax_size() {
        let archive = make_archive_with_pax("size", b"xyz");
        let limits = Limits {
            strict: false,
            ..Default::default()
        };
        let mut parser = Parser::new(limits);
        let event = parser.parse(&archive).unwrap();
        match event {
            ParseEvent::Entry { entry, .. } => {
                // Should fall back to header size (0 from make_header)
                assert_eq!(entry.size, 0);
            }
            other => panic!("Expected Entry, got {other:?}"),
        }
    }

    #[test]
    fn test_strict_accepts_valid_pax_values() {
        let mut archive = Vec::new();
        archive.extend(make_pax_header(&[
            ("uid", b"2000"),
            ("gid", b"3000"),
            ("size", b"42"),
            ("mtime", b"1700000000"),
        ]));
        archive.extend_from_slice(&make_header(b"file.txt", 0, b'0'));
        archive.extend(zeroes(1024));

        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();
        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.uid, 2000);
                assert_eq!(entry.gid, 3000);
                assert_eq!(entry.size, 42);
                assert_eq!(entry.mtime, 1700000000);
            }
            other => panic!("Expected Entry, got {other:?}"),
        }
    }

    #[test]
    fn test_strict_accepts_fractional_mtime() {
        let archive = make_archive_with_pax("mtime", b"1234567890.123456");
        let mut parser = Parser::new(Limits::default());
        let event = parser.parse(&archive).unwrap();
        match event {
            ParseEvent::Entry { entry, .. } => {
                assert_eq!(entry.mtime, 1234567890);
            }
            other => panic!("Expected Entry, got {other:?}"),
        }
    }
}
