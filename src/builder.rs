//! Builder pattern for creating tar headers.
//!
//! This module provides [`HeaderBuilder`] for constructing tar headers and
//! [`PaxBuilder`] for creating PAX extended header records.
//!
//! # Example
//!
//! ```
//! use tar_core::builder::HeaderBuilder;
//! use tar_core::EntryType;
//!
//! let header = HeaderBuilder::new_ustar()
//!     .path(b"hello.txt").unwrap()
//!     .mode(0o644)
//!     .size(1024).unwrap()
//!     .entry_type(EntryType::Regular)
//!     .finish();
//! ```

use crate::{
    EntryType, Header, HeaderError, Result, GNU_MAGIC, GNU_VERSION, HEADER_SIZE, USTAR_MAGIC,
    USTAR_VERSION,
};

/// Write bytes to a fixed-size field, checking length.
///
/// The field is zero-filled first, then the value is copied. If the value
/// is shorter than the field, it will be null-terminated. If the value is
/// longer, an error is returned.
///
/// # Errors
///
/// Returns [`HeaderError::InvalidOctal`] (reused for field overflow) if
/// the value is too long for the field.
fn write_bytes(field: &mut [u8], value: &[u8]) -> Result<()> {
    if value.len() > field.len() {
        return Err(HeaderError::InvalidOctal(value.to_vec()));
    }
    field.fill(0);
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

/// Write a u64 value as octal ASCII to a field.
///
/// The value is formatted as octal with leading zeros and a trailing null
/// or space, following tar conventions. For example, mode 0o644 in an 8-byte
/// field becomes "0000644\0".
///
/// # Errors
///
/// Returns [`HeaderError::InvalidOctal`] if the value cannot fit in the field.
fn write_octal(field: &mut [u8], value: u64) -> Result<()> {
    // We need room for at least one digit and potentially a terminator
    if field.is_empty() {
        return Err(HeaderError::InvalidOctal(vec![]));
    }

    // Calculate how many octal digits we can fit (leaving room for null terminator)
    let max_digits = field.len() - 1;

    // Check if value fits: max value is 8^max_digits - 1
    let max_value = if max_digits >= 21 {
        u64::MAX // overflow-safe
    } else {
        (1u64 << (max_digits * 3)) - 1
    };

    if value > max_value {
        return Err(HeaderError::InvalidOctal(format!("{value:o}").into_bytes()));
    }

    // Format as octal with leading zeros
    field.fill(0);
    let octal_str = format!("{value:0width$o}", width = max_digits);
    let bytes = octal_str.as_bytes();
    field[..bytes.len()].copy_from_slice(bytes);
    // Last byte is already 0 (null terminator) from fill

    Ok(())
}

/// Builder for creating tar headers.
///
/// This provides a fluent API for constructing tar headers with proper
/// field formatting and checksum calculation.
///
/// # Example
///
/// ```
/// use tar_core::builder::HeaderBuilder;
/// use tar_core::EntryType;
///
/// let mut builder = HeaderBuilder::new_ustar();
/// builder
///     .path(b"example.txt").unwrap()
///     .mode(0o644)
///     .uid(1000).unwrap()
///     .gid(1000).unwrap()
///     .size(0).unwrap()
///     .mtime(1234567890).unwrap()
///     .entry_type(EntryType::Regular);
///
/// let header_bytes = builder.finish();
/// ```
#[derive(Clone)]
pub struct HeaderBuilder {
    header: [u8; HEADER_SIZE],
}

impl HeaderBuilder {
    /// Create a new builder for a UStar format header.
    #[must_use]
    pub fn new_ustar() -> Self {
        let mut header = [0u8; HEADER_SIZE];
        header[257..263].copy_from_slice(USTAR_MAGIC);
        header[263..265].copy_from_slice(USTAR_VERSION);
        Self { header }
    }

    /// Create a new builder for a GNU tar format header.
    #[must_use]
    pub fn new_gnu() -> Self {
        let mut header = [0u8; HEADER_SIZE];
        header[257..263].copy_from_slice(GNU_MAGIC);
        header[263..265].copy_from_slice(GNU_VERSION);
        Self { header }
    }

    /// Set the file path (name field, bytes 0-100).
    ///
    /// # Errors
    ///
    /// Returns an error if the path is longer than 100 bytes.
    pub fn path(&mut self, path: &[u8]) -> Result<&mut Self> {
        write_bytes(&mut self.header[0..100], path)?;
        Ok(self)
    }

    /// Set the file mode (bytes 100-108).
    ///
    /// The mode is written as an octal ASCII string.
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        // Mode field is 8 bytes, should always fit
        let _ = write_octal(&mut self.header[100..108], u64::from(mode));
        self
    }

    /// Set the owner user ID (bytes 108-116).
    ///
    /// # Errors
    ///
    /// Returns an error if the UID doesn't fit in the 8-byte octal field.
    pub fn uid(&mut self, uid: u64) -> Result<&mut Self> {
        write_octal(&mut self.header[108..116], uid)?;
        Ok(self)
    }

    /// Set the owner group ID (bytes 116-124).
    ///
    /// # Errors
    ///
    /// Returns an error if the GID doesn't fit in the 8-byte octal field.
    pub fn gid(&mut self, gid: u64) -> Result<&mut Self> {
        write_octal(&mut self.header[116..124], gid)?;
        Ok(self)
    }

    /// Set the file size (bytes 124-136).
    ///
    /// # Errors
    ///
    /// Returns an error if the size doesn't fit in the 12-byte octal field.
    pub fn size(&mut self, size: u64) -> Result<&mut Self> {
        write_octal(&mut self.header[124..136], size)?;
        Ok(self)
    }

    /// Set the modification time as a Unix timestamp (bytes 136-148).
    ///
    /// # Errors
    ///
    /// Returns an error if the mtime doesn't fit in the 12-byte octal field.
    pub fn mtime(&mut self, mtime: u64) -> Result<&mut Self> {
        write_octal(&mut self.header[136..148], mtime)?;
        Ok(self)
    }

    /// Set the entry type (byte 156).
    pub fn entry_type(&mut self, entry_type: EntryType) -> &mut Self {
        self.header[156] = entry_type.to_byte();
        self
    }

    /// Set the link name for symbolic/hard links (bytes 157-257).
    ///
    /// # Errors
    ///
    /// Returns an error if the link name is longer than 100 bytes.
    pub fn link_name(&mut self, link: &[u8]) -> Result<&mut Self> {
        write_bytes(&mut self.header[157..257], link)?;
        Ok(self)
    }

    /// Set the owner user name (bytes 265-297, UStar/GNU only).
    ///
    /// # Errors
    ///
    /// Returns an error if the username is longer than 32 bytes.
    pub fn username(&mut self, name: &[u8]) -> Result<&mut Self> {
        write_bytes(&mut self.header[265..297], name)?;
        Ok(self)
    }

    /// Set the owner group name (bytes 297-329, UStar/GNU only).
    ///
    /// # Errors
    ///
    /// Returns an error if the group name is longer than 32 bytes.
    pub fn groupname(&mut self, name: &[u8]) -> Result<&mut Self> {
        write_bytes(&mut self.header[297..329], name)?;
        Ok(self)
    }

    /// Set device major and minor numbers (bytes 329-337 and 337-345).
    ///
    /// Used for character and block device entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the values don't fit in the 8-byte octal fields.
    pub fn device(&mut self, major: u32, minor: u32) -> Result<&mut Self> {
        write_octal(&mut self.header[329..337], u64::from(major))?;
        write_octal(&mut self.header[337..345], u64::from(minor))?;
        Ok(self)
    }

    /// Set the UStar prefix field for long paths (bytes 345-500).
    ///
    /// # Errors
    ///
    /// Returns an error if the prefix is longer than 155 bytes.
    pub fn prefix(&mut self, prefix: &[u8]) -> Result<&mut Self> {
        write_bytes(&mut self.header[345..500], prefix)?;
        Ok(self)
    }

    /// Get a reference to the current header for inspection.
    ///
    /// Note: The checksum field will not be valid until [`finish`](Self::finish)
    /// is called.
    #[must_use]
    pub fn as_header(&self) -> &Header {
        Header::from_bytes_exact(&self.header)
    }

    /// Compute the checksum and return the final header bytes.
    ///
    /// This fills in the checksum field (bytes 148-156) and returns
    /// the complete 512-byte header.
    #[must_use]
    pub fn finish(&mut self) -> [u8; HEADER_SIZE] {
        // Fill checksum field with spaces for calculation
        self.header[148..156].fill(b' ');

        // Compute unsigned sum of all bytes
        let checksum: u64 = self.header.iter().map(|&b| u64::from(b)).sum();

        // Write checksum using tar-rs compatible format:
        // 7 octal digits with leading zeros + null terminator
        // This fills the 8-byte field completely and matches tar-rs bit-for-bit.
        let checksum_str = format!("{checksum:07o}\0");
        self.header[148..156].copy_from_slice(checksum_str.as_bytes());

        self.header
    }
}

impl Default for HeaderBuilder {
    fn default() -> Self {
        Self::new_ustar()
    }
}

impl std::fmt::Debug for HeaderBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderBuilder")
            .field("header", self.as_header())
            .finish()
    }
}

/// Builder for PAX extended header records.
///
/// PAX extended headers contain key-value pairs that extend the basic
/// tar header format, allowing for longer paths, larger file sizes,
/// and additional metadata.
///
/// # Format
///
/// Each record has the format: `<length> <key>=<value>\n`
/// where `<length>` is the total record length including the length field itself.
///
/// # Example
///
/// ```
/// use tar_core::builder::PaxBuilder;
///
/// let mut builder = PaxBuilder::new();
/// builder
///     .path(b"/very/long/path/that/exceeds/100/characters/limit.txt")
///     .size(1_000_000_000_000);
/// let data = builder.finish();
/// ```
#[derive(Clone, Default)]
pub struct PaxBuilder {
    data: Vec<u8>,
}

impl PaxBuilder {
    /// Create a new empty PAX builder.
    #[must_use]
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Add a key-value record.
    ///
    /// The record is formatted as `<length> <key>=<value>\n`.
    pub fn add(&mut self, key: &str, value: &[u8]) -> &mut Self {
        // Calculate record length
        // Format: "<len> <key>=<value>\n"
        // We need to account for the length field itself, which creates
        // a chicken-and-egg problem. We solve it by trying different lengths.

        let key_bytes = key.as_bytes();
        // Base length without the length field: " " + key + "=" + value + "\n"
        let base_len = 1 + key_bytes.len() + 1 + value.len() + 1;

        // Find the correct total length (including the decimal length field)
        let len = Self::compute_record_length(base_len);

        // Format the record
        let record = format!("{len} ");
        self.data.extend_from_slice(record.as_bytes());
        self.data.extend_from_slice(key_bytes);
        self.data.push(b'=');
        self.data.extend_from_slice(value);
        self.data.push(b'\n');

        self
    }

    /// Compute the total record length including the length prefix.
    ///
    /// The tricky part is that the length includes itself, so we need to
    /// find a fixed point.
    fn compute_record_length(base_len: usize) -> usize {
        // Start with a guess
        let mut len = base_len + 1; // assume 1-digit length

        loop {
            let len_str = len.to_string();
            let actual = base_len + len_str.len();
            if actual == len {
                return len;
            }
            if actual < len {
                // We overestimated, but that's fine for some edge cases
                return len;
            }
            len = actual;
            // Safety: this will converge quickly (log10 iterations)
            if len > base_len + 20 {
                break;
            }
        }
        len
    }

    /// Add a path record.
    pub fn path(&mut self, path: &[u8]) -> &mut Self {
        self.add("path", path)
    }

    /// Add a linkpath record.
    pub fn linkpath(&mut self, path: &[u8]) -> &mut Self {
        self.add("linkpath", path)
    }

    /// Add a size record.
    pub fn size(&mut self, size: u64) -> &mut Self {
        self.add("size", size.to_string().as_bytes())
    }

    /// Add a uid record.
    pub fn uid(&mut self, uid: u64) -> &mut Self {
        self.add("uid", uid.to_string().as_bytes())
    }

    /// Add a gid record.
    pub fn gid(&mut self, gid: u64) -> &mut Self {
        self.add("gid", gid.to_string().as_bytes())
    }

    /// Add a uname (username) record.
    pub fn uname(&mut self, name: &[u8]) -> &mut Self {
        self.add("uname", name)
    }

    /// Add a gname (group name) record.
    pub fn gname(&mut self, name: &[u8]) -> &mut Self {
        self.add("gname", name)
    }

    /// Add an mtime record.
    pub fn mtime(&mut self, mtime: u64) -> &mut Self {
        self.add("mtime", mtime.to_string().as_bytes())
    }

    /// Add an atime record.
    pub fn atime(&mut self, atime: u64) -> &mut Self {
        self.add("atime", atime.to_string().as_bytes())
    }

    /// Add a ctime record.
    pub fn ctime(&mut self, ctime: u64) -> &mut Self {
        self.add("ctime", ctime.to_string().as_bytes())
    }

    /// Get the current data (for inspection).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return the finished PAX extended header data.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.data
    }
}

impl std::fmt::Debug for PaxBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaxBuilder")
            .field("data", &String::from_utf8_lossy(&self.data))
            .finish()
    }
}

// ============================================================================
// Entry Builder
// ============================================================================

/// How to handle long paths and other extensions.
///
/// When paths exceed 100 bytes or link targets exceed 100 bytes, tar archives
/// use extension mechanisms to store the full values. This enum selects which
/// mechanism to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExtensionMode {
    /// Use GNU extensions (LongLink/LongName pseudo-entries).
    ///
    /// This emits a pseudo-entry with typeflag 'L' (for long names) or 'K'
    /// (for long link targets), followed by the actual entry with a truncated
    /// name. This is widely compatible with GNU tar.
    #[default]
    Gnu,
    /// Use PAX extensions (extended headers).
    ///
    /// This emits a PAX extended header (typeflag 'x') containing the full
    /// path/linkpath, followed by the actual entry. This is the POSIX.1-2001
    /// standard approach.
    Pax,
}

/// Maximum length for the name field in a tar header.
pub const NAME_MAX_LEN: usize = 100;

/// Maximum length for the linkname field in a tar header.
pub const LINKNAME_MAX_LEN: usize = 100;

/// The canonical name used for GNU long link/name pseudo-entries.
const GNU_LONGLINK_NAME: &[u8] = b"././@LongLink";

/// Builder for complete tar entries including extension headers.
///
/// This handles the complexity of emitting multiple headers when paths
/// or link targets exceed the 100-byte limit. It supports both GNU
/// (LongLink/LongName) and PAX extension mechanisms.
///
/// # Sans-IO Design
///
/// This builder does not perform any I/O. It produces `Vec<[u8; 512]>` blocks
/// or contiguous `Vec<u8>` that can be written to any output.
///
/// # Extension Handling
///
/// - **Short paths** (≤100 bytes): Single header, no extensions needed
/// - **Long paths** (>100 bytes): Extension header + data blocks + main header
/// - **Long link targets**: Same as long paths, using appropriate extension
///
/// # Example
///
/// ```
/// use tar_core::builder::{EntryBuilder, ExtensionMode};
/// use tar_core::EntryType;
///
/// // Create a simple entry (short path)
/// let mut builder = EntryBuilder::new_gnu();
/// builder
///     .path(b"hello.txt")
///     .mode(0o644)
///     .size(1024).unwrap()
///     .entry_type(EntryType::Regular);
/// let blocks = builder.finish();
/// assert_eq!(blocks.len(), 1); // Just one header block
///
/// // Create an entry with a long path
/// let long_path = "a/".repeat(60) + "file.txt";
/// let mut builder = EntryBuilder::new_gnu();
/// builder
///     .path(long_path.as_bytes())
///     .mode(0o644)
///     .size(0).unwrap()
///     .entry_type(EntryType::Regular);
/// let blocks = builder.finish();
/// assert!(blocks.len() > 1); // Extension header(s) + main header
/// ```
#[derive(Clone)]
pub struct EntryBuilder {
    /// The primary header builder.
    header: HeaderBuilder,
    /// Long path (if > 100 bytes).
    long_path: Option<Vec<u8>>,
    /// Long link target (if > 100 bytes).
    long_link: Option<Vec<u8>>,
    /// PAX extensions builder (used when mode is Pax).
    pax: Option<PaxBuilder>,
    /// Extension mode preference.
    mode: ExtensionMode,
}

impl EntryBuilder {
    /// Create a new builder using GNU tar format for the underlying header.
    ///
    /// This sets the extension mode to GNU (LongLink/LongName).
    #[must_use]
    pub fn new_gnu() -> Self {
        Self {
            header: HeaderBuilder::new_gnu(),
            long_path: None,
            long_link: None,
            pax: None,
            mode: ExtensionMode::Gnu,
        }
    }

    /// Create a new builder using UStar format for the underlying header.
    ///
    /// This sets the extension mode to PAX (extended headers).
    #[must_use]
    pub fn new_ustar() -> Self {
        Self {
            header: HeaderBuilder::new_ustar(),
            long_path: None,
            long_link: None,
            pax: None,
            mode: ExtensionMode::Pax,
        }
    }

    /// Create a new builder with explicit format and extension mode.
    #[must_use]
    pub fn with_mode(header: HeaderBuilder, mode: ExtensionMode) -> Self {
        Self {
            header,
            long_path: None,
            long_link: None,
            pax: None,
            mode,
        }
    }

    /// Get the current extension mode.
    #[must_use]
    pub fn extension_mode(&self) -> ExtensionMode {
        self.mode
    }

    /// Set the extension mode.
    pub fn set_extension_mode(&mut self, mode: ExtensionMode) -> &mut Self {
        self.mode = mode;
        self
    }

    /// Set the file path.
    ///
    /// If the path exceeds 100 bytes, it will be stored using the configured
    /// extension mechanism (GNU or PAX). The main header's name field will
    /// contain a truncated version.
    pub fn path(&mut self, path: &[u8]) -> &mut Self {
        if path.len() > NAME_MAX_LEN {
            self.long_path = Some(path.to_vec());
            // Truncate for the main header (take the last 100 bytes as that's
            // often more useful, but GNU tar actually uses the first 100)
            let truncated = &path[..NAME_MAX_LEN.min(path.len())];
            let _ = self.header.path(truncated);
        } else {
            self.long_path = None;
            let _ = self.header.path(path);
        }
        self
    }

    /// Set the link target for symbolic/hard links.
    ///
    /// If the link target exceeds 100 bytes, it will be stored using the
    /// configured extension mechanism.
    pub fn link_name(&mut self, link: &[u8]) -> &mut Self {
        if link.len() > LINKNAME_MAX_LEN {
            self.long_link = Some(link.to_vec());
            let truncated = &link[..LINKNAME_MAX_LEN.min(link.len())];
            let _ = self.header.link_name(truncated);
        } else {
            self.long_link = None;
            let _ = self.header.link_name(link);
        }
        self
    }

    /// Set the file mode (permissions).
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        let _ = self.header.mode(mode);
        self
    }

    /// Set the owner user ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the UID doesn't fit in the header field.
    pub fn uid(&mut self, uid: u64) -> Result<&mut Self> {
        self.header.uid(uid)?;
        Ok(self)
    }

    /// Set the owner group ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the GID doesn't fit in the header field.
    pub fn gid(&mut self, gid: u64) -> Result<&mut Self> {
        self.header.gid(gid)?;
        Ok(self)
    }

    /// Set the file size.
    ///
    /// # Errors
    ///
    /// Returns an error if the size doesn't fit in the header field.
    pub fn size(&mut self, size: u64) -> Result<&mut Self> {
        self.header.size(size)?;
        Ok(self)
    }

    /// Set the modification time as a Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if the mtime doesn't fit in the header field.
    pub fn mtime(&mut self, mtime: u64) -> Result<&mut Self> {
        self.header.mtime(mtime)?;
        Ok(self)
    }

    /// Set the entry type.
    pub fn entry_type(&mut self, entry_type: EntryType) -> &mut Self {
        let _ = self.header.entry_type(entry_type);
        self
    }

    /// Set the owner user name.
    ///
    /// # Errors
    ///
    /// Returns an error if the username is longer than 32 bytes.
    pub fn username(&mut self, name: &[u8]) -> Result<&mut Self> {
        self.header.username(name)?;
        Ok(self)
    }

    /// Set the owner group name.
    ///
    /// # Errors
    ///
    /// Returns an error if the group name is longer than 32 bytes.
    pub fn groupname(&mut self, name: &[u8]) -> Result<&mut Self> {
        self.header.groupname(name)?;
        Ok(self)
    }

    /// Set device major and minor numbers.
    ///
    /// Used for character and block device entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the values don't fit in the header fields.
    pub fn device(&mut self, major: u32, minor: u32) -> Result<&mut Self> {
        self.header.device(major, minor)?;
        Ok(self)
    }

    /// Add a custom PAX extension record.
    ///
    /// This is useful for adding metadata that doesn't fit in standard
    /// header fields. The PAX extension will be emitted regardless of
    /// the extension mode setting.
    pub fn add_pax(&mut self, key: &str, value: &[u8]) -> &mut Self {
        let _ = self.pax.get_or_insert_with(PaxBuilder::new).add(key, value);
        self
    }

    /// Get a reference to the underlying header builder.
    #[must_use]
    pub fn header(&self) -> &HeaderBuilder {
        &self.header
    }

    /// Get a mutable reference to the underlying header builder.
    pub fn header_mut(&mut self) -> &mut HeaderBuilder {
        &mut self.header
    }

    /// Check if this entry requires extension headers.
    #[must_use]
    pub fn needs_extension(&self) -> bool {
        self.long_path.is_some() || self.long_link.is_some() || self.pax.is_some()
    }

    /// Build the complete header sequence as a vector of 512-byte blocks.
    ///
    /// Returns all blocks needed for this entry's headers:
    /// - For short paths: just the main header (1 block)
    /// - For GNU long paths: LongName header + data blocks + main header
    /// - For PAX: extended header + data blocks + main header
    #[must_use]
    pub fn finish(&mut self) -> Vec<[u8; HEADER_SIZE]> {
        let mut blocks = Vec::new();

        match self.mode {
            ExtensionMode::Gnu => {
                // Emit GNU LongLink for long link targets first
                if let Some(ref long_link) = self.long_link {
                    self.emit_gnu_long_entry(&mut blocks, EntryType::GnuLongLink, long_link);
                }

                // Emit GNU LongName for long paths
                if let Some(ref long_path) = self.long_path {
                    self.emit_gnu_long_entry(&mut blocks, EntryType::GnuLongName, long_path);
                }
            }
            ExtensionMode::Pax => {
                // Build PAX data with long path/link if needed
                let pax_data = self.build_pax_data();
                if !pax_data.is_empty() {
                    self.emit_pax_entry(&mut blocks, &pax_data);
                }
            }
        }

        // Emit the main header
        let main_header = self.header.finish();
        blocks.push(main_header);

        blocks
    }

    /// Build the complete header sequence as contiguous bytes.
    ///
    /// This is a convenience method that flattens the block vector.
    #[must_use]
    pub fn finish_bytes(&mut self) -> Vec<u8> {
        self.finish()
            .into_iter()
            .flat_map(|block| block.into_iter())
            .collect()
    }

    /// Emit a GNU LongLink/LongName pseudo-entry.
    fn emit_gnu_long_entry(
        &self,
        blocks: &mut Vec<[u8; HEADER_SIZE]>,
        entry_type: EntryType,
        data: &[u8],
    ) {
        // The data is null-terminated in GNU format
        let data_with_null_len = data.len() + 1;

        // Build the header for the pseudo-entry
        let mut ext_header = HeaderBuilder::new_gnu();
        let _ = ext_header.path(GNU_LONGLINK_NAME);
        let _ = ext_header.mode(0);
        let _ = ext_header.uid(0);
        let _ = ext_header.gid(0);
        let _ = ext_header.size(data_with_null_len as u64);
        let _ = ext_header.mtime(0);
        let _ = ext_header.entry_type(entry_type);

        blocks.push(ext_header.finish());

        // Emit data blocks (null-terminated, padded to 512 bytes)
        let num_data_blocks = data_with_null_len.div_ceil(HEADER_SIZE);
        let mut data_buf = vec![0u8; num_data_blocks * HEADER_SIZE];
        data_buf[..data.len()].copy_from_slice(data);
        // Null terminator is already in place (vec initialized to 0)

        for chunk in data_buf.chunks_exact(HEADER_SIZE) {
            let mut block = [0u8; HEADER_SIZE];
            block.copy_from_slice(chunk);
            blocks.push(block);
        }
    }

    /// Build PAX extension data for long paths/links and custom extensions.
    fn build_pax_data(&self) -> Vec<u8> {
        let mut pax = self.pax.clone().unwrap_or_default();

        if let Some(ref long_path) = self.long_path {
            let _ = pax.path(long_path);
        }

        if let Some(ref long_link) = self.long_link {
            let _ = pax.linkpath(long_link);
        }

        pax.finish()
    }

    /// Emit a PAX extended header entry.
    fn emit_pax_entry(&self, blocks: &mut Vec<[u8; HEADER_SIZE]>, pax_data: &[u8]) {
        // Build a name for the PAX header (following tar conventions)
        // Format: "PaxHeaders.0/<truncated_name>"
        let pax_name = self.build_pax_header_name();

        // Build the PAX header
        let mut pax_header = HeaderBuilder::new_ustar();
        let _ = pax_header.path(&pax_name);
        let _ = pax_header.mode(0o644);
        let _ = pax_header.uid(0);
        let _ = pax_header.gid(0);
        let _ = pax_header.size(pax_data.len() as u64);
        let _ = pax_header.mtime(0);
        let _ = pax_header.entry_type(EntryType::XHeader);

        blocks.push(pax_header.finish());

        // Emit data blocks (padded to 512 bytes)
        let num_data_blocks = pax_data.len().div_ceil(HEADER_SIZE);
        let mut data_buf = vec![0u8; num_data_blocks * HEADER_SIZE];
        data_buf[..pax_data.len()].copy_from_slice(pax_data);

        for chunk in data_buf.chunks_exact(HEADER_SIZE) {
            let mut block = [0u8; HEADER_SIZE];
            block.copy_from_slice(chunk);
            blocks.push(block);
        }
    }

    /// Build the name for a PAX extended header.
    fn build_pax_header_name(&self) -> Vec<u8> {
        // Get the base name from the header's current path
        let path = self.header.as_header().path_bytes();
        let base_name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);

        // Build: "PaxHeaders.0/<basename>" (truncated to fit)
        let mut name = b"PaxHeaders.0/".to_vec();
        let remaining = NAME_MAX_LEN.saturating_sub(name.len());
        let truncated_base = &base_name[..remaining.min(base_name.len())];
        name.extend_from_slice(truncated_base);

        name
    }
}

impl Default for EntryBuilder {
    fn default() -> Self {
        Self::new_gnu()
    }
}

impl std::fmt::Debug for EntryBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryBuilder")
            .field("mode", &self.mode)
            .field("needs_extension", &self.needs_extension())
            .field("long_path_len", &self.long_path.as_ref().map(|p| p.len()))
            .field("long_link_len", &self.long_link.as_ref().map(|l| l.len()))
            .field("header", &self.header)
            .finish()
    }
}

/// Calculate the number of 512-byte blocks needed to store `size` bytes.
///
/// This is useful for calculating content block counts.
#[must_use]
pub const fn blocks_for_size(size: u64) -> u64 {
    size.div_ceil(HEADER_SIZE as u64)
}

/// Pad data to a 512-byte boundary.
///
/// Returns the data with zero-padding appended to reach a multiple of 512 bytes.
#[must_use]
pub fn pad_to_block_boundary(data: &[u8]) -> Vec<u8> {
    let padded_len = data.len().div_ceil(HEADER_SIZE) * HEADER_SIZE;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaxExtensions;

    #[test]
    fn test_write_bytes() {
        let mut field = [0u8; 10];

        // Normal case
        write_bytes(&mut field, b"hello").unwrap();
        assert_eq!(&field[..5], b"hello");
        assert_eq!(field[5..], [0, 0, 0, 0, 0]);

        // Exact fit
        write_bytes(&mut field, b"0123456789").unwrap();
        assert_eq!(&field, b"0123456789");

        // Too long
        assert!(write_bytes(&mut field, b"12345678901").is_err());
    }

    #[test]
    fn test_write_octal() {
        // 8-byte field (like mode)
        let mut field = [0u8; 8];

        write_octal(&mut field, 0o644).unwrap();
        assert_eq!(&field, b"0000644\0");

        write_octal(&mut field, 0o755).unwrap();
        assert_eq!(&field, b"0000755\0");

        write_octal(&mut field, 0).unwrap();
        assert_eq!(&field, b"0000000\0");

        // 12-byte field (like size)
        let mut field12 = [0u8; 12];
        write_octal(&mut field12, 0o77777777777).unwrap();
        assert_eq!(&field12, b"77777777777\0");

        // Test max value that fits
        write_octal(&mut field, 0o7777777).unwrap();
        assert_eq!(&field, b"7777777\0");
    }

    #[test]
    fn test_write_octal_overflow() {
        let mut field = [0u8; 8];
        // Value too large for 7 octal digits
        assert!(write_octal(&mut field, 0o100000000).is_err());
    }

    #[test]
    fn test_header_builder_basic() {
        let builder = HeaderBuilder::new_ustar();
        let header = builder.as_header();
        assert!(header.is_ustar());
        assert!(!header.is_gnu());
    }

    #[test]
    fn test_header_builder_gnu() {
        let builder = HeaderBuilder::new_gnu();
        let header = builder.as_header();
        assert!(header.is_gnu());
        assert!(!header.is_ustar());
    }

    #[test]
    fn test_header_builder_file() {
        let mut builder = HeaderBuilder::new_ustar();
        builder
            .path(b"test.txt")
            .unwrap()
            .mode(0o644)
            .uid(1000)
            .unwrap()
            .gid(1000)
            .unwrap()
            .size(1024)
            .unwrap()
            .mtime(1234567890)
            .unwrap()
            .entry_type(EntryType::Regular)
            .username(b"user")
            .unwrap()
            .groupname(b"group")
            .unwrap();

        let header_bytes = builder.finish();
        let header = Header::from_bytes_exact(&header_bytes);

        assert_eq!(header.path_bytes(), b"test.txt");
        assert_eq!(header.mode().unwrap(), 0o644);
        assert_eq!(header.uid().unwrap(), 1000);
        assert_eq!(header.gid().unwrap(), 1000);
        assert_eq!(header.entry_size().unwrap(), 1024);
        assert_eq!(header.mtime().unwrap(), 1234567890);
        assert_eq!(header.entry_type(), EntryType::Regular);
        assert_eq!(header.username().unwrap(), b"user");
        assert_eq!(header.groupname().unwrap(), b"group");

        // Verify checksum
        assert!(header.verify_checksum().is_ok());
    }

    #[test]
    fn test_header_builder_symlink() {
        let mut builder = HeaderBuilder::new_ustar();
        builder
            .path(b"link")
            .unwrap()
            .mode(0o777)
            .entry_type(EntryType::Symlink)
            .link_name(b"target")
            .unwrap()
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap();

        let header_bytes = builder.finish();
        let header = Header::from_bytes_exact(&header_bytes);

        assert_eq!(header.path_bytes(), b"link");
        assert_eq!(header.entry_type(), EntryType::Symlink);
        assert_eq!(header.link_name_bytes(), b"target");
        assert!(header.verify_checksum().is_ok());
    }

    #[test]
    fn test_header_builder_directory() {
        let mut builder = HeaderBuilder::new_ustar();
        builder
            .path(b"mydir/")
            .unwrap()
            .mode(0o755)
            .entry_type(EntryType::Directory)
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap();

        let header_bytes = builder.finish();
        let header = Header::from_bytes_exact(&header_bytes);

        assert_eq!(header.entry_type(), EntryType::Directory);
        assert!(header.verify_checksum().is_ok());
    }

    #[test]
    fn test_header_builder_device() {
        let mut builder = HeaderBuilder::new_ustar();
        builder
            .path(b"null")
            .unwrap()
            .mode(0o666)
            .entry_type(EntryType::Char)
            .device(1, 3)
            .unwrap()
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap();

        let header_bytes = builder.finish();
        let header = Header::from_bytes_exact(&header_bytes);

        assert_eq!(header.entry_type(), EntryType::Char);
        assert_eq!(header.device_major().unwrap(), Some(1));
        assert_eq!(header.device_minor().unwrap(), Some(3));
        assert!(header.verify_checksum().is_ok());
    }

    #[test]
    fn test_pax_builder_basic() {
        let mut builder = PaxBuilder::new();
        let _ = builder.add("key", b"value").add("another", b"test");
        let data = builder.finish();

        // Parse it back
        let mut iter = PaxExtensions::new(&data);

        let ext1 = iter.next().unwrap().unwrap();
        assert_eq!(ext1.key().unwrap(), "key");
        assert_eq!(ext1.value().unwrap(), "value");

        let ext2 = iter.next().unwrap().unwrap();
        assert_eq!(ext2.key().unwrap(), "another");
        assert_eq!(ext2.value().unwrap(), "test");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_pax_builder_path() {
        let long_path = b"/very/long/path/that/exceeds/one/hundred/characters/which/is/the/limit/for/the/standard/tar/name/field.txt";

        let mut builder = PaxBuilder::new();
        let _ = builder.path(long_path);
        let data = builder.finish();

        let ext = PaxExtensions::new(&data).next().unwrap().unwrap();
        assert_eq!(ext.key().unwrap(), "path");
        assert_eq!(ext.value_bytes(), long_path);
    }

    #[test]
    fn test_pax_builder_size() {
        let mut builder = PaxBuilder::new();
        let _ = builder.size(1_000_000_000_000);
        let data = builder.finish();

        let exts = PaxExtensions::new(&data);
        assert_eq!(exts.get_u64("size"), Some(1_000_000_000_000));
    }

    #[test]
    fn test_pax_builder_multiple() {
        let mut builder = PaxBuilder::new();
        let _ = builder
            .path(b"/some/path")
            .uid(65534)
            .gid(65534)
            .uname(b"nobody")
            .gname(b"nogroup")
            .mtime(1700000000);
        let data = builder.finish();

        let exts = PaxExtensions::new(&data);
        assert_eq!(exts.get("path"), Some("/some/path"));
        assert_eq!(exts.get_u64("uid"), Some(65534));
        assert_eq!(exts.get_u64("gid"), Some(65534));
        assert_eq!(exts.get("uname"), Some("nobody"));
        assert_eq!(exts.get("gname"), Some("nogroup"));
        assert_eq!(exts.get_u64("mtime"), Some(1700000000));
    }

    #[test]
    fn test_pax_record_length_calculation() {
        // Test edge cases for length calculation
        // Record "9 k=v\n" has length 6, but we write "9" which is 1 digit
        // Actually need "6 k=v\n" which is length 6 - that works!

        let mut builder = PaxBuilder::new();
        let _ = builder.add("k", b"v");
        let data = builder.finish();
        assert_eq!(&data, b"6 k=v\n");

        // Longer key/value
        let mut builder = PaxBuilder::new();
        let _ = builder.add("path", b"/a/b/c/d/e/f");
        let data = builder.finish();
        // "XX path=/a/b/c/d/e/f\n" where XX is the length
        // Base: " path=/a/b/c/d/e/f\n" = 1 + 4 + 1 + 12 + 1 = 19
        // With "19": total 21, but we wrote 19... need 21
        // With "21": total 21, works!
        assert!(data.starts_with(b"21 path="));
    }

    #[test]
    fn test_roundtrip() {
        // Build a header, serialize it, parse it back, verify fields match
        let mut builder = HeaderBuilder::new_ustar();
        builder
            .path(b"roundtrip_test.txt")
            .unwrap()
            .mode(0o755)
            .uid(1001)
            .unwrap()
            .gid(1002)
            .unwrap()
            .size(4096)
            .unwrap()
            .mtime(1609459200)
            .unwrap()
            .entry_type(EntryType::Regular)
            .username(b"testuser")
            .unwrap()
            .groupname(b"testgroup")
            .unwrap();

        let header_bytes = builder.finish();

        // Parse it back
        let parsed = Header::from_bytes(&header_bytes).unwrap();

        // Verify all fields match
        assert_eq!(parsed.path_bytes(), b"roundtrip_test.txt");
        assert_eq!(parsed.mode().unwrap(), 0o755);
        assert_eq!(parsed.uid().unwrap(), 1001);
        assert_eq!(parsed.gid().unwrap(), 1002);
        assert_eq!(parsed.entry_size().unwrap(), 4096);
        assert_eq!(parsed.mtime().unwrap(), 1609459200);
        assert_eq!(parsed.entry_type(), EntryType::Regular);
        assert_eq!(parsed.username().unwrap(), b"testuser");
        assert_eq!(parsed.groupname().unwrap(), b"testgroup");

        // Checksum must be valid
        parsed.verify_checksum().unwrap();
    }

    #[test]
    fn test_roundtrip_gnu() {
        let mut builder = HeaderBuilder::new_gnu();
        let _ = builder
            .path(b"gnu_test.dat")
            .unwrap()
            .mode(0o600)
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap()
            .entry_type(EntryType::Regular);

        let header_bytes = builder.finish();
        let parsed = Header::from_bytes(&header_bytes).unwrap();

        assert!(parsed.is_gnu());
        assert_eq!(parsed.path_bytes(), b"gnu_test.dat");
        parsed.verify_checksum().unwrap();
    }

    #[test]
    fn test_header_builder_default() {
        let builder = HeaderBuilder::default();
        assert!(builder.as_header().is_ustar());
    }

    #[test]
    fn test_header_builder_debug() {
        let builder = HeaderBuilder::new_ustar();
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("HeaderBuilder"));
    }

    #[test]
    fn test_pax_builder_debug() {
        let builder = PaxBuilder::new();
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("PaxBuilder"));
    }

    #[test]
    fn test_path_too_long() {
        let mut builder = HeaderBuilder::new_ustar();
        let long_path = [b'a'; 101];
        assert!(builder.path(&long_path).is_err());
    }

    #[test]
    fn test_link_name_too_long() {
        let mut builder = HeaderBuilder::new_ustar();
        let long_link = [b'b'; 101];
        assert!(builder.link_name(&long_link).is_err());
    }

    #[test]
    fn test_username_too_long() {
        let mut builder = HeaderBuilder::new_ustar();
        let long_name = [b'u'; 33];
        assert!(builder.username(&long_name).is_err());
    }

    #[test]
    fn test_pax_builder_linkpath() {
        let mut builder = PaxBuilder::new();
        let _ = builder.linkpath(b"/target/of/symlink");
        let data = builder.finish();

        let exts = PaxExtensions::new(&data);
        assert_eq!(exts.get("linkpath"), Some("/target/of/symlink"));
    }

    #[test]
    fn test_pax_builder_times() {
        let mut builder = PaxBuilder::new();
        let _ = builder.mtime(1000).atime(2000).ctime(3000);
        let data = builder.finish();

        let exts = PaxExtensions::new(&data);
        assert_eq!(exts.get_u64("mtime"), Some(1000));
        assert_eq!(exts.get_u64("atime"), Some(2000));
        assert_eq!(exts.get_u64("ctime"), Some(3000));
    }

    // =========================================================================
    // EntryBuilder Tests
    // =========================================================================

    #[test]
    fn test_entry_builder_short_path_no_extension() {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"hello.txt")
            .mode(0o644)
            .size(1024)
            .unwrap()
            .mtime(1234567890)
            .unwrap()
            .uid(1000)
            .unwrap()
            .gid(1000)
            .unwrap()
            .entry_type(EntryType::Regular);

        assert!(!builder.needs_extension());

        let blocks = builder.finish();
        assert_eq!(blocks.len(), 1, "short path should produce single header");

        // Verify the header is valid
        let header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(header.path_bytes(), b"hello.txt");
        assert_eq!(header.mode().unwrap(), 0o644);
        assert_eq!(header.entry_size().unwrap(), 1024);
        assert!(header.verify_checksum().is_ok());
    }

    #[test]
    fn test_entry_builder_path_exactly_100_bytes() {
        // Path exactly 100 bytes should NOT require extension
        let path = "a".repeat(100);
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(path.as_bytes())
            .mode(0o644)
            .size(0)
            .unwrap()
            .entry_type(EntryType::Regular);

        assert!(!builder.needs_extension());

        let blocks = builder.finish();
        assert_eq!(blocks.len(), 1);

        let header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(header.path_bytes().len(), 100);
    }

    #[test]
    fn test_entry_builder_gnu_long_path() {
        // Path > 100 bytes requires GNU LongName extension
        let long_path = "a/".repeat(60) + "file.txt"; // 128 bytes
        assert!(long_path.len() > 100);

        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(long_path.as_bytes())
            .mode(0o644)
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap()
            .entry_type(EntryType::Regular);

        assert!(builder.needs_extension());

        let blocks = builder.finish();
        // Should have: 1 LongName header + 1 data block + 1 main header = 3 blocks
        assert!(blocks.len() >= 3, "got {} blocks", blocks.len());

        // First block should be the GNU LongName header
        let ext_header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(ext_header.entry_type(), EntryType::GnuLongName);
        assert_eq!(ext_header.path_bytes(), b"././@LongLink");
        assert!(ext_header.verify_checksum().is_ok());

        // The size should be path length + 1 (null terminator)
        assert_eq!(ext_header.entry_size().unwrap(), long_path.len() as u64 + 1);

        // Second block should contain the path data (null-terminated)
        let data_block = &blocks[1];
        assert_eq!(&data_block[..long_path.len()], long_path.as_bytes());
        assert_eq!(data_block[long_path.len()], 0); // null terminator

        // Last block should be the main header
        let main_header = Header::from_bytes_exact(blocks.last().unwrap());
        assert_eq!(main_header.entry_type(), EntryType::Regular);
        assert!(main_header.verify_checksum().is_ok());
    }

    #[test]
    fn test_entry_builder_gnu_long_link() {
        // Link target > 100 bytes requires GNU LongLink extension
        let long_target = "/very/long/symlink/target/".repeat(5); // ~130 bytes
        assert!(long_target.len() > 100);

        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"mylink")
            .link_name(long_target.as_bytes())
            .mode(0o777)
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap()
            .entry_type(EntryType::Symlink);

        assert!(builder.needs_extension());

        let blocks = builder.finish();
        assert!(blocks.len() >= 3);

        // First block should be the GNU LongLink header
        let ext_header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(ext_header.entry_type(), EntryType::GnuLongLink);
        assert_eq!(ext_header.path_bytes(), b"././@LongLink");

        // Last block should be the symlink header
        let main_header = Header::from_bytes_exact(blocks.last().unwrap());
        assert_eq!(main_header.entry_type(), EntryType::Symlink);
    }

    #[test]
    fn test_entry_builder_gnu_long_path_and_link() {
        // Both path and link target > 100 bytes
        let long_path = "dir/".repeat(30) + "file"; // ~124 bytes
        let long_target = "target/".repeat(20); // 140 bytes

        assert!(long_path.len() > 100);
        assert!(long_target.len() > 100);

        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(long_path.as_bytes())
            .link_name(long_target.as_bytes())
            .mode(0o777)
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap()
            .entry_type(EntryType::Symlink);

        let blocks = builder.finish();
        // Should have: LongLink header + data + LongName header + data + main header
        // At minimum: 2 (for LongLink) + 2 (for LongName) + 1 (main) = 5 blocks
        assert!(blocks.len() >= 5, "got {} blocks", blocks.len());

        // First should be LongLink (for link target)
        let first = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(first.entry_type(), EntryType::GnuLongLink);

        // After LongLink data, should be LongName
        // Find the LongName header
        let longname_idx = blocks.iter().position(|b| {
            let h = Header::from_bytes_exact(b);
            h.entry_type() == EntryType::GnuLongName
        });
        assert!(longname_idx.is_some(), "should have LongName header");

        // Last should be main header
        let main = Header::from_bytes_exact(blocks.last().unwrap());
        assert_eq!(main.entry_type(), EntryType::Symlink);
    }

    #[test]
    fn test_entry_builder_pax_long_path() {
        let long_path = "pax/".repeat(30) + "file.txt"; // ~124 bytes
        assert!(long_path.len() > 100);

        let mut builder = EntryBuilder::new_ustar(); // Uses PAX mode
        builder
            .path(long_path.as_bytes())
            .mode(0o644)
            .size(0)
            .unwrap()
            .mtime(0)
            .unwrap()
            .uid(0)
            .unwrap()
            .gid(0)
            .unwrap()
            .entry_type(EntryType::Regular);

        assert_eq!(builder.extension_mode(), ExtensionMode::Pax);
        assert!(builder.needs_extension());

        let blocks = builder.finish();
        // Should have: PAX header + data block + main header
        assert!(blocks.len() >= 3);

        // First block should be the PAX extended header
        let pax_header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(pax_header.entry_type(), EntryType::XHeader);
        assert!(pax_header.verify_checksum().is_ok());

        // Second block should contain PAX records
        let pax_data = &blocks[1];
        // The PAX data should contain "path=<long_path>"
        let pax_str = String::from_utf8_lossy(pax_data);
        assert!(pax_str.contains("path="));
        assert!(pax_str.contains(&long_path));

        // Last block should be the main header
        let main_header = Header::from_bytes_exact(blocks.last().unwrap());
        assert_eq!(main_header.entry_type(), EntryType::Regular);
        assert!(main_header.is_ustar());
    }

    #[test]
    fn test_entry_builder_pax_long_link() {
        let long_target = "/long/symlink/target/".repeat(6);
        assert!(long_target.len() > 100);

        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"link")
            .link_name(long_target.as_bytes())
            .mode(0o777)
            .size(0)
            .unwrap()
            .entry_type(EntryType::Symlink);

        let blocks = builder.finish();

        // First block should be PAX header
        let pax_header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(pax_header.entry_type(), EntryType::XHeader);

        // PAX data should contain linkpath
        let pax_data = &blocks[1];
        let pax_str = String::from_utf8_lossy(pax_data);
        assert!(pax_str.contains("linkpath="));
    }

    #[test]
    fn test_entry_builder_custom_pax_extension() {
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"file.txt")
            .mode(0o644)
            .size(0)
            .unwrap()
            .add_pax("SCHILY.xattr.user.test", b"value")
            .entry_type(EntryType::Regular);

        assert!(builder.needs_extension()); // Due to custom PAX

        let blocks = builder.finish();
        assert!(blocks.len() >= 3);

        let pax_header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(pax_header.entry_type(), EntryType::XHeader);

        let pax_data = &blocks[1];
        let pax_str = String::from_utf8_lossy(pax_data);
        assert!(pax_str.contains("SCHILY.xattr.user.test=value"));
    }

    #[test]
    fn test_entry_builder_extension_mode_switching() {
        let long_path = "x/".repeat(60);

        // Default GNU mode
        let mut builder = EntryBuilder::new_gnu();
        assert_eq!(builder.extension_mode(), ExtensionMode::Gnu);

        // Switch to PAX mode
        builder.set_extension_mode(ExtensionMode::Pax);
        assert_eq!(builder.extension_mode(), ExtensionMode::Pax);

        builder
            .path(long_path.as_bytes())
            .mode(0o644)
            .size(0)
            .unwrap()
            .entry_type(EntryType::Regular);

        let blocks = builder.finish();
        // Should use PAX, not GNU
        let first = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(first.entry_type(), EntryType::XHeader);
    }

    #[test]
    fn test_entry_builder_finish_bytes() {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"test.txt")
            .mode(0o644)
            .size(0)
            .unwrap()
            .entry_type(EntryType::Regular);

        let bytes = builder.finish_bytes();
        assert_eq!(bytes.len(), 512);
        assert_eq!(&bytes[..512], builder.header().as_header().as_bytes());
    }

    #[test]
    fn test_entry_builder_directory() {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"mydir/")
            .mode(0o755)
            .size(0)
            .unwrap()
            .mtime(1234567890)
            .unwrap()
            .uid(1000)
            .unwrap()
            .gid(1000)
            .unwrap()
            .entry_type(EntryType::Directory);

        let blocks = builder.finish();
        assert_eq!(blocks.len(), 1);

        let header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(header.entry_type(), EntryType::Directory);
        assert!(header.verify_checksum().is_ok());
    }

    #[test]
    fn test_entry_builder_device() {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"null")
            .mode(0o666)
            .size(0)
            .unwrap()
            .device(1, 3)
            .unwrap()
            .entry_type(EntryType::Char);

        let blocks = builder.finish();
        let header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(header.entry_type(), EntryType::Char);
        assert_eq!(header.device_major().unwrap(), Some(1));
        assert_eq!(header.device_minor().unwrap(), Some(3));
    }

    #[test]
    fn test_entry_builder_with_mode() {
        let header = HeaderBuilder::new_gnu();
        let builder = EntryBuilder::with_mode(header, ExtensionMode::Pax);
        assert_eq!(builder.extension_mode(), ExtensionMode::Pax);
        assert!(builder.header().as_header().is_gnu());
    }

    #[test]
    fn test_entry_builder_default() {
        let builder = EntryBuilder::default();
        assert_eq!(builder.extension_mode(), ExtensionMode::Gnu);
    }

    #[test]
    fn test_entry_builder_debug() {
        let mut builder = EntryBuilder::new_gnu();
        builder.path(b"test.txt");
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EntryBuilder"));
        assert!(debug_str.contains("Gnu"));
    }

    #[test]
    fn test_blocks_for_size() {
        assert_eq!(blocks_for_size(0), 0);
        assert_eq!(blocks_for_size(1), 1);
        assert_eq!(blocks_for_size(511), 1);
        assert_eq!(blocks_for_size(512), 1);
        assert_eq!(blocks_for_size(513), 2);
        assert_eq!(blocks_for_size(1024), 2);
        assert_eq!(blocks_for_size(1025), 3);
    }

    #[test]
    fn test_pad_to_block_boundary() {
        // Empty
        let padded = pad_to_block_boundary(&[]);
        assert!(padded.is_empty());

        // Less than 512
        let data = [1u8; 100];
        let padded = pad_to_block_boundary(&data);
        assert_eq!(padded.len(), 512);
        assert_eq!(&padded[..100], &data);
        assert!(padded[100..].iter().all(|&b| b == 0));

        // Exactly 512
        let data = [2u8; 512];
        let padded = pad_to_block_boundary(&data);
        assert_eq!(padded.len(), 512);
        assert_eq!(&padded[..], &data);

        // More than 512
        let data = [3u8; 600];
        let padded = pad_to_block_boundary(&data);
        assert_eq!(padded.len(), 1024);
        assert_eq!(&padded[..600], &data);
        assert!(padded[600..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_entry_builder_very_long_path() {
        // Path that requires multiple data blocks
        let very_long_path = "x/".repeat(300); // 600 bytes
        assert!(very_long_path.len() > 512);

        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(very_long_path.as_bytes())
            .mode(0o644)
            .size(0)
            .unwrap()
            .entry_type(EntryType::Regular);

        let blocks = builder.finish();
        // LongName header + 2 data blocks (600+1 = 601 bytes, needs 2 blocks) + main header = 4
        assert!(blocks.len() >= 4, "got {} blocks", blocks.len());

        let ext_header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(ext_header.entry_type(), EntryType::GnuLongName);
        // Size should be 601 (path + null terminator)
        assert_eq!(ext_header.entry_size().unwrap(), 601);
    }

    #[test]
    fn test_entry_builder_username_groupname() {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"file.txt")
            .mode(0o644)
            .size(0)
            .unwrap()
            .username(b"testuser")
            .unwrap()
            .groupname(b"testgroup")
            .unwrap()
            .entry_type(EntryType::Regular);

        let blocks = builder.finish();
        let header = Header::from_bytes_exact(&blocks[0]);
        assert_eq!(header.username().unwrap(), b"testuser");
        assert_eq!(header.groupname().unwrap(), b"testgroup");
    }

    #[test]
    fn test_entry_builder_header_access() {
        let mut builder = EntryBuilder::new_gnu();
        builder.path(b"test.txt");

        // Read access
        assert!(builder.header().as_header().is_gnu());

        // Mutable access
        builder.header_mut().mode(0o755);
        assert_eq!(builder.header().as_header().mode().unwrap(), 0o755);
    }
}
