//! Integration test: minimal sync IO parser wrapping tar-core's sans-IO primitives.
//!
//! This exercises `TarStreamParser`, a `std::io::Read`-based wrapper around
//! tar-core's header parsing. It lives here (not in the core crate) because
//! tar-core is intentionally sans-IO and does not depend on `std::io::Read`.

#![allow(missing_docs)]

use std::borrow::Cow;
use std::io::{Cursor, Read};

use tar_core::parse::{Limits, ParseError};
use tar_core::{EntryType, Header, PaxExtensions, HEADER_SIZE, PAX_SCHILY_XATTR};

// =============================================================================
// TarStreamParser — a thin Read-based wrapper
// =============================================================================

/// Internal state for accumulating metadata entries.
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
}

/// A fully-resolved tar entry with all extensions applied.
#[derive(Debug)]
pub struct ParsedEntry<'a> {
    pub header_bytes: &'a [u8; 512],
    pub entry_type: EntryType,
    pub path: Cow<'a, [u8]>,
    pub link_target: Option<Cow<'a, [u8]>>,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub size: u64,
    pub uname: Option<Cow<'a, [u8]>>,
    pub gname: Option<Cow<'a, [u8]>>,
    pub dev_major: Option<u32>,
    pub dev_minor: Option<u32>,
    #[allow(clippy::type_complexity)]
    pub xattrs: Vec<(Cow<'a, [u8]>, Cow<'a, [u8]>)>,
    pub pax_data: Option<Cow<'a, [u8]>>,
}

impl<'a> ParsedEntry<'a> {
    #[must_use]
    pub fn path_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.path)
    }

    #[must_use]
    pub fn is_file(&self) -> bool {
        self.entry_type.is_file()
    }

    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.entry_type.is_dir()
    }

    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.entry_type.is_symlink()
    }

    #[must_use]
    pub fn is_hard_link(&self) -> bool {
        self.entry_type.is_hard_link()
    }

    #[must_use]
    pub fn padded_size(&self) -> u64 {
        self.size.next_multiple_of(512)
    }
}

/// Streaming tar parser wrapping a `Read` source.
///
/// This is a minimal sync-IO wrapper around tar-core's header parsing.
/// It handles GNU long name/link and PAX extended headers transparently.
#[derive(Debug)]
pub struct TarStreamParser<R> {
    reader: R,
    limits: Limits,
    pending: PendingMetadata,
    header_buf: [u8; HEADER_SIZE],
    pos: u64,
    done: bool,
}

type Result<T> = std::result::Result<T, ParseError>;

impl<R: Read> TarStreamParser<R> {
    pub fn new(reader: R, limits: Limits) -> Self {
        Self {
            reader,
            limits,
            pending: PendingMetadata::default(),
            header_buf: [0u8; HEADER_SIZE],
            pos: 0,
            done: false,
        }
    }

    #[allow(dead_code)]
    pub fn with_defaults(reader: R) -> Self {
        Self::new(reader, Limits::default())
    }

    #[allow(dead_code)]
    pub fn position(&self) -> u64 {
        self.pos
    }

    pub fn next_entry(&mut self) -> Result<Option<ParsedEntry<'_>>> {
        if self.done {
            return Ok(None);
        }

        loop {
            if self.pending.count > self.limits.max_pending_entries {
                return Err(ParseError::TooManyPendingEntries {
                    count: self.pending.count,
                    limit: self.limits.max_pending_entries,
                });
            }

            let got_header = read_exact_or_eof(&mut self.reader, &mut self.header_buf)?;
            if !got_header {
                self.done = true;
                if !self.pending.is_empty() {
                    return Err(ParseError::OrphanedMetadata);
                }
                return Ok(None);
            }
            self.pos += HEADER_SIZE as u64;

            if self.header_buf.iter().all(|&b| b == 0) {
                self.done = true;
                if !self.pending.is_empty() {
                    return Err(ParseError::OrphanedMetadata);
                }
                return Ok(None);
            }

            let header = Header::from_bytes_exact(&self.header_buf);
            header.verify_checksum()?;

            let entry_type = header.entry_type();
            let size = header.entry_size()?;
            let padded_size = size
                .checked_next_multiple_of(512)
                .ok_or(ParseError::InvalidSize(size))?;

            match entry_type {
                EntryType::GnuLongName => {
                    self.handle_gnu_long_name(size, padded_size)?;
                    continue;
                }
                EntryType::GnuLongLink => {
                    self.handle_gnu_long_link(size, padded_size)?;
                    continue;
                }
                EntryType::XHeader => {
                    self.handle_pax_header(size, padded_size)?;
                    continue;
                }
                EntryType::XGlobalHeader => {
                    self.skip_bytes(padded_size)?;
                    continue;
                }
                _ => {
                    let gnu_long_name = self.pending.gnu_long_name.take();
                    let gnu_long_link = self.pending.gnu_long_link.take();
                    let pax_extensions = self.pending.pax_extensions.take();
                    self.pending.count = 0;

                    let entry = self.resolve_entry_with_pending(
                        gnu_long_name,
                        gnu_long_link,
                        pax_extensions,
                    )?;
                    return Ok(Some(entry));
                }
            }
        }
    }

    pub fn skip_content(&mut self, size: u64) -> Result<()> {
        let padded = size
            .checked_next_multiple_of(512)
            .ok_or(ParseError::InvalidSize(size))?;
        self.skip_bytes(padded)
    }

    pub fn skip_padding(&mut self, content_size: u64) -> Result<()> {
        let padded = content_size
            .checked_next_multiple_of(512)
            .ok_or(ParseError::InvalidSize(content_size))?;
        let padding = padded - content_size;
        if padding > 0 {
            self.skip_bytes(padding)?;
        }
        Ok(())
    }

    pub fn reader(&mut self) -> &mut R {
        &mut self.reader
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn skip_bytes(&mut self, len: u64) -> Result<()> {
        let mut remaining = len;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            self.reader.read_exact(&mut buf[..to_read])?;
            remaining -= to_read as u64;
        }
        self.pos += len;
        Ok(())
    }

    fn handle_gnu_long_name(&mut self, size: u64, padded_size: u64) -> Result<()> {
        if self.pending.gnu_long_name.is_some() {
            return Err(ParseError::DuplicateGnuLongName);
        }
        if size > self.limits.max_gnu_long_size {
            return Err(ParseError::GnuLongTooLarge {
                size,
                limit: self.limits.max_gnu_long_size,
            });
        }
        let mut data = self.read_vec(size as usize)?;
        self.skip_bytes(padded_size - size)?;
        data.pop_if(|&mut x| x == 0);
        if data.len() > self.limits.max_path_len {
            return Err(ParseError::PathTooLong {
                len: data.len(),
                limit: self.limits.max_path_len,
            });
        }
        self.pending.gnu_long_name = Some(data);
        self.pending.count += 1;
        Ok(())
    }

    fn handle_gnu_long_link(&mut self, size: u64, padded_size: u64) -> Result<()> {
        if self.pending.gnu_long_link.is_some() {
            return Err(ParseError::DuplicateGnuLongLink);
        }
        if size > self.limits.max_gnu_long_size {
            return Err(ParseError::GnuLongTooLarge {
                size,
                limit: self.limits.max_gnu_long_size,
            });
        }
        let mut data = self.read_vec(size as usize)?;
        self.skip_bytes(padded_size - size)?;
        data.pop_if(|&mut x| x == 0);
        if data.len() > self.limits.max_path_len {
            return Err(ParseError::PathTooLong {
                len: data.len(),
                limit: self.limits.max_path_len,
            });
        }
        self.pending.gnu_long_link = Some(data);
        self.pending.count += 1;
        Ok(())
    }

    fn handle_pax_header(&mut self, size: u64, padded_size: u64) -> Result<()> {
        if self.pending.pax_extensions.is_some() {
            return Err(ParseError::DuplicatePaxHeader);
        }
        if size > self.limits.max_pax_size {
            return Err(ParseError::PaxTooLarge {
                size,
                limit: self.limits.max_pax_size,
            });
        }
        let data = self.read_vec(size as usize)?;
        self.skip_bytes(padded_size - size)?;
        self.pending.pax_extensions = Some(data);
        self.pending.count += 1;
        Ok(())
    }

    fn resolve_entry_with_pending(
        &self,
        gnu_long_name: Option<Vec<u8>>,
        gnu_long_link: Option<Vec<u8>>,
        pax_extensions: Option<Vec<u8>>,
    ) -> Result<ParsedEntry<'_>> {
        let header = Header::from_bytes_exact(&self.header_buf);

        let mut path: Cow<'_, [u8]> = Cow::Borrowed(header.path_bytes());
        let mut link_target: Option<Cow<'_, [u8]>> = None;
        let mut uid = header.uid()?;
        let mut gid = header.gid()?;
        let mut mtime = header.mtime()?;
        let mut entry_size = header.entry_size()?;
        let mut xattrs = Vec::new();
        let mut uname: Option<Cow<'_, [u8]>> = header.username().map(Cow::Borrowed);
        let mut gname: Option<Cow<'_, [u8]>> = header.groupname().map(Cow::Borrowed);

        // Handle UStar prefix for path
        if let Some(prefix) = header.prefix() {
            if !prefix.is_empty() {
                let mut full_path = prefix.to_vec();
                full_path.push(b'/');
                full_path.extend_from_slice(header.path_bytes());
                path = Cow::Owned(full_path);
            }
        }

        if let Some(long_name) = gnu_long_name {
            path = Cow::Owned(long_name);
        }

        if let Some(long_link) = gnu_long_link {
            link_target = Some(Cow::Owned(long_link));
        } else {
            let header_link = header.link_name_bytes();
            if !header_link.is_empty() {
                link_target = Some(Cow::Borrowed(header_link));
            }
        }

        let pax_data: Option<Cow<'_, [u8]>> =
            pax_extensions.as_ref().map(|v| Cow::Owned(v.clone()));

        if let Some(ref pax) = pax_extensions {
            let extensions = PaxExtensions::new(pax);

            for ext in extensions {
                let ext = ext?;
                let key = ext.key().map_err(ParseError::from)?;
                let value = ext.value_bytes();

                match key {
                    "path" => {
                        if value.len() > self.limits.max_path_len {
                            return Err(ParseError::PathTooLong {
                                len: value.len(),
                                limit: self.limits.max_path_len,
                            });
                        }
                        path = Cow::Owned(value.to_vec());
                    }
                    "linkpath" => {
                        if value.len() > self.limits.max_path_len {
                            return Err(ParseError::PathTooLong {
                                len: value.len(),
                                limit: self.limits.max_path_len,
                            });
                        }
                        link_target = Some(Cow::Owned(value.to_vec()));
                    }
                    "size" => {
                        if let Ok(v) = ext.value() {
                            if let Ok(s) = v.parse::<u64>() {
                                entry_size = s;
                            }
                        }
                    }
                    "uid" => {
                        if let Ok(v) = ext.value() {
                            if let Ok(u) = v.parse::<u64>() {
                                uid = u;
                            }
                        }
                    }
                    "gid" => {
                        if let Ok(v) = ext.value() {
                            if let Ok(g) = v.parse::<u64>() {
                                gid = g;
                            }
                        }
                    }
                    "mtime" => {
                        if let Ok(v) = ext.value() {
                            if let Some(s) = v.split('.').next() {
                                if let Ok(m) = s.parse::<u64>() {
                                    mtime = m;
                                }
                            }
                        }
                    }
                    "uname" => {
                        uname = Some(Cow::Owned(value.to_vec()));
                    }
                    "gname" => {
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

        if path.len() > self.limits.max_path_len {
            return Err(ParseError::PathTooLong {
                len: path.len(),
                limit: self.limits.max_path_len,
            });
        }

        Ok(ParsedEntry {
            header_bytes: &self.header_buf,
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
            pax_data,
        })
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => {
                if total == 0 {
                    return Ok(false);
                }
                return Err(ParseError::UnexpectedEof { pos: 0 });
            }
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

// =============================================================================
// Test helpers
// =============================================================================

fn create_tar_with<F>(f: F) -> Vec<u8>
where
    F: FnOnce(&mut tar::Builder<&mut Vec<u8>>),
{
    let mut data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut data);
        f(&mut builder);
        builder.finish().unwrap();
    }
    data
}

fn append_file(builder: &mut tar::Builder<&mut Vec<u8>>, path: &str, content: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_uid(1000);
    header.set_gid(1000);
    header.set_mtime(1234567890);
    header.set_size(content.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    builder.append_data(&mut header, path, content).unwrap();
}

// =============================================================================
// Basic parsing tests
// =============================================================================

#[test]
fn test_empty_tar() {
    let data = create_tar_with(|_| {});
    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());
    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_single_file() {
    let data = create_tar_with(|b| {
        append_file(b, "hello.txt", b"Hello, World!");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"hello.txt");
    assert_eq!(entry.entry_type, EntryType::Regular);
    assert_eq!(entry.size, 13);
    assert_eq!(entry.mode, 0o644);
    assert_eq!(entry.uid, 1000);
    assert_eq!(entry.gid, 1000);
    assert_eq!(entry.mtime, 1234567890);

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_multiple_files() {
    let data = create_tar_with(|b| {
        append_file(b, "file1.txt", b"Content 1");
        append_file(b, "file2.txt", b"Content 2");
        append_file(b, "file3.txt", b"Content 3");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    for i in 1..=3 {
        let entry = parser.next_entry().unwrap().expect("should have entry");
        assert_eq!(entry.path.as_ref(), format!("file{i}.txt").as_bytes());
        let size = entry.size;
        drop(entry);
        parser.skip_content(size).unwrap();
    }

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_directory() {
    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        b.append_data(&mut header, "mydir/", std::io::empty())
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"mydir/");
    assert_eq!(entry.entry_type, EntryType::Directory);
    assert!(entry.is_dir());

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_symlink() {
    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        b.append_link(&mut header, "link", "target").unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"link");
    assert_eq!(entry.entry_type, EntryType::Symlink);
    assert!(entry.is_symlink());
    assert_eq!(entry.link_target.as_ref().unwrap().as_ref(), b"target");

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_hardlink() {
    let data = create_tar_with(|b| {
        append_file(b, "original.txt", b"content");

        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        b.append_link(&mut header, "hardlink.txt", "original.txt")
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry1 = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry1.path.as_ref(), b"original.txt");
    let size = entry1.size;
    drop(entry1);
    parser.skip_content(size).unwrap();

    let entry2 = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry2.path.as_ref(), b"hardlink.txt");
    assert_eq!(entry2.entry_type, EntryType::Link);
    assert!(entry2.is_hard_link());
    assert_eq!(
        entry2.link_target.as_ref().unwrap().as_ref(),
        b"original.txt"
    );

    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// GNU long name/link tests
// =============================================================================

#[test]
fn test_gnu_long_name() {
    let long_path = format!("very/long/path/{}", "x".repeat(120));

    let data = create_tar_with(|b| {
        append_file(b, &long_path, b"content");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), long_path.as_bytes());
    assert_eq!(entry.entry_type, EntryType::Regular);

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();
    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_gnu_long_link() {
    let long_target = "t".repeat(120);

    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        b.append_link(&mut header, "link", &long_target).unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"link");
    assert!(entry.is_symlink());
    assert_eq!(
        entry.link_target.as_ref().unwrap().as_ref(),
        long_target.as_bytes()
    );

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_gnu_long_name_and_link() {
    let long_path = "p".repeat(120);
    let long_target = "t".repeat(120);

    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        b.append_link(&mut header, &long_path, &long_target)
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), long_path.as_bytes());
    assert_eq!(
        entry.link_target.as_ref().unwrap().as_ref(),
        long_target.as_bytes()
    );

    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// PAX extension tests
// =============================================================================

#[test]
fn test_pax_long_path() {
    let long_path = format!("pax/path/{}", "y".repeat(200));

    let data = create_tar_with(|b| {
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o644);
        header.set_size(7);
        header.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut header, &long_path, b"content".as_slice())
            .unwrap();
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), long_path.as_bytes());

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();
    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// Security limit tests
// =============================================================================

#[test]
fn test_path_too_long() {
    let long_path = "x".repeat(200);

    let data = create_tar_with(|b| {
        append_file(b, &long_path, b"content");
    });

    let limits = Limits {
        max_path_len: 100,
        ..Default::default()
    };
    let mut parser = TarStreamParser::new(Cursor::new(data), limits);

    let err = parser.next_entry().unwrap_err();
    assert!(matches!(
        err,
        ParseError::PathTooLong {
            len: 200,
            limit: 100
        }
    ));
}

#[test]
fn test_gnu_long_too_large() {
    let long_path = "x".repeat(200);

    let data = create_tar_with(|b| {
        append_file(b, &long_path, b"content");
    });

    let limits = Limits {
        max_gnu_long_size: 100,
        ..Default::default()
    };
    let mut parser = TarStreamParser::new(Cursor::new(data), limits);

    let err = parser.next_entry().unwrap_err();
    assert!(matches!(err, ParseError::GnuLongTooLarge { .. }));
}

// =============================================================================
// Cross-checking with tar crate
// =============================================================================

#[test]
fn test_crosscheck_simple() {
    let data = create_tar_with(|b| {
        append_file(b, "file1.txt", b"Hello");
        append_file(b, "file2.txt", b"World");
    });

    let mut tar_archive = tar::Archive::new(Cursor::new(data.clone()));
    let tar_entries: Vec<_> = tar_archive.entries().unwrap().collect();

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());
    let mut our_entries = Vec::new();
    while let Some(entry) = parser.next_entry().unwrap() {
        let info = (
            entry.path.to_vec(),
            entry.size,
            entry.mode,
            entry.uid,
            entry.gid,
            entry.mtime,
        );
        let size = entry.size;
        drop(entry);
        our_entries.push(info);
        parser.skip_content(size).unwrap();
    }

    assert_eq!(tar_entries.len(), our_entries.len());

    for (tar_entry, our_entry) in tar_entries.into_iter().zip(our_entries.into_iter()) {
        let tar_entry = tar_entry.unwrap();
        let tar_header = tar_entry.header();

        assert_eq!(
            tar_header.path_bytes().as_ref(),
            our_entry.0.as_slice(),
            "path mismatch"
        );
        assert_eq!(tar_header.size().unwrap(), our_entry.1, "size mismatch");
        assert_eq!(tar_header.mode().unwrap(), our_entry.2, "mode mismatch");
        assert_eq!(tar_header.uid().unwrap(), our_entry.3, "uid mismatch");
        assert_eq!(tar_header.gid().unwrap(), our_entry.4, "gid mismatch");
        assert_eq!(tar_header.mtime().unwrap(), our_entry.5, "mtime mismatch");
    }
}

#[test]
fn test_crosscheck_gnu_long_names() {
    let paths = vec![
        "short.txt".to_string(),
        format!("medium/{}", "m".repeat(80)),
        format!("long/{}", "l".repeat(150)),
    ];

    let data = create_tar_with(|b| {
        for path in &paths {
            append_file(b, path, b"content");
        }
    });

    let mut tar_archive = tar::Archive::new(Cursor::new(data.clone()));
    let tar_paths: Vec<_> = tar_archive
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_path_buf())
        .collect();

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());
    let mut our_paths = Vec::new();
    while let Some(entry) = parser.next_entry().unwrap() {
        let path = String::from_utf8_lossy(&entry.path).to_string();
        let size = entry.size;
        drop(entry);
        our_paths.push(path);
        parser.skip_content(size).unwrap();
    }

    assert_eq!(tar_paths.len(), our_paths.len());
    for (tar_path, our_path) in tar_paths.into_iter().zip(our_paths.into_iter()) {
        assert_eq!(tar_path.to_string_lossy(), our_path);
    }
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn test_empty_file() {
    let data = create_tar_with(|b| {
        append_file(b, "empty.txt", b"");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.path.as_ref(), b"empty.txt");
    assert_eq!(entry.size, 0);

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_read_content() {
    let data = create_tar_with(|b| {
        append_file(b, "file.txt", b"Hello, World!");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.size, 13);
    let size = entry.size;
    drop(entry);

    let mut content = vec![0u8; size as usize];
    std::io::Read::read_exact(parser.reader(), &mut content).unwrap();
    assert_eq!(content, b"Hello, World!");

    parser.skip_padding(size).unwrap();

    assert!(parser.next_entry().unwrap().is_none());
}

#[test]
fn test_padded_size() {
    let data = create_tar_with(|b| {
        append_file(b, "file.txt", b"x");
    });

    let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

    let entry = parser.next_entry().unwrap().expect("should have entry");
    assert_eq!(entry.size, 1);
    assert_eq!(entry.padded_size(), 512);

    let size = entry.size;
    drop(entry);
    parser.skip_content(size).unwrap();
    assert!(parser.next_entry().unwrap().is_none());
}

// =============================================================================
// Proptest cross-checking
// =============================================================================

mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn path_strategy() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[a-zA-Z0-9_][a-zA-Z0-9_.+-]{0,50}")
            .expect("valid regex")
            .prop_filter("non-empty", |s| !s.is_empty())
    }

    fn content_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..1024)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn test_roundtrip_single_file(path in path_strategy(), content in content_strategy()) {
            let data = create_tar_with(|b| {
                append_file(b, &path, &content);
            });

            let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());

            let entry = parser.next_entry().unwrap().expect("should have entry");
            prop_assert_eq!(entry.path.as_ref(), path.as_bytes());
            prop_assert_eq!(entry.size, content.len() as u64);
            let size = entry.size;
            drop(entry);

            let mut read_content = vec![0u8; size as usize];
            if size > 0 {
                std::io::Read::read_exact(parser.reader(), &mut read_content).unwrap();
                parser.skip_padding(size).unwrap();
            }
            prop_assert_eq!(read_content, content);

            prop_assert!(parser.next_entry().unwrap().is_none());
        }

        #[test]
        fn test_roundtrip_multiple_files(
            paths in prop::collection::vec(path_strategy(), 1..8)
        ) {
            let data = create_tar_with(|b| {
                for (i, path) in paths.iter().enumerate() {
                    let content = format!("content{i}");
                    append_file(b, path, content.as_bytes());
                }
            });

            let mut tar_archive = tar::Archive::new(Cursor::new(data.clone()));
            let tar_count = tar_archive.entries().unwrap().count();

            let mut parser = TarStreamParser::new(Cursor::new(data), Limits::default());
            let mut our_count = 0;
            while let Some(entry) = parser.next_entry().unwrap() {
                our_count += 1;
                let size = entry.size;
                drop(entry);
                parser.skip_content(size).unwrap();
            }

            prop_assert_eq!(tar_count, our_count);
            prop_assert_eq!(our_count, paths.len());
        }
    }
}
