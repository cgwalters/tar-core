//! Shared test utilities for tar-core.
//!
//! Provides an owned entry type and helpers to parse tar archives with
//! both tar-core and the `tar` crate, for use in integration tests and
//! fuzz targets.

use std::io::{Cursor, Read};

use tar_core::parse::{Limits, ParseEvent, Parser};
use tar_core::{HEADER_SIZE, PAX_SCHILY_XATTR};

/// Owned snapshot of a parsed tar entry, including content bytes.
///
/// All byte-oriented fields use `Vec<u8>` since tar paths and xattr
/// values are not necessarily valid UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEntry {
    pub entry_type: u8,
    pub path: Vec<u8>,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub size: u64,
    pub uname: Option<Vec<u8>>,
    pub gname: Option<Vec<u8>>,
    /// Device major number (for block/char devices).
    pub dev_major: Option<u32>,
    /// Device minor number (for block/char devices).
    pub dev_minor: Option<u32>,
    /// Extended attributes (from PAX `SCHILY.xattr.*` records).
    /// Each pair is `(attr_name, value)` where `attr_name` is the part
    /// after `SCHILY.xattr.` (e.g. `user.mime_type`).
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    pub content: Vec<u8>,
}

/// Maximum content size read per entry (prevents OOM on fuzzed inputs).
const MAX_CONTENT_READ: u64 = 256 * 1024;

/// Parse a tar archive with tar-core's sans-IO parser using permissive limits.
pub fn parse_tar_core(data: &[u8]) -> Vec<OwnedEntry> {
    parse_tar_core_with_limits(data, Limits::permissive())
}

/// Parse a tar archive with tar-core using the given limits.
pub fn parse_tar_core_with_limits(data: &[u8], limits: Limits) -> Vec<OwnedEntry> {
    let mut results = Vec::new();
    let mut parser = Parser::new(limits);
    let mut offset = 0;

    loop {
        if offset > data.len() {
            break;
        }
        let input = &data[offset..];

        match parser.parse(input) {
            Ok(ParseEvent::NeedData { .. }) => break,
            Ok(ParseEvent::Entry { consumed, entry })
            | Ok(ParseEvent::SparseEntry {
                consumed, entry, ..
            }) => {
                offset += consumed;

                let size = entry.size;
                let read_size = size.min(MAX_CONTENT_READ) as usize;

                let content_end = offset.saturating_add(read_size);
                let (content, truncated) = if content_end <= data.len() {
                    (data[offset..content_end].to_vec(), false)
                } else {
                    (data[offset..].to_vec(), true)
                };

                let xattrs: Vec<(Vec<u8>, Vec<u8>)> = entry
                    .xattrs
                    .iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect();

                results.push(OwnedEntry {
                    entry_type: entry.entry_type.to_byte(),
                    path: entry.path.to_vec(),
                    link_target: entry.link_target.as_ref().map(|v| v.to_vec()),
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    mtime: entry.mtime,
                    size,
                    uname: entry.uname.as_ref().map(|v| v.to_vec()),
                    gname: entry.gname.as_ref().map(|v| v.to_vec()),
                    dev_major: entry.dev_major,
                    dev_minor: entry.dev_minor,
                    xattrs,
                    content,
                });

                if truncated {
                    break;
                }

                // Advance past content + padding.
                let padded = (size as usize).next_multiple_of(HEADER_SIZE);
                if offset.saturating_add(padded) > data.len() {
                    break;
                }
                offset += padded;
            }
            Ok(ParseEvent::End { .. }) => break,
            Err(_) => break,
        }
    }

    results
}

/// Parse a tar archive with the `tar` crate, returning owned entries.
pub fn parse_tar_rs(data: &[u8]) -> Vec<OwnedEntry> {
    let mut results = Vec::new();
    let cursor = Cursor::new(data);
    let mut archive = tar::Archive::new(cursor);

    let entries = match archive.entries() {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(_) => break,
        };
        let header = entry.header().clone();

        let path = entry.path_bytes().into_owned();
        let size = entry.size();
        let entry_type = header.entry_type().as_byte();
        let mode = header.mode().unwrap_or(0);
        let uid = header.uid().unwrap_or(0);
        let gid = header.gid().unwrap_or(0);
        let mtime = header.mtime().unwrap_or(0);
        // entry.link_name_bytes() applies PAX linkpath and GNU long link
        // overrides, unlike header.link_name_bytes() which is raw.
        let link_target = entry
            .link_name_bytes()
            .filter(|b| !b.is_empty())
            .map(|b| b.to_vec());

        // Extract PAX-overridden uname/gname and xattrs from PAX extensions.
        // tar-rs does not expose PAX uname/gname through entry-level methods,
        // so we must read the raw PAX records ourselves.
        let mut uname: Option<Vec<u8>> = None;
        let mut gname: Option<Vec<u8>> = None;
        let mut xattrs = Vec::new();
        if let Ok(Some(pax)) = entry.pax_extensions() {
            for ext in pax.flatten() {
                if let Ok(key) = std::str::from_utf8(ext.key_bytes()) {
                    if let Some(attr_name) = key.strip_prefix(PAX_SCHILY_XATTR) {
                        xattrs.push((attr_name.as_bytes().to_vec(), ext.value_bytes().to_vec()));
                    } else if key == "uname" {
                        uname = Some(ext.value_bytes().to_vec());
                    } else if key == "gname" {
                        gname = Some(ext.value_bytes().to_vec());
                    }
                }
            }
        }
        // Fall back to raw header values if PAX didn't override.
        if uname.is_none() {
            uname = header
                .username_bytes()
                .filter(|b| !b.is_empty())
                .map(|b| b.to_vec());
        }
        if gname.is_none() {
            gname = header
                .groupname_bytes()
                .filter(|b| !b.is_empty())
                .map(|b| b.to_vec());
        }

        let read_size = size.min(MAX_CONTENT_READ) as usize;
        let mut content = vec![0u8; read_size];
        if entry.read_exact(&mut content).is_err() {
            break;
        }

        let dev_major = header.device_major().unwrap_or(None);
        let dev_minor = header.device_minor().unwrap_or(None);

        results.push(OwnedEntry {
            entry_type,
            path,
            link_target,
            mode,
            uid,
            gid,
            mtime,
            size,
            uname,
            gname,
            dev_major,
            dev_minor,
            xattrs,
            content,
        });
    }

    results
}
