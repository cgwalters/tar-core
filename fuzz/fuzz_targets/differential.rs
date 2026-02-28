//! Differential fuzz target: compare tar-core against the `tar` crate.
//!
//! For any arbitrary byte input we parse it with both parsers and compare
//! results. The primary invariant is that tar-core must never panic. A
//! secondary goal is that whenever tar-rs successfully parses an entry,
//! tar-core should produce a matching entry with equivalent metadata.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use tar_core::parse::{Limits, ParseEvent, Parsed, Parser};
use tar_core::HEADER_SIZE;

/// Metadata extracted from a single tar entry, used for comparison.
#[derive(Debug)]
struct EntryInfo {
    path: Vec<u8>,
    size: u64,
    entry_type: u8,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
}

/// Parse with the `tar` crate and collect entry metadata.
fn parse_with_tar_rs(data: &[u8]) -> Vec<EntryInfo> {
    let mut results = Vec::new();
    let cursor = Cursor::new(data);
    let mut archive = tar::Archive::new(cursor);

    let entries = match archive.entries() {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => break,
        };
        let header = entry.header();

        let path = entry.path_bytes().into_owned();

        let size = match header.size() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let entry_type = header.entry_type().as_byte();
        let mode = header.mode().unwrap_or(0);
        let uid = header.uid().unwrap_or(0);
        let gid = header.gid().unwrap_or(0);
        let mtime = header.mtime().unwrap_or(0);

        results.push(EntryInfo {
            path,
            size,
            entry_type,
            mode,
            uid,
            gid,
            mtime,
        });
    }

    results
}

/// Parse with tar-core and collect entry metadata.
fn parse_with_tar_core(data: &[u8]) -> Vec<EntryInfo> {
    let mut results = Vec::new();
    let mut parser = Parser::new(Limits::permissive());
    let mut offset = 0;

    loop {
        if offset > data.len() {
            break;
        }
        let input = &data[offset..];

        match parser.parse(input) {
            Ok(Parsed {
                event: ParseEvent::NeedData { .. },
                ..
            }) => break,
            Ok(Parsed {
                consumed,
                event: ParseEvent::Entry(entry),
            }) => {
                offset += consumed;

                let entry_type = entry.entry_type.to_byte();
                results.push(EntryInfo {
                    path: entry.path.to_vec(),
                    size: entry.size,
                    entry_type,
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    mtime: entry.mtime,
                });

                // Skip content + padding
                let padded = (entry.size as usize).next_multiple_of(HEADER_SIZE);
                if offset.saturating_add(padded) > data.len() {
                    let _ = parser.advance_content(entry.size);
                    break;
                }
                offset += padded;
                if parser.advance_content(entry.size).is_err() {
                    break;
                }
            }
            Ok(Parsed {
                event: ParseEvent::End,
                ..
            }) => break,
            Err(_) => break,
        }
    }

    results
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to keep things tractable.
    if data.len() > 256 * 1024 {
        return;
    }

    let tar_rs_entries = parse_with_tar_rs(data);
    let tar_core_entries = parse_with_tar_core(data);

    // For each entry that tar-rs parsed successfully, check that tar-core
    // produced a corresponding entry with matching metadata.
    let common = tar_rs_entries.len().min(tar_core_entries.len());
    for i in 0..common {
        let rs = &tar_rs_entries[i];
        let core = &tar_core_entries[i];

        // Path comparison: both should agree.
        assert_eq!(
            rs.path,
            core.path,
            "path mismatch at entry {i}: tar-rs={:?} tar-core={:?}",
            String::from_utf8_lossy(&rs.path),
            String::from_utf8_lossy(&core.path),
        );
        assert_eq!(rs.size, core.size, "size mismatch at entry {i}");
        assert_eq!(
            rs.entry_type, core.entry_type,
            "entry_type mismatch at entry {i}"
        );
        assert_eq!(rs.mode, core.mode, "mode mismatch at entry {i}");
        assert_eq!(rs.uid, core.uid, "uid mismatch at entry {i}");
        assert_eq!(rs.gid, core.gid, "gid mismatch at entry {i}");
        assert_eq!(rs.mtime, core.mtime, "mtime mismatch at entry {i}");
    }

    // If tar-rs found entries that tar-core did not, that's noteworthy but
    // not necessarily a bug (tar-rs may be more lenient in some cases).
    // We don't panic here because edge-case differences are expected.
});
