//! Fuzz target: build a tar archive with EntryBuilder, parse it back, and
//! verify roundtrip equivalence.
//!
//! The invariant: if EntryBuilder successfully produces an archive, Parser
//! must parse it back to identical metadata and content.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tar_core::builder::EntryBuilder;
use tar_core::parse::{Limits, ParseEvent, Parser};
use tar_core::{EntryType, SparseEntry, HEADER_SIZE};

#[derive(Debug, Arbitrary)]
struct FuzzEntry {
    path_bytes: Vec<u8>,
    mode: u16,
    uid: u16,
    gid: u16,
    mtime: u32,
    uname_bytes: Vec<u8>,
    gname_bytes: Vec<u8>,
    content: Vec<u8>,
    use_pax: bool,
    /// Selects entry type: 0=Regular, 1=Directory, 2=Symlink, 3=Hardlink
    entry_kind: u8,
    link_target_bytes: Vec<u8>,
    /// (gap, length) pairs to build a sparse map
    sparse_entries: Vec<(u16, u16)>,
    /// When true and entry_kind selects Regular, build a sparse entry
    use_sparse: bool,
}

/// Strip NUL bytes, ensure non-empty, clamp length.
fn sanitize(raw: &[u8], max_len: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = raw.iter().copied().filter(|&b| b != 0).collect();
    if out.is_empty() {
        return None;
    }
    out.truncate(max_len);
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let entry: FuzzEntry = match FuzzEntry::arbitrary(&mut u) {
        Ok(e) => e,
        Err(_) => return,
    };

    let path = match sanitize(&entry.path_bytes, 200) {
        Some(p) => p,
        None => return,
    };
    let uname = match sanitize(&entry.uname_bytes, 64) {
        Some(n) => n,
        None => return,
    };
    let gname = match sanitize(&entry.gname_bytes, 64) {
        Some(n) => n,
        None => return,
    };

    let mut content = entry.content;
    content.truncate(8192);
    let mode = (entry.mode as u32) & 0o7777;
    let uid = entry.uid as u64;
    let gid = entry.gid as u64;
    let mtime = entry.mtime as u64;

    // Build sparse map if applicable
    let is_sparse = entry.use_sparse && entry.entry_kind % 4 == 0;
    let sparse_map: Vec<SparseEntry> = if is_sparse {
        let mut map = Vec::new();
        let mut cursor = 0u64;
        for &(gap, length) in entry.sparse_entries.iter().take(50) {
            if length == 0 {
                continue;
            }
            let offset = cursor.saturating_add(gap as u64);
            map.push(SparseEntry {
                offset,
                length: length as u64,
            });
            cursor = offset.saturating_add(length as u64);
        }
        map
    } else {
        Vec::new()
    };

    // Pick entry type and adjust content/link accordingly
    let (entry_type, link_target) = match entry.entry_kind % 4 {
        1 => {
            content.clear(); // directories have no content
            (EntryType::Directory, None)
        }
        2 => {
            content.clear(); // symlinks have no content
            let target = match sanitize(&entry.link_target_bytes, 90) {
                Some(t) => t,
                None => return,
            };
            (EntryType::Symlink, Some(target))
        }
        3 => {
            content.clear(); // hardlinks have no content
            let target = match sanitize(&entry.link_target_bytes, 90) {
                Some(t) => t,
                None => return,
            };
            (EntryType::Link, Some(target))
        }
        _ => (EntryType::Regular, None),
    };

    // Build the archive
    let mut builder = if entry.use_pax {
        EntryBuilder::new_ustar()
    } else {
        EntryBuilder::new_gnu()
    };

    builder.path(&path).entry_type(entry_type);
    if let Some(ref target) = link_target {
        builder.link_name(target);
    }

    macro_rules! try_set {
        ($expr:expr) => {
            match $expr {
                Ok(_) => {}
                Err(_) => return,
            }
        };
    }

    // For sparse entries, the on-disk size is the sum of sparse chunk lengths
    // and content is just zero-filled padding.
    let on_disk_size: u64;
    let real_size: u64;
    if is_sparse && !sparse_map.is_empty() {
        on_disk_size = sparse_map.iter().map(|e| e.length).sum();
        real_size = sparse_map.last().map(|e| e.offset + e.length).unwrap_or(0);
        content = vec![0u8; on_disk_size as usize];
        builder.sparse(&sparse_map, real_size);
    } else if is_sparse {
        // Empty sparse map: treat as empty regular file
        on_disk_size = 0;
        real_size = 0;
        content.clear();
    } else {
        on_disk_size = content.len() as u64;
        real_size = 0; // unused for non-sparse
    }

    try_set!(builder.mode(mode));
    try_set!(builder.uid(uid));
    try_set!(builder.gid(gid));
    try_set!(builder.size(on_disk_size));
    try_set!(builder.mtime(mtime));

    // For GNU, truncate uname/gname to 32 bytes
    let uname_for_tar;
    let gname_for_tar;
    if entry.use_pax {
        uname_for_tar = uname.clone();
        gname_for_tar = gname.clone();
    } else {
        uname_for_tar = if uname.len() > 32 {
            uname[..32].to_vec()
        } else {
            uname.clone()
        };
        gname_for_tar = if gname.len() > 32 {
            gname[..32].to_vec()
        } else {
            gname.clone()
        };
    }
    try_set!(builder.username(&uname_for_tar));
    try_set!(builder.groupname(&gname_for_tar));

    let header_bytes = builder.finish_bytes();

    let mut archive = Vec::with_capacity(header_bytes.len() + content.len() + HEADER_SIZE * 3);
    archive.extend_from_slice(&header_bytes);
    archive.extend_from_slice(&content);
    let padding = (HEADER_SIZE - (content.len() % HEADER_SIZE)) % HEADER_SIZE;
    archive.extend(std::iter::repeat_n(0u8, padding));
    // End-of-archive marker
    archive.extend(std::iter::repeat_n(0u8, HEADER_SIZE * 2));

    // Parse it back
    let mut parser = Parser::new(Limits::default());
    let mut offset = 0;

    let input = &archive[offset..];
    let event = match parser.parse(input) {
        Ok(e) => e,
        other => {
            panic!("expected successful parse from archive we just built, got: {other:?}");
        }
    };

    // Extract parsed entry and verify sparse-specific fields
    let parsed_entry = match event {
        ParseEvent::Entry { consumed, entry } => {
            assert!(
                !is_sparse || sparse_map.is_empty(),
                "expected SparseEntry for non-empty sparse, got Entry"
            );
            offset += consumed;
            entry
        }
        ParseEvent::SparseEntry {
            consumed,
            entry,
            sparse_map: parsed_sparse_map,
            real_size: parsed_real_size,
        } => {
            assert!(
                is_sparse && !sparse_map.is_empty(),
                "expected Entry for non-sparse, got SparseEntry"
            );
            assert_eq!(
                sparse_map.len(),
                parsed_sparse_map.len(),
                "sparse_map length mismatch"
            );
            for (i, expected) in sparse_map.iter().enumerate() {
                assert_eq!(*expected, parsed_sparse_map[i], "sparse_map[{i}] mismatch");
            }
            assert_eq!(real_size, parsed_real_size, "real_size mismatch");
            offset += consumed;
            entry
        }
        other => {
            panic!("expected Entry or SparseEntry from archive we just built, got: {other:?}");
        }
    };

    // Verify roundtrip
    assert_eq!(path, parsed_entry.path.as_ref(), "path mismatch");
    if is_sparse && !sparse_map.is_empty() {
        // Sparse entries have GnuSparse type in GNU mode; in PAX mode
        // the parser may report Regular. Just check on-disk size.
        assert_eq!(on_disk_size, parsed_entry.size, "on-disk size mismatch");
    } else {
        assert_eq!(entry_type, parsed_entry.entry_type, "entry_type mismatch");
        assert_eq!(content.len() as u64, parsed_entry.size, "size mismatch");
    }
    assert_eq!(mode, parsed_entry.mode, "mode mismatch");
    assert_eq!(uid, parsed_entry.uid, "uid mismatch");
    assert_eq!(gid, parsed_entry.gid, "gid mismatch");
    assert_eq!(mtime, parsed_entry.mtime, "mtime mismatch");

    // Verify link target for symlinks/hardlinks
    if let Some(ref expected_target) = link_target {
        let parsed_target = parsed_entry
            .link_target
            .as_ref()
            .expect("expected link_target on symlink/hardlink");
        assert_eq!(
            expected_target.as_slice(),
            parsed_target.as_ref(),
            "link_target mismatch"
        );
    }

    if let Some(parsed_uname) = &parsed_entry.uname {
        assert_eq!(
            uname_for_tar.as_slice(),
            parsed_uname.as_ref(),
            "uname mismatch"
        );
    }
    if let Some(parsed_gname) = &parsed_entry.gname {
        assert_eq!(
            gname_for_tar.as_slice(),
            parsed_gname.as_ref(),
            "gname mismatch"
        );
    }

    // Verify content (only for non-sparse regular files)
    if !is_sparse && !content.is_empty() {
        let parsed_content = &archive[offset..offset + content.len()];
        assert_eq!(content, parsed_content, "content mismatch");
    }

    // Skip past content + padding
    let padded = content.len().next_multiple_of(HEADER_SIZE);
    offset += padded;

    match parser.parse(&archive[offset..]) {
        Ok(ParseEvent::End { .. }) => {}
        other => {
            panic!("expected End after single entry, got: {other:?}");
        }
    }
});
