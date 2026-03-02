//! Differential fuzz target: compare tar-core against the `tar` crate.
//!
//! For any arbitrary byte input we parse it with both parsers and compare
//! results including file content and xattrs. The primary invariant is that
//! tar-core must never panic. A secondary goal is that whenever tar-rs
//! successfully parses an entry, tar-core should produce a matching entry
//! with equivalent metadata, xattrs, and identical content bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tar_core_testutil::{parse_tar_core, parse_tar_rs, OwnedEntry};

/// Compare entries parsed by tar-rs and tar-core, asserting equivalence.
fn compare_entries(tar_rs_entries: &[OwnedEntry], tar_core_entries: &[OwnedEntry]) {
    assert_eq!(
        tar_core_entries.len(),
        tar_rs_entries.len(),
        "entry count mismatch: tar-core={} tar-rs={}",
        tar_core_entries.len(),
        tar_rs_entries.len(),
    );

    for (i, (rs, core)) in tar_rs_entries.iter().zip(tar_core_entries).enumerate() {
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
        assert_eq!(
            rs.link_target, core.link_target,
            "link_target mismatch at entry {i}"
        );
        assert_eq!(rs.uname, core.uname, "uname mismatch at entry {i}");
        assert_eq!(rs.gname, core.gname, "gname mismatch at entry {i}");
        assert_eq!(
            rs.dev_major, core.dev_major,
            "dev_major mismatch at entry {i}"
        );
        assert_eq!(
            rs.dev_minor, core.dev_minor,
            "dev_minor mismatch at entry {i}"
        );
        assert_eq!(
            rs.content, core.content,
            "content mismatch at entry {i} (size={})",
            rs.size,
        );
        assert_eq!(rs.xattrs, core.xattrs, "xattr mismatch at entry {i}");
    }
}

/// Preprocess fuzz input to fix up tar header checksums.
///
/// Walks through 512-byte aligned blocks. For each non-zero block (potential
/// header), computes and sets a valid checksum. Then attempts to parse the
/// size field to skip over content blocks, advancing to the next header.
///
/// This dramatically improves fuzzing coverage by allowing the parser to get
/// past the checksum verification gate and exercise deeper parsing logic
/// (PAX extensions, GNU long name/link, sparse files, etc.).
fn fixup_checksums(data: &mut [u8]) {
    let mut offset = 0;
    while offset + 512 <= data.len() {
        let block = &data[offset..offset + 512];

        // Skip zero blocks (end-of-archive markers)
        if block.iter().all(|&b| b == 0) {
            offset += 512;
            continue;
        }

        // Fill checksum field (bytes 148..156) with spaces
        let block = &mut data[offset..offset + 512];
        block[148..156].fill(b' ');

        // Compute checksum: unsigned sum of all 512 bytes
        let checksum: u64 = block.iter().map(|&b| u64::from(b)).sum();

        // Encode as 7 octal digits + NUL terminator
        let cksum_str = format!("{:07o}\0", checksum);
        let cksum_bytes = cksum_str.as_bytes();
        let copy_len = cksum_bytes.len().min(8);
        block[148..148 + copy_len].copy_from_slice(&cksum_bytes[..copy_len]);

        offset += 512;

        // Try to parse the size field (bytes 124..136) to skip content blocks
        let size_field = &data[offset - 512 + 124..offset - 512 + 136];
        if let Some(size) = parse_octal_simple(size_field) {
            let padded = ((size as usize) + 511) & !511;
            if offset + padded <= data.len() {
                offset += padded;
            }
        }
    }
}

/// Simple octal parser for the size field - doesn't need to handle base-256
/// since we're just trying to skip content. Returns None on any parse failure.
fn parse_octal_simple(bytes: &[u8]) -> Option<u64> {
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| b != b' ' && b != 0)
        .collect();
    if trimmed.is_empty() {
        return Some(0);
    }
    let s = core::str::from_utf8(&trimmed).ok()?;
    u64::from_str_radix(s, 8).ok()
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    // 90% of the time, fix up checksums to exercise deeper parser logic.
    // 10% of the time, pass raw bytes to test checksum validation itself.
    let should_fixup = !data.is_empty() && data[0] % 10 != 0;

    if should_fixup {
        let mut data = data.to_vec();
        fixup_checksums(&mut data);
        let tar_rs_entries = parse_tar_rs(&data);
        let tar_core_entries = parse_tar_core(&data);
        compare_entries(&tar_rs_entries, &tar_core_entries);
    } else {
        let tar_rs_entries = parse_tar_rs(data);
        let tar_core_entries = parse_tar_core(data);
        compare_entries(&tar_rs_entries, &tar_core_entries);
    }
});
