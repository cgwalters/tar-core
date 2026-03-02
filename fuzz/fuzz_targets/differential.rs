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

/// Dump the raw 512-byte headers from the (post-fixup) data to stderr.
fn dump_headers(data: &[u8]) {
    let mut offset = 0;
    let mut i = 0;
    while offset + 512 <= data.len() {
        let block = &data[offset..offset + 512];
        if block.iter().all(|&b| b == 0) {
            eprintln!("block[{i}] @{offset}: <all zeros>");
            offset += 512;
            i += 1;
            continue;
        }
        let header = tar_core::Header::from_bytes(block.try_into().unwrap());
        eprintln!("block[{i}] @{offset}: {header:?}");
        offset += 512;
        i += 1;
    }
}

/// Compare entries parsed by tar-rs and tar-core, asserting equivalence.
///
/// tar-core is intentionally more lenient than tar-rs in some cases (e.g.
/// all-null numeric fields are accepted as 0), so we only require that
/// tar-core parses *at least* as many entries as tar-rs and that those
/// entries match.
fn compare_entries(data: &[u8], tar_rs_entries: &[OwnedEntry], tar_core_entries: &[OwnedEntry]) {
    if tar_core_entries.len() < tar_rs_entries.len() {
        eprintln!(
            "entry count mismatch: tar-core={} tar-rs={}",
            tar_core_entries.len(),
            tar_rs_entries.len()
        );
        dump_headers(data);
        for (i, e) in tar_rs_entries.iter().enumerate() {
            eprintln!("tar-rs  [{i}]: {e:?}");
        }
        for (i, e) in tar_core_entries.iter().enumerate() {
            eprintln!("tar-core[{i}]: {e:?}");
        }
        panic!(
            "tar-core parsed fewer entries than tar-rs: tar-core={} tar-rs={}",
            tar_core_entries.len(),
            tar_rs_entries.len(),
        );
    }

    for (i, (rs, core)) in tar_rs_entries.iter().zip(tar_core_entries).enumerate() {
        if rs != core {
            eprintln!("mismatch at entry {i}:");
            dump_headers(data);
            eprintln!("  tar-rs:   {rs:?}");
            eprintln!("  tar-core: {core:?}");
            panic!("entry {i} differs between tar-rs and tar-core");
        }
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
        compare_entries(&data, &tar_rs_entries, &tar_core_entries);
    } else {
        let tar_rs_entries = parse_tar_rs(data);
        let tar_core_entries = parse_tar_core(data);
        compare_entries(data, &tar_rs_entries, &tar_core_entries);
    }
});
