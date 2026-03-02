//! Fuzz target: feed arbitrary bytes into tar-core's Parser.
//!
//! Invariants under test:
//! - The parser must never panic on any input (with either default or permissive limits).
//! - Padded size is always >= size and block-aligned (or both zero).
//! - Parsed entry paths are never empty.
//! - Total consumed bytes never exceed the input length.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tar_core::parse::{Limits, ParseEvent, Parser};
use tar_core::HEADER_SIZE;

/// Drive a parser to completion over `data`, checking invariants on each entry.
/// Returns normally on errors or NeedData — the point is that it must not panic.
fn run_parser(data: &[u8], limits: Limits) {
    let mut parser = Parser::new(limits);
    let mut offset: usize = 0;

    loop {
        assert!(offset <= data.len(), "offset exceeded input length");
        let input = &data[offset..];

        match parser.parse(input) {
            Ok(ParseEvent::NeedData { .. }) => break,

            Ok(ParseEvent::Entry { consumed, entry })
            | Ok(ParseEvent::SparseEntry {
                consumed, entry, ..
            }) => {
                // consumed bytes must not exceed remaining input
                assert!(
                    consumed <= input.len(),
                    "consumed {consumed} > remaining {}",
                    input.len()
                );

                // Padded-size invariants
                assert!(
                    entry.padded_size() >= entry.size,
                    "padded_size {} < size {}",
                    entry.padded_size(),
                    entry.size
                );
                if entry.size == 0 {
                    assert_eq!(entry.padded_size(), 0, "size 0 should have padded_size 0");
                } else {
                    assert_eq!(
                        entry.padded_size() % HEADER_SIZE as u64,
                        0,
                        "padded_size {} not block-aligned",
                        entry.padded_size()
                    );
                }

                // Path must not be empty
                assert!(!entry.path.is_empty(), "entry path is empty");

                offset += consumed;

                // Skip content + padding; if not enough data remains, bail out.
                let padded = entry.padded_size() as usize;
                if offset.saturating_add(padded) > data.len() {
                    break;
                }
                offset += padded;
            }

            Ok(ParseEvent::GlobalExtensions { consumed, .. }) => {
                assert!(
                    consumed <= input.len(),
                    "GlobalExtensions consumed {consumed} > remaining {}",
                    input.len()
                );
                offset += consumed;
            }

            Ok(ParseEvent::End { consumed }) => {
                assert!(
                    consumed <= input.len(),
                    "End consumed {consumed} > remaining {}",
                    input.len()
                );
                offset += consumed;
                break;
            }

            // Parse errors are expected on fuzzed input — just stop.
            Err(_) => break,
        }
    }

    assert!(
        offset <= data.len(),
        "total consumed {offset} > input length {}",
        data.len()
    );
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
    // 90% of the time, fix up checksums to exercise deeper parser logic.
    // 10% of the time, pass raw bytes to test checksum validation itself.
    let should_fixup = !data.is_empty() && data[0] % 10 != 0;

    if should_fixup {
        let mut data = data.to_vec();
        fixup_checksums(&mut data);
        run_parser(&data, Limits::permissive());
        run_parser(&data, Limits::default());
    } else {
        run_parser(data, Limits::permissive());
        run_parser(data, Limits::default());
    }
});
