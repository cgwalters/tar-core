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
fn run_parser(data: &[u8], limits: Limits, verify_checksums: bool) {
    let mut parser = Parser::new(limits);
    parser.set_verify_checksums(verify_checksums);
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

fuzz_target!(|data: &[u8]| {
    // 90% of the time, skip checksum verification to exercise deeper parser
    // logic (PAX extensions, GNU long name/link, sparse files, field parsing,
    // etc.). Random fuzz input almost never has valid checksums, so without
    // this the fuzzer would break immediately on every input.
    //
    // 10% of the time, verify checksums normally to test that code path too.
    let skip_checksums = !data.is_empty() && data[0] % 10 != 0;

    run_parser(data, Limits::permissive(), !skip_checksums);
    run_parser(data, Limits::default(), !skip_checksums);
});
