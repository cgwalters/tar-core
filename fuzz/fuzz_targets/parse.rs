//! Fuzz target: feed arbitrary bytes into tar-core's Parser.
//!
//! Invariants under test:
//! - The parser must never panic on any input (with either default or permissive limits).
//! - Padded size is always >= size and block-aligned (or both zero).
//! - Parsed entry paths are never empty.
//! - Total consumed bytes never exceed the input length.
//!
//! The parser is exercised with variable-length short reads to stress the
//! NeedData/retry path that real callers hit with partial I/O. Each parse
//! call gets a different chunk size from a seeded RNG, simulating realistic
//! non-uniform read patterns.

#![no_main]

use std::mem::size_of;

use libfuzzer_sys::fuzz_target;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tar_core::parse::{Limits, ParseEvent, Parser};
use tar_core::HEADER_SIZE;

/// Max chunk size ceiling for short-read simulation (1 MiB).
const MAX_CHUNK_CEILING: u32 = 1024 * 1024;

/// Drive a parser to completion over `data`, feeding it variable-sized
/// chunks drawn from `rng` to simulate realistic partial reads.
///
/// On NeedData, the exposed window grows to provide the requested minimum.
/// After each successfully processed event, a fresh chunk size is drawn
/// from the RNG so the parser sees different split points throughout.
///
/// Checks invariants on each entry and returns normally on errors or
/// NeedData — the point is that it must not panic.
fn run_parser(data: &[u8], limits: Limits, verify_checksums: bool, rng: &mut SmallRng) {
    let mut parser = Parser::new(limits);
    parser.set_verify_checksums(verify_checksums);
    let mut offset: usize = 0;
    let mut window = rng.random_range(1..=MAX_CHUNK_CEILING) as usize;

    loop {
        assert!(offset <= data.len(), "offset exceeded input length");
        let remaining = data.len() - offset;
        if remaining == 0 {
            break;
        }

        let input = &data[offset..offset + remaining.min(window)];

        match parser.parse(input) {
            Ok(ParseEvent::NeedData { min_bytes }) => {
                if remaining < min_bytes {
                    break;
                }
                // Widen the window to satisfy the parser's request and retry.
                window = min_bytes;
                continue;
            }

            Ok(ParseEvent::Entry { consumed, entry })
            | Ok(ParseEvent::SparseEntry {
                consumed, entry, ..
            }) => {
                assert!(
                    consumed <= input.len(),
                    "consumed {consumed} > input len {}",
                    input.len()
                );

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

                assert!(!entry.path.is_empty(), "entry path is empty");

                offset += consumed;

                let padded = entry.padded_size() as usize;
                if offset.saturating_add(padded) > data.len() {
                    break;
                }
                offset += padded;

                window = rng.random_range(1..=MAX_CHUNK_CEILING) as usize;
            }

            Ok(ParseEvent::GlobalExtensions { consumed, .. }) => {
                assert!(
                    consumed <= input.len(),
                    "GlobalExtensions consumed {consumed} > input len {}",
                    input.len()
                );
                offset += consumed;
                window = rng.random_range(1..=MAX_CHUNK_CEILING) as usize;
            }

            Ok(ParseEvent::End { consumed }) => {
                assert!(
                    consumed <= input.len(),
                    "End consumed {consumed} > input len {}",
                    input.len()
                );
                offset += consumed;
                break;
            }

            Err(_) => break,
        }
    }

    assert!(
        offset <= data.len(),
        "total consumed {offset} > input length {}",
        data.len()
    );
}

/// Byte offset where the tar payload begins (after the config/seed header).
const PAYLOAD_OFFSET: usize = 1 + size_of::<u64>();

fuzz_target!(|data: &[u8]| {
    if data.len() < PAYLOAD_OFFSET {
        return;
    }

    // First byte: checksum behavior.
    // 90% skip checksums, 10% verify them.
    let skip_checksums = data[0] % 10 != 0;

    // Bytes 1..9: seed for the chunk-size RNG.
    let seed = u64::from_le_bytes(data[1..PAYLOAD_OFFSET].try_into().unwrap());
    let mut rng = SmallRng::seed_from_u64(seed);

    let payload = &data[PAYLOAD_OFFSET..];

    run_parser(payload, Limits::permissive(), !skip_checksums, &mut rng);
    run_parser(payload, Limits::default(), !skip_checksums, &mut rng);
});
