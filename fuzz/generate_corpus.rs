//! Generate seed corpus files for the `parse` fuzz target.
//!
//! Each seed exercises a distinct parser code path: empty archives, various
//! entry types, GNU long name/link extensions, PAX extended headers, edge-case
//! sizes, and multi-entry archives.
//!
//! Run via: `cargo run --manifest-path fuzz/Cargo.toml --bin generate-corpus`
//! or:      `just generate-corpus`

use std::fs;
use std::path::Path;

use tar_core::builder::EntryBuilder;
use tar_core::{EntryType, SparseEntry, HEADER_SIZE};

/// End-of-archive marker: two 512-byte zero blocks.
const EOA: [u8; 1024] = [0u8; 1024];

fn main() {
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/parse");
    fs::create_dir_all(&corpus_dir).expect("create corpus dir");

    let mut seeds: Vec<(&str, Vec<u8>)> = Vec::new();

    // 0. Empty archive (just end-of-archive markers)
    seeds.push(("empty", EOA.to_vec()));

    // 1. Single regular file, short path, no content
    seeds.push((
        "regular_empty",
        build_archive(
            |b| {
                b.path(b"hello.txt")
                    .entry_type(EntryType::Regular)
                    .mode(0o644)
                    .unwrap()
                    .size(0)
                    .unwrap();
            },
            &[],
        ),
    ));

    // 2. Single regular file with content
    seeds.push((
        "regular_content",
        build_archive(
            |b| {
                b.path(b"data.bin")
                    .entry_type(EntryType::Regular)
                    .mode(0o755)
                    .unwrap()
                    .size(13)
                    .unwrap()
                    .uid(1000)
                    .unwrap()
                    .gid(1000)
                    .unwrap()
                    .mtime(1700000000)
                    .unwrap();
            },
            b"Hello, world!",
        ),
    ));

    // 3. GNU long name (path > 100 chars)
    {
        let long_path = "deep/".repeat(25) + "file.txt"; // 130 chars
        seeds.push((
            "gnu_long_name",
            build_archive(
                |b| {
                    b.path(long_path.as_bytes())
                        .entry_type(EntryType::Regular)
                        .mode(0o644)
                        .unwrap()
                        .size(0)
                        .unwrap();
                },
                &[],
            ),
        ));
    }

    // 4. GNU long link (symlink target > 100 chars)
    {
        let long_target = "/usr/share/".to_string() + &"x".repeat(100);
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"mylink")
            .link_name(long_target.as_bytes())
            .entry_type(EntryType::Symlink)
            .mode(0o777)
            .unwrap()
            .size(0)
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("gnu_long_link", archive));
    }

    // 5. GNU long name AND long link combined
    {
        let long_path = "a/".repeat(60) + "linked";
        let long_target = "b/".repeat(60) + "target";
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(long_path.as_bytes())
            .link_name(long_target.as_bytes())
            .entry_type(EntryType::Symlink)
            .mode(0o777)
            .unwrap()
            .size(0)
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("gnu_long_both", archive));
    }

    // 6. Symlink (short target)
    {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"link.txt")
            .link_name(b"target.txt")
            .entry_type(EntryType::Symlink)
            .mode(0o777)
            .unwrap()
            .size(0)
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("symlink", archive));
    }

    // 7. Hardlink
    {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"hardlink.txt")
            .link_name(b"original.txt")
            .entry_type(EntryType::Link)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("hardlink", archive));
    }

    // 8. Directory
    seeds.push((
        "directory",
        build_archive(
            |b| {
                b.path(b"mydir/")
                    .entry_type(EntryType::Directory)
                    .mode(0o755)
                    .unwrap()
                    .size(0)
                    .unwrap();
            },
            &[],
        ),
    ));

    // 9. FIFO
    seeds.push((
        "fifo",
        build_archive(
            |b| {
                b.path(b"mypipe")
                    .entry_type(EntryType::Fifo)
                    .mode(0o644)
                    .unwrap()
                    .size(0)
                    .unwrap();
            },
            &[],
        ),
    ));

    // 10. Character device
    {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"dev/null")
            .entry_type(EntryType::Char)
            .mode(0o666)
            .unwrap()
            .size(0)
            .unwrap()
            .device(1, 3)
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("char_device", archive));
    }

    // 11. Block device
    {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"dev/sda")
            .entry_type(EntryType::Block)
            .mode(0o660)
            .unwrap()
            .size(0)
            .unwrap()
            .device(8, 0)
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("block_device", archive));
    }

    // 12. PAX extended header with long path
    {
        let long_path = "pax/".repeat(40) + "readme.md"; // 169 chars
        seeds.push((
            "pax_long_path",
            build_archive_pax(
                |b| {
                    b.path(long_path.as_bytes())
                        .entry_type(EntryType::Regular)
                        .mode(0o644)
                        .unwrap()
                        .size(4)
                        .unwrap();
                },
                b"test",
            ),
        ));
    }

    // 13. PAX with large uid/gid (overflow octal)
    {
        seeds.push((
            "pax_large_ids",
            build_archive_pax(
                |b| {
                    b.path(b"bigids.txt")
                        .entry_type(EntryType::Regular)
                        .mode(0o644)
                        .unwrap()
                        .size(0)
                        .unwrap()
                        .uid(u64::from(u32::MAX) + 1)
                        .unwrap()
                        .gid(u64::from(u32::MAX) + 1)
                        .unwrap();
                },
                &[],
            ),
        ));
    }

    // 14. PAX with custom xattr
    {
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"xattr.txt")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap();
        builder
            .add_pax("SCHILY.xattr.user.test", b"value123")
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("pax_xattr", archive));
    }

    // 15. PAX with multiple extensions (path + size + mtime + xattr)
    {
        let long_path = "multi_pax/".repeat(15) + "complex.dat";
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(long_path.as_bytes())
            .entry_type(EntryType::Regular)
            .mode(0o600)
            .unwrap()
            .size(7)
            .unwrap()
            .mtime(9999999999)
            .unwrap();
        builder
            .add_pax(
                "SCHILY.xattr.security.selinux",
                b"system_u:object_r:usr_t:s0",
            )
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(b"payload");
        let pad = (HEADER_SIZE - 7) % HEADER_SIZE;
        archive.extend(std::iter::repeat_n(0u8, pad));
        archive.extend_from_slice(&EOA);
        seeds.push(("pax_multi_ext", archive));
    }

    // 16. Multiple files in one archive
    {
        let mut archive = Vec::new();
        for i in 0..5u8 {
            let name = format!("file_{i}.txt");
            let content = format!("content {i}");
            let mut builder = EntryBuilder::new_gnu();
            builder
                .path(name.as_bytes())
                .entry_type(EntryType::Regular)
                .mode(0o644)
                .unwrap()
                .size(content.len() as u64)
                .unwrap();
            archive.extend_from_slice(&builder.finish_bytes());
            archive.extend_from_slice(content.as_bytes());
            let pad = (HEADER_SIZE - (content.len() % HEADER_SIZE)) % HEADER_SIZE;
            archive.extend(std::iter::repeat_n(0u8, pad));
        }
        archive.extend_from_slice(&EOA);
        seeds.push(("multi_file", archive));
    }

    // 17. Mixed types: dir + file + symlink
    {
        let mut archive = Vec::new();

        let mut b = EntryBuilder::new_gnu();
        b.path(b"project/")
            .entry_type(EntryType::Directory)
            .mode(0o755)
            .unwrap()
            .size(0)
            .unwrap();
        archive.extend_from_slice(&b.finish_bytes());

        let content = b"fn main() {}";
        let mut b = EntryBuilder::new_gnu();
        b.path(b"project/main.rs")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(content.len() as u64)
            .unwrap();
        archive.extend_from_slice(&b.finish_bytes());
        archive.extend_from_slice(content);
        let pad = (HEADER_SIZE - (content.len() % HEADER_SIZE)) % HEADER_SIZE;
        archive.extend(std::iter::repeat_n(0u8, pad));

        let mut b = EntryBuilder::new_gnu();
        b.path(b"project/latest")
            .link_name(b"main.rs")
            .entry_type(EntryType::Symlink)
            .mode(0o777)
            .unwrap()
            .size(0)
            .unwrap();
        archive.extend_from_slice(&b.finish_bytes());

        archive.extend_from_slice(&EOA);
        seeds.push(("mixed_types", archive));
    }

    // 18. Content exactly 512 bytes (block boundary)
    {
        let content = vec![0xABu8; 512];
        seeds.push((
            "exact_block",
            build_archive(
                |b| {
                    b.path(b"block.bin")
                        .entry_type(EntryType::Regular)
                        .mode(0o644)
                        .unwrap()
                        .size(512)
                        .unwrap();
                },
                &content,
            ),
        ));
    }

    // 19. Content just over block boundary (513 bytes)
    {
        let content = vec![0xCDu8; 513];
        seeds.push((
            "over_block",
            build_archive(
                |b| {
                    b.path(b"overblock.bin")
                        .entry_type(EntryType::Regular)
                        .mode(0o644)
                        .unwrap()
                        .size(513)
                        .unwrap();
                },
                &content,
            ),
        ));
    }

    // 20. setuid mode
    seeds.push((
        "mode_setuid",
        build_archive(
            |b| {
                b.path(b"setuid.bin")
                    .entry_type(EntryType::Regular)
                    .mode(0o4755)
                    .unwrap()
                    .size(0)
                    .unwrap();
            },
            &[],
        ),
    ));

    // 21. Minimal valid header (no EOA — tests truncated input)
    {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"minimal")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap();
        seeds.push(("minimal_header", builder.finish_bytes()));
    }

    // 22. Username and groupname in header
    {
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"owned.txt")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap()
            .uid(1000)
            .unwrap()
            .gid(1000)
            .unwrap()
            .username(b"testuser")
            .unwrap()
            .groupname(b"testgroup")
            .unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("uname_gname", archive));
    }

    // 23. PAX linkpath override
    {
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"pax_link")
            .link_name(b"short")
            .entry_type(EntryType::Symlink)
            .mode(0o777)
            .unwrap()
            .size(0)
            .unwrap();
        // Force a PAX linkpath by using a long target
        let long_target = "/target/".repeat(20) + "dest";
        builder.link_name(long_target.as_bytes());
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("pax_linkpath", archive));
    }

    // 24. PAX uname/gname override (long names that overflow header fields)
    {
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"pax_owner.txt")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap();
        // 33-byte names overflow the 32-byte GNU header field, requiring PAX
        let long_uname = "u".repeat(33);
        let long_gname = "g".repeat(33);
        builder.username(long_uname.as_bytes()).unwrap();
        builder.groupname(long_gname.as_bytes()).unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("pax_uname_gname", archive));
    }

    // 25. PAX fractional mtime
    {
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"fractional_mtime.txt")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap()
            .mtime(1700000000)
            .unwrap();
        builder.add_pax("mtime", b"1700000000.123456789").unwrap();
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("pax_fractional_mtime", archive));
    }

    // 26. Single zero block followed by valid header (mid-stream zero block recovery)
    {
        let mut archive = Vec::new();
        // One zero block (not two, so not end-of-archive)
        archive.extend(std::iter::repeat_n(0u8, HEADER_SIZE));
        // A valid entry
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"after_zero.txt")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap();
        archive.extend_from_slice(&builder.finish_bytes());
        archive.extend_from_slice(&EOA);
        seeds.push(("zero_block_recovery", archive));
    }

    // 27. V7 format (no magic/version — old-style header)
    // We create a raw header without ustar magic
    {
        let mut raw = [0u8; HEADER_SIZE];
        // path: "v7file.txt"
        raw[0..10].copy_from_slice(b"v7file.txt");
        // mode: "0000644\0"
        raw[100..108].copy_from_slice(b"0000644\0");
        // uid: "0001000\0"
        raw[108..116].copy_from_slice(b"0001000\0");
        // gid: "0001000\0"
        raw[116..124].copy_from_slice(b"0001000\0");
        // size: "00000000000\0"
        raw[124..136].copy_from_slice(b"00000000000\0");
        // mtime: "00000000000\0"
        raw[136..148].copy_from_slice(b"00000000000\0");
        // typeflag: '0' (regular)
        raw[156] = b'0';
        // No magic — this is a V7 header
        // Compute checksum
        // Checksum field (148..156) should be spaces during computation
        raw[148..156].copy_from_slice(b"        ");
        let cksum: u32 = raw.iter().map(|&b| b as u32).sum();
        let cksum_str = format!("{cksum:06o}\0 ");
        raw[148..156].copy_from_slice(cksum_str.as_bytes());

        let mut archive = raw.to_vec();
        archive.extend_from_slice(&EOA);
        seeds.push(("v7_format", archive));
    }

    // 28. GNU sparse, 2 inline entries
    {
        let sparse_map = [
            SparseEntry {
                offset: 0,
                length: 100,
            },
            SparseEntry {
                offset: 1000,
                length: 200,
            },
        ];
        let on_disk: u64 = 300;
        let real_size: u64 = 1200;
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"sparse_gnu_basic.bin")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(on_disk)
            .unwrap()
            .sparse(&sparse_map, real_size);
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend(vec![0u8; on_disk.next_multiple_of(512) as usize]);
        archive.extend_from_slice(&EOA);
        seeds.push(("sparse_gnu_basic", archive));
    }

    // 29. GNU sparse, 6 entries (needs extension block: >4 inline descriptors)
    {
        let sparse_map: Vec<SparseEntry> = (0..6)
            .map(|i| SparseEntry {
                offset: i * 1000,
                length: 50,
            })
            .collect();
        let on_disk: u64 = 300;
        let real_size: u64 = 5050;
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"sparse_gnu_ext.bin")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(on_disk)
            .unwrap()
            .sparse(&sparse_map, real_size);
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend(vec![0u8; on_disk.next_multiple_of(512) as usize]);
        archive.extend_from_slice(&EOA);
        seeds.push(("sparse_gnu_ext", archive));
    }

    // 30. GNU sparse, 28 entries (multiple extension blocks: 4 inline + 21 + 3)
    {
        let sparse_map: Vec<SparseEntry> = (0..28)
            .map(|i| SparseEntry {
                offset: i * 500,
                length: 30,
            })
            .collect();
        let on_disk: u64 = 28 * 30;
        let real_size: u64 = 27 * 500 + 30;
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"sparse_gnu_multi_ext.bin")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(on_disk)
            .unwrap()
            .sparse(&sparse_map, real_size);
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend(vec![0u8; on_disk.next_multiple_of(512) as usize]);
        archive.extend_from_slice(&EOA);
        seeds.push(("sparse_gnu_multi_ext", archive));
    }

    // 31. PAX sparse v1.0, 2 entries
    {
        let sparse_map = [
            SparseEntry {
                offset: 0,
                length: 100,
            },
            SparseEntry {
                offset: 3000,
                length: 400,
            },
        ];
        let on_disk: u64 = 500;
        let real_size: u64 = 3400;
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"sparse_pax_basic.dat")
            .mode(0o644)
            .unwrap()
            .size(on_disk)
            .unwrap()
            .sparse(&sparse_map, real_size);
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend(vec![0u8; on_disk.next_multiple_of(512) as usize]);
        archive.extend_from_slice(&EOA);
        seeds.push(("sparse_pax_basic", archive));
    }

    // 32. PAX sparse v1.0, 10 entries
    {
        let sparse_map: Vec<SparseEntry> = (0..10)
            .map(|i| SparseEntry {
                offset: i * 1000,
                length: 50,
            })
            .collect();
        let on_disk: u64 = 500;
        let real_size: u64 = 9050;
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"sparse_pax_many.dat")
            .mode(0o644)
            .unwrap()
            .size(on_disk)
            .unwrap()
            .sparse(&sparse_map, real_size);
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend(vec![0u8; on_disk.next_multiple_of(512) as usize]);
        archive.extend_from_slice(&EOA);
        seeds.push(("sparse_pax_many", archive));
    }

    // 33. GNU sparse with long path (>100 bytes)
    {
        let long_path = "sparse/".repeat(20) + "data.bin"; // 148 chars
        let sparse_map = [
            SparseEntry {
                offset: 0,
                length: 200,
            },
            SparseEntry {
                offset: 4096,
                length: 100,
            },
        ];
        let on_disk: u64 = 300;
        let real_size: u64 = 4196;
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(long_path.as_bytes())
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(on_disk)
            .unwrap()
            .sparse(&sparse_map, real_size);
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend(vec![0u8; on_disk.next_multiple_of(512) as usize]);
        archive.extend_from_slice(&EOA);
        seeds.push(("sparse_gnu_longpath", archive));
    }

    // 34. PAX sparse with long path (>100 bytes)
    {
        let long_path = "paxsparse/".repeat(15) + "file.dat"; // 158 chars
        let sparse_map = [
            SparseEntry {
                offset: 0,
                length: 512,
            },
            SparseEntry {
                offset: 8192,
                length: 256,
            },
        ];
        let on_disk: u64 = 768;
        let real_size: u64 = 8448;
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(long_path.as_bytes())
            .mode(0o644)
            .unwrap()
            .size(on_disk)
            .unwrap()
            .sparse(&sparse_map, real_size);
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend(vec![0u8; on_disk.next_multiple_of(512) as usize]);
        archive.extend_from_slice(&EOA);
        seeds.push(("sparse_pax_longpath", archive));
    }

    // Write seeds
    let mut count = 0;
    for (name, data) in &seeds {
        let path = corpus_dir.join(name);
        fs::write(&path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        count += 1;
        println!("{:>4}  {:>6} bytes  {}", count, data.len(), name);
    }
    println!("\nGenerated {count} seed files in {}", corpus_dir.display());
}

/// Build a single-entry GNU archive with optional content.
fn build_archive(configure: impl FnOnce(&mut EntryBuilder), content: &[u8]) -> Vec<u8> {
    let mut builder = EntryBuilder::new_gnu();
    configure(&mut builder);
    assemble(builder, content)
}

/// Build a single-entry PAX/UStar archive with optional content.
fn build_archive_pax(configure: impl FnOnce(&mut EntryBuilder), content: &[u8]) -> Vec<u8> {
    let mut builder = EntryBuilder::new_ustar();
    configure(&mut builder);
    assemble(builder, content)
}

/// Assemble header + content + padding + EOA into a complete archive.
fn assemble(mut builder: EntryBuilder, content: &[u8]) -> Vec<u8> {
    let hdr = builder.finish_bytes();
    let mut archive = Vec::with_capacity(hdr.len() + content.len() + HEADER_SIZE + EOA.len());
    archive.extend_from_slice(&hdr);
    if !content.is_empty() {
        archive.extend_from_slice(content);
        let pad = (HEADER_SIZE - (content.len() % HEADER_SIZE)) % HEADER_SIZE;
        archive.extend(std::iter::repeat_n(0u8, pad));
    }
    archive.extend_from_slice(&EOA);
    archive
}
