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
use tar_core::{EntryType, HEADER_SIZE};

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

    // 5. Symlink (short target)
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

    // 6. Hardlink
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

    // 7. Directory
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

    // 8. FIFO
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

    // 9. PAX extended header with long path
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

    // 10. PAX with large uid/gid (overflow octal)
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

    // 11. PAX with custom xattr
    {
        let mut builder = EntryBuilder::new_ustar();
        builder
            .path(b"xattr.txt")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap();
        builder.add_pax("SCHILY.xattr.user.test", b"value123");
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(&EOA);
        seeds.push(("pax_xattr", archive));
    }

    // 12. Multiple files in one archive
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

    // 13. Mixed types: dir + file + symlink
    {
        let mut archive = Vec::new();

        // Directory
        let mut b = EntryBuilder::new_gnu();
        b.path(b"project/")
            .entry_type(EntryType::Directory)
            .mode(0o755)
            .unwrap()
            .size(0)
            .unwrap();
        archive.extend_from_slice(&b.finish_bytes());

        // Regular file with content
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

        // Symlink
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

    // 14. File with size near block boundary (exactly 512 bytes of content)
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

    // 15. File with size just over block boundary (513 bytes)
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

    // 16. Various mode values
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

    // 17. Minimal valid header (just 512 bytes, no EOA)
    {
        let mut builder = EntryBuilder::new_gnu();
        builder
            .path(b"minimal")
            .entry_type(EntryType::Regular)
            .mode(0o644)
            .unwrap()
            .size(0)
            .unwrap();
        // No EOA marker — tests parser behavior on truncated input
        seeds.push(("minimal_header", builder.finish_bytes()));
    }

    // 18. PAX with uname and gname
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

    // 19. GNU long name AND long link combined
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

    // 20. Character device entry
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

    // 21. Block device entry
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

    // 22. PAX with multiple extensions (path + size + mtime + xattr)
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
        builder.add_pax(
            "SCHILY.xattr.security.selinux",
            b"system_u:object_r:usr_t:s0",
        );
        let hdr = builder.finish_bytes();
        let mut archive = hdr;
        archive.extend_from_slice(b"payload");
        let pad = (HEADER_SIZE - 7) % HEADER_SIZE;
        archive.extend(std::iter::repeat_n(0u8, pad));
        archive.extend_from_slice(&EOA);
        seeds.push(("pax_multi_ext", archive));
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
