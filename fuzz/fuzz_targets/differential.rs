//! Differential fuzz target: compare tar-core against the `tar` crate.
//!
//! For any arbitrary byte input we parse it with both parsers and compare
//! results including file content and xattrs. The primary invariant is that
//! tar-core must never panic. A secondary goal is that whenever tar-rs
//! successfully parses an entry, tar-core should produce a matching entry
//! with equivalent metadata, xattrs, and identical content bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tar_core_testutil::{parse_tar_core, parse_tar_rs};

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let tar_rs_entries = parse_tar_rs(data);
    let tar_core_entries = parse_tar_core(data);

    assert_eq!(
        tar_core_entries.len(),
        tar_rs_entries.len(),
        "entry count mismatch: tar-core={} tar-rs={}",
        tar_core_entries.len(),
        tar_rs_entries.len(),
    );

    for i in 0..tar_rs_entries.len() {
        let rs = &tar_rs_entries[i];
        let core = &tar_core_entries[i];

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
});
