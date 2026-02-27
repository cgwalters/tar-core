//! Cross-language roundtrip integration test: tar-core <-> Python tarfile.
//!
//! This test validates that tar archives built by tar-core can be correctly
//! parsed by Python's `tarfile` module, and vice versa. It uses proptest to
//! generate random entry parameters and tests both GNU and PAX extension modes.
//!
//! Run with: `cargo test --test interop_python -- --ignored --nocapture`

#![cfg(unix)]
#![allow(missing_docs)]

use std::process::Command;

use base64::Engine;
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use tar_core::builder::EntryBuilder;
use tar_core::parse::{Limits, ParseEvent, Parser};
use tar_core::{EntryType, HEADER_SIZE};

// =============================================================================
// Python helper script (embedded)
// =============================================================================

const PYTHON_HELPER: &str = r#"
import json, sys, tarfile, base64, io, os

def parse_tar(tar_path):
    entries = []
    with tarfile.open(tar_path, "r:") as tf:
        for member in tf.getmembers():
            entry = {
                "path": member.name,
                "mode": member.mode,
                "uid": member.uid,
                "gid": member.gid,
                "size": member.size,
                "mtime": member.mtime,
                "uname": member.uname,
                "gname": member.gname,
                "content": "",
            }
            if member.isreg() and member.size > 0:
                f = tf.extractfile(member)
                if f is not None:
                    entry["content"] = base64.b64encode(f.read()).decode("ascii")
            entries.append(entry)
    return entries

def generate_tar(tar_path, fmt, entries):
    fmt_map = {"gnu": tarfile.GNU_FORMAT, "pax": tarfile.PAX_FORMAT}
    tar_fmt = fmt_map[fmt]
    with tarfile.open(tar_path, "w:", format=tar_fmt) as tf:
        for e in entries:
            info = tarfile.TarInfo(name=e["path"])
            info.mode = e["mode"]
            info.uid = e["uid"]
            info.gid = e["gid"]
            info.size = e["size"]
            info.mtime = e["mtime"]
            info.uname = e["uname"]
            info.gname = e["gname"]
            info.type = tarfile.REGTYPE
            content = base64.b64decode(e["content"])
            assert len(content) == e["size"], f"content length {len(content)} != size {e['size']}"
            tf.addfile(info, io.BytesIO(content))

cmd = json.loads(sys.stdin.read())
if cmd["mode"] == "parse":
    result = parse_tar(cmd["tar_path"])
    print(json.dumps(result))
elif cmd["mode"] == "generate":
    generate_tar(cmd["tar_path"], cmd["format"], cmd["entries"])
    print(json.dumps({"ok": True}))
else:
    print(json.dumps({"error": "unknown mode"}), file=sys.stderr)
    sys.exit(1)
"#;

// =============================================================================
// JSON types for communication with Python
// =============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TarEntryJson {
    path: String,
    mode: u32,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: u64,
    uname: String,
    gname: String,
    content: String, // base64-encoded
}

#[derive(Debug, Serialize)]
struct ParseCommand {
    mode: &'static str,
    tar_path: String,
}

#[derive(Debug, Serialize)]
struct GenerateCommand {
    mode: &'static str,
    tar_path: String,
    format: String,
    entries: Vec<TarEntryJson>,
}

// =============================================================================
// Test parameters
// =============================================================================

#[derive(Debug, Clone)]
struct EntryParams {
    path: String,
    mode: u32,
    uid: u64,
    gid: u64,
    size: usize,
    mtime: u64,
    username: String,
    groupname: String,
    content: Vec<u8>,
}

/// Generates ASCII alphanumeric paths of the given length range,
/// with slashes for directory separators. Always starts with an
/// alphanumeric character and never has consecutive slashes or
/// trailing slashes.
fn path_strategy(min_len: usize, max_len: usize) -> impl Strategy<Value = String> {
    // Generate a base path using segments
    let segment = "[a-zA-Z0-9][a-zA-Z0-9_]{0,15}";
    let num_segments = 1..=(max_len / 4).max(1);
    prop::collection::vec(
        proptest::string::string_regex(segment).expect("valid regex"),
        num_segments,
    )
    .prop_map(|segs| segs.join("/"))
    .prop_filter("path length in range", move |s| {
        s.len() >= min_len && s.len() <= max_len
    })
}

fn short_path_strategy() -> impl Strategy<Value = String> {
    path_strategy(1, 90)
}

fn long_path_strategy() -> impl Strategy<Value = String> {
    // Paths > 100 bytes to trigger GNU LongName / PAX path extensions
    path_strategy(101, 200)
}

fn username_strategy(max_len: usize) -> impl Strategy<Value = String> {
    let segment = "[a-zA-Z][a-zA-Z0-9_]*";
    proptest::string::string_regex(segment)
        .expect("valid regex")
        .prop_filter("username length in range", move |s| {
            !s.is_empty() && s.len() <= max_len
        })
}

fn short_username_strategy() -> impl Strategy<Value = String> {
    username_strategy(31)
}

fn long_username_strategy() -> impl Strategy<Value = String> {
    // Usernames > 32 bytes to trigger PAX uname extension
    let segment = "[a-zA-Z][a-zA-Z0-9_]*";
    proptest::string::string_regex(segment)
        .expect("valid regex")
        .prop_filter("long username", |s| s.len() > 32 && s.len() <= 64)
}

fn entry_params_strategy(
    path_strat: impl Strategy<Value = String>,
    uname_strat: impl Strategy<Value = String>,
) -> impl Strategy<Value = EntryParams> {
    (
        path_strat,
        0u32..0o7777,
        0u64..65536,
        0u64..65536,
        0usize..8192,
        0u64..0xFFFF_FFFFu64,
        uname_strat,
        username_strategy(31), // groupname always short for simplicity
    )
        .prop_flat_map(|(path, mode, uid, gid, size, mtime, username, groupname)| {
            let content_strat = prop::collection::vec(any::<u8>(), size..=size);
            content_strat.prop_map(move |content| EntryParams {
                path: path.clone(),
                mode,
                uid,
                gid,
                size,
                mtime,
                username: username.clone(),
                groupname: groupname.clone(),
                content,
            })
        })
}

// =============================================================================
// Tar building helpers
// =============================================================================

/// Build a tar archive from entry params using tar-core's EntryBuilder.
fn build_tar_core_archive(entries: &[EntryParams], use_pax: bool) -> Vec<u8> {
    let mut archive = Vec::new();

    for entry in entries {
        let mut builder = if use_pax {
            EntryBuilder::new_ustar()
        } else {
            EntryBuilder::new_gnu()
        };

        builder
            .path(entry.path.as_bytes())
            .mode(entry.mode)
            .expect("mode fits")
            .uid(entry.uid)
            .expect("uid fits")
            .gid(entry.gid)
            .expect("gid fits")
            .size(entry.size as u64)
            .expect("size fits")
            .mtime(entry.mtime)
            .expect("mtime fits")
            .entry_type(EntryType::Regular);

        // Username/groupname: for PAX mode, long names get stored as PAX
        // extensions automatically. For GNU mode, names must fit in 32 bytes.
        if use_pax {
            builder
                .username(entry.username.as_bytes())
                .expect("pax handles overflow");
            builder
                .groupname(entry.groupname.as_bytes())
                .expect("pax handles overflow");
        } else if entry.username.len() <= 32 && entry.groupname.len() <= 32 {
            builder
                .username(entry.username.as_bytes())
                .expect("fits in gnu");
            builder
                .groupname(entry.groupname.as_bytes())
                .expect("fits in gnu");
        }
        // else: skip username/groupname for GNU mode with long names

        let header_bytes = builder.finish_bytes();
        archive.extend_from_slice(&header_bytes);

        // Write content
        archive.extend_from_slice(&entry.content);

        // Pad to 512-byte boundary
        let padding = (HEADER_SIZE - (entry.size % HEADER_SIZE)) % HEADER_SIZE;
        archive.extend(std::iter::repeat_n(0u8, padding));
    }

    // End-of-archive: two 512-byte zero blocks
    archive.extend(std::iter::repeat_n(0u8, HEADER_SIZE * 2));
    archive
}

/// Parse a tar archive using tar-core's sans-IO Parser, returning metadata
/// and content for each entry.
fn parse_with_tar_core(data: &[u8]) -> Vec<(EntryParams, Vec<u8>)> {
    let mut parser = Parser::new(Limits::default());
    let mut results = Vec::new();
    let mut offset = 0;

    loop {
        let input = &data[offset..];
        match parser.parse(input).expect("parse should succeed") {
            ParseEvent::NeedData { .. } => {
                panic!("unexpected NeedData: archive should be complete in memory");
            }
            ParseEvent::Entry { consumed, entry } => {
                offset += consumed;

                let size = entry.size as usize;
                let path = String::from_utf8_lossy(&entry.path).to_string();
                let uname = entry
                    .uname
                    .as_ref()
                    .map(|u| String::from_utf8_lossy(u).to_string())
                    .unwrap_or_default();
                let gname = entry
                    .gname
                    .as_ref()
                    .map(|g| String::from_utf8_lossy(g).to_string())
                    .unwrap_or_default();

                // Read content
                let content = data[offset..offset + size].to_vec();
                let padded = size.next_multiple_of(HEADER_SIZE);
                offset += padded;
                parser
                    .advance_content(size as u64)
                    .expect("advance should succeed");

                results.push((
                    EntryParams {
                        path,
                        mode: entry.mode,
                        uid: entry.uid,
                        gid: entry.gid,
                        size,
                        mtime: entry.mtime,
                        username: uname,
                        groupname: gname,
                        content: content.clone(),
                    },
                    content,
                ));
            }
            ParseEvent::End { consumed } => {
                offset += consumed;
                let _ = offset; // suppress unused warning
                break;
            }
        }
    }

    results
}

// =============================================================================
// Python interaction helpers
// =============================================================================

fn run_python(input_json: &str) -> String {
    let output = Command::new("python3")
        .arg("-c")
        .arg(PYTHON_HELPER)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn python3")
        .wait_with_output()
        .expect("failed to wait on python3");

    // We need to actually pipe stdin, so let's use a different approach
    drop(output);

    let mut child = Command::new("python3")
        .arg("-c")
        .arg(PYTHON_HELPER)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn python3");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(input_json.as_bytes())
            .expect("failed to write stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on python3");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "python3 exited with {}: {}",
            output.status,
            stderr.trim_end()
        );
    }

    String::from_utf8(output.stdout).expect("python output is not UTF-8")
}

fn python_parse(tar_path: &str) -> Vec<TarEntryJson> {
    let cmd = ParseCommand {
        mode: "parse",
        tar_path: tar_path.to_string(),
    };
    let input = serde_json::to_string(&cmd).unwrap();
    let output = run_python(&input);
    serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!("failed to parse python output: {e}\noutput: {output}");
    })
}

fn python_generate(tar_path: &str, format: &str, entries: &[TarEntryJson]) {
    let cmd = GenerateCommand {
        mode: "generate",
        tar_path: tar_path.to_string(),
        format: format.to_string(),
        entries: entries.to_vec(),
    };
    let input = serde_json::to_string(&cmd).unwrap();
    let output = run_python(&input);
    let result: serde_json::Value = serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!("failed to parse python generate output: {e}\noutput: {output}");
    });
    assert!(
        result.get("ok").is_some(),
        "python generate failed: {result}"
    );
}

fn entry_params_to_json(params: &EntryParams) -> TarEntryJson {
    TarEntryJson {
        path: params.path.clone(),
        mode: params.mode,
        uid: params.uid,
        gid: params.gid,
        size: params.size as u64,
        mtime: params.mtime,
        uname: params.username.clone(),
        gname: params.groupname.clone(),
        content: base64::engine::general_purpose::STANDARD.encode(&params.content),
    }
}

// =============================================================================
// Assertion helpers
// =============================================================================

/// Actual entry metadata parsed from either Python JSON or tar-core.
struct ActualEntry<'a> {
    path: &'a str,
    mode: u32,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: u64,
    uname: &'a str,
    gname: &'a str,
    content: &'a [u8],
}

fn assert_entry_matches(label: &str, expected: &EntryParams, actual: &ActualEntry<'_>) {
    assert_eq!(expected.path, actual.path, "{label}: path mismatch");
    assert_eq!(
        expected.mode, actual.mode,
        "{label}: mode mismatch (expected {:#o}, got {:#o})",
        expected.mode, actual.mode
    );
    assert_eq!(expected.uid, actual.uid, "{label}: uid mismatch");
    assert_eq!(expected.gid, actual.gid, "{label}: gid mismatch");
    assert_eq!(expected.size as u64, actual.size, "{label}: size mismatch");
    assert_eq!(expected.mtime, actual.mtime, "{label}: mtime mismatch");
    // Username/groupname may be empty if not set (GNU mode with long names)
    if !expected.username.is_empty() && !actual.uname.is_empty() {
        assert_eq!(expected.username, actual.uname, "{label}: uname mismatch");
    }
    if !expected.groupname.is_empty() && !actual.gname.is_empty() {
        assert_eq!(expected.groupname, actual.gname, "{label}: gname mismatch");
    }
    assert_eq!(
        expected.content,
        actual.content,
        "{label}: content mismatch (lengths: expected={}, got={})",
        expected.content.len(),
        actual.content.len()
    );
}

// =============================================================================
// The actual roundtrip test
// =============================================================================

fn roundtrip_test(entries: Vec<EntryParams>, use_pax: bool) {
    let tmpdir = TempDir::new().expect("failed to create tmpdir");
    let format_name = if use_pax { "pax" } else { "gnu" };

    // --- Direction 1: tar-core -> Python ---

    let tar_core_path = tmpdir.path().join(format!("tarcore_{format_name}.tar"));
    let tar_data = build_tar_core_archive(&entries, use_pax);
    std::fs::write(&tar_core_path, &tar_data).expect("failed to write tar");

    let parsed_by_python = python_parse(tar_core_path.to_str().unwrap());

    assert_eq!(
        entries.len(),
        parsed_by_python.len(),
        "{format_name}: entry count mismatch (tar-core -> python)"
    );

    for (i, (expected, py_entry)) in entries.iter().zip(parsed_by_python.iter()).enumerate() {
        let py_content = base64::engine::general_purpose::STANDARD
            .decode(&py_entry.content)
            .unwrap_or_else(|e| panic!("failed to decode base64 content: {e}"));

        assert_entry_matches(
            &format!("{format_name} tar-core->python entry[{i}]"),
            expected,
            &ActualEntry {
                path: &py_entry.path,
                mode: py_entry.mode,
                uid: py_entry.uid,
                gid: py_entry.gid,
                size: py_entry.size,
                mtime: py_entry.mtime,
                uname: &py_entry.uname,
                gname: &py_entry.gname,
                content: &py_content,
            },
        );
    }

    // --- Direction 2: Python -> tar-core ---

    let python_tar_path = tmpdir.path().join(format!("python_{format_name}.tar"));
    let json_entries: Vec<TarEntryJson> = entries.iter().map(entry_params_to_json).collect();
    python_generate(
        python_tar_path.to_str().unwrap(),
        format_name,
        &json_entries,
    );

    let python_tar_data = std::fs::read(&python_tar_path).expect("failed to read python tar");
    let parsed_by_tarcore = parse_with_tar_core(&python_tar_data);

    assert_eq!(
        entries.len(),
        parsed_by_tarcore.len(),
        "{format_name}: entry count mismatch (python -> tar-core)"
    );

    for (i, (expected, (parsed, content))) in
        entries.iter().zip(parsed_by_tarcore.iter()).enumerate()
    {
        assert_entry_matches(
            &format!("{format_name} python->tar-core entry[{i}]"),
            expected,
            &ActualEntry {
                path: &parsed.path,
                mode: parsed.mode,
                uid: parsed.uid,
                gid: parsed.gid,
                size: parsed.size as u64,
                mtime: parsed.mtime,
                uname: &parsed.username,
                gname: &parsed.groupname,
                content,
            },
        );
    }
}

// =============================================================================
// Proptest-driven tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Roundtrip with short paths in GNU mode.
    #[test]
    #[ignore]
    fn roundtrip_gnu_short_paths(
        entries in prop::collection::vec(
            entry_params_strategy(short_path_strategy(), short_username_strategy()),
            1..=3
        )
    ) {
        roundtrip_test(entries, false);
    }

    /// Roundtrip with short paths in PAX mode.
    #[test]
    #[ignore]
    fn roundtrip_pax_short_paths(
        entries in prop::collection::vec(
            entry_params_strategy(short_path_strategy(), short_username_strategy()),
            1..=3
        )
    ) {
        roundtrip_test(entries, true);
    }

    /// Roundtrip with long paths (>100 bytes) in GNU mode.
    #[test]
    #[ignore]
    fn roundtrip_gnu_long_paths(
        entries in prop::collection::vec(
            entry_params_strategy(long_path_strategy(), short_username_strategy()),
            1..=2
        )
    ) {
        roundtrip_test(entries, false);
    }

    /// Roundtrip with long paths (>100 bytes) in PAX mode.
    #[test]
    #[ignore]
    fn roundtrip_pax_long_paths(
        entries in prop::collection::vec(
            entry_params_strategy(long_path_strategy(), short_username_strategy()),
            1..=2
        )
    ) {
        roundtrip_test(entries, true);
    }

    /// Roundtrip with long usernames (>32 bytes) in PAX mode.
    /// PAX mode stores these as PAX uname extensions.
    #[test]
    #[ignore]
    fn roundtrip_pax_long_usernames(
        entries in prop::collection::vec(
            entry_params_strategy(short_path_strategy(), long_username_strategy()),
            1..=2
        )
    ) {
        roundtrip_test(entries, true);
    }
}

// =============================================================================
// Deterministic smoke test
// =============================================================================

#[test]
#[ignore]
fn smoke_test_roundtrip() {
    // A fixed set of entries covering various edge cases.
    let entries = vec![
        // Short path, small content
        EntryParams {
            path: "hello.txt".into(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            size: 13,
            mtime: 1234567890,
            username: "testuser".into(),
            groupname: "testgroup".into(),
            content: b"Hello, World!".to_vec(),
        },
        // Empty file
        EntryParams {
            path: "empty".into(),
            mode: 0o600,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            username: "root".into(),
            groupname: "root".into(),
            content: vec![],
        },
        // Long path (>100 bytes, triggers extensions)
        EntryParams {
            path: format!(
                "very/long/path/that/exceeds/one/hundred/bytes/{}",
                "x".repeat(60)
            ),
            mode: 0o755,
            uid: 65535,
            gid: 65535,
            size: 512,
            mtime: 0xFFFFFFF0,
            username: "nobody".into(),
            groupname: "nogroup".into(),
            content: vec![0xAB; 512],
        },
    ];

    roundtrip_test(entries.clone(), false); // GNU
    roundtrip_test(entries, true); // PAX
}

#[test]
#[ignore]
fn smoke_test_long_username_pax() {
    // Username > 32 bytes, only works with PAX
    let long_uname = "a_very_long_username_that_exceeds_thirtytwo_bytes";
    assert!(long_uname.len() > 32);

    let entries = vec![EntryParams {
        path: "file_with_long_uname.txt".into(),
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        size: 4,
        mtime: 1700000000,
        username: long_uname.into(),
        groupname: "staff".into(),
        content: b"data".to_vec(),
    }];

    roundtrip_test(entries, true);
}
