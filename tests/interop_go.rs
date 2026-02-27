//! Cross-language roundtrip integration test: tar-core <-> Go archive/tar.
//!
//! This test validates that tar archives built by tar-core can be correctly
//! parsed by Go's archive/tar package, and vice versa. It uses proptest to
//! generate random entry parameters and tests both GNU and PAX extension modes.
//!
//! Requires Go 1.23+. Run with:
//!   GOPATH=$HOME/gopath PATH=$HOME/go/bin:$PATH cargo test --test interop_go -- --ignored --nocapture

#![allow(missing_docs)]
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use base64::Engine;
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use tar_core::builder::EntryBuilder;
use tar_core::parse::{Limits, ParseEvent, Parser};
use tar_core::{EntryType, HEADER_SIZE};

// ============================================================================
// Go helper program (embedded source)
// ============================================================================

const GO_HELPER_SRC: &str = r#"
package main

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Command struct {
	Mode    string  `json:"mode"`
	TarPath string  `json:"tar_path"`
	Format  string  `json:"format,omitempty"`
	Entries []Entry `json:"entries,omitempty"`
}

type Entry struct {
	Path    string `json:"path"`
	Mode    int64  `json:"mode"`
	Uid     int    `json:"uid"`
	Gid     int    `json:"gid"`
	Size    int64  `json:"size"`
	Mtime   int64  `json:"mtime"`
	Uname   string `json:"uname"`
	Gname   string `json:"gname"`
	Content string `json:"content"` // base64
}

func parseTar(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var entries []Entry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "tar next: %v\n", err)
			os.Exit(1)
		}

		var content []byte
		if hdr.Size > 0 {
			content, err = io.ReadAll(tr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read content: %v\n", err)
				os.Exit(1)
			}
		}

		entries = append(entries, Entry{
			Path:    hdr.Name,
			Mode:    int64(hdr.Mode),
			Uid:     hdr.Uid,
			Gid:     hdr.Gid,
			Size:    hdr.Size,
			Mtime:   hdr.ModTime.Unix(),
			Uname:   hdr.Uname,
			Gname:   hdr.Gname,
			Content: base64.StdEncoding.EncodeToString(content),
		})
	}

	json.NewEncoder(os.Stdout).Encode(entries)
}

func generateTar(cmd Command) {
	f, err := os.Create(cmd.TarPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	defer tw.Close()

	for _, e := range cmd.Entries {
		content, err := base64.StdEncoding.DecodeString(e.Content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "base64 decode: %v\n", err)
			os.Exit(1)
		}

		var format tar.Format
		switch cmd.Format {
		case "gnu":
			format = tar.FormatGNU
		case "pax":
			format = tar.FormatPAX
		default:
			format = tar.FormatGNU
		}

		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     e.Path,
			Mode:     e.Mode,
			Uid:      e.Uid,
			Gid:      e.Gid,
			Size:     int64(len(content)),
			ModTime:  timeFromUnix(e.Mtime),
			Uname:    e.Uname,
			Gname:    e.Gname,
			Format:   format,
		}

		if err := tw.WriteHeader(hdr); err != nil {
			fmt.Fprintf(os.Stderr, "write header: %v\n", err)
			os.Exit(1)
		}
		if _, err := tw.Write(content); err != nil {
			fmt.Fprintf(os.Stderr, "write content: %v\n", err)
			os.Exit(1)
		}
	}
}

func timeFromUnix(sec int64) (t __TIME_TYPE__) {
	return __TIME_FUNC__
}

func main() {
	var cmd Command
	if err := json.NewDecoder(os.Stdin).Decode(&cmd); err != nil {
		fmt.Fprintf(os.Stderr, "json decode: %v\n", err)
		os.Exit(1)
	}

	switch cmd.Mode {
	case "parse":
		parseTar(cmd.TarPath)
	case "generate":
		generateTar(cmd)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", cmd.Mode)
		os.Exit(1)
	}
}
"#;

// We need to fix up the Go source to use time.Unix properly. The placeholder
// approach avoids Go import issues in the const string.
fn go_helper_source() -> String {
    let src = GO_HELPER_SRC
        .replace("__TIME_TYPE__", "time.Time")
        .replace("__TIME_FUNC__", "time.Unix(sec, 0)");
    // Add the time import
    src.replace("import (", "import (\n\t\"time\"")
}

// ============================================================================
// JSON types matching the Go program
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct GoCommand {
    mode: String,
    tar_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entries: Option<Vec<GoEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoEntry {
    path: String,
    mode: i64,
    uid: i32,
    gid: i32,
    size: i64,
    mtime: i64,
    uname: String,
    gname: String,
    content: String, // base64
}

// ============================================================================
// Go binary compilation (cached)
// ============================================================================

fn compile_go_helper(dir: &Path) -> PathBuf {
    let src_path = dir.join("helper.go");
    let bin_path = dir.join("helper");

    std::fs::write(&src_path, go_helper_source()).expect("write Go source");

    let go_bin = format!("{}/go/bin/go", std::env::var("HOME").unwrap());
    let output = Command::new(&go_bin)
        .arg("build")
        .arg("-o")
        .arg(&bin_path)
        .arg(&src_path)
        .env(
            "GOPATH",
            format!("{}/gopath", std::env::var("HOME").unwrap()),
        )
        .output()
        .expect("failed to run go build");

    if !output.status.success() {
        panic!(
            "go build failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    bin_path
}

/// Returns the path to the compiled Go helper binary.
/// Compiles it once on first call (uses a static TempDir to keep the binary alive).
fn go_helper_bin() -> &'static Path {
    static HELPER: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, bin) = HELPER.get_or_init(|| {
        let dir = TempDir::new().expect("create tempdir for Go helper");
        let bin = compile_go_helper(dir.path());
        (dir, bin)
    });
    bin.as_path()
}

fn run_go_parse(go_bin: &Path, tar_path: &Path) -> Vec<GoEntry> {
    let cmd = GoCommand {
        mode: "parse".into(),
        tar_path: tar_path.to_str().unwrap().into(),
        format: None,
        entries: None,
    };
    let input = serde_json::to_string(&cmd).unwrap();

    let output = Command::new(go_bin)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run Go helper");

    if !output.status.success() {
        panic!(
            "Go helper parse failed:\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).expect("parse Go JSON output")
}

fn run_go_generate(go_bin: &Path, tar_path: &Path, format: &str, entries: Vec<GoEntry>) {
    let cmd = GoCommand {
        mode: "generate".into(),
        tar_path: tar_path.to_str().unwrap().into(),
        format: Some(format.into()),
        entries: Some(entries),
    };
    let input = serde_json::to_string(&cmd).unwrap();

    let output = Command::new(go_bin)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .expect("failed to run Go helper");

    if !output.status.success() {
        panic!(
            "Go helper generate failed:\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ============================================================================
// tar-core archive building
// ============================================================================

/// Parameters for a single tar entry.
#[derive(Debug, Clone)]
struct EntryParams {
    path: String,
    mode: u32,
    uid: u32,
    gid: u32,
    #[allow(dead_code)]
    size: usize,
    mtime: u32,
    username: String,
    groupname: String,
    content: Vec<u8>,
}

/// Build a tar archive from entry params using tar-core's EntryBuilder.
/// `format` is "gnu" or "pax".
fn build_tar_core_archive(entries: &[EntryParams], format: &str) -> Vec<u8> {
    let mut archive = Vec::new();

    for entry in entries {
        let mut builder = match format {
            "gnu" => EntryBuilder::new_gnu(),
            "pax" => EntryBuilder::new_ustar(),
            _ => panic!("unknown format: {format}"),
        };

        builder
            .path(entry.path.as_bytes())
            .mode(entry.mode)
            .unwrap()
            .uid(entry.uid as u64)
            .unwrap()
            .gid(entry.gid as u64)
            .unwrap()
            .size(entry.content.len() as u64)
            .unwrap()
            .mtime(entry.mtime as u64)
            .unwrap()
            .entry_type(EntryType::Regular);

        // username/groupname: in PAX mode, long names go into PAX extensions
        // In GNU mode, names > 32 bytes will error, so we truncate for GNU.
        if format == "gnu" {
            let uname = if entry.username.len() > 32 {
                &entry.username[..32]
            } else {
                &entry.username
            };
            let gname = if entry.groupname.len() > 32 {
                &entry.groupname[..32]
            } else {
                &entry.groupname
            };
            builder.username(uname.as_bytes()).unwrap();
            builder.groupname(gname.as_bytes()).unwrap();
        } else {
            builder.username(entry.username.as_bytes()).unwrap();
            builder.groupname(entry.groupname.as_bytes()).unwrap();
        }

        let header_bytes = builder.finish_bytes();
        archive.extend_from_slice(&header_bytes);

        // Write content
        archive.extend_from_slice(&entry.content);

        // Pad to 512-byte boundary
        let padding = (HEADER_SIZE - (entry.content.len() % HEADER_SIZE)) % HEADER_SIZE;
        archive.extend(std::iter::repeat_n(0u8, padding));
    }

    // End-of-archive: two 512-byte zero blocks
    archive.extend(std::iter::repeat_n(0u8, HEADER_SIZE * 2));

    archive
}

/// Parse a tar archive using tar-core's sans-IO parser.
/// Returns a list of (path, mode, uid, gid, size, mtime, uname, gname, content).
fn parse_tar_core_archive(data: &[u8]) -> Vec<EntryParams> {
    let mut parser = Parser::new(Limits::default());
    let mut results = Vec::new();
    let mut offset = 0;

    loop {
        let input = &data[offset..];
        match parser.parse(input).expect("parse should succeed") {
            ParseEvent::NeedData { .. } => {
                panic!("unexpected NeedData — archive should be complete in memory");
            }
            ParseEvent::Entry { consumed, entry } => {
                offset += consumed;

                let path = String::from_utf8_lossy(&entry.path).into_owned();
                let mode = entry.mode;
                let uid = entry.uid as u32;
                let gid = entry.gid as u32;
                let size = entry.size as usize;
                let mtime = entry.mtime as u32;
                let uname = entry
                    .uname
                    .as_ref()
                    .map(|u| String::from_utf8_lossy(u).into_owned())
                    .unwrap_or_default();
                let gname = entry
                    .gname
                    .as_ref()
                    .map(|g| String::from_utf8_lossy(g).into_owned())
                    .unwrap_or_default();

                // Read content
                let content = data[offset..offset + size].to_vec();
                let padded_size = size.next_multiple_of(HEADER_SIZE);
                offset += padded_size;
                parser
                    .advance_content(entry.size)
                    .expect("advance_content should succeed");

                results.push(EntryParams {
                    path,
                    mode,
                    uid,
                    gid,
                    size,
                    mtime,
                    username: uname,
                    groupname: gname,
                    content,
                });
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

// ============================================================================
// Comparison helpers
// ============================================================================

fn assert_entries_match(label: &str, expected: &[EntryParams], actual: &[GoEntry]) {
    assert_eq!(
        expected.len(),
        actual.len(),
        "{label}: entry count mismatch: expected {}, got {}",
        expected.len(),
        actual.len()
    );

    let b64 = base64::engine::general_purpose::STANDARD;

    for (i, (exp, act)) in expected.iter().zip(actual.iter()).enumerate() {
        assert_eq!(exp.path, act.path, "{label} entry[{i}]: path mismatch");
        assert_eq!(
            exp.mode as i64, act.mode,
            "{label} entry[{i}]: mode mismatch (expected 0o{:o}, got 0o{:o})",
            exp.mode, act.mode
        );
        assert_eq!(exp.uid as i32, act.uid, "{label} entry[{i}]: uid mismatch");
        assert_eq!(exp.gid as i32, act.gid, "{label} entry[{i}]: gid mismatch");
        assert_eq!(
            exp.content.len() as i64,
            act.size,
            "{label} entry[{i}]: size mismatch"
        );
        assert_eq!(
            exp.mtime as i64, act.mtime,
            "{label} entry[{i}]: mtime mismatch"
        );

        // Content comparison
        let actual_content = b64.decode(&act.content).unwrap_or_default();
        assert_eq!(
            exp.content,
            actual_content,
            "{label} entry[{i}]: content mismatch (expected {} bytes, got {} bytes)",
            exp.content.len(),
            actual_content.len()
        );
    }
}

fn assert_parsed_entries_match(label: &str, expected: &[EntryParams], actual: &[EntryParams]) {
    assert_eq!(
        expected.len(),
        actual.len(),
        "{label}: entry count mismatch: expected {}, got {}",
        expected.len(),
        actual.len()
    );

    for (i, (exp, act)) in expected.iter().zip(actual.iter()).enumerate() {
        assert_eq!(exp.path, act.path, "{label} entry[{i}]: path mismatch");
        assert_eq!(
            exp.mode, act.mode,
            "{label} entry[{i}]: mode mismatch (expected 0o{:o}, got 0o{:o})",
            exp.mode, act.mode
        );
        assert_eq!(exp.uid, act.uid, "{label} entry[{i}]: uid mismatch");
        assert_eq!(exp.gid, act.gid, "{label} entry[{i}]: gid mismatch");
        assert_eq!(
            exp.content.len(),
            act.content.len(),
            "{label} entry[{i}]: size mismatch"
        );
        assert_eq!(exp.mtime, act.mtime, "{label} entry[{i}]: mtime mismatch");
        assert_eq!(
            exp.content, act.content,
            "{label} entry[{i}]: content mismatch"
        );
    }
}

fn entries_to_go(entries: &[EntryParams]) -> Vec<GoEntry> {
    let b64 = base64::engine::general_purpose::STANDARD;
    entries
        .iter()
        .map(|e| GoEntry {
            path: e.path.clone(),
            mode: e.mode as i64,
            uid: e.uid as i32,
            gid: e.gid as i32,
            size: e.content.len() as i64,
            mtime: e.mtime as i64,
            uname: e.username.clone(),
            gname: e.groupname.clone(),
            content: b64.encode(&e.content),
        })
        .collect()
}

// ============================================================================
// Proptest strategies
// ============================================================================

/// Generate an ASCII path segment: alphanumeric characters.
fn path_segment() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z0-9][a-zA-Z0-9_]{0,19}")
        .expect("valid regex")
        .prop_filter("non-empty", |s| !s.is_empty())
}

/// Generate a path of 1-200 bytes with slashes.
fn path_strategy(min_len: usize, max_len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(path_segment(), 1..=10)
        .prop_map(|segments| segments.join("/"))
        .prop_filter("length in range", move |s| {
            s.len() >= min_len && s.len() <= max_len
        })
}

/// Short path that fits in 100-byte name field.
fn short_path_strategy() -> impl Strategy<Value = String> {
    path_strategy(1, 95)
}

/// Long path that exceeds 100 bytes (triggers extensions).
fn long_path_strategy() -> impl Strategy<Value = String> {
    path_strategy(101, 200)
}

/// Username/groupname: 1-64 ASCII alphanumeric bytes.
fn name_strategy(max_len: usize) -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!("[a-zA-Z][a-zA-Z0-9_]{{0,{}}}", max_len - 1))
        .expect("valid regex")
        .prop_filter("non-empty", |s| !s.is_empty())
        .prop_filter("length ok", move |s| s.len() <= max_len)
}

/// Username that fits in the 32-byte header field.
fn short_username_strategy() -> impl Strategy<Value = String> {
    name_strategy(31)
}

/// Username that exceeds 32 bytes (triggers PAX uname extension).
fn long_username_strategy() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z][a-zA-Z0-9_]{32,50}")
        .expect("valid regex")
        .prop_filter("long enough", |s| s.len() > 32)
}

fn content_strategy(max_size: usize) -> impl Strategy<Value = Vec<u8>> {
    (0..=max_size).prop_flat_map(|size| prop::collection::vec(any::<u8>(), size..=size))
}

fn entry_params_strategy() -> impl Strategy<Value = EntryParams> {
    (
        short_path_strategy(),
        0u32..0o7777u32,
        0u32..65535u32,
        0u32..65535u32,
        0usize..4096usize,
        // Use a range that fits in both GNU octal and Go's time handling.
        // GNU 12-byte octal max is 0o77777777777 (~8.5 billion), but we
        // keep it within a reasonable range.
        0u32..0x7FFFFFFFu32,
        short_username_strategy(),
        name_strategy(31),
    )
        .prop_flat_map(|(path, mode, uid, gid, size, mtime, username, groupname)| {
            content_strategy(size).prop_map(move |content| EntryParams {
                path: path.clone(),
                mode,
                uid,
                gid,
                size: content.len(),
                mtime,
                username: username.clone(),
                groupname: groupname.clone(),
                content,
            })
        })
}

/// Entry with a long path (> 100 bytes).
fn long_path_entry_strategy() -> impl Strategy<Value = EntryParams> {
    (
        long_path_strategy(),
        0u32..0o7777u32,
        0u32..65535u32,
        0u32..65535u32,
        0usize..2048usize,
        0u32..0x7FFFFFFFu32,
        short_username_strategy(),
        name_strategy(31),
    )
        .prop_flat_map(|(path, mode, uid, gid, size, mtime, username, groupname)| {
            content_strategy(size).prop_map(move |content| EntryParams {
                path: path.clone(),
                mode,
                uid,
                gid,
                size: content.len(),
                mtime,
                username: username.clone(),
                groupname: groupname.clone(),
                content,
            })
        })
}

/// Entry with a long username (> 32 bytes) — for PAX mode testing.
fn long_uname_entry_strategy() -> impl Strategy<Value = EntryParams> {
    (
        short_path_strategy(),
        0u32..0o7777u32,
        0u32..65535u32,
        0u32..65535u32,
        0usize..2048usize,
        0u32..0x7FFFFFFFu32,
        long_username_strategy(),
        name_strategy(31),
    )
        .prop_flat_map(|(path, mode, uid, gid, size, mtime, username, groupname)| {
            content_strategy(size).prop_map(move |content| EntryParams {
                path: path.clone(),
                mode,
                uid,
                gid,
                size: content.len(),
                mtime,
                username: username.clone(),
                groupname: groupname.clone(),
                content,
            })
        })
}

// ============================================================================
// Core roundtrip logic
// ============================================================================

/// Roundtrip: tar-core builds -> Go parses -> verify
/// Then: Go builds -> tar-core parses -> verify
fn roundtrip_test(entries: &[EntryParams], format: &str) {
    let go_bin = go_helper_bin();
    let tmp = TempDir::new().expect("create tempdir");

    // -- Direction 1: tar-core -> Go --
    let tar_path = tmp.path().join("rust_built.tar");
    let archive_data = build_tar_core_archive(entries, format);
    std::fs::write(&tar_path, &archive_data).expect("write tar file");

    let go_parsed = run_go_parse(go_bin, &tar_path);

    // For GNU mode, usernames > 32 bytes get truncated. Build the expected
    // comparison entries accordingly.
    let expected_for_go: Vec<EntryParams> = entries
        .iter()
        .map(|e| {
            let mut e = e.clone();
            if format == "gnu" {
                if e.username.len() > 32 {
                    e.username = e.username[..32].to_string();
                }
                if e.groupname.len() > 32 {
                    e.groupname = e.groupname[..32].to_string();
                }
            }
            e
        })
        .collect();

    assert_entries_match(
        &format!("tar-core->{format}->Go"),
        &expected_for_go,
        &go_parsed,
    );

    // Also verify uname/gname from Go's output
    for (i, (exp, act)) in expected_for_go.iter().zip(go_parsed.iter()).enumerate() {
        assert_eq!(
            exp.username, act.uname,
            "tar-core->{format}->Go entry[{i}]: uname mismatch"
        );
        assert_eq!(
            exp.groupname, act.gname,
            "tar-core->{format}->Go entry[{i}]: gname mismatch"
        );
    }

    // -- Direction 2: Go -> tar-core --
    let go_tar_path = tmp.path().join("go_built.tar");
    let go_entries = entries_to_go(&expected_for_go);
    run_go_generate(go_bin, &go_tar_path, format, go_entries);

    let go_archive_data = std::fs::read(&go_tar_path).expect("read Go-built tar");
    let rust_parsed = parse_tar_core_archive(&go_archive_data);

    assert_parsed_entries_match(
        &format!("Go->{format}->tar-core"),
        &expected_for_go,
        &rust_parsed,
    );

    // Also verify uname/gname from tar-core's parse
    for (i, (exp, act)) in expected_for_go.iter().zip(rust_parsed.iter()).enumerate() {
        assert_eq!(
            exp.username, act.username,
            "Go->{format}->tar-core entry[{i}]: uname mismatch"
        );
        assert_eq!(
            exp.groupname, act.groupname,
            "Go->{format}->tar-core entry[{i}]: gname mismatch"
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Roundtrip with GNU format and short paths.
    #[test]
    #[ignore]
    fn roundtrip_gnu_short(entries in prop::collection::vec(entry_params_strategy(), 1..4)) {
        roundtrip_test(&entries, "gnu");
    }

    /// Roundtrip with PAX format and short paths.
    #[test]
    #[ignore]
    fn roundtrip_pax_short(entries in prop::collection::vec(entry_params_strategy(), 1..4)) {
        roundtrip_test(&entries, "pax");
    }

    /// Roundtrip with GNU format and long paths (>100 bytes, triggers LongName).
    #[test]
    #[ignore]
    fn roundtrip_gnu_long_path(entry in long_path_entry_strategy()) {
        roundtrip_test(&[entry], "gnu");
    }

    /// Roundtrip with PAX format and long paths (>100 bytes, triggers PAX path).
    #[test]
    #[ignore]
    fn roundtrip_pax_long_path(entry in long_path_entry_strategy()) {
        roundtrip_test(&[entry], "pax");
    }

    /// Roundtrip with PAX format and long usernames (>32 bytes, triggers PAX uname).
    #[test]
    #[ignore]
    fn roundtrip_pax_long_uname(entry in long_uname_entry_strategy()) {
        roundtrip_test(&[entry], "pax");
    }

    /// Mixed entries: combine short paths, long paths, and various content sizes.
    #[test]
    #[ignore]
    fn roundtrip_mixed_gnu(
        short in entry_params_strategy(),
        long in long_path_entry_strategy(),
    ) {
        roundtrip_test(&[short, long], "gnu");
    }

    #[test]
    #[ignore]
    fn roundtrip_mixed_pax(
        short in entry_params_strategy(),
        long in long_path_entry_strategy(),
    ) {
        roundtrip_test(&[short, long], "pax");
    }
}

/// Deterministic smoke test to catch basic issues without proptest.
#[test]
#[ignore]
fn smoke_test_roundtrip() {
    let entries = vec![
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
        EntryParams {
            path: "empty.txt".into(),
            mode: 0o600,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            username: "root".into(),
            groupname: "root".into(),
            content: vec![],
        },
        EntryParams {
            // Long path > 100 bytes
            path: format!("very/long/path/{}", "x".repeat(100)),
            mode: 0o755,
            uid: 65534,
            gid: 65534,
            size: 512,
            mtime: 1700000000,
            username: "nobody".into(),
            groupname: "nogroup".into(),
            content: vec![0xAB; 512],
        },
    ];

    for format in &["gnu", "pax"] {
        eprintln!("--- smoke test: {format} ---");
        roundtrip_test(&entries, format);
        eprintln!("--- smoke test: {format} PASSED ---");
    }
}

/// Test with long username in PAX mode specifically.
#[test]
#[ignore]
fn smoke_test_pax_long_uname() {
    let entries = vec![EntryParams {
        path: "file_with_long_uname.dat".into(),
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        size: 64,
        mtime: 1234567890,
        username: "a_very_long_username_that_exceeds_32_bytes_easily".into(),
        groupname: "shortgrp".into(),
        content: vec![42; 64],
    }];

    roundtrip_test(&entries, "pax");
}
