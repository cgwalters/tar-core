# tar-rs rebase on tar-core: status and plan

This document tracks the work of rebasing the [tar-rs](https://github.com/alexcrichton/tar-rs)
crate onto [tar-core](https://github.com/cgwalters/tar-core), so that tar-rs
becomes a thin I/O layer on top of tar-core's sans-IO parsing and building.

The working tree lives at `target/tar-rs` (a git checkout with our rebase
commits on top of upstream).

## Completed work

### tar-rs commits (on top of upstream)

1. **`eaacdea` archive: Replace entry parsing with tar-core Parser** — The
   `EntriesFields` iterator now holds a `tar_core::parse::Parser` and drives
   parsing via `NeedData`/`Entry`/`End` events instead of doing its own header
   reading, checksum verification, GNU long-name/PAX extension accumulation,
   and UStar prefix handling.

2. **`c7dca38` archive: Drop advance\_content call** — Removed stale
   `advance_content()` that the parser no longer needs.

3. **`3634ade` archive: Use entry.padded\_size() instead of manual padding
   arithmetic** — Delegates padding calculation to `ParsedEntry::padded_size()`.

4. **`6cfd66f` archive: Delegate GNU sparse parsing to tar-core** — Replaces
   tar-rs's own sparse-header I/O with `ParseEvent::SparseEntry`.

5. **`6cef434` header: Delegate field readers and set\_cksum to tar-core** —
   `Header::entry_size()`, `uid()`, `gid()`, `mtime()`, `mode()`,
   `username_bytes()`, `groupname_bytes()`, `device_major()`,
   `device_minor()`, `calculate_cksum()`, and `set_cksum()` now delegate to
   `tar_core::Header` methods. Removed ~19 lines of duplicated numeric parsing.

6. **`d087d16` header: Replace struct definitions with repr(transparent)
   wrappers over tar-core** — `OldHeader`, `UstarHeader`, `GnuHeader`,
   `GnuExtSparseHeader` are now `#[repr(transparent)]` newtype wrappers with
   `Deref`/`DerefMut` to the corresponding tar-core types. `GnuSparseHeader`
   is a type alias for `tar_core::GnuSparseHeader`. Removed the unsafe
   `cast()`/`cast_mut()` helpers, the duplicate `GnuSparseHeader` impl block
   and Debug impl, and the `GNU_EXT_SPARSE_HEADERS_COUNT` constant. Net -80
   lines.

### tar-core prep commit

- **`b2a2336` Rename header struct fields for tar-rs compatibility** — Changed
  tar-core's field names to match tar-rs (`checksum`→`cksum`,
  `devmajor`→`dev_major`, `devminor`→`dev_minor`, `typeflag`→`linkflag` in
  `OldHeader`). Changed single-byte fields from `u8` to `[u8; 1]` for
  compatibility (`typeflag`, `isextended`, `unused`). Added `offset()`,
  `set_offset()`, `length()`, `set_length()` methods to `GnuSparseHeader`.

All 78 tar-rs integration tests pass with zero test modifications.

### Summary of delegation

| Area                         | Status                   |
|------------------------------|--------------------------|
| Entry parsing state machine  | delegated                |
| Header checksum verification | delegated                |
| GNU long name/link           | delegated                |
| PAX extension parsing        | delegated                |
| UStar prefix handling        | delegated                |
| GNU sparse headers           | delegated                |
| PAX sparse (v0.0/0.1/1.0)   | delegated                |
| Content/padding size calc    | delegated                |
| Security limits              | delegated                |
| Header field readers         | delegated (10 methods)   |
| set_cksum / calculate_cksum  | delegated                |
| Header struct types          | delegated (wrappers)     |

## Remaining work

### Header field setters (medium priority)

`set_size()`, `set_uid()`, `set_gid()`, `set_mtime()`, `set_mode()` are NOT
yet delegated. tar-rs's versions unconditionally use base-256 fallback for
large values (always infallible), while tar-core's are format-aware (can fail
for ustar). These have different error semantics and need careful handling.

The sub-header setters on `UstarHeader`/`GnuHeader` (`set_device_major`,
`set_username`, etc.) still use tar-rs's own `octal_into` / `copy_into`.

**Status:** not started — requires deciding whether to match tar-rs semantics
(always infallible) or adopt tar-core's format-aware approach.

### Duplicate numeric codec (medium priority)

`octal_from()`, `octal_into()`, `num_field_wrapper_from/into()`,
`numeric_extended_from/into()`, `truncate()` still exist in tar-rs. The
*readers* are no longer called from `Header` methods (delegated to tar-core),
but are still used by `UstarHeader`/`GnuHeader` sub-header methods. The
*writers* are used by all setters.

Removing these requires delegating the remaining sub-header reader/writer
methods and the main `Header` setters.

**Status:** partially obsolete, blocked on setter delegation

### PAX type unification (low priority)

tar-rs `pax.rs` has its own `PaxExtensions` / `PaxExtension` types. tar-core's
version is better (proper length-based parsing, binary value support). Could
replace with re-exports.

PAX constants are already re-exported (`pub use tar_core::PAX_*`).

**Status:** not started

### EntryType unification (deferred)

tar-rs has its own `EntryType` with different variant names (`GNULongName` vs
`GnuLongName`, `__Nonexhaustive(u8)` vs `Other(u8)`). Re-exporting from
tar-core would be a public API break. Deferred to next major version.

### Builder integration (deferred)

tar-core provides `PaxBuilder`, `HeaderBuilder`, and `EntryBuilder` that could
replace parts of tar-rs's `builder.rs`. Lower priority since it's more complex
and less duplicated than parsing.

## What stays in tar-rs

These pieces are inherently I/O-bound or platform-specific:

- `Header` struct and its I/O methods (`set_metadata`, `set_path`, etc.)
- `Archive` struct and config (reader wrapping, `set_mask()`, etc.)
- `Entries`/`EntriesFields` I/O iterator (feeds bytes to `Parser`)
- `Entry`/`EntryFields` structs and `Read` impls
- `unpack()` / `unpack_in()` / `unpack_dir()` filesystem operations
- `fill_from()` / `fill_platform_from()` metadata conversion
- `path2bytes()` / `bytes2path()` platform path conversion
- `TarError` I/O error wrapping
- `Builder` archive writing

## Notes on API compatibility

The struct replacement uses `#[repr(transparent)]` wrappers with `Deref` to
tar-core types. This means:

- All tar-core fields are accessible directly (field names match tar-rs)
- Inherent I/O methods remain on the wrapper types
- `GnuSparseHeader::offset()` and `::length()` now return
  `tar_core::Result<u64>` instead of `io::Result<u64>` — callers using
  `.unwrap()` are unaffected, but code matching on the error type will notice
- The `Debug` impl for `GnuSparseHeader` is now tar-core's version
