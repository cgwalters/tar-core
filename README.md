# tar-core

Sans-IO tar header parsing and building for sync and async runtimes.

## Overview

`tar-core` provides zero-copy parsing and building of tar archives that works
with any I/O model. The `Parser` has no trait bounds on readers - it just
processes byte slices. This enables code sharing between sync crates like
[tar-rs](https://crates.io/crates/tar) and async crates like
[tokio-tar](https://crates.io/crates/tokio-tar).

## Why tar-core?

Both `tar-rs` and `tokio-tar` implement essentially the same tar parsing logic,
but they can't share code because one uses `std::io::Read` and the other uses
`tokio::io::AsyncRead`. `tar-core` solves this by separating the parsing logic
from I/O:

- **tar-rs** wraps `tar-core` with `std::io::Read`
- **tokio-tar** wraps `tar-core` with `tokio::io::AsyncRead`
- **Same parsing logic** for both - GNU long names, PAX extensions, checksums

## Key Features

- **Zero-copy parsing** via [zerocopy](https://crates.io/crates/zerocopy)
- **GNU extension support**: Long name/link (`L`/`K` headers), sparse files
- **PAX extended header support**: Unlimited path lengths, UTF-8, xattrs
- **EntryBuilder** for creating tar archives
- **Bit-identical output** with tar-rs (verified via property tests)
- **CVE-2025-62518 (TARmageddon) protection** via configurable limits

## Usage

### Parsing headers

```rust
use tar_core::{Header, EntryType};

// Parse a header from raw bytes
let data = [0u8; 512]; // Would come from a tar file
let header = Header::from_bytes(&data).unwrap();

// Access header fields
let entry_type = header.entry_type();
let path = header.path_bytes();
let size = header.entry_size().unwrap();
```

### Building entries

```rust
use tar_core::{EntryBuilder, ExtensionMode};

let mut builder = EntryBuilder::new_file(b"path/to/file.txt")
    .mode(0o644)
    .uid(1000)
    .gid(1000)
    .size(1024);

// Build headers (may include PAX/GNU extension headers)
let headers = builder.build(ExtensionMode::Pax).unwrap();
```

### Sans-IO parsing

```rust
use tar_core::parse::{Parser, ParseEvent};
use tar_core::stream::Limits;

let mut parser = Parser::new(Limits::default());

// Feed data and get events - no I/O traits required
match parser.parse(data) {
    Ok(ParseEvent::Entry { consumed, entry }) => {
        println!("Found: {}", entry.path_lossy());
    }
    Ok(ParseEvent::NeedData { min_bytes }) => {
        // Read more data into buffer
    }
    Ok(ParseEvent::End { consumed }) => {
        // Archive complete
    }
    Err(e) => eprintln!("Parse error: {}", e),
}
```

## Supported Formats

- **POSIX.1-1988** (V7/Old): Original Unix tar format
- **UStar (POSIX.1-2001)**: Adds magic, user/group names, path prefix
- **GNU tar**: Long name/link extensions, sparse files, atime/ctime
- **PAX**: Unlimited path lengths, UTF-8, extended attributes

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
