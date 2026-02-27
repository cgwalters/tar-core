//! Sans-IO tar archive parser.
//!
//! This module provides a low-level, sans-IO state machine parser for tar archives.
//! Unlike the [`stream`] module which wraps a `Read` implementation, this parser
//! operates on `&[u8]` slices directly, making it suitable for:
//!
//! - Async I/O (tokio, async-std)
//! - Custom buffering strategies
//! - Zero-copy parsing in memory-mapped archives
//! - Embedding in other parsers
//!
//! # Design
//!
//! The parser is a state machine that processes bytes and emits [`ParseEvent`]s.
//! The caller is responsible for:
//!
//! 1. Providing input data via [`Parser::parse`]
//! 2. Handling events (headers, content markers, end-of-archive)
//! 3. Managing the buffer and reading more data when needed
//!
//! # Example
//!
//! ```
//! use tar_core::parse::{Parser, ParseEvent};
//! use tar_core::stream::Limits;
//!
//! let mut parser = Parser::new(Limits::default());
//!
//! // Simulated tar data (in practice, read from file/network)
//! let data = [0u8; 1024]; // Two zero blocks = end of archive
//!
//! match parser.parse(&data) {
//!     Ok(ParseEvent::End { consumed }) => {
//!         println!("End of archive after {} bytes", consumed);
//!     }
//!     Ok(event) => {
//!         println!("Got event {:?}", event);
//!     }
//!     Err(e) => {
//!         eprintln!("Parse error: {}", e);
//!     }
//! }
//! ```
//!
//! [`stream`]: crate::stream

mod parser;

pub use parser::{ParseEvent, ParsedEntry, Parser};
