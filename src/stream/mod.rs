//! Types for streaming tar parsers: limits, errors, and shared definitions.
//!
//! This module provides the building blocks used by tar stream parsers:
//!
//! - [`Limits`] — configurable security limits to prevent resource exhaustion
//! - [`StreamError`] — error types for stream parsing
//!
//! The actual `Read`-based streaming parser (`TarStreamParser`) is not part of
//! this crate because tar-core is intentionally sans-IO. See the integration
//! tests for a minimal sync-IO example, or use the sans-IO [`parse`] module
//! to build your own async or sync wrapper.
//!
//! [`parse`]: crate::parse

mod error;
mod limits;

pub use error::{Result, StreamError};
pub use limits::Limits;
