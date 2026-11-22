//! hello-core — shared error types, identifier newtypes, and traits.
//!
//! This crate has zero dependency on any other hello-* crate so it can be
//! imported freely from any layer without creating cycles.

pub mod error;
pub mod types;

pub use error::*;
pub use types::*;
