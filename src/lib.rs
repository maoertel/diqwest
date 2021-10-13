//! This crate extends `reqwest` to be able to send requests with digest auth flow.
//!
//! It is currently implemented for async usage only.
//!
//! # Example
//!
//! Usage:
//!
//! ```
//! use diqwest::core::WithDigestAuth;
//! use reqwest::{Client, Response};
//!
//! // Call `.send_with_basic_auth()` at the end of your request builder chain like you would use `send()`
//! let response: Response = Client::new()
//!   .get("url")
//!   .send_with_digest_auth("username", "password")
//!   .await?;
//!
//! ```

pub mod core;
pub mod error;
