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
//! // Call `.send_with_digest_auth()` on `RequestBuilder` like `send()`
//! let response: Response = Client::new()
//!   .get("url")
//!   .send_with_digest_auth("username", "password")
//!   .await?;
//!
//! ```

pub mod core;
pub mod error;
