//! This crate extends `reqwest` to be able to send requests with digest auth flow.
//!
//! It is currently implemented for async usage only.
//!
//! When you send the request with digest auth flow this first request will be executed. In case
//! the response is a `401` the `www-authenticate` header is parsed and the answer is calculated.
//! The initial request is executed again with additional `Authorization` header. The response
//! will be returned from `send_with_digest_auth()`.
//!
//! In case the first response is not a `401` this first response is returned from
//! `send_with_digest_auth()` without any manipulation.
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
