//! This crate extends `reqwest` to be able to send requests with digest auth flow.
//!
//! When you send a request with digest auth flow this first request will be executed. In case
//! the response is a `401` the `www-authenticate` header is parsed and the answer is calculated.
//! The initial request is executed again with additional `Authorization` header. The response
//! will be returned from `send_with_digest_auth()`.
//!
//! In case the first response is not a `401` this first response is returned from
//! `send_with_digest_auth()` without any manipulation. In case the first response is a `401`
//! but the `www-authenticate` header is missing the first reponse is returned as well.
//!
//! # Examples
//!
//! By default this crate works async:
//!
//! ```compile_fail
//! use diqwest::WithDigestAuth;
//! use reqwest::{Client, Response};
//!
//! // Call `.send_with_digest_auth()` on `RequestBuilder` like `send()`
//! let response: Response = Client::new()
//!   .get("url")
//!   .send_with_digest_auth("username", "password")
//!   .await?;
//!
//! ```
//!
//! In case you need blocking behavior enable the `blocking` feature in your `Cargo.toml`.
//!
//! ```compile_fail
//! use diqwest::blocking::WithDigestAuth;
//! use reqwest::blocking::{Client, Response};
//!
//! // Call `.send_with_digest_auth()` on `RequestBuilder` like `send()`
//! let response: Response = Client::new()
//!   .get("url")
//!   .send_with_digest_auth("username", "password")?;
//!
//! ```
//!

#[cfg(feature = "blocking")]
pub mod blocking;
pub mod common;
pub mod error;

use std::future::Future;

use digest_auth::AuthContext;
use reqwest::header::{HeaderMap, AUTHORIZATION};
use reqwest::{Body, Method};
use reqwest::{Request, RequestBuilder, Response, StatusCode};
use url::Url;

use crate::common::{get_answer, AsBytes, Build, CloneRequestBuilder, TryClone, WithHeaders, WithRequest};
use crate::error::{Error, Result};

/// A trait to extend the functionality of an async `RequestBuilder` to send a request with digest auth flow.
///
/// Call it at the end of your `RequestBuilder` chain like you would use `send()`.
pub trait WithDigestAuth {
  fn send_with_digest_auth(&self, username: &str, password: &str) -> impl Future<Output = Result<Response>> + Send;
}

impl WithDigestAuth for RequestBuilder {
  async fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response> {
    let first_response = self.refresh()?.send().await?;
    match first_response.status() {
      StatusCode::UNAUTHORIZED => try_digest_auth(self, first_response, username, password).await,
      _ => Ok(first_response),
    }
  }
}

async fn try_digest_auth(
  request_builder: &RequestBuilder,
  first_response: Response,
  username: &str,
  password: &str,
) -> Result<Response> {
  if let Some(answer) = get_answer(request_builder, first_response.headers(), username, password)? {
    return Ok(
      request_builder
        .refresh()?
        .header(AUTHORIZATION, answer.to_header_string())
        .send()
        .await?,
    );
  };

  Ok(first_response)
}

impl TryClone for RequestBuilder {
  fn try_clone(&self) -> Option<Self> {
    self.try_clone()
  }
}

impl Build<Request> for RequestBuilder {
  fn build(self) -> Result<Request> {
    Ok(self.build()?)
  }
}

impl AsBytes for Body {
  fn as_bytes(&self) -> Option<&[u8]> {
    self.as_bytes()
  }
}

impl WithRequest<Body> for Request {
  fn method(&self) -> &Method {
    self.method()
  }

  fn url(&self) -> &Url {
    self.url()
  }

  fn body(&self) -> Option<&Body> {
    self.body()
  }
}

impl WithHeaders for Response {
  fn headers(&self) -> &HeaderMap {
    self.headers()
  }
}

#[cfg(test)]
mod tests {
  use crate::common::parse_digest_auth_header;
  use crate::WithDigestAuth;

  use digest_auth::HttpMethod;
  use mockito::{Mock, Server};
  use reqwest::header::{HeaderMap, HeaderValue};
  use reqwest::{Client, RequestBuilder, StatusCode};

  const PATH: &str = "/test";

  fn create_request(server: &Server) -> RequestBuilder {
    Client::new().get(format!("{domain}{PATH}", domain = server.url()))
  }

  #[tokio::test]
  async fn given_non_digest_auth_endpoint_when_send_with_da_then_request_executed_normally() {
    // Given I have a GET request against a non digest auth endpoint
    let mut server = mockito::Server::new_async().await;
    let mock = server.mock("GET", PATH).with_status(200).create();
    let request = create_request(&server);

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").await.unwrap();

    // Then the response's status is OK
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::OK);
  }

  #[tokio::test]
  async fn given_non_digest_auth_endpoint_unauthorized_when_send_with_da_then_request_fails_with_401() {
    // Given I have a GET request against a non digest auth  but authorized endpoint
    let mut server = mockito::Server::new_async().await;
    let mock = server.mock("GET", PATH).with_status(401).create();
    let request = create_request(&server);

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").await.unwrap();

    // Then the response's final status is UNAUTHORIZED
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn given_digest_auth_endpoint_authorized_when_send_with_da_then_request_succeeds() {
    // Given I have a GET request against a digest auth endpoint with valid 'www-authenticate' header
    let mut server = mockito::Server::new_async().await;
    let www_authenticate = "Digest realm=\"testrealm@host.com\",qop=\"auth,auth-int\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
    let mut header = HeaderMap::new();
    header.insert("www-authenticate", HeaderValue::from_static(www_authenticate));
    let auth_header = parse_digest_auth_header(&header, PATH, HttpMethod::GET, None, "username", "password").unwrap();

    let first_request = server
      .mock("GET", PATH)
      .with_status(401)
      .with_header("www-authenticate", www_authenticate)
      .create();
    let second_request = server
      .mock("GET", PATH)
      .with_header("Authorization", &auth_header.to_header_string())
      .with_status(200)
      .create();

    let request = create_request(&server);

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").await.unwrap();

    // Then the response's final status is OK
    Mock::assert(&first_request);
    Mock::assert(&second_request);
    assert_eq!(&response.status(), &StatusCode::OK);
  }
}
