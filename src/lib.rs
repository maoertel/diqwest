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
//! By default this crate works async.
//!
//! # Example
//!
//! Usage:
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
//! # Example
//!
//! Usage:
//!
//! //! ```compile_fail
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
pub mod error;

use async_trait::async_trait;
use digest_auth::{AuthContext, AuthorizationHeader, HttpMethod};
use error::Error;
use reqwest::header::HeaderMap;
use reqwest::{RequestBuilder, Response, StatusCode};

use crate::error::Error::RequestBuilderNotCloneable;
use crate::error::Result;

/// A trait to extend the functionality of an async `RequestBuilder` to send a request with digest auth flow.
///
/// Call it at the end of your `RequestBuilder` chain like you would use `send()`.
#[async_trait]
pub trait WithDigestAuth {
  async fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response>;
}

#[async_trait]
impl WithDigestAuth for RequestBuilder {
  async fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response> {
    fn clone_request_builder(request_builder: &RequestBuilder) -> Result<RequestBuilder> {
      request_builder.try_clone().ok_or(RequestBuilderNotCloneable)
    }

    let first_response = clone_request_builder(self)?.send().await?;
    match first_response.status() {
      StatusCode::UNAUTHORIZED => {
        let request = clone_request_builder(self)?.build()?;
        let url = request.url();
        let method = HttpMethod::from(request.method().as_str());
        let body = request.body().and_then(|b| b.as_bytes());
        let answer = parse_digest_auth_header(first_response.headers(), url.as_str(), method, body, username, password);

        match answer {
          Ok(answer) => Ok(
            clone_request_builder(self)?
              .header("Authorization", answer.to_header_string())
              .send()
              .await?,
          ),
          Err(error::Error::AuthHeaderMissing) => Ok(first_response),
          Err(error) => Err(error),
        }
      }
      _ => Ok(first_response),
    }
  }
}

fn parse_digest_auth_header(
  header: &HeaderMap,
  uri: &str,
  method: HttpMethod,
  body: Option<&[u8]>,
  username: &str,
  password: &str,
) -> Result<AuthorizationHeader> {
  let www_auth = header.get("www-authenticate").ok_or(Error::AuthHeaderMissing)?.to_str()?;
  let context = AuthContext::new_with_method(username, password, uri, body, method);
  let mut prompt = digest_auth::parse(www_auth)?;

  Ok(prompt.respond(&context)?)
}

#[cfg(test)]
mod tests {
  use crate::{parse_digest_auth_header, WithDigestAuth};

  use digest_auth::HttpMethod;
  use mockito::{mock, Mock};
  use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, StatusCode,
  };

  #[tokio::test]
  async fn given_non_digest_auth_endpoint_when_send_with_da_then_request_executed_normally() {
    // Given I have a GET request against a non digest auth endpoint
    let mock = mock("GET", "/test").with_status(200).create();
    let request = Client::new().get(format!("{}/test", mockito::server_url()));

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").await.unwrap();

    // Then the response's status is OK
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::OK);
  }

  #[tokio::test]
  async fn given_non_digest_auth_endpoint_unauthorized_when_send_with_da_then_request_fails_with_401() {
    // Given I have a GET request against a non digest auth  but authorized endpoint
    let mock = mock("GET", "/test").with_status(401).create();
    let request = Client::new().get(format!("{}/test", mockito::server_url()));

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").await.unwrap();

    // Then the response's final status is UNAUTHORIZED
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn given_digest_auth_endpoint_authorized_when_send_with_da_then_request_succeeds() {
    // Given I have a GET request against a digest auth endpoint with valid 'www-authenticate' header
    let url = format!("{}/test", mockito::server_url());
    let www_authenticate = "Digest realm=\"testrealm@host.com\",qop=\"auth,auth-int\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
    let mut header = HeaderMap::new();
    header.insert("www-authenticate", HeaderValue::from_static(www_authenticate));
    let auth_header = parse_digest_auth_header(&header, &url, HttpMethod::GET, None, "username", "password").unwrap();

    let first_request = mock("GET", "/test")
      .with_status(401)
      .with_header("www-authenticate", www_authenticate)
      .create();
    let second_request = mock("GET", "/test")
      .with_header("Authorization", &auth_header.to_header_string())
      .with_status(200)
      .create();

    let request = Client::new().get(&url);

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").await.unwrap();

    // Then the response's final status is OK
    Mock::assert(&first_request);
    Mock::assert(&second_request);
    assert_eq!(&response.status(), &StatusCode::OK);
  }
}
