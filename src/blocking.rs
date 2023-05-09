use reqwest::blocking::{Body, Request, RequestBuilder, Response};
use reqwest::{header::AUTHORIZATION, Method, StatusCode};
use url::Url;

use crate::common::{calculate_answer, clone_request_builder, AsBytes, Build, RequestIt, TryClone};
use crate::error::Error::AuthHeaderMissing;
use crate::error::Result;

/// A trait to extend the functionality of a blocking `RequestBuilder` to send a request with digest auth flow.
///
/// Call it at the end of your `RequestBuilder` chain like you would use `send()`.
pub trait WithDigestAuth {
  fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response>;
}

impl WithDigestAuth for RequestBuilder {
  fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response> {
    let first_response = clone_request_builder(self)?.send()?;
    match first_response.status() {
      StatusCode::UNAUTHORIZED => {
        let answer = calculate_answer(self, first_response.headers(), username, password);

        match answer {
          Ok(answer) => Ok(
            clone_request_builder(self)?
              .header(AUTHORIZATION, answer.to_header_string())
              .send()?,
          ),
          Err(AuthHeaderMissing) => Ok(first_response),
          Err(error) => Err(error),
        }
      }
      _ => Ok(first_response),
    }
  }
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

impl RequestIt<Body> for Request {
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

#[cfg(test)]
mod tests {
  use crate::blocking::WithDigestAuth;
  use crate::common::parse_digest_auth_header;

  use digest_auth::HttpMethod;
  use mockito::{mock, Mock};
  use reqwest::blocking::Client;
  use reqwest::{
    header::{HeaderMap, HeaderValue},
    StatusCode,
  };

  #[test]
  fn given_non_digest_auth_endpoint_when_send_with_da_then_request_executed_normally() {
    // Given I have a GET request against a non digest auth endpoint
    let path = "/test";
    let mock = mock("GET", path).with_status(200).create();
    let request = Client::new().get(format!("{domain}{path}", domain = mockito::server_url()));

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").unwrap();

    // Then the response's status is OK
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::OK);
  }

  #[test]
  fn given_non_digest_auth_endpoint_unauthorized_when_send_with_da_then_request_fails_with_401() {
    // Given I have a GET request against a non digest auth  but authorized endpoint
    let path = "/test";
    let mock = mock("GET", path).with_status(401).create();
    let request = Client::new().get(format!("{domain}{path}", domain = mockito::server_url()));

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").unwrap();

    // Then the response's final status is UNAUTHORIZED
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn given_digest_auth_endpoint_authorized_when_send_with_da_then_request_succeeds() {
    // Given I have a GET request against a digest auth endpoint with valid 'www-authenticate' header
    let path = "/test";
    let url = format!("{domain}{path}", domain = mockito::server_url());
    let www_authenticate = "Digest realm=\"testrealm@host.com\",qop=\"auth,auth-int\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
    let mut header = HeaderMap::new();
    header.insert("www-authenticate", HeaderValue::from_static(www_authenticate));
    let auth_header = parse_digest_auth_header(&header, path, HttpMethod::GET, None, "username", "password").unwrap();

    let first_request = mock("GET", path)
      .with_status(401)
      .with_header("www-authenticate", www_authenticate)
      .create();
    let second_request = mock("GET", path)
      .with_header("Authorization", &auth_header.to_header_string())
      .with_status(200)
      .create();

    let request = Client::new().get(url);

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").unwrap();

    // Then the response's final status is OK
    Mock::assert(&first_request);
    Mock::assert(&second_request);
    assert_eq!(&response.status(), &StatusCode::OK);
  }
}
