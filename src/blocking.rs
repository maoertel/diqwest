use digest_auth::HttpMethod;
use reqwest::blocking::{RequestBuilder, Response};
use reqwest::StatusCode;

use crate::error::Error::{AuthHeaderMissing, RequestBuilderNotCloneable};
use crate::error::Result;
use crate::parse_digest_auth_header;

/// A trait to extend the functionality of a blocking `RequestBuilder` to send a request with digest auth flow.
///
/// Call it at the end of your `RequestBuilder` chain like you would use `send()`.
pub trait WithDigestAuth {
  fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response>;
}

impl WithDigestAuth for RequestBuilder {
  fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response> {
    fn clone_request_builder(request_builder: &RequestBuilder) -> Result<RequestBuilder> {
      request_builder.try_clone().ok_or(RequestBuilderNotCloneable)
    }

    let first_response = clone_request_builder(self)?.send()?;
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
              .send()?,
          ),
          Err(AuthHeaderMissing) => Ok(first_response),
          Err(error) => Err(error),
        }
        // Ok(
        //   clone_request_builder(self)?
        //     .header("Authorization", answer.to_header_string())
        //     .send()?,
        // )
      }
      _ => Ok(first_response),
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::blocking::WithDigestAuth;
  use crate::parse_digest_auth_header;

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
    let mock = mock("GET", "/test").with_status(200).create();
    let request = Client::new().get(format!("{}/test", mockito::server_url()));

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").unwrap();

    // Then the response's status is OK
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::OK);
  }

  #[test]
  fn given_non_digest_auth_endpoint_unauthorized_when_send_with_da_then_request_fails_with_401() {
    // Given I have a GET request against a non digest auth  but authorized endpoint
    let mock = mock("GET", "/test").with_status(401).create();
    let request = Client::new().get(format!("{}/test", mockito::server_url()));

    // When I send with digest auth
    let response = request.send_with_digest_auth("username", "password").unwrap();

    // Then the response's final status is UNAUTHORIZED
    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn given_digest_auth_endpoint_authorized_when_send_with_da_then_request_succeeds() {
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
    let response = request.send_with_digest_auth("username", "password").unwrap();

    // Then the response's final status is OK
    Mock::assert(&first_request);
    Mock::assert(&second_request);
    assert_eq!(&response.status(), &StatusCode::OK);
  }
}
