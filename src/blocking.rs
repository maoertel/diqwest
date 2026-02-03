use digest_auth::HttpMethod;
use reqwest::Method;
use reqwest::StatusCode;
use reqwest::blocking::Body;
use reqwest::blocking::Request;
use reqwest::blocking::RequestBuilder;
use reqwest::blocking::Response;
use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderMap;
use url::Position;
use url::Url;

use crate::common::AsBytes;
use crate::common::Build;
use crate::common::CloneRequestBuilder;
use crate::common::TryClone;
use crate::common::WWW_AUTHENTICATE;
use crate::common::WithHeaders;
use crate::common::WithRequest;
use crate::common::get_answer;
use crate::error::Error;
use crate::error::Result;
use crate::session::DigestAuthCredentials;

/// A trait to extend the functionality of a blocking `RequestBuilder` to send a request with digest auth flow.
///
/// Call it at the end of your `RequestBuilder` chain like you would use `send()`.
pub trait WithDigestAuth {
  /// Sends the request with digest authentication.
  ///
  /// Accepts either a tuple of credentials `("username", "password")` for simple usage,
  /// or a `&DigestAuthSession` for cached authentication.
  fn send_digest_auth<C: DigestAuthCredentials>(&self, credentials: C) -> Result<Response>;

  /// Sends the request with digest authentication.
  #[deprecated(since = "4.0.0", note = "Use send_digest_auth instead")]
  fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response>;
}

impl WithDigestAuth for RequestBuilder {
  fn send_digest_auth<C: DigestAuthCredentials>(&self, credentials: C) -> Result<Response> {
    let request = self.refresh()?.build()?;
    let host = request.url().host_str().ok_or(Error::MissingHost)?;
    let path = &request.url()[Position::AfterPort..];
    let method = HttpMethod::from(request.method().as_str());
    let body = request.body().and_then(|b| b.as_bytes());

    match try_preemptive_auth(self, &credentials, host, path, method, body)? {
      PreemptiveAuthResult::Success(response) => return Ok(response),
      PreemptiveAuthResult::CacheStale | PreemptiveAuthResult::NoCache => {}
    }

    // Normal flow: send without auth first
    let first_response = self.refresh()?.send()?;

    match first_response.status() {
      StatusCode::UNAUTHORIZED => try_digest_auth_with_credentials(self, first_response, host, credentials),
      _ => Ok(first_response),
    }
  }

  fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response> {
    self.send_digest_auth(crate::Credentials::new(username, password))
  }
}

/// Result of attempting preemptive authentication with cached credentials.
enum PreemptiveAuthResult {
  /// Preemptive auth succeeded, return this response.
  Success(Response),
  /// Cache was stale (got 401), cleared cache, try normal flow.
  CacheStale,
  /// No cached credentials available.
  NoCache,
}

/// Attempts preemptive authentication using cached credentials.
fn try_preemptive_auth<C: DigestAuthCredentials>(
  request_builder: &RequestBuilder,
  credentials: &C,
  host: &str,
  path: &str,
  method: HttpMethod<'_>,
  body: Option<&[u8]>,
) -> Result<PreemptiveAuthResult> {
  if credentials.cached_context(host)?.is_none() {
    return Ok(PreemptiveAuthResult::NoCache);
  }

  let empty_headers = HeaderMap::new();
  let answer = credentials.calculate_authorization(host, path, method, body, &empty_headers)?;

  let mut headers = HeaderMap::new();
  headers.insert(AUTHORIZATION, answer.to_header_string().parse()?);

  let response = request_builder.refresh()?.headers(headers).send()?;

  match response.status() {
    StatusCode::UNAUTHORIZED => {
      credentials.clear_context(host)?;
      Ok(PreemptiveAuthResult::CacheStale)
    }
    _ => Ok(PreemptiveAuthResult::Success(response)),
  }
}

fn try_digest_auth_with_credentials<C: DigestAuthCredentials>(
  request_builder: &RequestBuilder,
  first_response: Response,
  host: &str,
  credentials: C,
) -> Result<Response> {
  // Store the www-authenticate header for caching (best-effort, ignore parse errors)
  if let Some(www_auth) = first_response.headers().get(WWW_AUTHENTICATE)
    && let Ok(www_auth_str) = www_auth.to_str()
  {
    credentials.store_context(host, www_auth_str)?;
  }

  if let Some(answer) = get_answer(
    request_builder,
    first_response.headers(),
    credentials.username(),
    credentials.password(),
  )? {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, answer.to_header_string().parse()?);

    return Ok(request_builder.refresh()?.headers(headers).send()?);
  }

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
  use crate::Credentials;
  use crate::DigestAuthSession;
  use crate::blocking::WithDigestAuth;
  use crate::common::parse_digest_auth_header;

  use digest_auth::HttpMethod;
  use mockito::Mock;
  use mockito::Server;
  use reqwest::StatusCode;
  use reqwest::blocking::Client;
  use reqwest::blocking::RequestBuilder;
  use reqwest::header::HeaderMap;
  use reqwest::header::HeaderValue;

  const PATH: &str = "/test";
  const WWW_AUTHENTICATE: &str = "Digest realm=\"testrealm@host.com\",qop=\"auth,auth-int\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

  fn create_request(server: &Server) -> RequestBuilder {
    Client::new().get(format!("{domain}{PATH}", domain = server.url()))
  }

  #[test]
  fn given_non_digest_auth_endpoint_when_send_with_da_then_request_executed_normally() {
    let mut server = mockito::Server::new();
    let mock = server.mock("GET", PATH).with_status(200).create();
    let request = create_request(&server);

    let response = request.send_digest_auth(Credentials::new("username", "password")).unwrap();

    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::OK);
  }

  #[test]
  fn given_non_digest_auth_endpoint_unauthorized_when_send_with_da_then_request_fails_with_401() {
    let mut server = mockito::Server::new();
    let mock = server.mock("GET", PATH).with_status(401).create();
    let request = create_request(&server);

    let response = request.send_digest_auth(Credentials::new("username", "password")).unwrap();

    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn given_digest_auth_endpoint_authorized_when_send_with_da_then_request_succeeds() {
    let mut server = mockito::Server::new();
    let mut header = HeaderMap::new();
    header.insert("www-authenticate", HeaderValue::from_static(WWW_AUTHENTICATE));
    let auth_header = parse_digest_auth_header(&header, PATH, HttpMethod::GET, None, "username", "password").unwrap();

    let first_request = server
      .mock("GET", PATH)
      .with_status(401)
      .with_header("www-authenticate", WWW_AUTHENTICATE)
      .create();
    let second_request = server
      .mock("GET", PATH)
      .with_header("Authorization", &auth_header.to_header_string())
      .with_status(200)
      .create();

    let request = create_request(&server);

    let response = request.send_digest_auth(Credentials::new("username", "password")).unwrap();

    Mock::assert(&first_request);
    Mock::assert(&second_request);
    assert_eq!(&response.status(), &StatusCode::OK);
  }

  #[test]
  fn given_session_second_request_uses_cached_credentials() {
    let mut server = mockito::Server::new();
    let session = DigestAuthSession::new("username", "password");

    // First request: expect 401 then authenticated request
    let first_401 = server
      .mock("GET", PATH)
      .with_status(401)
      .with_header("www-authenticate", WWW_AUTHENTICATE)
      .expect(1)
      .create();

    let first_success = server
      .mock("GET", PATH)
      .match_header("Authorization", mockito::Matcher::Regex(r"Digest.*".to_string()))
      .with_status(200)
      .expect(1)
      .create();

    let request1 = create_request(&server);
    let response1 = request1.send_digest_auth(&session).unwrap();
    assert_eq!(response1.status(), StatusCode::OK);

    Mock::assert(&first_401);
    Mock::assert(&first_success);

    // Second request: should use cached credentials (preemptive auth)
    let second_401 = server
      .mock("GET", PATH)
      .with_status(401)
      .with_header("www-authenticate", WWW_AUTHENTICATE)
      .expect(0)
      .create();

    let second_success = server
      .mock("GET", PATH)
      .match_header("Authorization", mockito::Matcher::Regex(r"Digest.*".to_string()))
      .with_status(200)
      .expect(1)
      .create();

    let request2 = create_request(&server);
    let response2 = request2.send_digest_auth(&session).unwrap();
    assert_eq!(response2.status(), StatusCode::OK);

    Mock::assert(&second_401);
    Mock::assert(&second_success);
  }

  #[test]
  #[allow(deprecated)]
  fn deprecated_method_still_works() {
    let mut server = mockito::Server::new();
    let mock = server.mock("GET", PATH).with_status(200).create();
    let request = create_request(&server);

    let response = request.send_with_digest_auth("username", "password").unwrap();

    Mock::assert(&mock);
    assert_eq!(&response.status(), &StatusCode::OK);
  }
}
