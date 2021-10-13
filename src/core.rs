use async_trait::async_trait;
use digest_auth::{AuthContext, HttpMethod};
use http::StatusCode;
use reqwest::{RequestBuilder, Response};

use Error::RequestBuilderNotCloneableError;

use crate::error::{Error, Result};

/// A trait to extend the functionality of a `RequestBuilder` to send a request with digest auth flow.
///
/// Call it at the end of your `RequestBuilder` chain like you would use `send()`.
#[async_trait]
pub trait WithDigestAuth {
  async fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response>;
}

#[async_trait]
impl WithDigestAuth for RequestBuilder {
  async fn send_with_digest_auth(&self, username: &str, password: &str) -> Result<Response> {
    fn clone_request_builder(request_builder: &RequestBuilder) -> std::result::Result<RequestBuilder, Error> {
      request_builder.try_clone().ok_or(RequestBuilderNotCloneableError)
    }

    let first_response = clone_request_builder(self)?.send().await?;
    match first_response.status() {
      StatusCode::UNAUTHORIZED => {
        let request = clone_request_builder(self)?.build()?;
        let url = request.url();
        let method = HttpMethod::from(request.method().as_str());
        let body = request.body().and_then(|b| b.as_bytes());
        let answer =
            DigestAuthHelper::parse_digest_auth_header(first_response, url.as_str(), method, body, username, password)?;

        Ok(clone_request_builder(self)?.header("Authorization", answer).send().await?)
      }
      _ => Ok(first_response),
    }
  }
}

struct DigestAuthHelper;

impl DigestAuthHelper {
  fn parse_digest_auth_header(
    response: Response,
    uri: &str,
    method: HttpMethod,
    body: Option<&[u8]>,
    public: &str,
    private: &str,
  ) -> Result<String> {
    let www_auth = response.headers()["www-authenticate"].to_str()?;
    let context = AuthContext::new_with_method(public, private, uri, body, method);
    let mut prompt = digest_auth::parse(www_auth)?;

    Ok(prompt.respond(&context)?.to_header_string())
  }
}
