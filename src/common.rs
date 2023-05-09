use digest_auth::AuthorizationHeader;
use digest_auth::HttpMethod;
use reqwest::header::HeaderMap;
use reqwest::Method;
use url::Position;
use url::Url;

use crate::error::{Error, Result};
use crate::AuthContext;
use crate::Error::RequestBuilderNotCloneable;

pub(crate) trait TryClone {
  fn try_clone(&self) -> Option<Self>
  where
    Self: Sized;
}

pub(crate) trait Build<R> {
  fn build(self) -> Result<R>;
}

pub(crate) trait RequestIt<B>
where
  B: AsBytes,
{
  fn url(&self) -> &Url;
  fn method(&self) -> &Method;
  fn body(&self) -> Option<&B>;
}

pub(crate) trait AsBytes {
  fn as_bytes(&self) -> Option<&[u8]>;
}

pub(crate) fn clone_request_builder<T: TryClone>(request_builder: &T) -> Result<T> {
  request_builder.try_clone().ok_or(RequestBuilderNotCloneable)
}

pub(crate) fn parse_digest_auth_header(
  header: &HeaderMap,
  path: &str,
  method: HttpMethod,
  body: Option<&[u8]>,
  username: &str,
  password: &str,
) -> Result<AuthorizationHeader> {
  let www_auth = header.get("www-authenticate").ok_or(Error::AuthHeaderMissing)?.to_str()?;
  let context = AuthContext::new_with_method(username, password, path, body, method);
  let mut prompt = digest_auth::parse(www_auth)?;

  Ok(prompt.respond(&context)?)
}

pub(crate) fn calculate_answer<B, R, BO>(
  request_builder: &B,
  headers: &HeaderMap,
  username: &str,
  password: &str,
) -> Result<AuthorizationHeader>
where
  BO: AsBytes,
  R: RequestIt<BO>,
  B: Build<R> + TryClone,
{
  let request = clone_request_builder(request_builder)?.build()?;
  let path = &request.url()[Position::AfterPort..];
  let method = HttpMethod::from(request.method().as_str());
  let body = request.body().and_then(|b| b.as_bytes());

  parse_digest_auth_header(headers, path, method, body, username, password)
}
