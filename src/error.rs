use std::fmt::{Debug, Display, Formatter};
use std::result;

use reqwest::header::ToStrError;

#[derive(Debug)]
pub enum Error {
  Reqwest(reqwest::Error),
  DigestAuth(digest_auth::Error),
  ToStr(reqwest::header::ToStrError),
  AuthHeaderMissing,
  RequestBuilderNotCloneable,
}

pub type Result<T> = result::Result<T, Error>;

impl Display for Error {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Error::Reqwest(e) => std::fmt::Display::fmt(e, f),
      Error::DigestAuth(e) => std::fmt::Display::fmt(e, f),
      Error::ToStr(e) => std::fmt::Display::fmt(e, f),
      Error::RequestBuilderNotCloneable => write!(f, "Request body must not be a stream."),
      Error::AuthHeaderMissing => write!(f, "The header 'www-authenticate' is missing."),
    }
  }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
  fn from(e: reqwest::Error) -> Self {
    Error::Reqwest(e)
  }
}

impl From<digest_auth::Error> for Error {
  fn from(e: digest_auth::Error) -> Self {
    Error::DigestAuth(e)
  }
}

impl From<reqwest::header::ToStrError> for Error {
  fn from(e: ToStrError) -> Self {
    Error::ToStr(e)
  }
}
