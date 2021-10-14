use std::fmt::{Debug, Display, Formatter};
use std::result;

use reqwest::header::ToStrError;

use Error::RequestBuilderNotCloneableError;

use crate::error::Error::{DigestAuthError, ReqwestError, ToStrError as MyToStrError};

#[derive(Debug)]
pub enum Error {
  ReqwestError(reqwest::Error),
  DigestAuthError(digest_auth::Error),
  ToStrError(reqwest::header::ToStrError),
  RequestBuilderNotCloneableError,
}

pub type Result<T> = result::Result<T, Error>;

impl Display for Error {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      ReqwestError(e) => std::fmt::Display::fmt(e, f),
      DigestAuthError(e) => std::fmt::Display::fmt(e, f),
      MyToStrError(e) => std::fmt::Display::fmt(e, f),
      RequestBuilderNotCloneableError => write!(f, "Request body must not be a stream."),
    }
  }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
  fn from(e: reqwest::Error) -> Self {
    ReqwestError(e)
  }
}

impl From<digest_auth::Error> for Error {
  fn from(e: digest_auth::Error) -> Self {
    DigestAuthError(e)
  }
}

impl From<reqwest::header::ToStrError> for Error {
  fn from(e: ToStrError) -> Self {
    MyToStrError(e)
  }
}
