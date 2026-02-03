use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use digest_auth::AuthContext;
use digest_auth::AuthorizationHeader;
use digest_auth::HttpMethod;
use reqwest::header::HeaderMap;

use crate::common::parse_digest_auth_header;
use crate::error::Error;
use crate::error::Result;

/// Cached digest authentication context for a specific host/realm combination.
pub struct DigestAuthContext {
  pub(crate) nonce: String,
  pub(crate) realm: String,
  pub(crate) opaque: Option<String>,
  pub(crate) qop: Option<String>,
  pub(crate) nc: AtomicU32,
}

impl DigestAuthContext {
  /// Creates a new context from a www-authenticate header response.
  pub(crate) fn from_header(header: &str) -> Result<Self> {
    let prompt = digest_auth::parse(header)?;
    // Convert Qop to string - take the first qop option
    let qop = prompt.qop.and_then(|qops| {
      qops.first().map(|q| match q {
        digest_auth::Qop::AUTH => "auth".to_string(),
        digest_auth::Qop::AUTH_INT => "auth-int".to_string(),
      })
    });
    Ok(Self {
      nonce: prompt.nonce,
      realm: prompt.realm,
      opaque: prompt.opaque,
      qop,
      nc: AtomicU32::new(0),
    })
  }

  /// Increments and returns the nonce count.
  pub(crate) fn next_nc(&self) -> u32 {
    self.nc.fetch_add(1, Ordering::SeqCst) + 1
  }
}

/// Trait for types that can provide digest authentication credentials.
///
/// This trait is implemented for:
/// - `(&str, &str)` tuples - simple username/password without caching
/// - `&DigestAuthSession` - with caching support
pub trait DigestAuthCredentials {
  /// Returns the username.
  fn username(&self) -> &str;

  /// Returns the password.
  fn password(&self) -> &str;

  /// Retrieves cached auth context for a host, if available.
  fn cached_context<'h>(&self, host: &'h str) -> Result<Option<CachedContextGuard<'_, 'h>>>;

  /// Stores auth context for a host after successful authentication.
  /// Returns Ok(true) if stored, Ok(false) if parse failed (non-fatal).
  fn store_context(&self, host: &str, www_authenticate: &str) -> Result<bool>;

  /// Clears cached context for a host.
  fn clear_context(&self, host: &str) -> Result<()>;

  /// Calculates the authorization header, using cache if available.
  fn calculate_authorization(
    &self,
    host: &str,
    path: &str,
    method: HttpMethod,
    body: Option<&[u8]>,
    response_headers: &HeaderMap,
  ) -> Result<AuthorizationHeader> {
    if let Some(ctx) = self.cached_context(host)? {
      return ctx.create_authorization(self.username(), self.password(), path, method, body);
    }

    parse_digest_auth_header(response_headers, path, method, body, self.username(), self.password())
  }
}

/// Guard type for accessing cached context.
pub struct CachedContextGuard<'a, 'h> {
  ctx: RwLockReadGuard<'a, HashMap<String, DigestAuthContext>>,
  host: &'h str,
}

impl<'a, 'h> CachedContextGuard<'a, 'h> {
  pub(crate) fn realm(&self) -> &str {
    &self.ctx.get(self.host).unwrap().realm
  }

  pub(crate) fn nonce(&self) -> &str {
    &self.ctx.get(self.host).unwrap().nonce
  }

  pub(crate) fn opaque(&self) -> Option<&str> {
    self.ctx.get(self.host).unwrap().opaque.as_deref()
  }

  pub(crate) fn qop(&self) -> Option<&str> {
    self.ctx.get(self.host).unwrap().qop.as_deref()
  }

  pub(crate) fn next_nc(&self) -> u32 {
    self.ctx.get(self.host).unwrap().next_nc()
  }

  pub(crate) fn create_authorization(
    &self,
    username: &str,
    password: &str,
    path: &str,
    method: HttpMethod,
    body: Option<&[u8]>,
  ) -> Result<AuthorizationHeader> {
    let nc = self.next_nc();
    let mut prompt = digest_auth::parse(&format!(
      "Digest realm=\"{}\", nonce=\"{}\"{}{}",
      self.realm(),
      self.nonce(),
      self.opaque().map(|o| format!(", opaque=\"{}\"", o)).unwrap_or_default(),
      self.qop().map(|q| format!(", qop=\"{}\"", q)).unwrap_or_default(),
    ))?;
    prompt.nc = nc;

    let context = AuthContext::new_with_method(username, password, path, body, method);
    Ok(prompt.respond(&context)?)
  }
}

/// Session for digest authentication with credential caching.
///
/// Use this when making multiple requests to the same server to avoid
/// the initial 401 challenge on subsequent requests.
///
/// # Example
///
/// ```ignore
/// use diqwest::DigestAuthSession;
/// use reqwest::Client;
///
/// let client = Client::new();
/// let session = DigestAuthSession::new("username", "password");
///
/// // First request: 401 -> auth -> 200 (caches credentials)
/// let resp1 = client.get(url).send_digest_auth(&session).await?;
///
/// // Second request: preemptive auth -> 200 (no 401)
/// let resp2 = client.get(url).send_digest_auth(&session).await?;
/// ```
pub struct DigestAuthSession {
  username: String,
  password: String,
  cache: RwLock<HashMap<String, DigestAuthContext>>,
}

impl DigestAuthSession {
  /// Creates a new digest auth session with the given credentials.
  pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
    Self {
      username: username.into(),
      password: password.into(),
      cache: RwLock::new(HashMap::new()),
    }
  }

  /// Clears all cached authentication contexts.
  pub fn clear_cache(&self) -> Result<()> {
    self.cache.write().map_err(|_| Error::LockPoisoned)?.clear();
    Ok(())
  }

  /// Removes cached context for a specific host.
  pub fn clear_host(&self, host: &str) -> Result<()> {
    self.cache.write().map_err(|_| Error::LockPoisoned)?.remove(host);
    Ok(())
  }
}

impl DigestAuthCredentials for &DigestAuthSession {
  fn username(&self) -> &str {
    &self.username
  }

  fn password(&self) -> &str {
    &self.password
  }

  fn cached_context<'h>(&self, host: &'h str) -> Result<Option<CachedContextGuard<'_, 'h>>> {
    let cache = self.cache.read().map_err(|_| Error::LockPoisoned)?;
    if cache.contains_key(host) {
      return Ok(Some(CachedContextGuard { ctx: cache, host }));
    }

    Ok(None)
  }

  fn store_context(&self, host: &str, www_authenticate: &str) -> Result<bool> {
    let ctx = match DigestAuthContext::from_header(www_authenticate) {
      Ok(ctx) => ctx,
      Err(_) => return Ok(false), // Parse error is non-fatal
    };
    self
      .cache
      .write()
      .map_err(|_| Error::LockPoisoned)?
      .insert(host.to_string(), ctx);
    Ok(true)
  }

  fn clear_context(&self, host: &str) -> Result<()> {
    self
      .cache
      .write()
      .map_err(|_| Error::LockPoisoned)?
      .remove(host);
    Ok(())
  }
}

/// Simple credentials without caching.
///
/// Use this for one-off requests where caching is not needed.
///
/// # Example
///
/// ```ignore
/// use diqwest::Credentials;
///
/// let creds = Credentials::new("username", "password");
/// request.send_digest_auth(creds).await?;
/// ```
pub struct Credentials {
  username: String,
  password: String,
}

impl Credentials {
  /// Creates new credentials with the given username and password.
  pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
    Self {
      username: username.into(),
      password: password.into(),
    }
  }
}

impl DigestAuthCredentials for Credentials {
  fn username(&self) -> &str {
    &self.username
  }

  fn password(&self) -> &str {
    &self.password
  }

  fn cached_context<'h>(&self, _host: &'h str) -> Result<Option<CachedContextGuard<'_, 'h>>> {
    Ok(None)
  }

  fn store_context(&self, _host: &str, _www_authenticate: &str) -> Result<bool> {
    Ok(false) // No caching support
  }

  fn clear_context(&self, _host: &str) -> Result<()> {
    Ok(()) // No caching support
  }
}

impl DigestAuthCredentials for &Credentials {
  fn username(&self) -> &str {
    &self.username
  }

  fn password(&self) -> &str {
    &self.password
  }

  fn cached_context<'h>(&self, _host: &'h str) -> Result<Option<CachedContextGuard<'_, 'h>>> {
    Ok(None)
  }

  fn store_context(&self, _host: &str, _www_authenticate: &str) -> Result<bool> {
    Ok(false) // No caching support
  }

  fn clear_context(&self, _host: &str) -> Result<()> {
    Ok(()) // No caching support
  }
}
