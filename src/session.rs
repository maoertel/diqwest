use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;

use digest_auth::{AuthorizationHeader, HttpMethod};
use reqwest::header::HeaderMap;

use crate::common::parse_digest_auth_header;
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
            qops.first().map(|q| {
                match q {
                    digest_auth::Qop::AUTH => "auth".to_string(),
                    digest_auth::Qop::AUTH_INT => "auth-int".to_string(),
                }
            })
        });
        Ok(Self {
            nonce: prompt.nonce.to_string(),
            realm: prompt.realm.to_string(),
            opaque: prompt.opaque.map(|s| s.to_string()),
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
    fn cached_context(&self, host: &str) -> Option<CachedContextGuard<'_>>;

    /// Stores auth context for a host after successful authentication.
    fn store_context(&self, host: &str, www_authenticate: &str) -> Result<()>;

    /// Calculates the authorization header, using cache if available.
    fn calculate_authorization(
        &self,
        host: &str,
        path: &str,
        method: HttpMethod,
        body: Option<&[u8]>,
        response_headers: &HeaderMap,
    ) -> Result<(AuthorizationHeader, bool)> {
        // Check if we have a cached context
        if let Some(ctx) = self.cached_context(host) {
            let nc = ctx.next_nc();
            let mut prompt = digest_auth::parse(
                &format!(
                    "Digest realm=\"{}\", nonce=\"{}\"{}{}",
                    ctx.realm(),
                    ctx.nonce(),
                    ctx.opaque().map(|o| format!(", opaque=\"{}\"", o)).unwrap_or_default(),
                    ctx.qop().map(|q| format!(", qop=\"{}\"", q)).unwrap_or_default(),
                )
            )?;
            prompt.nc = nc;

            let context = digest_auth::AuthContext::new_with_method(
                self.username(),
                self.password(),
                path,
                body,
                method,
            );

            let header = prompt.respond(&context)?;
            return Ok((header, true)); // true = used cache
        }

        // No cache, parse from response headers
        let header = parse_digest_auth_header(
            response_headers,
            path,
            method,
            body,
            self.username(),
            self.password(),
        )?;

        Ok((header, false)) // false = did not use cache
    }
}

/// Guard type for accessing cached context.
pub struct CachedContextGuard<'a> {
    ctx: std::sync::RwLockReadGuard<'a, HashMap<String, DigestAuthContext>>,
    host: String,
}

impl<'a> CachedContextGuard<'a> {
    pub(crate) fn realm(&self) -> &str {
        &self.ctx.get(&self.host).unwrap().realm
    }

    pub(crate) fn nonce(&self) -> &str {
        &self.ctx.get(&self.host).unwrap().nonce
    }

    pub(crate) fn opaque(&self) -> Option<&str> {
        self.ctx.get(&self.host).unwrap().opaque.as_deref()
    }

    pub(crate) fn qop(&self) -> Option<&str> {
        self.ctx.get(&self.host).unwrap().qop.as_deref()
    }

    pub(crate) fn next_nc(&self) -> u32 {
        self.ctx.get(&self.host).unwrap().next_nc()
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
    pub fn clear_cache(&self) {
        self.cache.write().unwrap().clear();
    }

    /// Removes cached context for a specific host.
    pub fn clear_host(&self, host: &str) {
        self.cache.write().unwrap().remove(host);
    }
}

impl DigestAuthCredentials for &DigestAuthSession {
    fn username(&self) -> &str {
        &self.username
    }

    fn password(&self) -> &str {
        &self.password
    }

    fn cached_context(&self, host: &str) -> Option<CachedContextGuard<'_>> {
        let cache = self.cache.read().unwrap();
        if cache.contains_key(host) {
            Some(CachedContextGuard {
                ctx: cache,
                host: host.to_string(),
            })
        } else {
            None
        }
    }

    fn store_context(&self, host: &str, www_authenticate: &str) -> Result<()> {
        let ctx = DigestAuthContext::from_header(www_authenticate)?;
        self.cache.write().unwrap().insert(host.to_string(), ctx);
        Ok(())
    }
}

/// Implementation for simple tuple credentials (no caching).
impl DigestAuthCredentials for (&str, &str) {
    fn username(&self) -> &str {
        self.0
    }

    fn password(&self) -> &str {
        self.1
    }

    fn cached_context(&self, _host: &str) -> Option<CachedContextGuard<'_>> {
        None
    }

    fn store_context(&self, _host: &str, _www_authenticate: &str) -> Result<()> {
        // No-op for simple credentials
        Ok(())
    }
}

/// Also implement for owned strings tuple.
impl DigestAuthCredentials for (String, String) {
    fn username(&self) -> &str {
        &self.0
    }

    fn password(&self) -> &str {
        &self.1
    }

    fn cached_context(&self, _host: &str) -> Option<CachedContextGuard<'_>> {
        None
    }

    fn store_context(&self, _host: &str, _www_authenticate: &str) -> Result<()> {
        Ok(())
    }
}

/// Implement for references to owned strings tuple.
impl DigestAuthCredentials for (&String, &String) {
    fn username(&self) -> &str {
        self.0
    }

    fn password(&self) -> &str {
        self.1
    }

    fn cached_context(&self, _host: &str) -> Option<CachedContextGuard<'_>> {
        None
    }

    fn store_context(&self, _host: &str, _www_authenticate: &str) -> Result<()> {
        Ok(())
    }
}
