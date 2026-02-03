# diqwest

This crate extends `reqwest` to be able to send requests with digest auth flow.

When you send a request with digest auth flow this first request will be executed. In case the response is a `401` the `www-authenticate` header is parsed and the answer is calculated. The initial request is executed again with additional `Authorization` header. The response will be returned from `send_digest_auth()`.

In case the first response is not a `401` this first response is returned from `send_digest_auth()` without any manipulation. In case the first response is a `401` but the `www-authenticate` header is missing the first response is returned as well.

`diqwest` is a lean crate and has nearly no dependencies:
- `reqwest`, for sure, as `diqwest` is an extension to it. Without any enabled features and no default features.
- `digest_auth` is used to calculate the answer. Without any enabled feature and no default features.
- `url` is used to validate urls on type level. Without any enabled feature and no default features.

That's it. No other dependencies are used. Not even `thiserror` is used to not force it on you.

## Examples

### Simple usage (no caching)

For one-off requests, pass credentials as a tuple or use `Credentials`:

```rust
use diqwest::WithDigestAuth;
use reqwest::Client;

// Using a tuple (no allocation for credentials)
let response = Client::new()
  .get("https://example.com/api")
  .send_digest_auth(("username", "password"))
  .await?;

// Or using Credentials
use diqwest::Credentials;

let creds = Credentials::new("username", "password");
let response = Client::new()
  .get("https://example.com/api")
  .send_digest_auth(creds)
  .await?;
```

### With session (caching)

Use `DigestAuthSession` when making multiple requests to the same server to avoid the 401 challenge on subsequent requests:

```rust
use diqwest::{WithDigestAuth, DigestAuthSession};
use reqwest::Client;

let client = Client::new();
let session = DigestAuthSession::new("username", "password");

// First request: 401 -> auth -> 200 (credentials cached)
let resp1 = client.get("https://example.com/api")
  .send_digest_auth(&session)
  .await?;

// Subsequent requests: preemptive auth -> 200 (no 401 challenge)
let resp2 = client.get("https://example.com/other")
  .send_digest_auth(&session)
  .await?;
```

This can significantly improve performance by eliminating the 401 round-trip on subsequent requests.

#### Cache invalidation

If the server's nonce becomes stale, the library automatically clears the cache and retries. You can also manually invalidate the cache:

```rust
// Invalidate cache for a specific host
session.invalidate_host("example.com")?;

// Invalidate all cached credentials
session.invalidate_all()?;
```

### Blocking

Enable the `blocking` feature in your `Cargo.toml`:

```toml
[dependencies]
diqwest = { version = "4", features = ["blocking"] }
```

```rust
use diqwest::blocking::WithDigestAuth;
use reqwest::blocking::Client;

let response = Client::new()
  .get("https://example.com/api")
  .send_digest_auth(("username", "password"))?;
```

`DigestAuthSession` works the same way in blocking mode.
