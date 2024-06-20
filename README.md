# diqwest

This crate extends `reqwest` to be able to send requests with digest auth flow.

When you send a request with digest auth flow this first request will be executed. In case the response is a `401` the `www-authenticate` header is parsed and the answer is calculated. The initial request is executed again with additional `Authorization` header. The response will be returned from `send_with_digest_auth()`.

In case the first response is not a `401` this first response is returned from `send_with_digest_auth()` without any manipulation. In case the first response is a `401` but the `www-authenticate` header is missing the first reponse is returned as well.

`diqwest` is a lean crate and has nearly no dependencies:
- `reqwest`, for sure, as `diqwest` is an extension to it. Without any enabled features and no default features.
- `digest_auth` is used to calculate the answer. Without any enabled feature and no default features.
- `url` is used to parse parse a url on type level. Without any enabled feature and no default features.

That's it. No other dependencies are used. Not even `thiserror` is used to not force it on you.

## Examples

### Async (default)
```rust
use diqwest::WithDigestAuth;
use reqwest::{Client, Response};

// Call `.send_with_digest_auth()` on `RequestBuilder` like `send()`
let response: Response = Client::new()
  .get("url")
  .send_with_digest_auth("username", "password")
  .await?;
```

### Blocking (feature flag `blocking` has to be enabled in `Cargo.toml`)

```rust
use diqwest::blocking::WithDigestAuth;
use reqwest::blocking::{Client, Response};

// Call `.send_with_digest_auth()` on `RequestBuilder` like `send()`
let response: Response = Client::new()
  .get("url")
  .send_with_digest_auth("username", "password")?;
```
