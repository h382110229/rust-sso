//! Cloudflare Access JWT validation.
//!
//! Cloudflare Access protects resources by injecting a signed JWT into every
//! request via the `Cf-Access-Jwt-Assertion` header.  This module:
//!
//! 1. Fetches the team's JWKS from
//!    `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`.
//! 2. Caches the key set in memory and refreshes it periodically (or on
//!    verification failure).
//! 3. Validates the assertion JWT against those public keys (RS256).
//!
//! # Usage
//! ```rust,ignore
//! // Build once and clone into AppState
//! let cf = CfAccessValidator::new("your-team", reqwest::Client::new());
//!
//! // In a middleware or handler:
//! let claims = cf.validate(jwt_str).await?;
//! ```

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, Header, TokenData, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ──────────────────────────────────────────────────────────────────────────────
// CF Access JWT Claims
// ──────────────────────────────────────────────────────────────────────────────

/// Claims embedded in a Cloudflare Access JWT.
///
/// Cloudflare documents the full claim set at
/// <https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/>.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfAccessClaims {
    /// Issuer – `https://<team>.cloudflareaccess.com`
    pub iss: String,
    /// Subject – the user's Cloudflare identity UUID
    pub sub: String,
    /// Audience – list of application AUD tags
    pub aud: Vec<String>,
    /// Expiration timestamp (Unix seconds)
    pub exp: i64,
    /// Issued-at timestamp (Unix seconds)
    pub iat: i64,
    /// JWT ID
    pub jti: Option<String>,
    /// Authenticated user email
    pub email: String,
    /// Identity provider type (e.g. `"google"`, `"github"`, `"onetimepin"`)
    #[serde(rename = "type", default)]
    pub identity_type: String,
    /// Country code of the request origin (ISO 3166-1 alpha-2)
    #[serde(default)]
    pub country: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// JWKS response types
// ──────────────────────────────────────────────────────────────────────────────

/// A single JWK from the Cloudflare JWKS endpoint.
#[derive(Debug, Deserialize, Clone)]
struct CfJwk {
    /// Key ID
    pub kid: String,
    /// Algorithm (expected: `"RS256"`)
    pub alg: Option<String>,
    /// RSA modulus (Base64URL)
    pub n: String,
    /// RSA exponent (Base64URL)
    pub e: String,
}

/// The JWKS document returned by Cloudflare Access.
#[derive(Debug, serde::Deserialize)]
struct CfJwkSet {
    pub keys: Vec<CfJwk>,
    // `public_cert` is also present but we only need `keys`.
}

// ──────────────────────────────────────────────────────────────────────────────
// Key cache
// ──────────────────────────────────────────────────────────────────────────────

/// How long to cache Cloudflare's public keys before re-fetching.
const CACHE_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

#[derive(Clone)]
struct KeyCache {
    keys: Vec<CfJwk>,
    fetched_at: Instant,
}

impl KeyCache {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() > CACHE_TTL
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Validator
// ──────────────────────────────────────────────────────────────────────────────

/// Validates Cloudflare Access JWTs issued for a specific team domain.
///
/// Clone this struct cheaply – it wraps its state in an [`Arc`].
#[derive(Clone)]
pub struct CfAccessValidator {
    inner: Arc<CfAccessValidatorInner>,
}

struct CfAccessValidatorInner {
    team_domain: String,
    http: reqwest::Client,
    cache: RwLock<Option<KeyCache>>,
}

impl CfAccessValidator {
    /// Create a new validator for the given Cloudflare Access team.
    ///
    /// `team_domain` can be either the bare team name (`"my-team"`) or the full
    /// domain (`"my-team.cloudflareaccess.com"`).  Both forms are accepted.
    pub fn new(team_domain: impl Into<String>, http: reqwest::Client) -> Self {
        let team_domain = team_domain.into();
        // Normalise: strip any https:// prefix the user might have included.
        let team_domain = team_domain
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string();

        // Ensure the domain is fully qualified.
        let team_domain = if team_domain.contains('.') {
            team_domain
        } else {
            format!("{team_domain}.cloudflareaccess.com")
        };

        Self {
            inner: Arc::new(CfAccessValidatorInner {
                team_domain,
                http,
                cache: RwLock::new(None),
            }),
        }
    }

    /// The JWKS URL for this team.
    fn jwks_url(&self) -> String {
        format!(
            "https://{}/cdn-cgi/access/certs",
            self.inner.team_domain
        )
    }

    /// The expected issuer for JWTs from this team.
    fn expected_issuer(&self) -> String {
        format!("https://{}", self.inner.team_domain)
    }

    // ── Key fetching ─────────────────────────────────────────────────────────

    /// Fetch and cache the JWKS from Cloudflare, returning the key list.
    ///
    /// Uses a read-lock optimistic path; only upgrades to a write-lock when the
    /// cache is missing or stale.
    async fn get_keys(&self) -> anyhow::Result<Vec<CfJwk>> {
        // Fast path: cache is warm and fresh.
        {
            let cache = self.inner.cache.read().await;
            if let Some(ref kc) = *cache {
                if !kc.is_stale() {
                    debug!("CF Access JWKS cache hit");
                    return Ok(kc.keys.clone());
                }
            }
        }

        // Slow path: fetch and repopulate.
        self.fetch_and_cache_keys().await
    }

    /// Actually fetch from the network and update the cache.
    async fn fetch_and_cache_keys(&self) -> anyhow::Result<Vec<CfJwk>> {
        let url = self.jwks_url();
        info!(url, "Fetching Cloudflare Access JWKS");

        let resp = self
            .inner
            .http
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .context("HTTP request to Cloudflare JWKS endpoint failed")?
            .error_for_status()
            .context("Cloudflare JWKS endpoint returned an error status")?;

        let jwk_set: CfJwkSet = resp
            .json()
            .await
            .context("Failed to parse Cloudflare JWKS JSON")?;

        info!(count = jwk_set.keys.len(), "Received CF Access public keys");

        let keys = jwk_set.keys;

        let mut cache = self.inner.cache.write().await;
        *cache = Some(KeyCache {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });

        Ok(keys)
    }

    // ── Validation ───────────────────────────────────────────────────────────

    /// Validate a Cloudflare Access JWT.
    ///
    /// 1. Decodes the header to find the `kid`.
    /// 2. Looks up the matching public key from the JWKS cache (re-fetching if
    ///    necessary).
    /// 3. Verifies the signature, expiry, and issuer.
    ///
    /// `audiences` should be the list of CF Access **Application Audience (AUD)
    /// tags** for the resource being protected.  Pass an empty slice to skip
    /// audience validation (useful for internal services).
    pub async fn validate(
        &self,
        token: &str,
        audiences: &[&str],
    ) -> anyhow::Result<CfAccessClaims> {
        // 1. Peek at the JWT header to get the key ID.
        let header: Header = decode_header(token)
            .context("Failed to decode JWT header")?;
        let kid = header.kid.as_deref().unwrap_or_default();

        // 2. Find the matching public key.
        let decoding_key = self.find_key(token, kid).await?;

        // 3. Validate the token.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.expected_issuer()]);
        if audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(audiences);
        }

        let data: TokenData<CfAccessClaims> =
            decode(token, &decoding_key, &validation)
                .context("CF Access JWT validation failed")?;

        Ok(data.claims)
    }

    /// Find the [`DecodingKey`] for the given `kid`, re-fetching if not found.
    async fn find_key(&self, token: &str, kid: &str) -> anyhow::Result<DecodingKey> {
        // Try from cache first.
        if let Some(key) = self.build_decoding_key_for_kid(kid).await? {
            return Ok(key);
        }

        // Not found – the key set may have rotated.  Refresh and try once more.
        warn!(kid, "CF Access key not found in cache, refreshing JWKS");
        self.fetch_and_cache_keys().await?;

        self.build_decoding_key_for_kid(kid)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No CF Access public key found for kid='{}' after JWKS refresh",
                    kid
                )
            })
    }

    /// Build a [`DecodingKey`] for the first key in the cache whose `kid`
    /// matches.  Returns `None` if not found.
    async fn build_decoding_key_for_kid(&self, kid: &str) -> anyhow::Result<Option<DecodingKey>> {
        let cache = self.inner.cache.read().await;
        let Some(ref kc) = *cache else {
            return Ok(None);
        };

        for jwk in &kc.keys {
            if jwk.kid == kid || kid.is_empty() {
                let dk = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                    .context("Failed to build DecodingKey from JWK RSA components")?;
                return Ok(Some(dk));
            }
        }

        Ok(None)
    }

    /// Invalidate the key cache (forces a re-fetch on the next validation).
    pub async fn invalidate_cache(&self) {
        let mut cache = self.inner.cache.write().await;
        *cache = None;
        debug!("CF Access JWKS cache invalidated");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Axum extractor
// ──────────────────────────────────────────────────────────────────────────────

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, header},
};

/// Axum extractor that validates the `Cf-Access-Jwt-Assertion` header.
///
/// # Usage
/// ```rust,ignore
/// async fn protected(
///     CfAccessUser(claims): CfAccessUser,
/// ) -> impl IntoResponse {
///     Json(serde_json::json!({ "email": claims.email }))
/// }
/// ```
pub struct CfAccessUser(pub CfAccessClaims);

#[async_trait]
impl FromRequestParts<crate::AppState> for CfAccessUser {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::AppState,
    ) -> Result<Self, Self::Rejection> {
        const HEADER: &str = "cf-access-jwt-assertion";

        let token = parts
            .headers
            .get(HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Cf-Access-Jwt-Assertion header"))?;

        let validator = state
            .cf_access
            .as_ref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "CF Access not configured"))?;

        // No audience restriction at extractor level – handlers can check aud.
        let claims = validator
            .validate(token, &[])
            .await
            .map_err(|e| {
                warn!(error = %e, "CF Access JWT validation failed");
                (StatusCode::UNAUTHORIZED, "Invalid Cloudflare Access token")
            })?;

        Ok(CfAccessUser(claims))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests (mocked with httpmock)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_bare_team_name() {
        let v = CfAccessValidator::new("acme", reqwest::Client::new());
        assert_eq!(v.inner.team_domain, "acme.cloudflareaccess.com");
    }

    #[test]
    fn normalises_full_domain() {
        let v = CfAccessValidator::new("acme.cloudflareaccess.com", reqwest::Client::new());
        assert_eq!(v.inner.team_domain, "acme.cloudflareaccess.com");
    }

    #[test]
    fn normalises_https_prefix() {
        let v =
            CfAccessValidator::new("https://acme.cloudflareaccess.com", reqwest::Client::new());
        assert_eq!(v.inner.team_domain, "acme.cloudflareaccess.com");
    }

    #[test]
    fn expected_issuer_format() {
        let v = CfAccessValidator::new("acme", reqwest::Client::new());
        assert_eq!(
            v.expected_issuer(),
            "https://acme.cloudflareaccess.com"
        );
    }
}
