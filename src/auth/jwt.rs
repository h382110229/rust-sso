//! JWT issuance and verification using RS256.
//!
//! # Overview
//! - An RSA-2048 key pair is generated once at startup and held in [`JwtKeys`].
//! - [`JwtKeys::sign`] mints access tokens with standard OIDC claims.
//! - [`JwtKeys::verify`] validates a token, returning its [`Claims`].
//! - [`JwtKeys::jwks`] returns the public key as a JWK Set suitable for
//!   publishing at `/.well-known/jwks.json`.
//!
//! # Usage
//! ```rust,ignore
//! let keys = JwtKeys::generate()?;
//! let token = keys.sign(&claims)?;
//! let verified = keys.verify(&token, &["my-audience"])?;
//! let jwks = keys.jwks();
//! ```

use std::sync::Arc;

use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
};
use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Claims
// ──────────────────────────────────────────────────────────────────────────────

/// Standard + custom JWT claims carried in every issued token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (`iss`)
    pub iss: String,
    /// Subject – user's UUID (`sub`)
    pub sub: String,
    /// Audience (`aud`) – list of intended recipients
    pub aud: Vec<String>,
    /// Issued-at timestamp, seconds since Unix epoch (`iat`)
    pub iat: i64,
    /// Expiration timestamp, seconds since Unix epoch (`exp`)
    pub exp: i64,
    /// JWT ID – unique identifier for this token (`jti`)
    pub jti: String,
    /// User's email address (custom claim)
    pub email: String,
    /// Comma-separated role list (custom claim, e.g. `"admin,user"`)
    #[serde(default)]
    pub roles: String,
}

impl Claims {
    /// Construct a new [`Claims`] with sane defaults.
    ///
    /// * `issuer`  – value of the `iss` claim (from config).
    /// * `subject` – the user's persistent UUID.
    /// * `email`   – the user's email address.
    /// * `audience`– list of `aud` values (e.g. `["my-client"]`).
    /// * `ttl_secs`– how long the token should remain valid.
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        email: impl Into<String>,
        audience: Vec<String>,
        ttl_secs: i64,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: issuer.into(),
            sub: subject.into(),
            email: email.into(),
            aud: audience,
            iat: now,
            exp: now + ttl_secs,
            jti: uuid::Uuid::new_v4().to_string(),
            roles: String::new(),
        }
    }

    /// Attach a role list (replaces the current value).
    pub fn with_roles(mut self, roles: impl Into<String>) -> Self {
        self.roles = roles.into();
        self
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// JWK / JWKS types
// ──────────────────────────────────────────────────────────────────────────────

/// A single JSON Web Key (public RSA key, RS256).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type – always `"RSA"`.
    pub kty: String,
    /// Intended use – always `"sig"`.
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm – always `"RS256"`.
    pub alg: String,
    /// Key ID matching the `kid` header in issued tokens.
    pub kid: String,
    /// RSA modulus (Base64URL, no padding).
    pub n: String,
    /// RSA public exponent (Base64URL, no padding).
    pub e: String,
}

/// JSON Web Key Set – the response body for `/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

// ──────────────────────────────────────────────────────────────────────────────
// JwtKeys
// ──────────────────────────────────────────────────────────────────────────────

/// Holder of the RS256 key pair.
///
/// Cheaply cloneable via the inner [`Arc`]; clone this into `AppState`.
#[derive(Clone)]
pub struct JwtKeys {
    inner: Arc<JwtKeysInner>,
}

struct JwtKeysInner {
    /// Key ID embedded in every issued token header.
    kid: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Pre-serialised JWK for the JWKS endpoint.
    jwk: Jwk,
}

impl JwtKeys {
    /// Generate a fresh RSA-2048 key pair.
    ///
    /// This is an expensive operation – call it **once** at startup.
    pub fn generate() -> anyhow::Result<Self> {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048)
            .context("Failed to generate RSA-2048 private key")?;
        let pub_key = RsaPublicKey::from(&priv_key);

        let kid = uuid::Uuid::new_v4().to_string();

        // Encode keys in PKCS#8 PEM for jsonwebtoken
        let priv_pem = priv_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .context("Failed to encode RSA private key as PKCS#8 PEM")?;
        let pub_pem = pub_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .context("Failed to encode RSA public key as PEM")?;

        let encoding_key = EncodingKey::from_rsa_pem(priv_pem.as_bytes())
            .context("jsonwebtoken could not parse RSA private key PEM")?;
        let decoding_key = DecodingKey::from_rsa_pem(pub_pem.as_bytes())
            .context("jsonwebtoken could not parse RSA public key PEM")?;

        // Build JWK from raw key components
        let jwk = Jwk {
            kty: "RSA".into(),
            use_: "sig".into(),
            alg: "RS256".into(),
            kid: kid.clone(),
            n: URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be()),
        };

        Ok(Self {
            inner: Arc::new(JwtKeysInner {
                kid,
                encoding_key,
                decoding_key,
                jwk,
            }),
        })
    }

    /// Load keys from existing PEM files (useful for persistent key storage).
    ///
    /// `priv_pem` – PKCS#8 PEM-encoded RSA private key.
    /// `pub_pem`  – PKCS#8 / SPKI PEM-encoded RSA public key.
    /// `kid`      – A stable key identifier string.
    pub fn from_pem(priv_pem: &[u8], pub_pem: &[u8], kid: impl Into<String>) -> anyhow::Result<Self> {
        let kid = kid.into();

        let encoding_key = EncodingKey::from_rsa_pem(priv_pem)
            .context("jsonwebtoken could not parse RSA private key PEM")?;
        let decoding_key = DecodingKey::from_rsa_pem(pub_pem)
            .context("jsonwebtoken could not parse RSA public key PEM")?;

        // Parse the public key to extract n / e for JWK
        let pub_key = rsa::RsaPublicKey::from_public_key_pem(
            std::str::from_utf8(pub_pem).context("pub_pem is not valid UTF-8")?,
        )
        .context("Failed to parse RSA public key from PEM")?;

        let jwk = Jwk {
            kty: "RSA".into(),
            use_: "sig".into(),
            alg: "RS256".into(),
            kid: kid.clone(),
            n: URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be()),
        };

        Ok(Self {
            inner: Arc::new(JwtKeysInner {
                kid,
                encoding_key,
                decoding_key,
                jwk,
            }),
        })
    }

    // ── Signing ──────────────────────────────────────────────────────────────

    /// Sign the given [`Claims`], returning a compact JWT string.
    pub fn sign(&self, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.inner.kid.clone());
        encode(&header, claims, &self.inner.encoding_key)
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /// Verify a compact JWT string, returning the decoded [`Claims`].
    ///
    /// `audiences` – the list of accepted `aud` values. Pass an empty slice to
    /// skip audience validation (not recommended for production).
    pub fn verify(
        &self,
        token: &str,
        audiences: &[&str],
    ) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        if audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(audiences);
        }
        decode::<Claims>(token, &self.inner.decoding_key, &validation)
    }

    // ── JWKS ─────────────────────────────────────────────────────────────────

    /// Return the public key as a [`JwkSet`] for the JWKS endpoint.
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.inner.jwk.clone()],
        }
    }

    /// The key ID (`kid`) embedded in every issued token.
    pub fn kid(&self) -> &str {
        &self.inner.kid
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keys() -> JwtKeys {
        JwtKeys::generate().expect("key generation must succeed")
    }

    #[test]
    fn round_trip() {
        let keys = make_keys();
        let claims = Claims::new(
            "test-issuer",
            "user-uuid-1234",
            "alice@example.com",
            vec!["my-app".to_string()],
            3600,
        );

        let token = keys.sign(&claims).expect("sign must succeed");
        let data = keys
            .verify(&token, &["my-app"])
            .expect("verify must succeed");

        assert_eq!(data.claims.sub, "user-uuid-1234");
        assert_eq!(data.claims.email, "alice@example.com");
    }

    #[test]
    fn jwks_contains_kid() {
        let keys = make_keys();
        let jwks = keys.jwks();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, keys.kid());
        assert!(!jwks.keys[0].n.is_empty());
        assert!(!jwks.keys[0].e.is_empty());
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let keys = make_keys();
        let claims = Claims::new(
            "iss",
            "sub",
            "x@x.com",
            vec!["correct-aud".to_string()],
            3600,
        );
        let token = keys.sign(&claims).unwrap();
        assert!(keys.verify(&token, &["wrong-aud"]).is_err());
    }
}
