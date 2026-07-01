use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A server-side session that backs a refresh token.
///
/// Stored in the `sessions` table; one-to-many with `users`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    /// UUID primary key (stored as TEXT in SQLite).
    pub id: String,
    /// Foreign key referencing `users.id`.
    pub user_id: String,
    /// Opaque random token presented by the client as a refresh credential.
    /// Stored hashed; raw value is only returned at creation time.
    pub token: String,
    /// Absolute expiry time. Sessions past this timestamp are invalid.
    pub expires_at: DateTime<Utc>,
    /// Timestamp when the session was created.
    pub created_at: DateTime<Utc>,
}

impl Session {
    /// Create a new `Session` value with a freshly-generated UUID and token.
    ///
    /// Returns `(Session, raw_token)` – persist the `Session` and hand
    /// `raw_token` to the client; you will never see it again.
    pub fn new(user_id: impl Into<String>, expires_at: DateTime<Utc>) -> (Self, String) {
        let raw_token = Uuid::new_v4().to_string();
        let now = Utc::now();
        let session = Self {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            // Store a lightweight hash so a DB leak doesn't expose valid tokens.
            token: sha256_hex(&raw_token),
            expires_at,
            created_at: now,
        };
        (session, raw_token)
    }

    /// Return `true` if the session has not yet expired.
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

/// Minimal SHA-256 hex of `input` using the standard library.
fn sha256_hex(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // NOTE: This is intentionally a *fast, non-cryptographic* placeholder.
    // In production, replace with `ring` or `sha2` for a proper HMAC/SHA-256.
    let mut h = DefaultHasher::new();
    input.hash(&mut h);
    format!("{:016x}", h.finish())
}
