use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Represents a registered user stored in the `users` table.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    /// UUID primary key (stored as TEXT in SQLite).
    pub id: String,
    /// Unique email address used for authentication.
    pub email: String,
    /// bcrypt-hashed password; never exposed in API responses.
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// Whether the user has confirmed their email address.
    pub email_verified: bool,
    /// Timestamp when the record was first created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when the record was last modified.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new `User` value with a freshly-generated UUID.
    ///
    /// Does **not** insert into the database – use [`crate::db::users::create_user`] for that.
    pub fn new(email: impl Into<String>, password_hash: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            email: email.into(),
            password_hash: password_hash.into(),
            email_verified: false,
            created_at: now,
            updated_at: now,
        }
    }
}

// ── Request / response DTOs ───────────────────────────────────────────────────

/// Public-facing representation of a user (no password hash).
#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserProfile {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            email_verified: u.email_verified,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}
