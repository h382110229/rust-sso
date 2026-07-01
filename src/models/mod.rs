use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[sqlx(rename = "password_hash")]
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_active: bool,
    pub is_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OAuthClient {
    pub id: Uuid,
    pub client_id: String,
    #[sqlx(rename = "client_secret_hash")]
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub client_secret_hash: Option<String>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub is_public: bool,
    pub token_endpoint_auth_method: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub code: String,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub token_hash: String,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SigningKey {
    pub id: Uuid,
    pub kid: String,
    pub algorithm: String,
    pub public_key_pem: String,
    #[sqlx(rename = "private_key_pem")]
    #[serde(skip_serializing)]
    pub private_key_pem: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct PasswordReset {
    pub id: Uuid,
    pub token_hash: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}