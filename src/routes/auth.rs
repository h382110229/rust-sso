use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::models::User;
use crate::AppState;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            created_at: user.created_at.to_rfc3339(),
        }
    }
}

pub async fn register(State(state): State<AppState>, Json(req): Json<RegisterRequest>) -> Response {
    if let Err(errors) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "validation_error", "details": errors.to_string() })),
        )
            .into_response();
    }

    let existing = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, display_name, avatar_url, is_active, is_email_verified, created_at, updated_at, last_login_at FROM users WHERE email = $1"
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await;

    if let Ok(Some(_)) = existing {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "email_already_exists" })),
        )
            .into_response();
    }

    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "password_hashing_failed", "details": e.to_string() })),
            )
        })
        .unwrap()
        .to_string();

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id, email, password_hash, display_name, avatar_url, is_active, is_email_verified, created_at, updated_at, last_login_at",
    )
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&req.display_name)
    .fetch_one(&state.db)
    .await;

    match user {
        Ok(user) => {
            let _ = create_default_oauth_client(&state.db, user.id).await;
            let response = AuthResponse {
                user: user.into(),
                access_token: String::new(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_in: 3600,
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed_to_create_user" })),
            )
                .into_response()
        }
    }
}

pub async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    if let Err(errors) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "validation_error", "details": errors.to_string() })),
        )
            .into_response();
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, display_name, avatar_url, is_active, is_email_verified, created_at, updated_at, last_login_at FROM users WHERE email = $1 AND is_active = true"
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        _ => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "invalid_credentials" }))).into_response(),
    };

    let password_hash = user.password_hash.as_deref().unwrap_or("");
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "invalid_password_hash" }))).into_response(),
    };

    let argon2 = Argon2::default();
    if argon2.verify_password(req.password.as_bytes(), &parsed_hash).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "invalid_credentials" }))).into_response();
    }

    let _ = sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await;

    let response = AuthResponse {
        user: user.into(),
        access_token: "temp_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn create_default_oauth_client(db: &sqlx::PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    let client_id = format!("user-{}", user_id);
    let client_secret = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, scopes, is_public) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (client_id) DO NOTHING",
    )
    .bind(&client_id)
    .bind(&client_secret)
    .bind("Default Client")
    .bind(vec!["http://localhost/callback"])
    .bind(vec!["openid", "profile", "email"])
    .bind(true)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn refresh_token() -> Response {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

pub async fn verify_token() -> Response {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

pub async fn request_password_reset() -> Response {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

pub async fn confirm_password_reset() -> Response {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}