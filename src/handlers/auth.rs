use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use bcrypt::{hash, verify};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    auth::jwt::Claims,
    db::{sessions, users},
    error::{AppError, Result},
    models::{session::Session, user::User},
};

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// The opaque refresh token returned at login.
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `POST /api/v1/auth/register`
///
/// Create a new user account. Returns a token pair on success.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>)> {
    // Basic validation
    if req.email.is_empty() || !req.email.contains('@') {
        return Err(AppError::Validation("Invalid email address".into()));
    }
    if req.password.len() < 8 {
        return Err(AppError::Validation(
            "Password must be at least 8 characters".into(),
        ));
    }

    // Hash password
    let bcrypt_cost = state.config.bcrypt.cost.clamp(4, 31);
    let password_hash = hash(&req.password, bcrypt_cost)?;

    // Create and persist user
    let user = User::new(&req.email, password_hash);
    users::create_user(&state.db, &user).await?;

    // Issue token pair
    let response = issue_token_pair(&state, &user).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// `POST /api/v1/auth/login`
///
/// Authenticate with email + password. Returns a token pair on success.
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>> {
    // Fetch user (map NotFound → InvalidCredentials to avoid enumeration)
    let user = users::get_user_by_email(&state.db, &req.email)
        .await
        .map_err(|_| AppError::InvalidCredentials)?;

    // Verify password
    let valid = verify(&req.password, &user.password_hash)?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    let response = issue_token_pair(&state, &user).await?;
    Ok(Json(response))
}

/// `POST /api/v1/auth/refresh`
///
/// Exchange a valid refresh token for a new token pair (token rotation).
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Hash the incoming token to look it up
    let mut h = DefaultHasher::new();
    req.refresh_token.hash(&mut h);
    let hashed = format!("{:016x}", h.finish());

    let session = sessions::get_session_by_token(&state.db, &hashed).await?;

    if !session.is_valid() {
        return Err(AppError::TokenExpired);
    }

    // Invalidate old session (rotation)
    sessions::delete_session(&state.db, &session.id).await?;

    // Fetch the user
    let user = users::get_user_by_id(&state.db, &session.user_id).await?;

    let response = issue_token_pair(&state, &user).await?;
    Ok(Json(response))
}

/// `POST /api/v1/auth/logout`
///
/// Invalidate the current refresh token session.
pub async fn logout(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<StatusCode> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    req.refresh_token.hash(&mut h);
    let hashed = format!("{:016x}", h.finish());

    // Best-effort delete; ignore not-found errors
    let _ = sessions::delete_session_by_token(&state.db, &hashed).await;

    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Create a refresh-token session and sign an access JWT, returning the pair.
async fn issue_token_pair(state: &AppState, user: &User) -> Result<AuthResponse> {
    let expiry_secs = state.config.jwt.access_token_expiry_secs;
    let refresh_expiry_secs = state.config.jwt.refresh_token_expiry_secs;

    // Sign an RS256 access JWT
    let access_token = state.jwt_keys.sign(&Claims::new(
        &state.config.jwt.issuer,
        &user.id,
        &user.email,
        vec![state.config.jwt.audience.clone()],
        expiry_secs as i64,
    ))?;

    // Create and persist a refresh-token session
    let expires_at = Utc::now() + chrono::Duration::seconds(refresh_expiry_secs as i64);
    let (session, raw_refresh) = Session::new(&user.id, expires_at);
    sessions::create_session(&state.db, &session).await?;

    Ok(AuthResponse {
        access_token,
        refresh_token: raw_refresh,
        token_type: "Bearer".into(),
        expires_in: expiry_secs,
    })
}
