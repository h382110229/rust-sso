#![allow(dead_code, unused_imports)]
//! OpenID Connect Provider implementation.
//!
//! Exposes four Axum route handlers ready to be mounted on a router:
//!
//! | Handler                  | HTTP Method | Path (example)                           |
//! |--------------------------|-------------|------------------------------------------|
//! | [`discovery_handler`]    | GET         | `/.well-known/openid-configuration`      |
//! | [`jwks_handler`]         | GET         | `/.well-known/jwks.json`                 |
//! | [`token_handler`]        | POST        | `/oauth/token`                           |
//! | [`userinfo_handler`]     | GET/POST    | `/oauth/userinfo`                        |
//!
//! # Wiring example (in `main.rs`)
//! ```rust,ignore
//! use axum::routing::{get, post};
//! use crate::auth::oidc::{discovery_handler, jwks_handler, token_handler, userinfo_handler};
//!
//! let oidc = Router::new()
//!     .route("/.well-known/openid-configuration", get(discovery_handler))
//!     .route("/.well-known/jwks.json", get(jwks_handler))
//!     .route("/oauth/token", post(token_handler))
//!     .route("/oauth/userinfo", get(userinfo_handler).post(userinfo_handler))
//!     .with_state(state);
//! ```

use axum::{
    Json,
    extract::{Form, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{AppState, auth::jwt::Claims, error::AppError};

// ──────────────────────────────────────────────────────────────────────────────
// Discovery document
// ──────────────────────────────────────────────────────────────────────────────

/// OIDC Discovery document returned at `/.well-known/openid-configuration`.
///
/// Follows the [OpenID Connect Discovery 1.0] specification.
///
/// [OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(Debug, Serialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
}

/// GET `/.well-known/openid-configuration`
///
/// Returns the OIDC discovery document built from runtime configuration.
pub async fn discovery_handler(State(state): State<AppState>) -> Json<OidcDiscovery> {
    let base = state.config.jwt.issuer.trim_end_matches('/').to_string();

    let discovery = OidcDiscovery {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/oauth/authorize"),
        token_endpoint: format!("{base}/oauth/token"),
        userinfo_endpoint: format!("{base}/oauth/userinfo"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        response_types_supported: vec!["code", "token", "id_token", "code token", "code id_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        scopes_supported: vec!["openid", "profile", "email"],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        claims_supported: vec!["sub", "iss", "aud", "iat", "exp", "email", "roles"],
        grant_types_supported: vec!["authorization_code", "refresh_token", "password"],
    };

    Json(discovery)
}

// ──────────────────────────────────────────────────────────────────────────────
// JWKS endpoint
// ──────────────────────────────────────────────────────────────────────────────

/// GET `/.well-known/jwks.json`
///
/// Returns the JSON Web Key Set containing the server's current RS256 public key.
/// Relying parties use this to verify tokens signed by this server.
pub async fn jwks_handler(State(state): State<AppState>) -> impl IntoResponse {
    let jwks = state.jwt_keys.jwks();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(jwks),
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// Token endpoint
// ──────────────────────────────────────────────────────────────────────────────

/// Supported grant types.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Resource Owner Password Credentials (RFC 6749 §4.3).
    Password,
    /// Authorization Code (RFC 6749 §4.1).
    AuthorizationCode,
    /// Refresh Token (RFC 6749 §6).
    RefreshToken,
}

/// Request body for `POST /oauth/token`.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    /// For `password` grant.
    pub username: Option<String>,
    /// For `password` grant.
    pub password: Option<String>,
    /// For `authorization_code` grant.
    pub code: Option<String>,
    /// For `authorization_code` grant.
    pub redirect_uri: Option<String>,
    /// For `refresh_token` grant.
    pub refresh_token: Option<String>,
    /// Space-separated requested scopes.
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Successful response for `POST /oauth/token`.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub scope: String,
}

/// POST `/oauth/token`
///
/// Issues access tokens.  Currently handles:
///   - `password` grant (direct credential exchange)
///   - `refresh_token` grant (exchange a refresh token for a new access token)
///
/// The `authorization_code` flow requires a separate `/oauth/authorize` handler
/// (not included here) which generates and stores a short-lived auth code.
pub async fn token_handler(
    State(state): State<AppState>,
    Form(req): Form<TokenRequest>,
) -> Result<Response, AppError> {
    match req.grant_type {
        GrantType::Password => handle_password_grant(state, req).await,
        GrantType::RefreshToken => handle_refresh_grant(state, req).await,
        GrantType::AuthorizationCode => handle_auth_code_grant(state, req).await,
    }
}

/// Resource Owner Password Credentials grant.
async fn handle_password_grant(
    state: AppState,
    req: TokenRequest,
) -> Result<Response, AppError> {
    let username = req
        .username
        .as_deref()
        .ok_or_else(|| AppError::Validation("username is required for password grant".into()))?;
    let password = req
        .password
        .as_deref()
        .ok_or_else(|| AppError::Validation("password is required for password grant".into()))?;

    debug!(username, "Processing password grant");

    // Look up the user in the database.
    let row = sqlx::query!(
        "SELECT id, email, password_hash, roles FROM users WHERE email = ? AND active = 1",
        username
    )
    .fetch_optional(&state.db)
    .await?;

    let user = row.ok_or(AppError::InvalidCredentials)?;

    // Verify the bcrypt hash.
    let hash = user.password_hash.unwrap_or_default();
    let valid = bcrypt::verify(password, &hash).map_err(|e| {
        warn!(error = %e, "bcrypt verification error");
        AppError::InvalidCredentials
    })?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    let ttl = state.config.jwt.access_token_expiry_secs as i64;
    let aud = vec![
        req.client_id
            .unwrap_or_else(|| state.config.jwt.audience.clone()),
    ];

    let claims = Claims::new(
        &state.config.jwt.issuer,
        user.id.unwrap_or_default().to_string(),
        &user.email,
        aud,
        ttl,
    )
    .with_roles(user.roles);

    let access_token = state.jwt_keys.sign(&claims).map_err(AppError::Jwt)?;

    // Issue a refresh token (opaque UUID stored in DB).
    let refresh_token = issue_refresh_token(&state, user.id.unwrap_or_default()).await?;

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt.access_token_expiry_secs,
        refresh_token: Some(refresh_token),
        id_token: None,
        scope: req.scope.unwrap_or_else(|| "openid email profile".into()),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Refresh Token grant.
async fn handle_refresh_grant(
    state: AppState,
    req: TokenRequest,
) -> Result<Response, AppError> {
    let rt = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::Validation("refresh_token is required".into()))?;

    // Look up refresh token in the DB.
    let row = sqlx::query!(
        r#"
        SELECT rt.user_id, u.email, u.roles
        FROM refresh_tokens rt
        JOIN users u ON u.id = rt.user_id
        WHERE rt.token = ?
          AND rt.revoked = 0
          AND rt.expires_at > strftime('%s', 'now')
        "#,
        rt
    )
    .fetch_optional(&state.db)
    .await?;

    let rec = row.ok_or_else(|| AppError::TokenInvalid("unknown or expired refresh token".into()))?;

    // Rotate: revoke old token, issue new one.
    sqlx::query!("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", rt)
        .execute(&state.db)
        .await?;

    let new_rt = issue_refresh_token(&state, rec.user_id).await?;

    let ttl = state.config.jwt.access_token_expiry_secs as i64;
    let aud = vec![state.config.jwt.audience.clone()];
    let claims = Claims::new(
        &state.config.jwt.issuer,
        rec.user_id.to_string(),
        &rec.email,
        aud,
        ttl,
    )
    .with_roles(rec.roles);

    let access_token = state.jwt_keys.sign(&claims).map_err(AppError::Jwt)?;

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: state.config.jwt.access_token_expiry_secs,
            refresh_token: Some(new_rt),
            id_token: None,
            scope: "openid email profile".into(),
        }),
    ).into_response())
}

/// Authorization Code grant (stub – requires `/oauth/authorize` implementation).
async fn handle_auth_code_grant(
    _state: AppState,
    _req: TokenRequest,
) -> Result<Response, AppError> {
    // TODO: look up the auth code in an `auth_codes` table, validate it,
    // exchange for tokens, and delete the code (one-time use).
    Err::<Response, _>(AppError::Validation(
        "authorization_code grant is not yet implemented".into(),
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// Userinfo endpoint
// ──────────────────────────────────────────────────────────────────────────────

/// OIDC UserInfo response body.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    pub roles: Vec<String>,
}

/// GET or POST `/oauth/userinfo`
///
/// Requires a valid Bearer access token in the `Authorization` header.
/// Returns claims about the authenticated user.
pub async fn userinfo_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Extract Bearer token from Authorization header.
    let token = extract_bearer(&headers)?;

    // Verify the token.
    let aud_str = state.config.jwt.audience.clone();
    let token_data = state
        .jwt_keys
        .verify(token, &[aud_str.as_str()])
        .map_err(AppError::Jwt)?;

    let claims = token_data.claims;

    // Optionally enrich from DB for fresh data.
    let row = sqlx::query!(
        "SELECT email, display_name FROM users WHERE id = ?",
        claims.sub
    )
    .fetch_optional(&state.db)
    .await?;

    let (email, name) = row
        .map(|r| (r.email, r.display_name))
        .unwrap_or_else(|| (claims.email.clone(), None));

    let roles: Vec<String> = if claims.roles.is_empty() {
        vec![]
    } else {
        claims.roles.split(',').map(str::trim).map(String::from).collect()
    };

    Ok(Json(UserInfoResponse {
        sub: claims.sub,
        email: email.clone(),
        email_verified: true,
        name,
        preferred_username: Some(email),
        roles,
    }))
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Extract the raw token string from `Authorization: Bearer <token>`.
fn extract_bearer(headers: &HeaderMap) -> Result<&str, AppError> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    auth.strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Authorization header must use Bearer scheme".into()))
}

/// Insert a new opaque refresh token into the `refresh_tokens` table.
///
/// Returns the generated token string.
async fn issue_refresh_token(state: &AppState, user_id: i64) -> Result<String, AppError> {
    let token = uuid::Uuid::new_v4().to_string();
    let expires_in = state.config.jwt.refresh_token_expiry_secs as i64;

    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (token, user_id, expires_at, revoked)
        VALUES (?, ?, strftime('%s', 'now') + ?, 0)
        "#,
        token,
        user_id,
        expires_in
    )
    .execute(&state.db)
    .await?;

    Ok(token)
}
