use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    auth::jwt::Claims,
    db::users,
    error::{AppError, Result},
    models::user::UserProfile,
};

// ── Middleware extractor key ──────────────────────────────────────────────────

/// Inserted into request extensions by the JWT auth middleware.
/// Handlers that require authentication extract this type.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub claims: Claims,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /api/v1/users/me`
///
/// Return the authenticated user's public profile.
pub async fn get_me(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedUser>,
) -> Result<Json<UserProfile>> {
    let user = users::get_user_by_id(&state.db, &auth.user_id).await?;
    Ok(Json(UserProfile::from(user)))
}

/// `PUT /api/v1/users/me/password`
///
/// Change the authenticated user's password.
/// Invalidates all existing refresh-token sessions after a successful change.
pub async fn change_password(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedUser>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode> {
    if req.new_password.len() < 8 {
        return Err(AppError::Validation(
            "New password must be at least 8 characters".into(),
        ));
    }

    let user = users::get_user_by_id(&state.db, &auth.user_id).await?;

    // Verify current password
    let valid = bcrypt::verify(&req.current_password, &user.password_hash)?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    // Hash and store new password
    let cost = state.config.bcrypt.cost.clamp(4, 31);
    let new_hash = bcrypt::hash(&req.new_password, cost)?;
    users::update_password_hash(&state.db, &auth.user_id, &new_hash).await?;

    // Invalidate all existing sessions (force re-login everywhere)
    crate::db::sessions::delete_all_sessions_for_user(&state.db, &auth.user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}
