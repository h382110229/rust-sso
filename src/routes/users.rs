use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::middleware::auth::AuthUser;
use crate::AppState;

#[derive(Serialize)]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
}

pub async fn me(State(state): State<AppState>, auth_user: AuthUser) -> Response {
    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT id, email, password_hash, display_name, avatar_url, is_active, is_email_verified, created_at, updated_at, last_login_at FROM users WHERE id = $1"
    )
    .bind(auth_user.user_id)
    .fetch_optional(&state.db)
    .await;

    match user {
        Ok(Some(user)) => (StatusCode::OK, Json(MeResponse {
            id: user.id.to_string(),
            email: user.email,
            display_name: user.display_name,
        })).into_response(),
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "user_not_found" }))).into_response(),
    }
}