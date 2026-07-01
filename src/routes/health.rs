use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    database: &'static str,
}

pub async fn health_check(State(state): State<AppState>) -> Response {
    let db_status = sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map(|_| "connected")
        .unwrap_or("disconnected");

    let health = HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        database: db_status,
    };

    (StatusCode::OK, Json(health)).into_response()
}