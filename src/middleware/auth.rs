use axum::{
    async_trait,
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::AppState;

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<AuthUser>().cloned().ok_or(StatusCode::UNAUTHORIZED)
    }
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    use axum::http::header;

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims = crate::utils::jwt::decode_token_unverified(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let signing_key = crate::services::oidc::get_active_signing_key(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _validated = crate::utils::jwt::decode_token(token, &signing_key.public_key_pem)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    request.extensions_mut().insert(AuthUser { user_id });

    Ok(next.run(request).await)
}