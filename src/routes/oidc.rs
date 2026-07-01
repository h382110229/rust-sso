use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};

use crate::{
    middleware::auth::AuthUser,
    models::*,
    services::{self, oidc},
    utils::jwt,
    AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/authorize", get(authorize_get).post(authorize_post))
        .route("/oauth/token", post(token))
        .route("/oauth/userinfo", get(userinfo))
        .route("/oauth/revoke", post(revoke))
}

#[derive(Debug, Serialize)]
pub struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    revocation_endpoint: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    claims_supported: Vec<String>,
}

pub async fn discovery(State(state): State<AppState>) -> Response {
    let config = &state.config;
    let base_url = format!("{}://{}", config.scheme, config.domain);

    let doc = DiscoveryDocument {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", base_url),
        token_endpoint: format!("{}/oauth/token", base_url),
        userinfo_endpoint: format!("{}/oauth/userinfo", base_url),
        jwks_uri: format!("{}/.well-known/jwks.json", base_url),
        revocation_endpoint: format!("{}/oauth/revoke", base_url),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        scopes_supported: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
        token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string(), "none".to_string()],
        grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        claims_supported: vec!["sub".to_string(), "email".to_string(), "name".to_string(), "iss".to_string(), "aud".to_string(), "exp".to_string(), "iat".to_string()],
    };

    (StatusCode::OK, axum::Json(doc)).into_response()
}

#[derive(Debug, Serialize)]
pub struct JwksResponse { keys: Vec<JwkKey> }

#[derive(Debug, Serialize)]
pub struct JwkKey {
    kty: String, kid: String, alg: String, n: String, e: String,
    #[serde(rename = "use")] pub key_use: String,
}

pub async fn jwks(State(state): State<AppState>) -> Response {
    let keys = sqlx::query_as::<_, SigningKey>(
        "SELECT id, kid, algorithm, public_key_pem, private_key_pem, is_active, created_at, rotated_at FROM signing_keys WHERE is_active = true",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let jwks: Vec<JwkKey> = keys.into_iter().filter_map(|key| {
        let (n, e) = parse_rsa_public_key(&key.public_key_pem)?;
        Some(JwkKey { kty: "RSA".to_string(), kid: key.kid, alg: "RS256".to_string(), n, e, key_use: "sig".to_string() })
    }).collect();

    (StatusCode::OK, axum::Json(JwksResponse { keys: jwks })).into_response()
}

fn parse_rsa_public_key(pem: &str) -> Option<(String, String)> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;
    let key = RsaPublicKey::from_public_key_pem(pem).ok()?;
    Some((URL_SAFE_NO_PAD.encode(&key.n().to_bytes_be()), URL_SAFE_NO_PAD.encode(&key.e().to_bytes_be())))
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    #[allow(dead_code)]
    code_challenge: Option<String>,
    #[allow(dead_code)]
    code_challenge_method: Option<String>,
}

pub async fn authorize_get(State(state): State<AppState>, Query(params): Query<AuthorizeParams>) -> Response {
    let client = match validate_client(&state.db, &params.client_id, &params.redirect_uri).await {
        Ok(c) => c,
        Err(e) => return error_response(&e, &params.redirect_uri, params.state.as_deref()),
    };

    if params.response_type != "code" {
        return error_response("unsupported_response_type", &params.redirect_uri, params.state.as_deref());
    }

    render_login_page(&client.client_name, &params).into_response()
}

pub async fn authorize_post(State(state): State<AppState>, Query(params): Query<AuthorizeParams>) -> Response {
    authorize_get(State(state), Query(params)).await
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    #[allow(dead_code)]
    client_secret: Option<String>,
    refresh_token: Option<String>,
    code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    id_token: String,
    scope: String,
}

pub async fn token(State(state): State<AppState>, axum::Json(req): axum::Json<TokenRequest>) -> Response {
    match req.grant_type.as_str() {
        "authorization_code" => handle_auth_code(state, req).await,
        "refresh_token" => handle_refresh(state, req).await,
        _ => (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error":"unsupported_grant_type"}))).into_response(),
    }
}

async fn handle_auth_code(state: AppState, req: TokenRequest) -> Response {
    let code = req.code.as_deref().unwrap_or("");
    let redirect_uri = req.redirect_uri.as_deref().unwrap_or("");
    let client_id = req.client_id.as_deref().unwrap_or("");

    let client = match validate_client(&state.db, client_id, redirect_uri).await {
        Ok(c) => c,
        Err(e) => return token_error_response(&e),
    };

    let auth_code = match oidc::validate_authorization_code(&state.db, code, client.id, redirect_uri, req.code_verifier.as_deref()).await {
        Ok(ac) => ac,
        Err(e) => return token_error_response(&e),
    };

    let user = match services::user::get_user_by_id(&state.db, auth_code.user_id).await {
        Ok(u) => u,
        Err(e) => return token_error_response(&e),
    };

    let signing_key = match oidc::get_active_signing_key(&state.db).await {
        Ok(k) => k,
        Err(e) => return token_error_response(&e),
    };

    let claims = jwt::Claims::new(&user, client_id, 3600, None, &auth_code.scopes.join(" "));
    let id_claims = jwt::Claims::new(&user, client_id, 3600, None, "openid");

    let access_token = match jwt::encode_token(&claims, &signing_key.private_key_pem, &signing_key.kid) {
        Ok(t) => t,
        Err(e) => return token_error_response(&e.to_string()),
    };

    let id_token = match jwt::encode_token(&id_claims, &signing_key.private_key_pem, &signing_key.kid) {
        Ok(t) => t,
        Err(e) => return token_error_response(&e.to_string()),
    };

    let refresh_token = oidc::create_refresh_token(&state.db, user.id, client.id, &auth_code.scopes, 30 * 24 * 3600).await.ok();

    (StatusCode::OK, axum::Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token,
        id_token,
        scope: auth_code.scopes.join(" "),
    })).into_response()
}

async fn handle_refresh(state: AppState, req: TokenRequest) -> Response {
    let rt = req.refresh_token.as_deref().unwrap_or("");
    let client_id = req.client_id.as_deref().unwrap_or("");

    let client = match validate_client(&state.db, client_id, "").await {
        Ok(c) => c,
        Err(e) => return token_error_response(&e),
    };

    let (user, scopes) = match oidc::validate_refresh_token(&state.db, rt, client.id).await {
        Ok(r) => r,
        Err(e) => return token_error_response(&e),
    };

    let signing_key = match oidc::get_active_signing_key(&state.db).await {
        Ok(k) => k,
        Err(e) => return token_error_response(&e),
    };

    let claims = jwt::Claims::new(&user, client_id, 3600, None, &scopes.join(" "));
    let access_token = match jwt::encode_token(&claims, &signing_key.private_key_pem, &signing_key.kid) {
        Ok(t) => t,
        Err(e) => return token_error_response(&e.to_string()),
    };

    (StatusCode::OK, axum::Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: None,
        id_token: String::new(),
        scope: scopes.join(" "),
    })).into_response()
}

#[derive(Debug, Serialize)]
pub struct UserinfoResponse { sub: String, email: String, name: Option<String>, email_verified: bool }

pub async fn userinfo(State(state): State<AppState>, auth_user: AuthUser) -> Response {
    let user = match services::user::get_user_by_id(&state.db, auth_user.user_id).await {
        Ok(u) => u,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    (StatusCode::OK, axum::Json(UserinfoResponse {
        sub: user.id.to_string(),
        email: user.email,
        name: user.display_name,
        email_verified: user.is_email_verified,
    })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    token: String,
    #[allow(dead_code)]
    client_id: Option<String>,
    #[allow(dead_code)]
    client_secret: Option<String>,
}

pub async fn revoke(State(state): State<AppState>, axum::Json(req): axum::Json<RevokeRequest>) -> Response {
    let _ = oidc::revoke_refresh_token(&state.db, &req.token).await;
    StatusCode::OK.into_response()
}

async fn validate_client(db: &sqlx::PgPool, client_id: &str, redirect_uri: &str) -> Result<OAuthClient, String> {
    let client = sqlx::query_as::<_, OAuthClient>(
        "SELECT id, client_id, client_secret_hash, client_name, redirect_uris, grant_types, response_types, scopes, is_public, token_endpoint_auth_method, created_at, updated_at FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?
    .ok_or_else(|| "invalid_client".to_string())?;

    if !client.redirect_uris.is_empty() && !client.redirect_uris.contains(&redirect_uri.to_string()) {
        return Err("invalid_redirect_uri".to_string());
    }

    Ok(client)
}

fn error_response(error: &str, redirect_uri: &str, state: Option<&str>) -> Response {
    let mut url = format!("{}?error={}", redirect_uri, error);
    if let Some(s) = state {
        url.push_str(&format!("&state={}", s));
    }
    Redirect::to(&url).into_response()
}

fn token_error_response(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({ "error": error }))).into_response()
}

fn render_login_page(client_name: &str, params: &AuthorizeParams) -> Html<String> {
    let action = format!(
        "/oauth/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}&nonce={}",
        urlencoding::encode(&params.client_id),
        urlencoding::encode(&params.redirect_uri),
        urlencoding::encode(&params.response_type),
        urlencoding::encode(params.scope.as_deref().unwrap_or("openid")),
        urlencoding::encode(params.state.as_deref().unwrap_or("")),
        urlencoding::encode(params.nonce.as_deref().unwrap_or("")),
    );

    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - {}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .login-card {{ background: white; padding: 2.5rem; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 420px; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; color: #1a1a2e; }}
        .subtitle {{ color: #666; margin-bottom: 2rem; font-size: 0.9rem; }}
        .form-group {{ margin-bottom: 1.25rem; }}
        label {{ display: block; margin-bottom: 0.5rem; font-weight: 500; color: #333; font-size: 0.875rem; }}
        input[type="email"], input[type="password"] {{ width: 100%; padding: 0.875rem; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1rem; transition: border-color 0.2s; }}
        input:focus {{ outline: none; border-color: #667eea; }}
        button {{ width: 100%; padding: 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: transform 0.1s; }}
        button:hover {{ transform: translateY(-1px); }}
        button:active {{ transform: translateY(0); }}
        .footer {{ text-align: center; margin-top: 1.5rem; color: #999; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <div class="login-card">
        <h1>Welcome to {}</h1>
        <p class="subtitle">Sign in with your account to continue</p>
        <form method="POST" action="{}">
            <div class="form-group">
                <label for="email">Email address</label>
                <input type="email" id="email" name="email" placeholder="Enter your email" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit">Sign in</button>
        </form>
        <div class="footer">
            <p>Powered by Rust SSO</p>
        </div>
    </div>
</body>
</html>"#,
        client_name, client_name, action
    ))
}