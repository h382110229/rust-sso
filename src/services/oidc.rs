use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::*;

pub async fn validate_authorization_code(
    db: &PgPool,
    code: &str,
    client_id: Uuid,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> Result<AuthorizationCode, String> {
    let auth_code = sqlx::query_as::<_, AuthorizationCode>(
        "SELECT id, code, user_id, client_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, used_at, created_at FROM authorization_codes WHERE code = $1 AND client_id = $2"
    )
    .bind(code)
    .bind(client_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?
    .ok_or_else(|| "invalid_grant".to_string())?;

    if auth_code.redirect_uri != redirect_uri {
        return Err("invalid_grant".to_string());
    }

    if auth_code.used_at.is_some() {
        return Err("code_already_used".to_string());
    }

    if auth_code.expires_at < Utc::now() {
        return Err("code_expired".to_string());
    }

    // Verify PKCE if challenge was provided
    if let Some(challenge) = &auth_code.code_challenge {
        let verifier = code_verifier.ok_or_else(|| "code_verifier_required".to_string())?;

        let computed_challenge = match auth_code.code_challenge_method.as_deref() {
            Some("S256") => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(&hasher.finalize())
            }
            _ => verifier.to_string(),
        };

        if computed_challenge != *challenge {
            return Err("invalid_code_verifier".to_string());
        }
    }

    // Mark code as used
    let _ = sqlx::query("UPDATE authorization_codes SET used_at = NOW() WHERE id = $1")
        .bind(auth_code.id)
        .execute(db)
        .await;

    Ok(auth_code)
}

#[allow(dead_code)]
pub async fn create_authorization_code(
    db: &PgPool,
    user_id: Uuid,
    client_id: Uuid,
    redirect_uri: &str,
    scopes: &[String],
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> Result<String, String> {
    let code = generate_random_token();
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO authorization_codes (code, user_id, client_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(&code)
    .bind(user_id)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(scopes)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    Ok(code)
}

pub async fn create_refresh_token(
    db: &PgPool,
    user_id: Uuid,
    client_id: Uuid,
    scopes: &[String],
    ttl_seconds: i64,
) -> Result<String, String> {
    let token = generate_random_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::seconds(ttl_seconds);

    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, user_id, client_id, scopes, expires_at) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(client_id)
    .bind(scopes)
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    Ok(token)
}

pub async fn validate_refresh_token(
    db: &PgPool,
    token: &str,
    client_id: Uuid,
) -> Result<(crate::models::User, Vec<String>), String> {
    let token_hash = hash_token(token);

    let rt = sqlx::query_as::<_, RefreshToken>(
        "SELECT id, token_hash, user_id, client_id, scopes, expires_at, revoked_at, created_at FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2"
    )
    .bind(&token_hash)
    .bind(client_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?
    .ok_or_else(|| "invalid_grant".to_string())?;

    if rt.expires_at < Utc::now() {
        return Err("token_expired".to_string());
    }

    if rt.revoked_at.is_some() {
        return Err("token_revoked".to_string());
    }

    let user = crate::services::user::get_user_by_id(db, rt.user_id).await?;

    Ok((user, rt.scopes))
}

pub async fn revoke_refresh_token(db: &PgPool, token: &str) -> Result<(), String> {
    let token_hash = hash_token(token);

    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    Ok(())
}

pub async fn get_active_signing_key(db: &PgPool) -> Result<SigningKey, String> {
    sqlx::query_as::<_, SigningKey>(
        "SELECT id, kid, algorithm, public_key_pem, private_key_pem, is_active, created_at, rotated_at FROM signing_keys WHERE is_active = true ORDER BY created_at DESC LIMIT 1"
    )
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?
    .ok_or_else(|| "no_active_signing_key".to_string())
}

fn generate_random_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}