use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::models::User;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum JwtError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Token expired")]
    Expired,
    #[error("Invalid token")]
    Invalid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub name: Option<String>,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub auth_time: u64,
    pub nonce: Option<String>,
    pub scope: String,
}

impl Claims {
    pub fn new(user: &User, client_id: &str, ttl_seconds: u64, nonce: Option<String>, scope: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            sub: user.id.to_string(),
            email: user.email.clone(),
            name: user.display_name.clone(),
            iss: "rust-sso".to_string(),
            aud: client_id.to_string(),
            iat: now,
            exp: now + ttl_seconds,
            auth_time: now,
            nonce,
            scope: scope.to_string(),
        }
    }
}

#[allow(dead_code)]
pub fn generate_rsa_keypair() -> Result<(String, String), JwtError> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| JwtError::Jwt(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidRsaKey(e.to_string())
        )))?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| JwtError::Jwt(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidRsaKey(e.to_string())
        )))?
        .to_string();
    let public_pem = public_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| JwtError::Jwt(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidRsaKey(e.to_string())
        )))?;

    Ok((private_pem, public_pem))
}

pub fn encode_token(claims: &Claims, private_key_pem: &str, kid: &str) -> Result<String, JwtError> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
    Ok(encode(&header, claims, &key)?)
}

pub fn decode_token(token: &str, public_key_pem: &str) -> Result<Claims, JwtError> {
    let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

pub fn decode_token_unverified(token: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let key = DecodingKey::from_secret(&[]);
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

#[allow(dead_code)]
pub fn generate_token() -> String {
    uuid::Uuid::new_v4().to_string().replace("-", "")
}

#[allow(dead_code)]
pub fn hash_token(token: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[allow(dead_code)]
pub mod password {
    use argon2::{
        password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
        Argon2,
    };
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum PasswordError {
        #[error("Hashing failed")]
        Hashing,
        #[error("Verification failed")]
        Verification,
    }

    pub fn hash_password(password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| PasswordError::Hashing)?
            .to_string())
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash = PasswordHash::new(hash).map_err(|_| PasswordError::Verification)?;
        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }
}