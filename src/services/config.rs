
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub server_addr: String,
    pub domain: String,
    pub scheme: String,
    pub jwt_issuer: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        Self {
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost:5432/rust_sso".to_string()),
            server_addr: env::var("SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            domain: env::var("DOMAIN").unwrap_or_else(|_| "localhost:8080".to_string()),
            scheme: env::var("SCHEME").unwrap_or_else(|_| "http".to_string()),
            jwt_issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "rust-sso".to_string()),
        }
    }
}