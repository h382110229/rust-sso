use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

/// Root configuration struct.
///
/// Values are merged in the following priority order (highest wins):
///   1. Environment variables (`APP__` prefix)
///   2. `config.toml` in the working directory
///   3. Hard-coded defaults via `Default` implementations
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub bcrypt: BcryptConfig,
    pub cors: CorsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Bind host, default `0.0.0.0`
    pub host: String,
    /// Bind port, default `8080`
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// SQLite connection URL, e.g. `sqlite://./data/sso.db`
    pub url: String,
    /// Maximum number of pooled connections
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    /// HMAC-SHA256 secret used to sign access tokens
    pub secret: String,
    /// Access token lifetime in seconds (default: 3600)
    pub access_token_expiry_secs: u64,
    /// Refresh token lifetime in seconds (default: 604800 = 7 days)
    pub refresh_token_expiry_secs: u64,
    /// Expected `iss` claim in issued tokens
    pub issuer: String,
    /// Expected `aud` claim in issued tokens
    pub audience: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BcryptConfig {
    /// bcrypt cost factor (4–31). Default is 12.
    pub cost: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    /// List of allowed origins. An empty list means "allow all".
    pub allowed_origins: Vec<String>,
}

impl Config {
    /// Load and merge configuration from all sources.
    pub fn load() -> Result<Self, ConfigError> {
        let cfg = RawConfig::builder()
            // ── Layer 1: built-in defaults ───────────────────────────────
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 8080)?
            .set_default("database.url", "sqlite://./data/sso.db")?
            .set_default("database.max_connections", 5)?
            .set_default("jwt.secret", "change-me-in-production")?
            .set_default("jwt.access_token_expiry_secs", 3600)?
            .set_default("jwt.refresh_token_expiry_secs", 604_800)?
            .set_default("jwt.issuer", "rust-sso")?
            .set_default("jwt.audience", "rust-sso-clients")?
            .set_default("bcrypt.cost", 12)?
            .set_default("cors.allowed_origins", Vec::<String>::new())?
            // ── Layer 2: config.toml (optional) ─────────────────────────
            .add_source(File::with_name("config").required(false))
            // ── Layer 3: environment variables (APP__SECTION__KEY) ───────
            //   Example: APP__SERVER__PORT=9090
            .add_source(
                Environment::with_prefix("APP")
                    .separator("__")
                    .try_parsing(true)
                    .list_separator(","),
            )
            .build()?;

        cfg.try_deserialize()
    }
}
