use axum::{
    Router,
    http::{HeaderValue, Method},
    response::Json,
};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod error;

/// Shared application state passed to all handlers
#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub config: Arc<config::Config>,
    /// RS256 key pair for JWT issuance and verification.
    pub jwt_keys: auth::jwt::JwtKeys,
    /// Optional Cloudflare Access validator (configured via `APP__CF_ACCESS__TEAM_DOMAIN`).
    pub cf_access: Option<auth::cf_access::CfAccessValidator>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file (ignore error if file is absent)
    if let Err(e) = dotenvy::dotenv() {
        warn!("Could not load .env file: {e}");
    }

    // Initialize structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_sso=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let cfg = config::Config::load().expect("Failed to load configuration");
    let cfg = Arc::new(cfg);

    info!("Configuration loaded: port={}", cfg.server.port);

    // Initialize SQLite connection pool
    let db_url = &cfg.database.url;
    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.database.max_connections)
        .connect(db_url)
        .await
        .unwrap_or_else(|e| panic!("Failed to connect to database '{db_url}': {e}"));

    // Run embedded migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Database migration failed");

    info!("Database migrations applied successfully");

    // Generate RS256 key pair (in-memory; swap for from_pem() to persist across restarts).
    let jwt_keys = auth::jwt::JwtKeys::generate()
        .expect("Failed to generate RS256 key pair");
    info!("RS256 JWT key pair generated (kid={})", jwt_keys.kid());

    // Optionally configure Cloudflare Access validation.
    // Set APP__CF_ACCESS__TEAM_DOMAIN=<team> (or leave unset to disable).
    let cf_access = std::env::var("APP__CF_ACCESS__TEAM_DOMAIN").ok().map(|team| {
        info!(team, "Cloudflare Access validation enabled");
        auth::cf_access::CfAccessValidator::new(team, reqwest::Client::new())
    });

    let state = AppState {
        db: pool,
        config: cfg.clone(),
        jwt_keys,
        cf_access,
    };

    // Build CORS layer
    let cors = build_cors(&cfg);

    // Build router
    let app = Router::new()
        .route("/health", axum::routing::get(health_handler))
        // Auth routes
        .nest("/api/v1/auth", auth_routes())
        // User routes
        .nest("/api/v1/users", user_routes())
        // SSO routes
        .nest("/api/v1/sso", sso_routes())
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let bind_addr = format!("{}:{}", cfg.server.host, cfg.server.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to '{bind_addr}': {e}"));

    info!("Server listening on http://{bind_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Health-check endpoint
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Stub auth router — replace with real handlers in src/handlers/auth.rs
fn auth_routes() -> Router<AppState> {
    use axum::routing::post;
    Router::new()
        .route("/register", post(stub_handler))
        .route("/login", post(stub_handler))
        .route("/logout", post(stub_handler))
        .route("/refresh", post(stub_handler))
}

/// Stub user router — replace with real handlers in src/handlers/user.rs
fn user_routes() -> Router<AppState> {
    use axum::routing::{delete, get, put};
    Router::new()
        .route("/me", get(stub_handler))
        .route("/me", put(stub_handler))
        .route("/me", delete(stub_handler))
}

/// Stub SSO router — replace with real handlers in src/handlers/sso.rs
fn sso_routes() -> Router<AppState> {
    use axum::routing::{get, post};
    Router::new()
        // OAuth2 / OIDC authorize & callback
        .route("/authorize", get(stub_handler))
        .route("/callback", get(stub_handler))
        // Token introspection
        .route("/introspect", post(stub_handler))
        // Client management
        .route("/clients", get(stub_handler))
        .route("/clients", post(stub_handler))
}

/// Temporary placeholder handler for routes not yet implemented
async fn stub_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "not implemented" }))
}

/// Build the CORS layer from configuration
fn build_cors(cfg: &config::Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = cfg
        .cors
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    let mut cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any);

    if origins.is_empty() {
        cors = cors.allow_origin(Any);
    } else {
        cors = cors.allow_origin(origins);
    }

    cors
}

/// Listen for SIGINT / SIGTERM and trigger graceful shutdown
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, stopping server");
}
