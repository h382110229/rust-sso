use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod middleware;
mod models;
mod routes;
mod services;
mod utils;

use routes::{auth, health, oidc};
use services::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<Config>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "rust_sso=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();
    let config = Config::from_env();
    tracing::info!("Starting SSO server on {}", config.server_addr);

    let pool = PgPoolOptions::new()
        .max_connections(100)
        .min_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("./migrations").run(&pool).await.expect("Failed to run migrations");
    tracing::info!("Database connected and migrations applied");

    let state = AppState { db: pool, config: Arc::new(config) };

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let public_routes = Router::new()
        .route("/health", get(health::health_check))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh_token))
        .route("/auth/verify", get(auth::verify_token))
        .route("/auth/password-reset/request", post(auth::request_password_reset))
        .route("/auth/password-reset/confirm", post(auth::confirm_password_reset))
        .merge(oidc::routes());

    let protected_routes = Router::new()
        .route("/oauth/userinfo", get(oidc::userinfo))
        .route("/api/me", get(routes::users::me))
        .layer(from_fn_with_state(state.clone(), middleware::auth::auth_middleware));

    let app = public_routes
        .merge(protected_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    tracing::info!("SSO server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}