//! OIDC HTTP handler wrappers.
//!
//! The heavy OIDC logic lives in [`crate::auth::oidc`].  This module simply
//! re-exports those handlers under the `handlers` namespace so the router can
//! import everything from one place.
//!
//! Mount these in `main.rs` (or a dedicated router builder):
//!
//! ```rust,ignore
//! use crate::handlers::oidc::{discovery, jwks, token, userinfo};
//!
//! let oidc_router = Router::new()
//!     .route("/.well-known/openid-configuration", get(discovery))
//!     .route("/.well-known/jwks.json",            get(jwks))
//!     .route("/oauth/token",                       post(token))
//!     .route("/oauth/userinfo",                    get(userinfo).post(userinfo))
//!     .with_state(state);
//! ```

/// GET `/.well-known/openid-configuration`
///
/// Returns the OIDC Provider Metadata discovery document.
pub use crate::auth::oidc::discovery_handler as discovery;

/// GET `/.well-known/jwks.json`
///
/// Returns the JSON Web Key Set with the server's current RS256 public key.
pub use crate::auth::oidc::jwks_handler as jwks;

/// POST `/oauth/token`
///
/// Issues access tokens via `password`, `refresh_token`, or
/// `authorization_code` grant.
pub use crate::auth::oidc::token_handler as token;

/// GET / POST `/oauth/userinfo`
///
/// Returns OIDC claims for the bearer-token-authenticated user.
pub use crate::auth::oidc::userinfo_handler as userinfo;
