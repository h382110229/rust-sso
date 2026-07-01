//! Authentication subsystem.
//!
//! # Modules
//! - [`jwt`]       – RS256 key management, token issuance and verification.
//! - [`oidc`]      – OpenID Connect provider endpoints (discovery, JWKS, token, userinfo).
//! - [`cf_access`] – Cloudflare Access JWT validation against the team's JWKS.
//! - [`email`]     – 6-digit email verification code generation, storage and SMTP delivery.

pub mod cf_access;
pub mod email;
pub mod jwt;
pub mod oidc;
