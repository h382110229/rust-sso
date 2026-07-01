#![allow(dead_code, unused)]
//! Email verification code flow.
//!
//! # Overview
//! 1. **Generate** a 6-digit numeric code and store it in the `email_codes`
//!    SQLite table with a 5-minute TTL.
//! 2. **Send** the code to the user's email address via SMTP (using `lettre`).
//! 3. **Verify** the code: look it up, check it hasn't expired, mark it used.
//!
//! # Configuration
//! The following environment variables / config keys are consumed:
//!
//! | Config key              | Env var (`APP__*`)         | Example                     |
//! |-------------------------|----------------------------|-----------------------------|
//! | `email.smtp_host`       | `APP__EMAIL__SMTP_HOST`    | `smtp.gmail.com`            |
//! | `email.smtp_port`       | `APP__EMAIL__SMTP_PORT`    | `587`                       |
//! | `email.smtp_user`       | `APP__EMAIL__SMTP_USER`    | `noreply@example.com`       |
//! | `email.smtp_password`   | `APP__EMAIL__SMTP_PASSWORD`| `super-secret`              |
//! | `email.from_address`    | `APP__EMAIL__FROM_ADDRESS` | `"My App <noreply@example.com>"` |
//!
//! # Database schema
//! The `email_codes` table must exist (add to a migration):
//! ```sql
//! CREATE TABLE IF NOT EXISTS email_codes (
//!     id         INTEGER PRIMARY KEY AUTOINCREMENT,
//!     email      TEXT    NOT NULL,
//!     code       TEXT    NOT NULL,
//!     purpose    TEXT    NOT NULL DEFAULT 'verify',
//!     used       INTEGER NOT NULL DEFAULT 0,
//!     created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
//!     expires_at INTEGER NOT NULL
//! );
//! CREATE INDEX IF NOT EXISTS idx_email_codes_email ON email_codes(email);
//! ```

use std::time::Duration;

use anyhow::Context;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tracing::{debug, info};

// ──────────────────────────────────────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────────────────────────────────────

/// SMTP/email configuration (mirrors the `[email]` section of `config.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (commonly 587 for STARTTLS, 465 for TLS).
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// SMTP login username.
    pub smtp_user: String,
    /// SMTP login password.
    pub smtp_password: String,
    /// The `From:` address, e.g. `"My App <noreply@example.com>"`.
    pub from_address: String,
}

fn default_smtp_port() -> u16 {
    587
}

// ──────────────────────────────────────────────────────────────────────────────
// Code purpose enum
// ──────────────────────────────────────────────────────────────────────────────

/// What the verification code is being used for (stored in the DB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodePurpose {
    /// First-time email address verification after registration.
    Verify,
    /// Password-reset flow.
    PasswordReset,
    /// Two-factor / step-up authentication.
    TwoFactor,
}

impl CodePurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::PasswordReset => "password_reset",
            Self::TwoFactor => "two_factor",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Code TTL
// ──────────────────────────────────────────────────────────────────────────────

/// How long a generated code remains valid.
const CODE_TTL_SECS: i64 = 5 * 60; // 5 minutes

// ──────────────────────────────────────────────────────────────────────────────
// EmailService
// ──────────────────────────────────────────────────────────────────────────────

/// Drives the email verification code flow.
///
/// Cheaply cloneable – all state is behind an [`std::sync::Arc`] internally.
#[derive(Clone)]
pub struct EmailService {
    db: SqlitePool,
    config: EmailConfig,
    /// App name shown in the subject / body.
    app_name: String,
}

impl EmailService {
    /// Construct a new [`EmailService`].
    ///
    /// * `db`       – SQLite pool (must have the `email_codes` table).
    /// * `config`   – SMTP configuration.
    /// * `app_name` – shown in email subjects, e.g. `"My SSO App"`.
    pub fn new(db: SqlitePool, config: EmailConfig, app_name: impl Into<String>) -> Self {
        Self {
            db,
            config,
            app_name: app_name.into(),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Generate a 6-digit verification code, store it, and send it by email.
    ///
    /// Any previously unused codes for the same `(email, purpose)` pair are
    /// invalidated before inserting the new one, so only one code is valid at
    /// a time per user/purpose.
    ///
    /// Returns the generated code (useful for tests / audit logging).
    pub async fn send_code(
        &self,
        email: &str,
        purpose: CodePurpose,
    ) -> anyhow::Result<String> {
        let code = generate_code();
        debug!(email, purpose = purpose.as_str(), code, "Generated email code");

        // Invalidate previous codes for this email + purpose.
        self.expire_old_codes(email, purpose).await?;

        // Persist the new code.
        self.store_code(email, &code, purpose).await?;

        // Send the email.
        self.deliver_email(email, &code, purpose)
            .await
            .context("Failed to deliver verification email")?;

        info!(email, purpose = purpose.as_str(), "Verification code sent");
        Ok(code)
    }

    /// Verify a submitted code.
    ///
    /// Returns `true` if the code is correct, unexpired, and unused.
    /// On success the code is immediately marked as used.
    ///
    /// Returns `false` (rather than an error) for wrong / expired codes so
    /// callers can return a uniform "invalid code" response without leaking
    /// information about why it failed.
    pub async fn verify_code(
        &self,
        email: &str,
        code: &str,
        purpose: CodePurpose,
    ) -> anyhow::Result<bool> {
        let purpose_str = purpose.as_str();

        let row = sqlx::query!(
            r#"
            SELECT id
            FROM email_codes
            WHERE email      = ?
              AND code       = ?
              AND purpose    = ?
              AND used       = 0
              AND expires_at > strftime('%s', 'now')
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            email,
            code,
            purpose_str,
        )
        .fetch_optional(&self.db)
        .await
        .context("DB error while verifying email code")?;

        let Some(rec) = row else {
            debug!(email, purpose = purpose_str, "Code not found or expired");
            return Ok(false);
        };

        // Mark as used.
        sqlx::query!("UPDATE email_codes SET used = 1 WHERE id = ?", rec.id)
            .execute(&self.db)
            .await
            .context("DB error while marking code as used")?;

        info!(email, purpose = purpose_str, "Email code verified successfully");
        Ok(true)
    }

    /// Check whether a code is valid *without* consuming it.
    ///
    /// Useful for multi-step flows where you want to validate before committing
    /// a state change.
    pub async fn peek_code(
        &self,
        email: &str,
        code: &str,
        purpose: CodePurpose,
    ) -> anyhow::Result<bool> {
        let purpose_str = purpose.as_str();

        let exists = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) AS cnt
            FROM email_codes
            WHERE email      = ?
              AND code       = ?
              AND purpose    = ?
              AND used       = 0
              AND expires_at > strftime('%s', 'now')
            "#,
            email,
            code,
            purpose_str,
        )
        .fetch_one(&self.db)
        .await
        .context("DB error while peeking email code")?;

        Ok(exists > 0)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Expire (mark used) all existing valid codes for `(email, purpose)`.
    async fn expire_old_codes(&self, email: &str, purpose: CodePurpose) -> anyhow::Result<()> {
        let purpose_str = purpose.as_str();
        sqlx::query!(
            "UPDATE email_codes SET used = 1 WHERE email = ? AND purpose = ? AND used = 0",
            email,
            purpose_str,
        )
        .execute(&self.db)
        .await
        .context("DB error while expiring old codes")?;
        Ok(())
    }

    /// Insert a new code record into `email_codes`.
    async fn store_code(
        &self,
        email: &str,
        code: &str,
        purpose: CodePurpose,
    ) -> anyhow::Result<()> {
        let purpose_str = purpose.as_str();
        let expires_at = chrono::Utc::now().timestamp() + CODE_TTL_SECS;

        sqlx::query!(
            r#"
            INSERT INTO email_codes (email, code, purpose, expires_at)
            VALUES (?, ?, ?, ?)
            "#,
            email,
            code,
            purpose_str,
            expires_at,
        )
        .execute(&self.db)
        .await
        .context("DB error while storing email code")?;

        Ok(())
    }

    /// Build and send the verification email via SMTP.
    async fn deliver_email(
        &self,
        to_email: &str,
        code: &str,
        purpose: CodePurpose,
    ) -> anyhow::Result<()> {
        let subject = match purpose {
            CodePurpose::Verify => format!("[{}] Your email verification code", self.app_name),
            CodePurpose::PasswordReset => format!("[{}] Your password reset code", self.app_name),
            CodePurpose::TwoFactor => {
                format!("[{}] Your two-factor authentication code", self.app_name)
            }
        };

        let body = build_email_body(&self.app_name, code, purpose);

        let from: Mailbox = self
            .config
            .from_address
            .parse()
            .context("Invalid from_address in config")?;
        let to: Mailbox = to_email.parse().context("Invalid recipient email address")?;

        let message = Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body)
            .context("Failed to build email message")?;

        // Build SMTP transport with STARTTLS.
        let creds = Credentials::new(
            self.config.smtp_user.clone(),
            self.config.smtp_password.clone(),
        );
        let mailer: AsyncSmtpTransport<Tokio1Executor> =
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.smtp_host)
                .context("Failed to create SMTP transport")?
                .credentials(creds)
                .port(self.config.smtp_port)
                .timeout(Some(Duration::from_secs(15)))
                .build();

        mailer
            .send(message)
            .await
            .context("SMTP send failed")?;

        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Generate a cryptographically random 6-digit numeric code (zero-padded).
fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    let n: u32 = rng.gen_range(0..1_000_000);
    format!("{n:06}")
}

/// Build the HTML body for the verification email.
fn build_email_body(app_name: &str, code: &str, purpose: CodePurpose) -> String {
    let action = match purpose {
        CodePurpose::Verify => "verify your email address",
        CodePurpose::PasswordReset => "reset your password",
        CodePurpose::TwoFactor => "complete your sign-in",
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verification Code</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; color: #333;">
  <h2 style="color: #1a1a1a;">{app_name}</h2>
  <p>Use the following 6-digit code to {action}:</p>
  <div style="
    font-size: 36px;
    font-weight: bold;
    letter-spacing: 8px;
    text-align: center;
    padding: 20px;
    background: #f4f4f4;
    border-radius: 8px;
    margin: 24px 0;
    color: #1a1a1a;
  ">
    {code}
  </div>
  <p style="color: #666; font-size: 14px;">
    This code expires in <strong>5 minutes</strong>. If you did not request this,
    please ignore this email.
  </p>
  <hr style="border: none; border-top: 1px solid #eee; margin-top: 32px;">
  <p style="color: #999; font-size: 12px;">
    Sent by {app_name} · Do not reply to this email.
  </p>
</body>
</html>"#,
        app_name = app_name,
        action = action,
        code = code,
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_format() {
        for _ in 0..100 {
            let code = generate_code();
            assert_eq!(code.len(), 6, "code must be exactly 6 characters");
            assert!(code.chars().all(|c| c.is_ascii_digit()), "code must be all digits");
        }
    }

    #[test]
    fn code_purpose_as_str() {
        assert_eq!(CodePurpose::Verify.as_str(), "verify");
        assert_eq!(CodePurpose::PasswordReset.as_str(), "password_reset");
        assert_eq!(CodePurpose::TwoFactor.as_str(), "two_factor");
    }

    #[test]
    fn email_body_contains_code() {
        let body = build_email_body("TestApp", "123456", CodePurpose::Verify);
        assert!(body.contains("123456"));
        assert!(body.contains("TestApp"));
        assert!(body.contains("5 minutes"));
    }
}
