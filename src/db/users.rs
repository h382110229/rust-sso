use chrono::Utc;
use sqlx::SqlitePool;

use crate::error::{AppError, Result};
use crate::models::user::User;

// ── CREATE ────────────────────────────────────────────────────────────────────

/// Insert a new user into the database.
///
/// Returns `AppError::Conflict` if the email address already exists.
pub async fn create_user(pool: &SqlitePool, user: &User) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
        user.id,
        user.email,
        user.password_hash,
        user.email_verified,
        user.created_at,
        user.updated_at,
    )
    .execute(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db) if db.is_unique_violation() => {
            AppError::Conflict(format!("Email '{}' is already registered", user.email))
        }
        other => AppError::Database(other),
    })?;

    Ok(())
}

// ── READ ──────────────────────────────────────────────────────────────────────

/// Fetch a user by their UUID primary key.
pub async fn get_user_by_id(pool: &SqlitePool, id: &str) -> Result<User> {
    sqlx::query_as!(
        User,
        r#"
        SELECT id, email, password_hash, email_verified AS "email_verified: bool",
               created_at AS "created_at: chrono::DateTime<chrono::Utc>",
               updated_at AS "updated_at: chrono::DateTime<chrono::Utc>"
        FROM   users
        WHERE  id = ?
        "#,
        id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("User '{}' not found", id)))
}

/// Fetch a user by their email address (case-insensitive).
pub async fn get_user_by_email(pool: &SqlitePool, email: &str) -> Result<User> {
    sqlx::query_as!(
        User,
        r#"
        SELECT id, email, password_hash, email_verified AS "email_verified: bool",
               created_at AS "created_at: chrono::DateTime<chrono::Utc>",
               updated_at AS "updated_at: chrono::DateTime<chrono::Utc>"
        FROM   users
        WHERE  lower(email) = lower(?)
        "#,
        email,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("User with email '{}' not found", email)))
}

// ── UPDATE ────────────────────────────────────────────────────────────────────

/// Update the bcrypt password hash for a user.
pub async fn update_password_hash(
    pool: &SqlitePool,
    user_id: &str,
    new_hash: &str,
) -> Result<()> {
    let updated_at = Utc::now();
    let rows = sqlx::query!(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        new_hash,
        updated_at,
        user_id,
    )
    .execute(pool)
    .await?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("User '{}' not found", user_id)));
    }
    Ok(())
}

/// Mark a user's email address as verified.
pub async fn verify_email(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let updated_at = Utc::now();
    let rows = sqlx::query!(
        "UPDATE users SET email_verified = TRUE, updated_at = ? WHERE id = ?",
        updated_at,
        user_id,
    )
    .execute(pool)
    .await?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("User '{}' not found", user_id)));
    }
    Ok(())
}

// ── DELETE ────────────────────────────────────────────────────────────────────

/// Permanently delete a user and cascade-delete their sessions.
pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let rows = sqlx::query!("DELETE FROM users WHERE id = ?", user_id)
        .execute(pool)
        .await?
        .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("User '{}' not found", user_id)));
    }
    Ok(())
}
