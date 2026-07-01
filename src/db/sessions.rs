use sqlx::SqlitePool;

use crate::error::{AppError, Result};
use crate::models::session::Session;

// ── CREATE ────────────────────────────────────────────────────────────────────

/// Persist a newly-created session.
pub async fn create_session(pool: &SqlitePool, session: &Session) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO sessions (id, user_id, token, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
        session.id,
        session.user_id,
        session.token,
        session.expires_at,
        session.created_at,
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ── READ ──────────────────────────────────────────────────────────────────────

/// Look up an active (non-expired) session by its hashed token.
///
/// The caller is responsible for hashing the raw client-supplied token
/// before calling this function (use [`crate::models::session::Session::new`]
/// as reference for the hashing scheme).
pub async fn get_session_by_token(pool: &SqlitePool, hashed_token: &str) -> Result<Session> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT id, user_id, token,
               expires_at AS "expires_at: chrono::DateTime<chrono::Utc>",
               created_at AS "created_at: chrono::DateTime<chrono::Utc>"
        FROM   sessions
        WHERE  token = ?
          AND  expires_at > datetime('now')
        "#,
        hashed_token,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Session not found or expired".into()))
}

/// Return all active sessions for a given user.
pub async fn get_sessions_by_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<Session>> {
    let sessions = sqlx::query_as!(
        Session,
        r#"
        SELECT id, user_id, token,
               expires_at AS "expires_at: chrono::DateTime<chrono::Utc>",
               created_at AS "created_at: chrono::DateTime<chrono::Utc>"
        FROM   sessions
        WHERE  user_id = ?
          AND  expires_at > datetime('now')
        ORDER  BY created_at DESC
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(sessions)
}

// ── DELETE ────────────────────────────────────────────────────────────────────

/// Invalidate (delete) a single session by its primary key.
pub async fn delete_session(pool: &SqlitePool, session_id: &str) -> Result<()> {
    let rows = sqlx::query!("DELETE FROM sessions WHERE id = ?", session_id)
        .execute(pool)
        .await?
        .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!(
            "Session '{}' not found",
            session_id
        )));
    }
    Ok(())
}

/// Invalidate (delete) a session by its hashed token value.
pub async fn delete_session_by_token(pool: &SqlitePool, hashed_token: &str) -> Result<()> {
    sqlx::query!("DELETE FROM sessions WHERE token = ?", hashed_token)
        .execute(pool)
        .await?;
    Ok(())
}

/// Invalidate **all** sessions for a given user (e.g. password change).
pub async fn delete_all_sessions_for_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query!("DELETE FROM sessions WHERE user_id = ?", user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Remove all sessions whose `expires_at` is in the past.
/// Intended to be called from a periodic maintenance task.
pub async fn purge_expired_sessions(pool: &SqlitePool) -> Result<u64> {
    let rows = sqlx::query!("DELETE FROM sessions WHERE expires_at <= datetime('now')")
        .execute(pool)
        .await?
        .rows_affected();
    Ok(rows)
}
