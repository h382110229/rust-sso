use sqlx::PgPool;
use uuid::Uuid;

use crate::models::User;

pub async fn get_user_by_id(db: &PgPool, user_id: Uuid) -> Result<User, String> {
    sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, display_name, avatar_url, is_active, is_email_verified, created_at, updated_at, last_login_at FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?
    .ok_or_else(|| "user_not_found".to_string())
}