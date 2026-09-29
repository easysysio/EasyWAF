// =========================================================
// settings.rs — EasyWAF
// Reading and writing the settings table.
//
// One key, one value, read and written here and nowhere
// else, so there is one place that says what saving a
// setting does.
// =========================================================

use sqlx::SqlitePool;

/// One setting's value. `None` when the key is not there, or cannot be read —
/// every caller treats both as "use the default".
pub async fn get(db: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar!("SELECT value FROM settings WHERE key = ?", key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// Store one setting, replacing any value it had.
pub async fn set(db: &SqlitePool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO settings (key, value, updated_at)
         VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                        updated_at = excluded.updated_at",
        key,
        value
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Store a setting where nothing could be done about a failure but say so:
/// status a background task keeps, such as when a channel was last fetched.
///
/// Logged rather than returned, so a status that stops being saved does not
/// stop without a word.
pub async fn record(db: &SqlitePool, key: &str, value: &str) {
    if let Err(e) = set(db, key, value).await {
        tracing::warn!(key, "Could not save a setting: {e}");
    }
}
