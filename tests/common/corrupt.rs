//! 测试专用的数据损坏注入 helper。
//!
//! 用独立的底层连接直接写坏某一行,模拟"数据库里已经坏了"的场景;
//! 测试断言只经公开 Storage/CLI/HTTP 入口,不直接读被注入的损坏行。

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Pool;
use sqlx::Sqlite;

/// 打开一个独立连接,仅用于损坏注入(不复用被测 Storage 的连接池)。
pub async fn connect(dsn: &str) -> Pool<Sqlite> {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rwc", dsn))
        .await
        .unwrap()
}

/// 把 blocks 表中指定 block_index 的 data 列改写为非法 JSON(语法错误)。
pub async fn corrupt_block_json(pool: &Pool<Sqlite>, block_index: i64) {
    sqlx::query("UPDATE blocks SET data = ? WHERE block_index = ?")
        .bind("{not valid json")
        .bind(block_index)
        .execute(pool)
        .await
        .unwrap();
}

/// 把 users 表中指定 user_id 的 metadata 列(JSON 字符串列)改写为非法 JSON。
/// metadata 列是 User 反序列化路径上唯一的 JSON 字符串字段,用它来触发
/// get_all_users 的 serde_json 解析失败,同时验证 password_hash 不泄露。
pub async fn corrupt_user_metadata(pool: &Pool<Sqlite>, user_id: &str) {
    sqlx::query("UPDATE users SET metadata = ? WHERE user_id = ?")
        .bind("{not valid json")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
}

/// 把 versions 表中指定 version_id 的 timestamp 列改写为非法值,触发解析失败。
pub async fn corrupt_version_timestamp(pool: &Pool<Sqlite>, version_id: &str) {
    sqlx::query("UPDATE versions SET timestamp = ? WHERE version_id = ?")
        .bind("not-a-timestamp")
        .bind(version_id)
        .execute(pool)
        .await
        .unwrap();
}

/// 在独立连接上执行任意破坏性 SQL(DROP TABLE / 写入类型不符的值等)。
pub async fn execute_sql(pool: &Pool<Sqlite>, sql: &str) {
    sqlx::query(sql).execute(pool).await.unwrap();
}
