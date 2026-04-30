use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::sync::Arc;

use crate::auth::User;
use crate::core::Block;
use crate::error::{DataChainError, Result};
use crate::versioning::Version;

/// 数据库存储
pub struct Storage {
    pool: Pool<Sqlite>,
}

impl Storage {
    /// 创建存储实例
    pub async fn new(dsn: &str) -> Result<Self> {
        // 确保数据目录存在
        if let Some(parent) = std::path::Path::new(dsn).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect(&format!("sqlite:{}?mode=rwc", dsn))
            .await?;

        let storage = Self { pool };
        storage.init_tables().await?;

        Ok(storage)
    }

    /// 初始化表
    async fn init_tables(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER UNIQUE NOT NULL,
                timestamp INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                difficulty INTEGER NOT NULL,
                hash TEXT UNIQUE NOT NULL,
                data TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                public_key TEXT,
                created_at DATETIME NOT NULL,
                last_login DATETIME,
                is_active INTEGER DEFAULT 1,
                metadata TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id TEXT UNIQUE NOT NULL,
                timestamp DATETIME NOT NULL,
                file_path TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                author TEXT NOT NULL,
                message TEXT,
                parent_version TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // 创建索引
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blocks_index ON blocks(block_index)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_versions_file_path ON versions(file_path)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// 保存区块
    pub async fn save_block(&self, block: &Block) -> Result<()> {
        let data = serde_json::to_string(block)?;
        let timestamp = block.timestamp.timestamp();

        sqlx::query(
            r#"
            INSERT INTO blocks (block_index, timestamp, previous_hash, merkle_root, nonce, difficulty, hash, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(block.index)
        .bind(timestamp)
        .bind(&block.previous_hash)
        .bind(&block.merkle_root)
        .bind(block.nonce as i64)
        .bind(block.difficulty as i32)
        .bind(&block.hash)
        .bind(&data)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 获取区块
    pub async fn get_block(&self, index: i64) -> Result<Block> {
        let row: (String,) = sqlx::query_as("SELECT data FROM blocks WHERE block_index = ?")
            .bind(index)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| DataChainError::BlockNotFound(index))?;

        let block: Block = serde_json::from_str(&row.0)?;
        Ok(block)
    }

    /// 获取所有区块
    pub async fn get_all_blocks(&self) -> Result<Vec<Block>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT data FROM blocks ORDER BY block_index ASC")
                .fetch_all(&self.pool)
                .await?;

        let blocks: Vec<Block> = rows
            .into_iter()
            .filter_map(|(data,)| serde_json::from_str(&data).ok())
            .collect();

        Ok(blocks)
    }

    /// 获取区块数量
    pub async fn get_block_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blocks")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// 保存用户
    pub async fn save_user(&self, user: &User) -> Result<()> {
        let created_at = user.created_at.to_rfc3339();
        let last_login = user.last_login.map(|t| t.to_rfc3339());
        let metadata = serde_json::to_string(&user.metadata)?;

        sqlx::query(
            r#"
            INSERT INTO users (user_id, username, password_hash, email, role, public_key, created_at, last_login, is_active, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user.user_id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.email)
        .bind(user.role.to_string())
        .bind(&user.public_key)
        .bind(&created_at)
        .bind(&last_login)
        .bind(user.is_active)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 获取所有用户
    pub async fn get_all_users(&self) -> Result<Vec<User>> {
        let rows: Vec<(String, String, String, String, String, Option<String>, String, Option<String>, bool, String)> =
            sqlx::query_as(
                "SELECT user_id, username, password_hash, email, role, public_key, created_at, last_login, is_active, metadata FROM users"
            )
            .fetch_all(&self.pool)
            .await?;

        let users: Vec<User> = rows
            .into_iter()
            .filter_map(|(user_id, username, password_hash, email, role, public_key, created_at, last_login, is_active, metadata)| {
                Some(User {
                    id: 0,
                    user_id,
                    username,
                    password_hash,
                    email,
                    role: role.parse().ok()?,
                    public_key,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at).ok()?.with_timezone(&chrono::Utc),
                    last_login: last_login.and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok().map(|dt| dt.with_timezone(&chrono::Utc))),
                    is_active,
                    metadata: serde_json::from_str(&metadata).unwrap_or_default(),
                })
            })
            .collect();

        Ok(users)
    }

    /// 保存版本
    pub async fn save_version(&self, version: &Version) -> Result<()> {
        let timestamp = version.timestamp.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO versions (version_id, timestamp, file_path, content_hash, size, author, message, parent_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&version.version_id)
        .bind(&timestamp)
        .bind(&version.file_path)
        .bind(&version.content_hash)
        .bind(version.size)
        .bind(&version.author)
        .bind(&version.message)
        .bind(&version.parent_version)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 获取所有版本
    pub async fn get_all_versions(&self) -> Result<Vec<Version>> {
        let rows: Vec<(String, String, String, String, i64, String, String, Option<String>)> =
            sqlx::query_as(
                "SELECT version_id, timestamp, file_path, content_hash, size, author, message, parent_version FROM versions"
            )
            .fetch_all(&self.pool)
            .await?;

        let versions: Vec<Version> = rows
            .into_iter()
            .filter_map(|(version_id, timestamp, file_path, content_hash, size, author, message, parent_version)| {
                Some(Version {
                    id: 0,
                    version_id,
                    timestamp: chrono::DateTime::parse_from_rfc3339(&timestamp).ok()?.with_timezone(&chrono::Utc),
                    file_path,
                    content_hash,
                    size,
                    author,
                    message,
                    parent_version,
                })
            })
            .collect();

        Ok(versions)
    }

    /// 关闭存储
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// 创建共享的 Storage 实例
pub async fn create_storage(dsn: &str) -> Result<Arc<Storage>> {
    let storage = Storage::new(dsn).await?;
    Ok(Arc::new(storage))
}
