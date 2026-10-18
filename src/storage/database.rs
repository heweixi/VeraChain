use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::sync::Arc;

use crate::aggregation::AggregationSummary;
use crate::auth::User;
use crate::core::{Block, MetadataEntry};
use crate::crosschain::{AnchorOutboxEntry, AnchorReceipt, AnchorStatus, SignedChainAnchor};
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

    /// 执行版本化 SQL migration。迁移文件采用幂等 DDL,兼容早期直接建表的数据库。
    async fn apply_migrations(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
        )
        .execute(&self.pool)
        .await?;

        let (current,): (i64,) =
            sqlx::query_as("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
                .fetch_one(&self.pool)
                .await?;

        let migrations: &[(i64, &str)] = &[
            (1, include_str!("../../migrations/001_base.sql")),
            (
                2,
                include_str!("../../migrations/002_pending_aggregations.sql"),
            ),
            (3, include_str!("../../migrations/003_anchor_outbox.sql")),
        ];
        for (version, sql) in migrations {
            if *version <= current {
                continue;
            }
            let mut tx = self.pool.begin().await?;
            for statement in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                sqlx::query(statement).execute(&mut *tx).await?;
            }
            sqlx::query("INSERT INTO schema_migrations (version) VALUES (?)")
                .bind(version)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        Ok(())
    }

    /// 初始化表（保留幂等建表作为旧数据库兼容兜底）。
    async fn init_tables(&self) -> Result<()> {
        self.apply_migrations().await?;
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

        // pending 和 aggregation 使用完整 JSON 保存领域对象，避免改变现有公开模型。
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS pending_metadata (
                data_id TEXT PRIMARY KEY NOT NULL,
                data TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS aggregations (
                summary_id TEXT PRIMARY KEY NOT NULL,
                created_at DATETIME NOT NULL,
                data TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // 跨链锚定 outbox（旧库兼容兜底，正式建表见 migration 003）。
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS anchor_outbox (
                anchor_id TEXT PRIMARY KEY NOT NULL,
                target_chain_id TEXT NOT NULL,
                data_id TEXT NOT NULL,
                signed TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                receipt TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_aggregations_created_at ON aggregations(created_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_anchor_outbox_status ON anchor_outbox(status)")
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

    /// 原子提交区块:在同一事务内写入区块并删除其已打包的 pending 元数据。
    ///
    /// 消除 save_block + delete_pending_metadata 两步之间崩溃导致的不一致窗口:
    /// 要么区块与 pending 删除一起生效,要么都回滚。
    pub async fn commit_block(&self, block: &Block) -> Result<()> {
        let data = serde_json::to_string(block)?;
        let timestamp = block.timestamp.timestamp();

        let mut tx = self.pool.begin().await?;

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
        .execute(&mut *tx)
        .await?;

        for entry in &block.metadata_list {
            sqlx::query("DELETE FROM pending_metadata WHERE data_id = ?")
                .bind(&entry.data_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
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

        rows.into_iter()
            .map(|(data,)| serde_json::from_str(&data).map_err(DataChainError::from))
            .collect()
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
            .map(
                |(
                    user_id,
                    username,
                    password_hash,
                    email,
                    role,
                    public_key,
                    created_at,
                    last_login,
                    is_active,
                    metadata,
                )| {
                    let role = role.parse().map_err(|e| {
                        DataChainError::StorageError(format!("invalid user role: {}", e))
                    })?;
                    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
                        .map_err(|e| {
                            DataChainError::StorageError(format!("invalid user created_at: {}", e))
                        })?
                        .with_timezone(&chrono::Utc);
                    let last_login = last_login
                        .map(|t| {
                            chrono::DateTime::parse_from_rfc3339(&t)
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                                .map_err(|e| {
                                    DataChainError::StorageError(format!(
                                        "invalid user last_login: {}",
                                        e
                                    ))
                                })
                        })
                        .transpose()?;
                    let metadata = serde_json::from_str(&metadata).map_err(|e| {
                        DataChainError::StorageError(format!("invalid user metadata: {}", e))
                    })?;
                    Ok(User {
                        id: 0,
                        user_id,
                        username,
                        password_hash,
                        email,
                        role,
                        public_key,
                        created_at,
                        last_login,
                        is_active,
                        metadata,
                    })
                },
            )
            .collect::<Result<Vec<_>>>()?;

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
            .map(
                |(
                    version_id,
                    timestamp,
                    file_path,
                    content_hash,
                    size,
                    author,
                    message,
                    parent_version,
                )| {
                    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp)
                        .map_err(|e| {
                            DataChainError::StorageError(format!(
                                "invalid version timestamp: {}",
                                e
                            ))
                        })?
                        .with_timezone(&chrono::Utc);
                    Ok(Version {
                        id: 0,
                        version_id,
                        timestamp,
                        file_path,
                        content_hash,
                        size,
                        author,
                        message,
                        parent_version,
                    })
                },
            )
            .collect::<Result<Vec<_>>>()?;

        Ok(versions)
    }

    /// 保存待打包元数据。
    pub async fn save_pending_metadata(&self, entry: &MetadataEntry) -> Result<()> {
        let data = serde_json::to_string(entry)?;
        sqlx::query("INSERT OR REPLACE INTO pending_metadata (data_id, data) VALUES (?, ?)")
            .bind(&entry.data_id)
            .bind(data)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 获取所有待打包元数据。
    pub async fn get_pending_metadata(&self) -> Result<Vec<MetadataEntry>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT data FROM pending_metadata ORDER BY created_at ASC, data_id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(data,)| serde_json::from_str(&data).map_err(DataChainError::from))
            .collect()
    }

    /// 删除已写入区块的待打包元数据。
    pub async fn delete_pending_metadata(&self, data_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM pending_metadata WHERE data_id = ?")
            .bind(data_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 保存聚合结果。
    pub async fn save_aggregation(&self, summary: &AggregationSummary) -> Result<()> {
        let data = serde_json::to_string(summary)?;
        sqlx::query(
            "INSERT OR REPLACE INTO aggregations (summary_id, created_at, data) VALUES (?, ?, ?)",
        )
        .bind(&summary.summary_id)
        .bind(summary.created_at.to_rfc3339())
        .bind(data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 获取单个聚合结果。
    pub async fn get_aggregation(&self, summary_id: &str) -> Result<AggregationSummary> {
        let row: (String,) = sqlx::query_as("SELECT data FROM aggregations WHERE summary_id = ?")
            .bind(summary_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| {
                DataChainError::AggregationFailed(format!("aggregation not found: {}", summary_id))
            })?;
        Ok(serde_json::from_str(&row.0)?)
    }

    /// 获取全部聚合结果，按创建时间恢复历史顺序。
    pub async fn get_all_aggregations(&self) -> Result<Vec<AggregationSummary>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT data FROM aggregations ORDER BY created_at ASC, summary_id ASC")
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter()
            .map(|(data,)| serde_json::from_str(&data).map_err(DataChainError::from))
            .collect()
    }

    /// 将签名锚定写入 outbox（pending）。重复 anchor_id 时覆盖。
    pub async fn enqueue_anchor(&self, signed: &SignedChainAnchor) -> Result<()> {
        let data = serde_json::to_string(signed)?;
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO anchor_outbox
                (anchor_id, target_chain_id, data_id, signed, status, attempts, updated_at)
            VALUES (?, ?, ?, ?, 'pending', 0, CURRENT_TIMESTAMP)
            "#,
        )
        .bind(&signed.anchor.anchor_id)
        .bind(&signed.anchor.target_chain_id)
        .bind(&signed.anchor.data_id)
        .bind(data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 列出待投递锚定（pending），按创建时间升序，限制批量大小。
    pub async fn list_pending_anchors(&self, limit: i64) -> Result<Vec<AnchorOutboxEntry>> {
        let rows: Vec<(String, String, i64, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT signed, status, attempts, last_error, receipt
            FROM anchor_outbox
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(signed, status, attempts, last_error, receipt)| {
                let signed: SignedChainAnchor = serde_json::from_str(&signed)?;
                let receipt = match receipt {
                    Some(r) => Some(serde_json::from_str(&r)?),
                    None => None,
                };
                Ok(AnchorOutboxEntry {
                    signed,
                    status: AnchorStatus::parse_status(&status),
                    attempts,
                    last_error,
                    receipt,
                    updated_at: chrono::Utc::now(),
                })
            })
            .collect()
    }

    /// 标记锚定已确认，记录回执。
    pub async fn mark_anchor_confirmed(
        &self,
        anchor_id: &str,
        receipt: &AnchorReceipt,
    ) -> Result<()> {
        let receipt_json = serde_json::to_string(receipt)?;
        sqlx::query(
            r#"
            UPDATE anchor_outbox
            SET status = 'confirmed', receipt = ?, last_error = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE anchor_id = ?
            "#,
        )
        .bind(receipt_json)
        .bind(anchor_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 记录一次投递尝试：更新 attempts、状态与错误信息。
    pub async fn mark_anchor_attempt(
        &self,
        anchor_id: &str,
        attempts: i64,
        status: AnchorStatus,
        error: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE anchor_outbox
            SET attempts = ?, status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE anchor_id = ?
            "#,
        )
        .bind(attempts)
        .bind(status.as_str())
        .bind(error)
        .bind(anchor_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 查询单个锚定条目（供 API 查询状态）。
    pub async fn get_anchor(&self, anchor_id: &str) -> Result<Option<AnchorOutboxEntry>> {
        let row: Option<(String, String, i64, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT signed, status, attempts, last_error, receipt
            FROM anchor_outbox WHERE anchor_id = ?
            "#,
        )
        .bind(anchor_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some((signed, status, attempts, last_error, receipt)) => {
                let signed: SignedChainAnchor = serde_json::from_str(&signed)?;
                let receipt = match receipt {
                    Some(r) => Some(serde_json::from_str(&r)?),
                    None => None,
                };
                Ok(Some(AnchorOutboxEntry {
                    signed,
                    status: AnchorStatus::parse_status(&status),
                    attempts,
                    last_error,
                    receipt,
                    updated_at: chrono::Utc::now(),
                }))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn pending_metadata_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let entry = MetadataEntry {
            data_id: "pending-1".to_string(),
            data_size: 10,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            owner: "tester".to_string(),
            hashes: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            parent_id: None,
            tags: Vec::new(),
        };

        storage.save_pending_metadata(&entry).await.unwrap();
        assert_eq!(storage.get_pending_metadata().await.unwrap().len(), 1);
        storage
            .delete_pending_metadata(&entry.data_id)
            .await
            .unwrap();
        assert!(storage.get_pending_metadata().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn commit_block_atomically_removes_pending() {
        use crate::core::{Block, MetadataEntry};
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();

        // 先放入两条 pending。
        for id in ["d1", "d2"] {
            let entry = MetadataEntry {
                data_id: id.to_string(),
                data_size: 1,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                owner: "t".to_string(),
                hashes: std::collections::HashMap::new(),
                metadata: std::collections::HashMap::new(),
                parent_id: None,
                tags: Vec::new(),
            };
            storage.save_pending_metadata(&entry).await.unwrap();
        }
        assert_eq!(storage.get_pending_metadata().await.unwrap().len(), 2);

        // 构造一个包含 d1 的区块并原子提交。
        let mut block = Block::new(1, "0".repeat(64), 2);
        block.metadata_list.push(MetadataEntry {
            data_id: "d1".to_string(),
            data_size: 1,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            owner: "t".to_string(),
            hashes: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            parent_id: None,
            tags: Vec::new(),
        });
        block.hash = "h".repeat(16);

        storage.commit_block(&block).await.unwrap();

        // 区块已落库;d1 的 pending 被同事务删除,d2 保留。
        assert_eq!(storage.get_block_count().await.unwrap(), 1);
        let remaining = storage.get_pending_metadata().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].data_id, "d2");
    }

    #[tokio::test]
    async fn aggregation_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let summary = AggregationSummary {
            summary_id: "summary-1".to_string(),
            summary_type: "manual".to_string(),
            level: 1,
            created_at: Utc::now(),
            time_range: None,
            block_range: Some((0, 1)),
            statistics: std::collections::HashMap::new(),
            merkle_root: "root".to_string(),
            metadata_count: 1,
            parent_summaries: Vec::new(),
            is_merged: false,
        };

        storage.save_aggregation(&summary).await.unwrap();
        assert_eq!(
            storage
                .get_aggregation("summary-1")
                .await
                .unwrap()
                .summary_id,
            "summary-1"
        );
        assert_eq!(storage.get_all_aggregations().await.unwrap().len(), 1);
    }
}
