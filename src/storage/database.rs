use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::sync::Arc;

use crate::aggregation::AggregationSummary;
use crate::auth::User;
use crate::catalog::{CatalogPayload, CatalogRecord};
use crate::core::{Block, MetadataEntry};
use crate::crosschain::{AnchorOutboxEntry, AnchorReceipt, AnchorStatus, SignedChainAnchor};
use crate::error::{corruption_from_json, CorruptionCategory, DataChainError, Result};
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
            (
                4,
                include_str!("../../migrations/004_revoked_refresh_tokens.sql"),
            ),
            (
                5,
                include_str!("../../migrations/005_metadata_projection.sql"),
            ),
            (
                6,
                include_str!("../../migrations/006_catalog_semantic_records.sql"),
            ),
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

    /// 初始化表结构:纯 migration 驱动。
    ///
    /// 建表/建索引的唯一事实源是 `migrations/NNN_*.sql`(经 `apply_migrations` 按
    /// `schema_migrations` 版本号顺序执行)。此处不再保留 `CREATE TABLE IF NOT EXISTS`
    /// 兜底——此前兜底与 migration 完全重叠(001~004 已覆盖 blocks/users/versions/
    /// pending_metadata/aggregations/anchor_outbox/revoked_refresh_tokens 全部表与索引),
    /// 两套逻辑并存只会带来漂移风险。
    ///
    /// 旧库兼容性:migration 全部为幂等 `CREATE TABLE/INDEX IF NOT EXISTS`。即便某个
    /// 旧库此前仅靠兜底建过表、`schema_migrations` 为空,升级时 apply_migrations 会从
    /// version 0 重跑所有迁移,已存在的表/索引被 IF NOT EXISTS 跳过,不会丢表或报错。
    ///
    /// 回滚约定:当前 migration 只前进(up-only),无自动 down。需要回滚时手动操作数据库;
    /// 需要数据回填(backfill)的迁移将在首次出现真实场景时(如独立 metadata 查询表)
    /// 作为带数据变换的 migration 引入。
    async fn init_tables(&self) -> Result<()> {
        self.apply_migrations().await?;
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

    /// 把单个区块的派生投影(metadata 查询表 + catalog_* 查询表)写入同一事务,
    /// 并删除其已打包的 pending 条目。由 `commit_block`(追加单块)与
    /// `rebuild_projections`(全量重放)共用,保证两条路径投影语义完全一致。
    ///
    /// 不写 blocks 表本身——区块落库仍由调用方(commit_block)负责,
    /// 重建路径在调用前已清空投影表,只需按区块顺序重放。
    async fn project_block_tx(tx: &mut sqlx::Transaction<'_, Sqlite>, block: &Block) -> Result<()> {
        for entry in &block.metadata_list {
            sqlx::query("DELETE FROM pending_metadata WHERE data_id = ?")
                .bind(&entry.data_id)
                .execute(&mut **tx)
                .await?;

            // 同事务写入 metadata 查询投影(只读副本,权威源仍是区块 metadata_list)。
            // data_id upsert 保证幂等:重放/回填同一条目不会重复。
            let entry_json = serde_json::to_string(entry)?;
            let tags_json = serde_json::to_string(&entry.tags)?;
            sqlx::query(
                r#"
                INSERT INTO metadata (data_id, owner, data_size, created_at, block_index, tags, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(data_id) DO UPDATE SET
                    owner = excluded.owner,
                    data_size = excluded.data_size,
                    created_at = excluded.created_at,
                    block_index = excluded.block_index,
                    tags = excluded.tags,
                    data = excluded.data
                "#,
            )
            .bind(&entry.data_id)
            .bind(&entry.owner)
            .bind(entry.data_size)
            .bind(entry.created_at.timestamp())
            .bind(block.index)
            .bind(&tags_json)
            .bind(&entry_json)
            .execute(&mut **tx)
            .await?;
        }

        // 同事务持久化语义目录记录并更新查询投影。记录本身已在 block.catalog_records
        // 并进入 merkle_root，是权威事实；catalog_* 表仅加速查询。
        for record in &block.catalog_records {
            let record_json = serde_json::to_string(record)?;
            sqlx::query("DELETE FROM pending_catalog_records WHERE record_id = ?")
                .bind(&record.record_id)
                .execute(&mut **tx)
                .await?;

            match &record.payload {
                CatalogPayload::Subject(v) => {
                    sqlx::query(
                        "INSERT INTO catalog_subjects (subject_id, subject_type, display_name, source_ref, issuer_identity, issuer_key, record_id, recorded_at, block_index, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(subject_id) DO NOTHING",
                    )
                    .bind(&v.subject_id)
                    .bind(&v.subject_type)
                    .bind(&v.display_name)
                    .bind(&v.source_ref)
                    .bind(&record.issuer_identity)
                    .bind(&record.issuer_key)
                    .bind(&record.record_id)
                    .bind(record.recorded_at)
                    .bind(block.index)
                    .bind(&record_json)
                    .execute(&mut **tx)
                    .await?;
                }
                CatalogPayload::Revision(v) => {
                    sqlx::query(
                        "INSERT INTO catalog_revisions (revision_id, subject_id, content_hash, parent_revision_id, source_ref, issuer_identity, issuer_key, record_id, recorded_at, block_index, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(revision_id) DO NOTHING",
                    )
                    .bind(&v.revision_id)
                    .bind(&v.subject_id)
                    .bind(&v.content_hash)
                    .bind(&v.parent_revision_id)
                    .bind(&v.source_ref)
                    .bind(&record.issuer_identity)
                    .bind(&record.issuer_key)
                    .bind(&record.record_id)
                    .bind(record.recorded_at)
                    .bind(block.index)
                    .bind(&record_json)
                    .execute(&mut **tx)
                    .await?;
                }
                CatalogPayload::Artifact(v) => {
                    sqlx::query(
                        "INSERT INTO catalog_artifacts (artifact_id, revision_id, artifact_hash, configuration_hash, platform, issuer_identity, issuer_key, record_id, recorded_at, block_index, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(artifact_id) DO NOTHING",
                    )
                    .bind(&v.artifact_id)
                    .bind(&v.revision_id)
                    .bind(&v.artifact_hash)
                    .bind(&v.configuration_hash)
                    .bind(&v.platform)
                    .bind(&record.issuer_identity)
                    .bind(&record.issuer_key)
                    .bind(&record.record_id)
                    .bind(record.recorded_at)
                    .bind(block.index)
                    .bind(&record_json)
                    .execute(&mut **tx)
                    .await?;
                }
                CatalogPayload::Claim(v) => {
                    sqlx::query(
                        "INSERT INTO catalog_claims (claim_id, subject_id, revision_id, artifact_id, category, status, evidence_ref, observed_at, effective_from, effective_to, supersedes_claim_id, issuer_identity, issuer_key, record_id, recorded_at, block_index, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(claim_id) DO NOTHING",
                    )
                    .bind(&v.claim_id)
                    .bind(&v.subject_id)
                    .bind(&v.revision_id)
                    .bind(&v.artifact_id)
                    .bind(&v.category)
                    .bind(&v.status)
                    .bind(&v.evidence_ref)
                    .bind(v.observed_at)
                    .bind(v.effective_from)
                    .bind(v.effective_to)
                    .bind(&v.supersedes_claim_id)
                    .bind(&record.issuer_identity)
                    .bind(&record.issuer_key)
                    .bind(&record.record_id)
                    .bind(record.recorded_at)
                    .bind(block.index)
                    .bind(&record_json)
                    .execute(&mut **tx)
                    .await?;
                }
            }
        }

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

        Self::project_block_tx(&mut tx, block).await?;

        tx.commit().await?;
        Ok(())
    }

    /// 获取区块。blocks 是权威源:JSON 解析失败视为数据损坏(fail-closed),
    /// key 用区块索引(与"blocks 的 key 用区块索引"的错误契约一致)。
    pub async fn get_block(&self, index: i64) -> Result<Block> {
        let row: (String,) = sqlx::query_as("SELECT data FROM blocks WHERE block_index = ?")
            .bind(index)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| DataChainError::BlockNotFound(index))?;

        serde_json::from_str(&row.0).map_err(|e| {
            corruption_from_json(
                CorruptionCategory::Authoritative,
                "blocks",
                Some(&index.to_string()),
                &e,
            )
        })
    }

    /// 获取所有区块。权威源严格读取:任一行 JSON 解析失败即整体 fail-closed,
    /// 返回 DataCorruption{table:"blocks", key:<block_index>}。
    pub async fn get_all_blocks(&self) -> Result<Vec<Block>> {
        let rows: Vec<(i64, String)> =
            sqlx::query_as("SELECT block_index, data FROM blocks ORDER BY block_index ASC")
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter()
            .map(|(block_index, data)| {
                serde_json::from_str(&data).map_err(|e| {
                    corruption_from_json(
                        CorruptionCategory::Authoritative,
                        "blocks",
                        Some(&block_index.to_string()),
                        &e,
                    )
                })
            })
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
                    // users 是权威源:任一字段解析失败即 fail-closed。key 统一用 user_id
                    // 主键(不用 email/username),reason 只走固定词表,不回显 role/日期/
                    // 原始 JSON 内容(避免间接泄露 password_hash 等敏感字段所在行)。
                    let role = role.parse().map_err(|_| DataChainError::DataCorruption {
                        category: CorruptionCategory::Authoritative,
                        table: "users",
                        key: user_id.clone(),
                        reason: "missing_field".to_string(),
                    })?;
                    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
                        .map_err(|_| DataChainError::DataCorruption {
                            category: CorruptionCategory::Authoritative,
                            table: "users",
                            key: user_id.clone(),
                            reason: "missing_field".to_string(),
                        })?
                        .with_timezone(&chrono::Utc);
                    let last_login = last_login
                        .map(|t| {
                            chrono::DateTime::parse_from_rfc3339(&t)
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                                .map_err(|_| DataChainError::DataCorruption {
                                    category: CorruptionCategory::Authoritative,
                                    table: "users",
                                    key: user_id.clone(),
                                    reason: "missing_field".to_string(),
                                })
                        })
                        .transpose()?;
                    let metadata = serde_json::from_str(&metadata).map_err(|e| {
                        corruption_from_json(
                            CorruptionCategory::Authoritative,
                            "users",
                            Some(&user_id),
                            &e,
                        )
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
                    // versions 是权威源:timestamp 解析失败即 fail-closed,key 用 version_id。
                    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp)
                        .map_err(|_| DataChainError::DataCorruption {
                            category: CorruptionCategory::Authoritative,
                            table: "versions",
                            key: version_id.clone(),
                            reason: "missing_field".to_string(),
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

    /// 获取所有待打包元数据。权威源严格读取:data_id 作 key。
    pub async fn get_pending_metadata(&self) -> Result<Vec<MetadataEntry>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT data_id, data FROM pending_metadata ORDER BY created_at ASC, data_id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(data_id, data)| {
                serde_json::from_str(&data).map_err(|e| {
                    corruption_from_json(
                        CorruptionCategory::Authoritative,
                        "pending_metadata",
                        Some(&data_id),
                        &e,
                    )
                })
            })
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

    /// 获取单个聚合结果。data 列坏 JSON 返回结构化 `DataCorruption`(权威源,key=summary_id)。
    pub async fn get_aggregation(&self, summary_id: &str) -> Result<AggregationSummary> {
        let row: (String, String) =
            sqlx::query_as("SELECT summary_id, data FROM aggregations WHERE summary_id = ?")
                .bind(summary_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| {
                    DataChainError::AggregationFailed(format!(
                        "aggregation not found: {}",
                        summary_id
                    ))
                })?;
        serde_json::from_str(&row.1).map_err(|e| {
            corruption_from_json(
                CorruptionCategory::Authoritative,
                "aggregations",
                Some(row.0.as_str()),
                &e,
            )
        })
    }

    /// 获取全部聚合结果，按创建时间恢复历史顺序。任一行坏 JSON 即返回
    /// 结构化 `DataCorruption`(权威源,key=summary_id)。
    pub async fn get_all_aggregations(&self) -> Result<Vec<AggregationSummary>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT summary_id, data FROM aggregations ORDER BY created_at ASC, summary_id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(summary_id, data)| {
                serde_json::from_str(&data).map_err(|e| {
                    corruption_from_json(
                        CorruptionCategory::Authoritative,
                        "aggregations",
                        Some(summary_id.as_str()),
                        &e,
                    )
                })
            })
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

    /// 将 outbox 行严格解析为条目;任何字段损坏均返回带 anchor_id 的 `DataCorruption`。
    fn parse_anchor_row(
        anchor_id: &str,
        signed: &str,
        status: &str,
        attempts: i64,
        last_error: Option<String>,
        receipt: Option<String>,
    ) -> Result<AnchorOutboxEntry> {
        let signed: SignedChainAnchor = serde_json::from_str(signed).map_err(|e| {
            corruption_from_json(
                CorruptionCategory::Authoritative,
                "anchor_outbox",
                Some(anchor_id),
                &e,
            )
        })?;
        let status = AnchorStatus::parse_status(status).map_err(|_| {
            DataChainError::DataCorruption {
                category: CorruptionCategory::Authoritative,
                table: "anchor_outbox",
                key: anchor_id.to_string(),
                reason: "unknown_status".to_string(),
            }
        })?;
        let receipt = match receipt {
            Some(r) => Some(serde_json::from_str(&r).map_err(|e| {
                corruption_from_json(
                    CorruptionCategory::Authoritative,
                    "anchor_outbox",
                    Some(anchor_id),
                    &e,
                )
            })?),
            None => None,
        };
        Ok(AnchorOutboxEntry {
            signed,
            status,
            attempts,
            last_error,
            receipt,
            updated_at: chrono::Utc::now(),
        })
    }

    /// 列出待投递锚定（pending），按创建时间升序，限制批量大小。
    pub async fn list_pending_anchors(&self, limit: i64) -> Result<Vec<AnchorOutboxEntry>> {
        let rows: Vec<(String, String, String, i64, Option<String>, Option<String>)> =
            sqlx::query_as(
                r#"
            SELECT anchor_id, signed, status, attempts, last_error, receipt
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
            .map(|(anchor_id, signed, status, attempts, last_error, receipt)| {
                Self::parse_anchor_row(&anchor_id, &signed, &status, attempts, last_error, receipt)
            })
            .collect()
    }

    /// 启动期只读全表扫描 anchor_outbox(不按 status 过滤),逐行严格校验
    /// status / signed / receipt。返回已校验行数;首个损坏行返回 `DataCorruption`。
    pub async fn scan_anchor_outbox(&self) -> Result<usize> {
        let rows: Vec<(String, String, String, i64, Option<String>, Option<String>)> =
            sqlx::query_as(
                r#"
            SELECT anchor_id, signed, status, attempts, last_error, receipt
            FROM anchor_outbox
            ORDER BY created_at ASC, anchor_id ASC
            "#,
            )
            .fetch_all(&self.pool)
            .await?;
        let mut count = 0usize;
        for (anchor_id, signed, status, attempts, last_error, receipt) in rows {
            Self::parse_anchor_row(&anchor_id, &signed, &status, attempts, last_error, receipt)?;
            count += 1;
        }
        Ok(count)
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
        let row: Option<(String, String, String, i64, Option<String>, Option<String>)> =
            sqlx::query_as(
                r#"
            SELECT anchor_id, signed, status, attempts, last_error, receipt
            FROM anchor_outbox WHERE anchor_id = ?
            "#,
            )
            .bind(anchor_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            None => Ok(None),
            Some((id, signed, status, attempts, last_error, receipt)) => Ok(Some(
                Self::parse_anchor_row(&id, &signed, &status, attempts, last_error, receipt)?,
            )),
        }
    }

    // ==================== 刷新令牌撤销（refresh token 持久化） ====================

    /// family 撤销哨兵行使用的 jti 约定前缀。该 jti 不对应真实令牌，
    /// 仅代表「整个 family 已被废止」。
    fn family_sentinel_jti(family_id: &str) -> String {
        format!("family:{}", family_id)
    }

    /// 抢占式撤销单个刷新令牌 jti：以 jti 为主键 `INSERT ... ON CONFLICT DO NOTHING`。
    ///
    /// 返回值区分并发语义：
    /// - `true`  = 本次调用成功写入（抢占成功，调用方可安全签发新令牌对）；
    /// - `false` = 该 jti 已存在（主键冲突，说明已被并发请求或之前的轮换消费）。
    ///
    /// 用数据库主键唯一性收口「检查-写入」之间的 TOCTOU 窗口：两个并发请求
    /// 用同一旧 refresh token 轮换时，只有一个能抢到插入，另一个得到 false，
    /// 从而被判定为复用/并发双花，避免一个旧 token 兑换出两对新令牌。
    pub async fn revoke_refresh(
        &self,
        jti: &str,
        user_id: &str,
        family_id: &str,
        reason: Option<&str>,
        expires_at: i64,
    ) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO revoked_refresh_tokens
                (jti, user_id, family_id, reason, expires_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(jti) DO NOTHING
            "#,
        )
        .bind(jti)
        .bind(user_id)
        .bind(family_id)
        .bind(reason)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        // rows_affected == 0 表示 jti 已存在、本次未抢占成功。
        Ok(result.rows_affected() > 0)
    }

    /// 查询某 jti 是否已被撤销。
    pub async fn is_jti_revoked(&self, jti: &str) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM revoked_refresh_tokens WHERE jti = ?")
                .bind(jti)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }

    /// 撤销整个 family：写入/更新一条哨兵行代表该 family 被整体废止。
    /// 后续任何属于该 family 的 jti 都应经 is_family_revoked 判定为已撤销。
    ///
    /// `ttl_secs` 由调用方传入刷新令牌有效期（见 `JwtHandler::refresh_expire_secs`），
    /// 哨兵行 expires_at = now + ttl_secs + 1 天余量。哨兵行只需覆盖「该 family
    /// 任何未过期 refresh token 的最长剩余寿命」，超过该寿命后族内所有 token 都已
    /// 自然过期、无法再用于轮换，哨兵行可被 purge 安全清理。
    /// 不再用 365 天魔法数，避免 refresh 有效期调大时 purge 误删哨兵行导致撤销失忆。
    pub async fn revoke_family(
        &self,
        user_id: &str,
        family_id: &str,
        reason: Option<&str>,
        ttl_secs: i64,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        // 哨兵行是幂等的（同一 family 重复撤销无害），忽略抢占成功与否的返回值。
        let sentinel_jti = Self::family_sentinel_jti(family_id);
        let sentinel_expires = now + ttl_secs + 24 * 3600;
        let now_ts = now;
        sqlx::query(
            r#"
            INSERT INTO revoked_refresh_tokens
                (jti, user_id, family_id, reason, expires_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(jti) DO UPDATE SET
                expires_at = excluded.expires_at,
                reason = excluded.reason,
                revoked_at = excluded.revoked_at
            "#,
        )
        .bind(&sentinel_jti)
        .bind(user_id)
        .bind(family_id)
        .bind(reason)
        .bind(sentinel_expires)
        .bind(now_ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 查询某 family 是否已被整体撤销（哨兵行存在即视为撤销）。
    pub async fn is_family_revoked(&self, user_id: &str, family_id: &str) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM revoked_refresh_tokens WHERE user_id = ? AND jti = ?")
                .bind(user_id)
                .bind(Self::family_sentinel_jti(family_id))
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }

    /// 清理已过期的撤销记录，返回删除行数。
    pub async fn purge_expired_refresh(&self, now_ts: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM revoked_refresh_tokens WHERE expires_at < ?")
            .bind(now_ts)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // ==================== metadata 查询投影(backlog #5) ====================

    /// 幂等 upsert 一条 metadata 投影。用于启动时回填历史区块元数据。
    /// 与 commit_block 内的投影写入逻辑一致,data_id 冲突即更新。
    pub async fn upsert_metadata_projection(
        &self,
        entry: &MetadataEntry,
        block_index: i64,
    ) -> Result<()> {
        let entry_json = serde_json::to_string(entry)?;
        let tags_json = serde_json::to_string(&entry.tags)?;
        sqlx::query(
            r#"
            INSERT INTO metadata (data_id, owner, data_size, created_at, block_index, tags, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(data_id) DO UPDATE SET
                owner = excluded.owner,
                data_size = excluded.data_size,
                created_at = excluded.created_at,
                block_index = excluded.block_index,
                tags = excluded.tags,
                data = excluded.data
            "#,
        )
        .bind(&entry.data_id)
        .bind(&entry.owner)
        .bind(entry.data_size)
        .bind(entry.created_at.timestamp())
        .bind(block_index)
        .bind(&tags_json)
        .bind(&entry_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 从已加载区块回填 metadata 投影(代码级 reconcile)。幂等,返回回填条目数。
    /// server 启动与 CLI 读命令前调用,确保投影覆盖历史上链元数据。
    pub async fn backfill_metadata_from_blocks(&self, blocks: &[Block]) -> Result<usize> {
        let mut n = 0usize;
        for block in blocks {
            for entry in &block.metadata_list {
                self.upsert_metadata_projection(entry, block.index).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// 投影表当前行数(回填时用于判断/日志)。
    pub async fn metadata_projection_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM metadata")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// 按 data_id 从投影读取单条元数据。
    pub async fn get_metadata_by_id(&self, data_id: &str) -> Result<Option<MetadataEntry>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT data FROM metadata WHERE data_id = ?")
            .bind(data_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some((data,)) => Ok(Some(serde_json::from_str(&data)?)),
            None => Ok(None),
        }
    }

    /// 按可选 owner / 时间范围过滤查询投影(过滤下推 SQL),按 created_at 升序返回。
    /// tag 过滤与分页由上层(MetadataManager)在结果上做,保持投影表最小。
    pub async fn query_metadata(
        &self,
        owner: Option<&str>,
        start_ts: Option<i64>,
        end_ts: Option<i64>,
    ) -> Result<Vec<MetadataEntry>> {
        let mut sql = String::from("SELECT data FROM metadata WHERE 1=1");
        if owner.is_some() {
            sql.push_str(" AND owner = ?");
        }
        if start_ts.is_some() {
            sql.push_str(" AND created_at >= ?");
        }
        if end_ts.is_some() {
            sql.push_str(" AND created_at <= ?");
        }
        sql.push_str(" ORDER BY created_at ASC, data_id ASC");

        let mut q = sqlx::query_as::<_, (String,)>(&sql);
        if let Some(o) = owner {
            q = q.bind(o.to_string());
        }
        if let Some(s) = start_ts {
            q = q.bind(s);
        }
        if let Some(e) = end_ts {
            q = q.bind(e);
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|(data,)| serde_json::from_str(&data).map_err(DataChainError::from))
            .collect()
    }

    /// 读取全部投影元数据(统计/全量列举用)。
    pub async fn get_all_metadata(&self) -> Result<Vec<MetadataEntry>> {
        self.query_metadata(None, None, None).await
    }

    // ==================== 可验证语义目录(Subject/Revision/Artifact/Claim) ====================

    /// 保存待打包目录记录。提交 API 先落库、后入内存队列，避免进程重启丢失已接受记录。
    pub async fn save_pending_catalog_record(&self, record: &CatalogRecord) -> Result<()> {
        let data = serde_json::to_string(record)?;
        sqlx::query(
            "INSERT INTO pending_catalog_records (record_id, data, created_at) VALUES (?, ?, ?) ON CONFLICT(record_id) DO NOTHING",
        )
        .bind(&record.record_id)
        .bind(data)
        .bind(record.recorded_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 恢复所有待打包目录记录。权威源严格读取:record_id 作 key。
    pub async fn get_pending_catalog_records(&self) -> Result<Vec<CatalogRecord>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT record_id, data FROM pending_catalog_records ORDER BY created_at ASC, record_id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(record_id, data)| {
                serde_json::from_str(&data).map_err(|e| {
                    corruption_from_json(
                        CorruptionCategory::Authoritative,
                        "pending_catalog_records",
                        Some(&record_id),
                        &e,
                    )
                })
            })
            .collect()
    }

    /// 从 Subject 查询投影读取一条记录。
    pub async fn get_catalog_subject(&self, subject_id: &str) -> Result<Option<CatalogRecord>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT data FROM catalog_subjects WHERE subject_id = ?")
                .bind(subject_id)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some((data,)) => Ok(Some(serde_json::from_str(&data)?)),
            None => Ok(None),
        }
    }

    /// 按 subject 查询其不可变版本，按记录时间升序。
    pub async fn get_catalog_revisions(&self, subject_id: &str) -> Result<Vec<CatalogRecord>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT data FROM catalog_revisions WHERE subject_id = ? ORDER BY recorded_at ASC, revision_id ASC",
        )
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(data,)| serde_json::from_str(&data).map_err(DataChainError::from))
            .collect()
    }

    /// 按 revision 查询构建/配置变体，按记录时间升序。
    pub async fn get_catalog_artifacts(&self, revision_id: &str) -> Result<Vec<CatalogRecord>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT data FROM catalog_artifacts WHERE revision_id = ? ORDER BY recorded_at ASC, artifact_id ASC",
        )
        .bind(revision_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(data,)| serde_json::from_str(&data).map_err(DataChainError::from))
            .collect()
    }

    /// 读取某 subject 的认证声明。Claim 保留完整历史，不在此处删除 withdrawn/superseded。
    pub async fn get_catalog_claims(&self, subject_id: &str) -> Result<Vec<CatalogRecord>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT data FROM catalog_claims WHERE subject_id = ? ORDER BY observed_at ASC, claim_id ASC",
        )
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(data,)| serde_json::from_str(&data).map_err(DataChainError::from))
            .collect()
    }

    /// 读取 Claim 历史及其上链高度，供 resolver 按策略计算指定时间点的有效结论。
    pub async fn get_catalog_claims_at_block(
        &self,
        subject_id: &str,
    ) -> Result<Vec<crate::catalog::CatalogRecordAtBlock>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT data, block_index FROM catalog_claims WHERE subject_id = ? ORDER BY block_index ASC, claim_id ASC",
        )
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(data, block_index)| {
                Ok(crate::catalog::CatalogRecordAtBlock {
                    record: serde_json::from_str(&data)?,
                    block_index,
                })
            })
            .collect()
    }

    // ==================== 可重建投影检测与重建(S3) ====================

    /// 可重建投影清单。aggregations 前置核实后排除:AggregationSummary 携带
    /// parent_summaries/is_merged 等递归合并历史状态,不是"当前区块集合"可确定性
    /// 推导的纯投影,而是跨多次聚合动作累积的状态机,移出可重建投影改为
    /// fail-closed(见 get_all_aggregations 不变,仍走裸反序列化错误 fail-closed)。
    const REBUILDABLE_TABLES: &'static [&'static str] = &[
        "metadata",
        "catalog_subjects",
        "catalog_revisions",
        "catalog_artifacts",
        "catalog_claims",
    ];

    /// 某张可重建投影表对已加载区块按"能否正常解析每一行"与"行数是否与推导值一致"
    /// 做检测;任一失败都视为该表需要重建。
    async fn projection_needs_rebuild(&self, table: &'static str, expected: i64) -> bool {
        let count_sql = format!("SELECT COUNT(*) FROM {}", table);
        let actual: Option<(i64,)> = sqlx::query_as(&count_sql)
            .fetch_one(&self.pool)
            .await
            .ok();
        let actual = match actual {
            Some((n,)) => n,
            None => return true,
        };
        if actual != expected {
            return true;
        }

        // 数量一致时再抽样校验可解析性:逐行尝试反序列化 data 列。
        let data_sql = format!("SELECT data FROM {}", table);
        let rows: Option<Vec<(String,)>> = sqlx::query_as(&data_sql).fetch_all(&self.pool).await.ok();
        match rows {
            None => true,
            Some(rows) => rows.iter().any(|(data,)| {
                serde_json::from_str::<serde_json::Value>(data).is_err()
            }),
        }
    }

    /// 期望的 metadata 投影行数:区块内全部 metadata_list 条目数(按 data_id 去重,
    /// 与 upsert 语义一致)。
    fn expected_metadata_count(blocks: &[Block]) -> i64 {
        let mut ids = std::collections::HashSet::new();
        for block in blocks {
            for entry in &block.metadata_list {
                ids.insert(entry.data_id.as_str());
            }
        }
        ids.len() as i64
    }

    /// 期望的某张 catalog_* 投影行数:区块内对应 payload 类型的记录数(按主键去重,
    /// 与 commit_block 的 `ON CONFLICT DO NOTHING` 首写者胜语义一致)。
    fn expected_catalog_count(blocks: &[Block], table: &'static str) -> i64 {
        let mut ids = std::collections::HashSet::new();
        for block in blocks {
            for record in &block.catalog_records {
                let id = match (&record.payload, table) {
                    (CatalogPayload::Subject(v), "catalog_subjects") => Some(v.subject_id.as_str()),
                    (CatalogPayload::Revision(v), "catalog_revisions") => {
                        Some(v.revision_id.as_str())
                    }
                    (CatalogPayload::Artifact(v), "catalog_artifacts") => {
                        Some(v.artifact_id.as_str())
                    }
                    (CatalogPayload::Claim(v), "catalog_claims") => Some(v.claim_id.as_str()),
                    _ => None,
                };
                if let Some(id) = id {
                    ids.insert(id);
                }
            }
        }
        ids.len() as i64
    }

    /// 清空全部可重建投影表(事务内),调用方负责随后按区块顺序重放并提交。
    async fn clear_projection_tables(tx: &mut sqlx::Transaction<'_, Sqlite>) -> Result<()> {
        for table in Self::REBUILDABLE_TABLES {
            let sql = format!("DELETE FROM {}", table);
            sqlx::query(&sql).execute(&mut **tx).await?;
        }
        Ok(())
    }

    /// 在同一事务内清空可重建投影表、按区块高度升序重放 `project_block_tx`、提交。
    /// 失败整体回滚(事务未提交,drop 时自动 rollback)。
    ///
    /// 调用方(`ensure_projections`)必须确保仅在区块校验通过后调用;本函数不重复
    /// 校验区块合法性。
    pub async fn rebuild_projections(&self, blocks: &[Block]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::clear_projection_tables(&mut tx).await?;
        for block in blocks {
            Self::project_block_tx(&mut tx, block).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// 启动时序第 7 步:检测可重建投影表与已加载区块是否一致,不一致则在单事务内
    /// 整体重建(清表→重放→提交)。仅应在区块校验(validate_loaded_blocks)通过后调用。
    ///
    /// 返回触发重建的表名列表(用于日志 `event=projection_rebuild tables=[..]`),
    /// 空列表表示投影已与区块一致,未发生任何写入(幂等、重复调用安全)。
    pub async fn ensure_projections(&self, blocks: &[Block]) -> Result<ProjectionReport> {
        let expected_metadata = Self::expected_metadata_count(blocks);
        let mut needs_rebuild = Vec::new();

        if self
            .projection_needs_rebuild("metadata", expected_metadata)
            .await
        {
            needs_rebuild.push("metadata");
        }
        for table in [
            "catalog_subjects",
            "catalog_revisions",
            "catalog_artifacts",
            "catalog_claims",
        ] {
            let expected = Self::expected_catalog_count(blocks, table);
            if self.projection_needs_rebuild(table, expected).await {
                needs_rebuild.push(table);
            }
        }

        if needs_rebuild.is_empty() {
            return Ok(ProjectionReport {
                rebuilt_tables: Vec::new(),
            });
        }

        // 任一表不一致即整体重建全部可重建投影表(清表→重放→提交为单事务,
        // 避免只重建部分表导致表间关联字段不一致)。
        self.rebuild_projections(blocks).await?;

        Ok(ProjectionReport {
            rebuilt_tables: needs_rebuild.into_iter().map(String::from).collect(),
        })
    }

    /// 关闭存储
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// `ensure_projections` 的结果报告。
#[derive(Debug, Clone, Default)]
pub struct ProjectionReport {
    /// 本次调用触发重建的表名(日志 `tables=[..]` 字段用)。空表示无需重建。
    pub rebuilt_tables: Vec<String>,
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

    /// 旧库升级安全性(backlog #6):移除 init_tables 兜底后,确认"仅靠旧兜底建过表、
    /// schema_migrations 为空"的历史库经纯 migration 驱动打开时不丢表、不报错、数据保留。
    #[tokio::test]
    async fn legacy_db_without_schema_migrations_upgrades_safely() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        let dsn = path.to_str().unwrap();

        // 1) 构造"旧库":直接用底层连接建一张 blocks 表并插入一行,
        //    故意不建 schema_migrations(模拟 migration 机制引入前、仅靠兜底建表的库)。
        {
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&format!("sqlite:{}?mode=rwc", dsn))
                .await
                .unwrap();
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
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO blocks (block_index, timestamp, previous_hash, merkle_root, nonce, difficulty, hash, data) \
                 VALUES (0, 0, '', 'root', 0, 0, 'legacy-hash', '{}')",
            )
            .execute(&pool)
            .await
            .unwrap();
            // 确认旧库此时没有 schema_migrations。
            let has_sm: Option<(String,)> = sqlx::query_as(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
            )
            .fetch_optional(&pool)
            .await
            .unwrap();
            assert!(has_sm.is_none(), "旧库不应有 schema_migrations");
            pool.close().await;
        }

        // 2) 用新代码(纯 migration 驱动)打开同一个库文件。
        let storage = Storage::new(dsn).await.unwrap();

        // 3) 旧数据保留:原 blocks 行仍在,未丢表、未清空。
        assert_eq!(
            storage.get_block_count().await.unwrap(),
            1,
            "旧库升级后原有区块应保留"
        );

        // 4) migration 新增的表(如 users)可正常使用:插入并读回。
        let user = User::new(
            "upgrade-tester".to_string(),
            "hash".to_string(),
            "u@legacy.local".to_string(),
            crate::auth::Role::User,
        );
        storage.save_user(&user).await.unwrap();
        assert_eq!(storage.get_all_users().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn revoked_refresh_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();

        let exp = Utc::now().timestamp() + 3600;
        assert!(!storage.is_jti_revoked("jti-1").await.unwrap());

        // 首次抢占成功返回 true。
        let first = storage
            .revoke_refresh("jti-1", "user-1", "fam-1", Some("rotated"), exp)
            .await
            .unwrap();
        assert!(first, "首次撤销应抢占成功");
        assert!(storage.is_jti_revoked("jti-1").await.unwrap());

        // 抢占语义：对同一 jti 的第二次撤销返回 false（主键冲突，未抢占成功），
        // 这是收口并发双花的关键——旧 token 只能被消费一次。
        let second = storage
            .revoke_refresh("jti-1", "user-1", "fam-1", Some("rotated"), exp)
            .await
            .unwrap();
        assert!(!second, "重复撤销同一 jti 应返回 false（抢占失败）");
        assert!(storage.is_jti_revoked("jti-1").await.unwrap());
    }

    #[tokio::test]
    async fn revoke_family_marks_whole_family() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();

        assert!(!storage.is_family_revoked("user-1", "fam-1").await.unwrap());
        // ttl_secs 用 7 天（与默认 refresh_expire_days 一致）。
        let ttl = 7 * 24 * 3600;
        storage
            .revoke_family("user-1", "fam-1", Some("reuse"), ttl)
            .await
            .unwrap();
        assert!(storage.is_family_revoked("user-1", "fam-1").await.unwrap());
        // 不同 family / 用户不受影响。
        assert!(!storage.is_family_revoked("user-1", "fam-2").await.unwrap());
        assert!(!storage.is_family_revoked("user-2", "fam-1").await.unwrap());
    }

    #[tokio::test]
    async fn purge_expired_refresh_removes_stale_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();

        let now = Utc::now().timestamp();
        storage
            .revoke_refresh("old", "u", "f", None, now - 100)
            .await
            .unwrap();
        storage
            .revoke_refresh("fresh", "u", "f", None, now + 3600)
            .await
            .unwrap();

        let removed = storage.purge_expired_refresh(now).await.unwrap();
        assert_eq!(removed, 1);
        assert!(!storage.is_jti_revoked("old").await.unwrap());
        assert!(storage.is_jti_revoked("fresh").await.unwrap());
    }

    /// backlog #5:commit_block 写 metadata 投影,query/get_by_id 命中;回填幂等。
    #[tokio::test]
    async fn metadata_projection_written_on_commit_and_queryable() {
        use crate::core::{Block, MetadataEntry};
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();

        let mk = |data_id: &str, owner: &str, tags: Vec<String>| MetadataEntry {
            data_id: data_id.to_string(),
            data_size: 10,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            owner: owner.to_string(),
            hashes: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            parent_id: None,
            tags,
        };

        let mut block = Block::new(1, "0".repeat(64), 2);
        block.hash = "h".repeat(16);
        block
            .metadata_list
            .push(mk("m1", "alice", vec!["x".into()]));
        block.metadata_list.push(mk("m2", "bob", vec!["y".into()]));

        storage.commit_block(&block).await.unwrap();

        // 投影写入:按 id / owner / 全量可查。
        assert_eq!(storage.metadata_projection_count().await.unwrap(), 2);
        assert_eq!(
            storage
                .get_metadata_by_id("m1")
                .await
                .unwrap()
                .unwrap()
                .owner,
            "alice"
        );
        assert!(storage.get_metadata_by_id("nope").await.unwrap().is_none());
        let alice = storage
            .query_metadata(Some("alice"), None, None)
            .await
            .unwrap();
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].data_id, "m1");
        assert_eq!(storage.get_all_metadata().await.unwrap().len(), 2);

        // 回填幂等:对同一区块再回填,计数不变。
        let n = storage
            .backfill_metadata_from_blocks(std::slice::from_ref(&block))
            .await
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(storage.metadata_projection_count().await.unwrap(), 2);
    }
}
