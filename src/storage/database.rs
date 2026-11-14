use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::aggregation::AggregationSummary;
use crate::auth::User;
use crate::catalog::{CatalogPayload, CatalogRecord};
use crate::core::{Block, KeyTransactionEntry, MetadataEntry};
use crate::crosschain::{AnchorOutboxEntry, AnchorReceipt, AnchorStatus, SignedChainAnchor};
use crate::error::{
    corruption_from_json, corruption_key, CorruptionCategory, DataChainError, Result,
};
use crate::versioning::Version;

/// 解锁结果:被删除的锁行数与窗口计数行数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlockOutcome {
    pub locks_cleared: u64,
    pub counters_cleared: u64,
}

/// 登录会话记录(sessions 表一行)。时间戳均为 Unix 秒。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: String,
    pub user_id: String,
    pub refresh_family: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<String>,
    /// 客户端 IP 的 HMAC 摘要(十六进制),不存明文 IP。
    pub ip_hash: Option<String>,
    /// 脱敏 IP 提示(如 `203.0.x.x`),仅用于会话列表展示。
    pub ip_hint: Option<String>,
    pub user_agent: Option<String>,
}

const SESSION_COLUMNS: &str = "id, user_id, refresh_family, created_at, last_seen_at, \
     expires_at, revoked_at, revoke_reason, ip_hash, ip_hint, user_agent";

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: String,
    user_id: String,
    refresh_family: String,
    created_at: i64,
    last_seen_at: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
    revoke_reason: Option<String>,
    ip_hash: Option<String>,
    ip_hint: Option<String>,
    user_agent: Option<String>,
}

impl From<SessionRow> for SessionRecord {
    fn from(r: SessionRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            refresh_family: r.refresh_family,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            revoke_reason: r.revoke_reason,
            ip_hash: r.ip_hash,
            ip_hint: r.ip_hint,
            user_agent: r.user_agent,
        }
    }
}

/// 审计日志保留期(秒):90 天。启动时清理更早的行。
pub const AUDIT_RETENTION_SECS: i64 = 90 * 24 * 3600;

/// 审计字段入库前的长度上限(字符数)。
const AUDIT_USERNAME_MAX_CHARS: usize = 128;
const AUDIT_USER_AGENT_MAX_CHARS: usize = 200;
const AUDIT_REASON_MAX_CHARS: usize = 200;

/// 认证审计事件(auth_audit_log 一行)。
///
/// 只记录事件元数据:**不得**放入密码、token、jti 或明文 IP;`ip_hash` 为 HMAC 摘要。
/// 文本字段在 [`Storage::append_audit_event`] 入库时统一截断并转义控制字符。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditEvent {
    /// 自增主键;写入时忽略,读取时填充。
    pub id: i64,
    /// Unix 秒。
    pub ts: i64,
    pub event_type: String,
    pub user_id: Option<String>,
    pub username_attempted: Option<String>,
    pub session_id: Option<String>,
    pub ip_hash: Option<String>,
    pub user_agent: Option<String>,
    /// `success` / `failure` / `denied`。
    pub result: String,
    pub reason: Option<String>,
    /// 管理员操作的操作者 user_id;`user_id` 仍表示被操作对象。CLI/自助操作为 `None`。
    pub actor_user_id: Option<String>,
}

impl AuditEvent {
    /// 以当前时间创建一个事件。
    pub fn new(event_type: &str, result: &str) -> Self {
        Self {
            ts: chrono::Utc::now().timestamp(),
            event_type: event_type.to_string(),
            result: result.to_string(),
            ..Self::default()
        }
    }

    pub fn user(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    pub fn username(mut self, username: &str) -> Self {
        self.username_attempted = Some(username.to_string());
        self
    }

    pub fn session(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }

    pub fn client(mut self, ip_hash: Option<&str>, user_agent: Option<&str>) -> Self {
        self.ip_hash = ip_hash.map(str::to_string);
        self.user_agent = user_agent.map(str::to_string);
        self
    }

    pub fn reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    /// 设置操作者(管理员)的 user_id。
    pub fn actor(mut self, actor_user_id: &str) -> Self {
        self.actor_user_id = Some(actor_user_id.to_string());
        self
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    ts: i64,
    event_type: String,
    user_id: Option<String>,
    username_attempted: Option<String>,
    session_id: Option<String>,
    ip_hash: Option<String>,
    user_agent: Option<String>,
    result: String,
    reason: Option<String>,
    actor_user_id: Option<String>,
}

/// 截断到 `max_chars` 个字符,并把控制字符(换行、ESC/ANSI 序列等)转义为可见文本,
/// 防止日志注入与终端转义序列污染。
fn sanitize_audit_text(raw: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for c in raw.chars().take(max_chars) {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let code = c as u32;
                if code <= 0xff {
                    out.push_str(&format!("\\x{:02x}", code));
                } else {
                    out.push_str(&format!("\\u{{{:x}}}", code));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// anchor_outbox 行:(anchor_id, signed, status, attempts, last_error, receipt)。
type AnchorOutboxRow = (String, String, String, i64, Option<String>, Option<String>);

/// 数据库存储
pub struct Storage {
    pool: Pool<Sqlite>,
    /// 用户 is_active 的进程内短 TTL 缓存:user_id -> (是否启用, 写入时刻)。
    active_cache: parking_lot::Mutex<HashMap<String, (bool, Instant)>>,
    /// 缓存 TTL(毫秒);0 表示禁用缓存。
    active_cache_ttl_ms: AtomicU64,
    /// 每次 is_active 写入后自增,用于丢弃"读发生在写之前"的陈旧回填。
    active_generation: AtomicU64,
    /// 登录限速使用的时间源(Unix 秒);默认系统时间,测试可经 [`Storage::set_clock`] 注入。
    clock: parking_lot::RwLock<Arc<dyn Fn() -> i64 + Send + Sync>>,
}

/// `identity_transactions` 查询使用的 SQLx 行元组。
type IdentityTransactionRow = (
    String,
    String,
    Option<String>,
    String,
    String,
    i64,
    String,
    Option<i64>,
);

/// 已接受的身份交易账本行。`transaction_id` 仅用于持久化/状态协调，不进入区块。
#[derive(Debug, Clone)]
pub struct StoredIdentityTransaction {
    pub transaction_id: String,
    pub submitter_user_id: String,
    pub idempotency_key: Option<String>,
    pub request_fingerprint: String,
    pub entry: KeyTransactionEntry,
    pub accepted_at: i64,
    pub status: String,
    pub committed_block_index: Option<i64>,
}

/// 创建或读取身份交易账本行的结果。
#[derive(Debug, Clone)]
pub struct CreateIdentityTransactionResult {
    pub transaction: StoredIdentityTransaction,
    pub created: bool,
}

/// is_active 缓存默认 TTL。
const DEFAULT_ACTIVE_CACHE_TTL: Duration = Duration::from_secs(5);

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

        let storage = Self {
            pool,
            active_cache: parking_lot::Mutex::new(HashMap::new()),
            active_cache_ttl_ms: AtomicU64::new(DEFAULT_ACTIVE_CACHE_TTL.as_millis() as u64),
            active_generation: AtomicU64::new(0),
            clock: parking_lot::RwLock::new(Arc::new(|| chrono::Utc::now().timestamp())),
        };
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
            (7, include_str!("../../migrations/007_sessions.sql")),
            (
                8,
                include_str!("../../migrations/008_login_rate_counters_and_audit.sql"),
            ),
            (9, include_str!("../../migrations/009_session_ip_hint.sql")),
            (
                10,
                include_str!("../../migrations/010_identity_transactions.sql"),
            ),
            (
                11,
                include_str!("../../migrations/011_identity_transaction_recovery_state.sql"),
            ),
            (12, include_str!("../../migrations/012_login_lockouts.sql")),
            (13, include_str!("../../migrations/013_audit_actor.sql")),
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
    /// 旧库兼容性:迁移 001~012 为幂等 `CREATE TABLE/INDEX IF NOT EXISTS`,旧库此前仅靠
    /// 兜底建过表、`schema_migrations` 为空时,从 version 0 重跑这些迁移不会丢表或报错。
    /// 但**并非全部迁移幂等**:迁移 013 的 `ALTER TABLE ... ADD COLUMN` 不幂等,若
    /// `schema_migrations` 记录丢失而列已存在,重跑会报 duplicate column 错误,需人工处理。
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

    /// 原子提交区块:在同一事务内写入区块、删除已打包的 pending 元数据，
    /// 并将映射中 `Some` 身份交易账本行转为 committed。
    ///
    /// `identity_transaction_ids` 必须与 `block.key_transactions` 逐项对齐；`None`
    /// 表示普通密钥交易，不触碰身份交易账本。
    /// 消除区块写入和 pending 状态转移之间的崩溃不一致窗口：要么全部生效，要么回滚。
    pub async fn commit_block(
        &self,
        block: &Block,
        identity_transaction_ids: &[Option<String>],
    ) -> Result<()> {
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

        if identity_transaction_ids.len() != block.key_transactions.len() {
            return Err(DataChainError::StorageError(format!(
                "identity transaction sidecar count {} does not match block key transaction count {}",
                identity_transaction_ids.len(),
                block.key_transactions.len()
            )));
        }
        for (transaction_id, entry) in identity_transaction_ids.iter().zip(&block.key_transactions)
        {
            let Some(transaction_id) = transaction_id else {
                continue;
            };
            let entry_json = serde_json::to_string(entry)?;
            let result = sqlx::query(
                "UPDATE identity_transactions SET status = 'committed', committed_block_index = ? WHERE transaction_id = ? AND status = 'pending' AND recovery_state = 'verified' AND entry = ?",
            )
            .bind(block.index)
            .bind(transaction_id)
            .bind(entry_json)
            .execute(&mut *tx)
            .await?;
            if result.rows_affected() != 1 {
                return Err(DataChainError::StorageError(format!(
                    "identity transaction is missing, not pending, or does not match block entry: {}",
                    transaction_id
                )));
            }
        }

        Self::project_block_tx(&mut tx, block).await?;

        tx.commit().await?;
        Ok(())
    }

    /// 创建身份交易账本行；携带幂等键的重复请求返回同一行。
    pub async fn create_or_get_identity_transaction(
        &self,
        submitter_user_id: &str,
        idempotency_key: Option<&str>,
        request_fingerprint: &str,
        entry: &KeyTransactionEntry,
        accepted_at: i64,
    ) -> Result<CreateIdentityTransactionResult> {
        if let Some(key) = idempotency_key {
            if let Some(existing) = self
                .get_identity_transaction_by_key(submitter_user_id, key)
                .await?
            {
                return self.identity_transaction_replay_result(existing, request_fingerprint);
            }
        }

        let transaction_id = uuid::Uuid::new_v4().to_string();
        let entry_json = serde_json::to_string(entry)?;
        let inserted = sqlx::query(
            "INSERT INTO identity_transactions (transaction_id, submitter_user_id, idempotency_key, request_fingerprint, entry, accepted_at, status, committed_block_index, recovery_state) VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL, 'verified')",
        )
        .bind(&transaction_id)
        .bind(submitter_user_id)
        .bind(idempotency_key)
        .bind(request_fingerprint)
        .bind(entry_json)
        .bind(accepted_at)
        .execute(&self.pool)
        .await;

        match inserted {
            Ok(_) => Ok(CreateIdentityTransactionResult {
                transaction: self
                    .get_identity_transaction(&transaction_id)
                    .await?
                    .ok_or_else(|| {
                        DataChainError::StorageError(
                            "new identity transaction disappeared".to_string(),
                        )
                    })?,
                created: true,
            }),
            Err(error) if idempotency_key.is_some() => {
                let existing = self
                    .get_identity_transaction_by_key(submitter_user_id, idempotency_key.unwrap())
                    .await?;
                match existing {
                    Some(existing) => {
                        self.identity_transaction_replay_result(existing, request_fingerprint)
                    }
                    None => Err(DataChainError::DatabaseError(error)),
                }
            }
            Err(error) => Err(DataChainError::DatabaseError(error)),
        }
    }

    fn identity_transaction_replay_result(
        &self,
        transaction: StoredIdentityTransaction,
        request_fingerprint: &str,
    ) -> Result<CreateIdentityTransactionResult> {
        if transaction.request_fingerprint != request_fingerprint {
            return Err(DataChainError::IdentityTransactionConflict);
        }
        Ok(CreateIdentityTransactionResult {
            transaction,
            created: false,
        })
    }

    /// 读取一条账本交易；不存在时返回 `None`。
    pub async fn get_identity_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<StoredIdentityTransaction>> {
        let row: Option<IdentityTransactionRow> = sqlx::query_as(
            "SELECT transaction_id, submitter_user_id, idempotency_key, request_fingerprint, entry, accepted_at, status, committed_block_index FROM identity_transactions WHERE transaction_id = ?",
        )
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(Self::decode_identity_transaction).transpose()
    }

    /// 按认证用户和幂等键读取账本交易。
    async fn get_identity_transaction_by_key(
        &self,
        submitter_user_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<StoredIdentityTransaction>> {
        let row: Option<IdentityTransactionRow> = sqlx::query_as(
            "SELECT transaction_id, submitter_user_id, idempotency_key, request_fingerprint, entry, accepted_at, status, committed_block_index FROM identity_transactions WHERE submitter_user_id = ? AND idempotency_key = ?",
        )
        .bind(submitter_user_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(Self::decode_identity_transaction).transpose()
    }

    fn decode_identity_transaction(
        row: IdentityTransactionRow,
    ) -> Result<StoredIdentityTransaction> {
        let (
            transaction_id,
            submitter_user_id,
            idempotency_key,
            request_fingerprint,
            entry_json,
            accepted_at,
            status,
            committed_block_index,
        ) = row;
        Ok(StoredIdentityTransaction {
            transaction_id,
            submitter_user_id,
            idempotency_key,
            request_fingerprint,
            entry: serde_json::from_str(&entry_json)?,
            accepted_at,
            status,
            committed_block_index,
        })
    }

    /// 读取待打包身份交易，按首次接受顺序恢复。
    ///
    /// 011 升级前(010 已建表)的 pending 行没有 transaction-to-block 可信映射；区块协议不包含
    /// transaction_id，不能用条目内容反推其是否已入块。此类记录必须拒绝启动恢复，
    /// 而不是有可能重复打包或误拒绝同内容的新交易。
    pub async fn get_pending_identity_transactions(
        &self,
    ) -> Result<Vec<StoredIdentityTransaction>> {
        let (unverifiable_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM identity_transactions WHERE status = 'pending' AND recovery_state != 'verified'",
        )
        .fetch_one(&self.pool)
        .await?;
        if unverifiable_count > 0 {
            return Err(DataChainError::StorageError(format!(
                "refusing to recover {} unverifiable legacy pending identity transaction(s)",
                unverifiable_count
            )));
        }

        let rows: Vec<IdentityTransactionRow> = sqlx::query_as(
            "SELECT transaction_id, submitter_user_id, idempotency_key, request_fingerprint, entry, accepted_at, status, committed_block_index FROM identity_transactions WHERE status = 'pending' AND recovery_state = 'verified' ORDER BY accepted_at ASC, transaction_id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(Self::decode_identity_transaction)
            .collect()
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
        let status =
            AnchorStatus::parse_status(status).map_err(|_| DataChainError::DataCorruption {
                category: CorruptionCategory::Authoritative,
                table: "anchor_outbox",
                key: anchor_id.to_string(),
                reason: "unknown_status".to_string(),
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
        let rows: Vec<AnchorOutboxRow> = sqlx::query_as(
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
            .map(
                |(anchor_id, signed, status, attempts, last_error, receipt)| {
                    Self::parse_anchor_row(
                        &anchor_id, &signed, &status, attempts, last_error, receipt,
                    )
                },
            )
            .collect()
    }

    /// 启动期只读全表扫描 anchor_outbox(不按 status 过滤),逐行严格校验
    /// status / signed / receipt。返回已校验行数;首个损坏行返回 `DataCorruption`。
    pub async fn scan_anchor_outbox(&self) -> Result<usize> {
        let rows: Vec<AnchorOutboxRow> = sqlx::query_as(
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

    // ==================== 认证状态严格只读扫描 ====================

    /// 严格扫描 `sessions` 全表:逐行按列类型解码,任一列类型不符即返回
    /// `DataCorruption{Authoritative, "sessions", key=id}`。
    ///
    /// 会话是访问决策依据(安全状态),损坏必须使启动 fail-closed。
    /// reason 取固定词表 `invalid_column:<列名>`,不回显行内容。返回扫描行数。
    pub async fn scan_sessions(&self) -> Result<usize> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT rowid, id, user_id, refresh_family, created_at, last_seen_at, expires_at, \
             revoked_at, revoke_reason, ip_hash, ip_hint, user_agent FROM sessions \
             ORDER BY rowid ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        for row in &rows {
            let key = Self::scan_row_key(row, "id");
            let invalid = |column: &str| DataChainError::DataCorruption {
                category: CorruptionCategory::Authoritative,
                table: "sessions",
                key: key.clone(),
                reason: format!("invalid_column:{}", column),
            };
            for column in ["id", "user_id", "refresh_family"] {
                row.try_get::<String, _>(column)
                    .map_err(|_| invalid(column))?;
            }
            for column in ["created_at", "last_seen_at", "expires_at"] {
                row.try_get::<i64, _>(column).map_err(|_| invalid(column))?;
            }
            row.try_get::<Option<i64>, _>("revoked_at")
                .map_err(|_| invalid("revoked_at"))?;
            for column in ["revoke_reason", "ip_hash", "ip_hint", "user_agent"] {
                row.try_get::<Option<String>, _>(column)
                    .map_err(|_| invalid(column))?;
            }
        }
        Ok(rows.len())
    }

    /// 严格扫描 `login_rate_counters` 全表(限速计数器同为安全状态,损坏必须 fail-closed)。
    /// 错误 key 固定为 `rowid=<n>`(rowid 不可得时退化为 `corruption_key(None)`)。
    /// 不使用 `key` 列:其值为 `user:<规范化用户名>`/`ip:<hash>`,用户名由攻击者可控,
    /// 且主键为 `(key, window_start)`、key 不唯一,回显会泄露用户名并污染日志。
    /// reason 同 [`Storage::scan_sessions`]。
    pub async fn scan_login_rate_counters(&self) -> Result<usize> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT rowid, key, window_start, count, locked_until FROM login_rate_counters \
             ORDER BY rowid ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        for row in &rows {
            let key = Self::scan_rowid_key(row);
            let invalid = |column: &str| DataChainError::DataCorruption {
                category: CorruptionCategory::Authoritative,
                table: "login_rate_counters",
                key: key.clone(),
                reason: format!("invalid_column:{}", column),
            };
            row.try_get::<String, _>("key")
                .map_err(|_| invalid("key"))?;
            for column in ["window_start", "count"] {
                row.try_get::<i64, _>(column).map_err(|_| invalid(column))?;
            }
            row.try_get::<Option<i64>, _>("locked_until")
                .map_err(|_| invalid("locked_until"))?;
        }
        Ok(rows.len())
    }

    /// 严格扫描 `auth_audit_log`(审计证据,启动时损坏只告警不阻塞,由调用方决定)。
    /// key 为自增主键 `id`;reason 同 [`Storage::scan_sessions`]。
    pub async fn scan_auth_audit_log(&self) -> Result<usize> {
        use futures_util::TryStreamExt;
        use sqlx::Row;
        // 流式逐行处理,审计表体量大时不会整表读入内存。
        let mut scanned: usize = 0;
        let mut rows = sqlx::query(
            "SELECT id, ts, event_type, user_id, username_attempted, session_id, ip_hash, \
             user_agent, result, reason, actor_user_id FROM auth_audit_log ORDER BY id ASC",
        )
        .fetch(&self.pool);
        while let Some(row) = rows.try_next().await? {
            scanned += 1;
            let key = row
                .try_get::<i64, _>("id")
                .map(|id| id.to_string())
                .unwrap_or_else(|_| corruption_key(None));
            let invalid = |column: &str| DataChainError::DataCorruption {
                category: CorruptionCategory::Authoritative,
                table: "auth_audit_log",
                key: key.clone(),
                reason: format!("invalid_column:{}", column),
            };
            row.try_get::<i64, _>("id").map_err(|_| invalid("id"))?;
            row.try_get::<i64, _>("ts").map_err(|_| invalid("ts"))?;
            for column in ["event_type", "result"] {
                row.try_get::<String, _>(column)
                    .map_err(|_| invalid(column))?;
            }
            for column in [
                "user_id",
                "username_attempted",
                "session_id",
                "ip_hash",
                "user_agent",
                "reason",
                "actor_user_id",
            ] {
                row.try_get::<Option<String>, _>(column)
                    .map_err(|_| invalid(column))?;
            }
        }
        Ok(scanned)
    }

    /// 扫描报错时的 key:优先取文本主键列,不可解码则退化为 `rowid=<n>`(不回显任何内容)。
    fn scan_row_key(row: &sqlx::sqlite::SqliteRow, key_column: &str) -> String {
        use sqlx::Row;
        match row.try_get::<String, _>(key_column) {
            Ok(key) => key,
            Err(_) => Self::scan_rowid_key(row),
        }
    }

    /// 仅用 `rowid=<n>` 作为扫描报错 key(用于主键含用户可控内容的表);rowid 不可得时退化为 `corruption_key(None)`。
    fn scan_rowid_key(row: &sqlx::sqlite::SqliteRow) -> String {
        use sqlx::Row;
        match row.try_get::<i64, _>("rowid") {
            Ok(rowid) => format!("rowid={}", rowid),
            Err(_) => corruption_key(None),
        }
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
        let row: Option<AnchorOutboxRow> = sqlx::query_as(
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

    // ==================== 登录会话(sessions) ====================

    /// 创建会话。
    pub async fn create_session(&self, session: &SessionRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO sessions
                (id, user_id, refresh_family, created_at, last_seen_at, expires_at,
                 revoked_at, revoke_reason, ip_hash, ip_hint, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&session.id)
        .bind(&session.user_id)
        .bind(&session.refresh_family)
        .bind(session.created_at)
        .bind(session.last_seen_at)
        .bind(session.expires_at)
        .bind(session.revoked_at)
        .bind(&session.revoke_reason)
        .bind(&session.ip_hash)
        .bind(&session.ip_hint)
        .bind(&session.user_agent)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 按 id 读取会话(含已撤销/已过期)。
    pub async fn get_session(&self, id: &str) -> Result<Option<SessionRecord>> {
        let row = sqlx::query_as::<_, SessionRow>(&format!(
            "SELECT {} FROM sessions WHERE id = ?",
            SESSION_COLUMNS
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(SessionRecord::from))
    }

    /// 列出某用户未撤销且 `expires_at > now` 的会话,按创建时间升序。
    pub async fn list_active_sessions(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<SessionRecord>> {
        let rows = sqlx::query_as::<_, SessionRow>(&format!(
            "SELECT {} FROM sessions \
             WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? \
             ORDER BY created_at ASC, id ASC",
            SESSION_COLUMNS
        ))
        .bind(user_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(SessionRecord::from).collect())
    }

    /// 撤销会话,并在同一事务内写入其 refresh family 的哨兵行。
    ///
    /// 返回 `true` 表示本次调用使会话由未撤销变为已撤销,`false` 表示会话不存在
    /// 或此前已撤销(幂等,不重复写入)。`ttl_secs` 用于哨兵行过期时间,语义同
    /// [`Storage::revoke_family`]。
    pub async fn revoke_session(&self, id: &str, reason: &str, ttl_secs: i64) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let mut tx = self.pool.begin().await?;

        // 条件更新兼作并发收口:只有一个调用能把 revoked_at 从 NULL 置位。
        let updated = sqlx::query(
            "UPDATE sessions SET revoked_at = ?, revoke_reason = ? \
             WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(reason)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            tx.commit().await?;
            return Ok(false);
        }

        let (user_id, family_id): (String, String) =
            sqlx::query_as("SELECT user_id, refresh_family FROM sessions WHERE id = ?")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
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
        .bind(Self::family_sentinel_jti(&family_id))
        .bind(&user_id)
        .bind(&family_id)
        .bind(reason)
        .bind(now + ttl_secs + 24 * 3600)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// 按 refresh family 读取会话(含已撤销/已过期)。family 与会话一一对应。
    pub async fn get_session_by_family(&self, family_id: &str) -> Result<Option<SessionRecord>> {
        let row = sqlx::query_as::<_, SessionRow>(&format!(
            "SELECT {} FROM sessions WHERE refresh_family = ?",
            SESSION_COLUMNS
        ))
        .bind(family_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(SessionRecord::from))
    }

    /// refresh 成功后更新会话的 `last_seen_at` 并顺延 `expires_at`。
    ///
    /// 仅作用于未撤销的会话;返回 `false` 表示会话已被撤销或不存在(与并发登出收口)。
    pub async fn touch_session(&self, id: &str, now: i64, new_expires_at: i64) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE sessions SET last_seen_at = ?, expires_at = MAX(expires_at, ?) \
             WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(new_expires_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// 撤销某用户全部未撤销会话,并在同一事务内写入各 family 的哨兵行。
    /// 返回本次被撤销的会话 id(幂等:已撤销的不重复返回)。
    pub async fn revoke_user_sessions(
        &self,
        user_id: &str,
        reason: &str,
        ttl_secs: i64,
    ) -> Result<Vec<String>> {
        let now = chrono::Utc::now().timestamp();
        let mut tx = self.pool.begin().await?;
        let ids =
            Self::revoke_user_sessions_in_tx(&mut tx, user_id, reason, ttl_secs, now, None).await?;
        tx.commit().await?;
        Ok(ids)
    }

    /// 事务内撤销用户全部未撤销会话(`except_session_id` 指定的会话除外)。
    /// 首条语句即为写操作(`UPDATE .. RETURNING`),
    /// 避免"先读后写"在多连接下的读锁升级冲突。
    async fn revoke_user_sessions_in_tx(
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        user_id: &str,
        reason: &str,
        ttl_secs: i64,
        now: i64,
        except_session_id: Option<&str>,
    ) -> Result<Vec<String>> {
        let revoked: Vec<(String, String)> = sqlx::query_as(
            "UPDATE sessions SET revoked_at = ?, revoke_reason = ? \
             WHERE user_id = ? AND revoked_at IS NULL AND id != ? \
             RETURNING id, refresh_family",
        )
        .bind(now)
        .bind(reason)
        .bind(user_id)
        // 无保留会话时绑定空串:会话 id 恒为非空 uuid,`id != ''` 恒真。
        .bind(except_session_id.unwrap_or(""))
        .fetch_all(&mut **tx)
        .await?;
        for (_, family_id) in &revoked {
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
            .bind(Self::family_sentinel_jti(family_id))
            .bind(user_id)
            .bind(family_id)
            .bind(reason)
            .bind(now + ttl_secs + 24 * 3600)
            .bind(now)
            .execute(&mut **tx)
            .await?;
        }
        Ok(revoked.into_iter().map(|(id, _)| id).collect())
    }

    /// 惰性清理:删除某用户已过期的会话行(走 `idx_sessions_user`),返回删除行数。
    pub async fn purge_expired_sessions_for_user(&self, user_id: &str, now: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ? AND expires_at < ?")
            .bind(user_id)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// 清理全部已过期的会话行(服务启动时调用),返回删除行数。
    pub async fn purge_expired_sessions(&self, now: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // ==================== 认证审计日志 ====================

    /// 追加一条审计事件。文本字段会截断并转义控制字符;用户名同时规范化为小写。
    pub async fn append_audit_event(&self, event: &AuditEvent) -> Result<()> {
        let username = event
            .username_attempted
            .as_deref()
            .map(|u| sanitize_audit_text(&u.trim().to_lowercase(), AUDIT_USERNAME_MAX_CHARS));
        let user_agent = event
            .user_agent
            .as_deref()
            .map(|ua| sanitize_audit_text(ua, AUDIT_USER_AGENT_MAX_CHARS));
        let reason = event
            .reason
            .as_deref()
            .map(|r| sanitize_audit_text(r, AUDIT_REASON_MAX_CHARS));
        let actor_user_id = event
            .actor_user_id
            .as_deref()
            .map(|a| sanitize_audit_text(a, AUDIT_USERNAME_MAX_CHARS));
        sqlx::query(
            r#"
            INSERT INTO auth_audit_log
                (ts, event_type, user_id, username_attempted, session_id,
                 ip_hash, user_agent, result, reason, actor_user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.ts)
        .bind(sanitize_audit_text(&event.event_type, 64))
        .bind(&event.user_id)
        .bind(username)
        .bind(&event.session_id)
        .bind(&event.ip_hash)
        .bind(user_agent)
        .bind(sanitize_audit_text(&event.result, 32))
        .bind(reason)
        .bind(actor_user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 按写入顺序(id 升序)读取最多 `limit` 条审计事件。
    pub async fn list_audit_events(&self, limit: i64) -> Result<Vec<AuditEvent>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT id, ts, event_type, user_id, username_attempted, session_id, \
                    ip_hash, user_agent, result, reason, actor_user_id \
             FROM auth_audit_log ORDER BY id ASC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AuditEvent {
                id: r.id,
                ts: r.ts,
                event_type: r.event_type,
                user_id: r.user_id,
                username_attempted: r.username_attempted,
                session_id: r.session_id,
                ip_hash: r.ip_hash,
                user_agent: r.user_agent,
                result: r.result,
                reason: r.reason,
                actor_user_id: r.actor_user_id,
            })
            .collect())
    }

    /// 删除 `ts < cutoff_ts` 的审计行(启动时按保留期清理),返回删除行数。
    pub async fn purge_audit_before(&self, cutoff_ts: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM auth_audit_log WHERE ts < ?")
            .bind(cutoff_ts)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// 替换登录限速使用的时间源(默认系统时间)。
    ///
    /// 仅供测试注入时钟;目前只影响登录限速计数(`now_secs`),
    /// 会话过期等其他路径仍使用系统时间。
    #[doc(hidden)]
    pub fn set_clock(&self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) {
        *self.clock.write() = clock;
    }

    /// 当前时间(Unix 秒),来自可注入的时间源。
    pub fn now_secs(&self) -> i64 {
        (self.clock.read())()
    }

    /// 设置 is_active 缓存 TTL(默认 5 秒;`Duration::ZERO` 表示禁用缓存)。
    pub fn set_active_cache_ttl(&self, ttl: Duration) {
        self.active_cache_ttl_ms
            .store(ttl.as_millis() as u64, Ordering::Relaxed);
        self.active_cache.lock().clear();
    }

    /// 带短 TTL 缓存地读取用户启用状态(鉴权热路径使用)。
    ///
    /// 缓存只存成功查询的结果;查库失败直接返回 `Err`(调用方应 fail-closed)。
    /// [`Storage::set_user_active`] 会同步清除本进程缓存,故本进程内的禁用/启用即时生效;
    /// 其他进程直接改库的变更最多滞后一个 TTL。
    pub async fn is_user_active_cached(&self, user_id: &str) -> Result<bool> {
        let ttl = Duration::from_millis(self.active_cache_ttl_ms.load(Ordering::Relaxed));
        if ttl.is_zero() {
            return self.is_user_active(user_id).await;
        }
        if let Some((active, at)) = self.active_cache.lock().get(user_id).copied() {
            if at.elapsed() < ttl {
                return Ok(active);
            }
        }
        let generation = self.active_generation.load(Ordering::SeqCst);
        let active = self.is_user_active(user_id).await?;
        let mut cache = self.active_cache.lock();
        // 查询期间若发生过写入,结果可能已陈旧,不回填。
        if self.active_generation.load(Ordering::SeqCst) == generation {
            cache.insert(user_id.to_string(), (active, Instant::now()));
        }
        Ok(active)
    }

    /// 读取用户启用状态(以 SQLite 为权威)。用户不存在视为非活跃(fail-closed)。
    pub async fn is_user_active(&self, user_id: &str) -> Result<bool> {
        let row: Option<(bool,)> = sqlx::query_as("SELECT is_active FROM users WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(active,)| active).unwrap_or(false))
    }

    /// 用户是否存在于 SQLite(不看启用状态)。
    pub async fn user_exists(&self, user_id: &str) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// 写入用户启用状态。**仅启用路径使用**;停用必须用
    /// `deactivate_user_and_revoke_sessions`(本函数不撤销会话与 refresh family)。
    /// 返回 `true` 表示用户存在并已更新。
    pub async fn set_user_active(&self, user_id: &str, active: bool) -> Result<bool> {
        let result = sqlx::query("UPDATE users SET is_active = ? WHERE user_id = ?")
            .bind(active)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        self.invalidate_active_cache(user_id);
        Ok(result.rows_affected() > 0)
    }

    /// 停用用户并在**同一事务**内撤销其全部会话与 refresh family。
    ///
    /// 返回 `None` 表示用户不存在;`Some(n)` 为本次被撤销的会话数。
    /// 提交后同步清本进程 is_active 缓存,其他进程最迟一个 TTL 内感知。
    pub async fn deactivate_user_and_revoke_sessions(
        &self,
        user_id: &str,
        reason: &str,
        ttl_secs: i64,
    ) -> Result<Option<u64>> {
        let now = chrono::Utc::now().timestamp();
        let mut tx = self.pool.begin().await?;
        // 单条条件 UPDATE:判定与更新原子完成,拒绝停用最后一名活跃管理员。
        // 目标已停用时条件为真,命中 1 行,保持幂等成功。
        let updated = sqlx::query(
            "UPDATE users SET is_active = 0 WHERE user_id = ? \
             AND NOT (is_active = 1 AND role = 'admin' \
                 AND (SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1) <= 1)",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            let exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
            tx.commit().await?;
            return if exists.is_some() {
                Err(DataChainError::LastAdminProtected)
            } else {
                Ok(None)
            };
        }
        let revoked =
            Self::revoke_user_sessions_in_tx(&mut tx, user_id, reason, ttl_secs, now, None).await?;
        tx.commit().await?;
        self.invalidate_active_cache(user_id);
        Ok(Some(revoked.len() as u64))
    }

    /// 读取用户的 bcrypt 哈希(SQLite 为权威)。用户不存在返回 `None`。
    pub async fn get_user_password_hash(&self, user_id: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT password_hash FROM users WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(hash,)| hash))
    }

    /// 单事务:把密码哈希从 `old_hash` 乐观更新为 `new_hash`,并撤销除 `keep_session_id`
    /// 外的全部未撤销会话(写 family 哨兵)。
    ///
    /// 首条语句即为写操作(`UPDATE users .. WHERE user_id = ? AND password_hash = ?`),
    /// 同时充当乐观并发控制:并发改密中后到者因哈希已变而更新 0 行。
    /// - 返回 `Ok(Some(ids))`:更新成功,`ids` 为被撤销的会话 id;
    /// - 返回 `Ok(None)`:0 行(用户不存在,或哈希已被并发改密/其他途径改变),
    ///   调用方按 401 invalid credentials 处理。
    pub async fn update_user_password_and_revoke_other_sessions(
        &self,
        user_id: &str,
        old_hash: &str,
        new_hash: &str,
        keep_session_id: Option<&str>,
        reason: &str,
        ttl_secs: i64,
    ) -> Result<Option<Vec<String>>> {
        let now = chrono::Utc::now().timestamp();
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE users SET password_hash = ? WHERE user_id = ? AND password_hash = ?",
        )
        .bind(new_hash)
        .bind(user_id)
        .bind(old_hash)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            tx.commit().await?;
            return Ok(None);
        }
        let ids = Self::revoke_user_sessions_in_tx(
            &mut tx,
            user_id,
            reason,
            ttl_secs,
            now,
            keep_session_id,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(ids))
    }

    /// 单事务:无条件把密码哈希置为 `new_hash`,并撤销该用户全部未撤销会话(写 family 哨兵)。
    ///
    /// 用于运维重置(CLI `user passwd`),不校验旧哈希;与 API 改密并发时后写者胜。
    /// 首条语句即为写操作(`UPDATE users SET password_hash = ? WHERE user_id = ?`)。
    /// 返回 `Ok(None)` 表示用户不存在(未改动);`Ok(Some(n))` 为被撤销的会话数。
    pub async fn set_user_password_and_revoke_all_sessions(
        &self,
        user_id: &str,
        new_hash: &str,
        reason: &str,
        ttl_secs: i64,
    ) -> Result<Option<u64>> {
        let now = chrono::Utc::now().timestamp();
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query("UPDATE users SET password_hash = ? WHERE user_id = ?")
            .bind(new_hash)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        if updated.rows_affected() == 0 {
            tx.commit().await?;
            return Ok(None);
        }
        let revoked =
            Self::revoke_user_sessions_in_tx(&mut tx, user_id, reason, ttl_secs, now, None).await?;
        tx.commit().await?;
        Ok(Some(revoked.len() as u64))
    }

    /// 清本进程 is_active 缓存,并让在途的旧读不再回填。
    fn invalidate_active_cache(&self, user_id: &str) {
        let mut cache = self.active_cache.lock();
        self.active_generation.fetch_add(1, Ordering::SeqCst);
        cache.remove(user_id);
    }

    // ==================== 登录限速计数器 ====================

    /// 原子递增固定窗口计数器,返回 `(递增后的计数, 窗口起点)`。
    ///
    /// 单条 `INSERT .. ON CONFLICT DO UPDATE .. RETURNING`,不先读后写,并发不漏计。
    /// 同时惰性清理该 key 已过期的旧窗口。
    pub async fn incr_login_counter(
        &self,
        key: &str,
        now: i64,
        window_secs: i64,
    ) -> Result<(i64, i64)> {
        let window_start = now - now.rem_euclid(window_secs);
        let (count,): (i64,) = sqlx::query_as(
            r#"
            INSERT INTO login_rate_counters (key, window_start, count)
            VALUES (?, ?, 1)
            ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1
            RETURNING count
            "#,
        )
        .bind(key)
        .bind(window_start)
        .fetch_one(&self.pool)
        .await?;
        sqlx::query("DELETE FROM login_rate_counters WHERE key = ? AND window_start < ?")
            .bind(key)
            .bind(window_start)
            .execute(&self.pool)
            .await?;
        Ok((count, window_start))
    }

    /// 当前窗口计数减一(不低于 0)。用于成功登录归还 IP 维度的名额。
    pub async fn decr_login_counter(&self, key: &str, now: i64, window_secs: i64) -> Result<()> {
        let window_start = now - now.rem_euclid(window_secs);
        sqlx::query(
            "UPDATE login_rate_counters SET count = MAX(count - 1, 0) \
             WHERE key = ? AND window_start = ?",
        )
        .bind(key)
        .bind(window_start)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 清空某 key 的全部计数(成功登录后重置用户名维度)。
    pub async fn reset_login_counter(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM login_rate_counters WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ==================== 用户名维度指数退避锁定(login_lockouts) ====================

    /// 查询 key 当前是否处于锁定期:`now < locked_until` 时返回 `Some(locked_until)`。
    pub async fn get_login_lock(&self, key: &str, now: i64) -> Result<Option<i64>> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT locked_until FROM login_lockouts WHERE key = ? AND locked_until > ?",
        )
        .bind(key)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(locked_until,)| locked_until))
    }

    /// 落锁并返回生效的 `locked_until`。
    ///
    /// 单条 `INSERT .. ON CONFLICT DO UPDATE .. RETURNING`,不先读后写:
    /// - 无记录:插入 `level=1`、`locked_until = now + min(base, max)`;
    /// - 仍在锁定期(`locked_until > now`):保持原值,并发请求不会重复升级;
    /// - 距上次锁定结束已满 `reset`(`now - locked_until >= reset`):级别回到 1;
    /// - 否则 `level = min(level + 1, 20)`,`locked_until = now + min(min(base,max) << level_before, max)`
    ///   (`level_before` 取旧级别并限制在 20 以内,避免移位溢出)。
    ///
    /// 随后在同一事务内删除该 key 的窗口计数(锁到期后拥有完整配额),并清理陈旧锁定行。
    /// SQL 一律用顺序 `?` 占位符并按出现顺序重复 bind,不依赖 `?N` 编号复用。
    pub async fn lock_login_key(
        &self,
        key: &str,
        now: i64,
        base_secs: i64,
        max_secs: i64,
        reset_secs: i64,
    ) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        let (locked_until,): (i64,) = sqlx::query_as(
            r#"
            INSERT INTO login_lockouts (key, level, locked_until)
            VALUES (?, 1, ? + MIN(?, ?))
            ON CONFLICT(key) DO UPDATE SET
                level = CASE
                    WHEN login_lockouts.locked_until > ? THEN login_lockouts.level
                    WHEN ? - login_lockouts.locked_until >= ? THEN 1
                    ELSE MIN(login_lockouts.level + 1, 20)
                END,
                locked_until = CASE
                    WHEN login_lockouts.locked_until > ? THEN login_lockouts.locked_until
                    WHEN ? - login_lockouts.locked_until >= ? THEN ? + MIN(?, ?)
                    ELSE ? + MIN(MIN(?, ?) << MIN(login_lockouts.level, 20), ?)
                END
            RETURNING locked_until
            "#,
        )
        // VALUES
        .bind(key)
        .bind(now)
        .bind(base_secs)
        .bind(max_secs)
        // level CASE
        .bind(now)
        .bind(now)
        .bind(reset_secs)
        // locked_until CASE
        .bind(now)
        .bind(now)
        .bind(reset_secs)
        .bind(now)
        .bind(base_secs)
        .bind(max_secs)
        .bind(now)
        .bind(base_secs)
        .bind(max_secs)
        .bind(max_secs)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM login_rate_counters WHERE key = ?")
            .bind(key)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM login_lockouts WHERE locked_until < ?")
            .bind(now - reset_secs)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(locked_until)
    }

    /// 解锁:单事务内对每个 key 依次删除 `login_lockouts` 与 `login_rate_counters` 的行,
    /// 返回累计删除行数。首条语句即为写操作(事务以写模式开始,避免读升级写的 BUSY)。
    pub async fn clear_login_keys(&self, keys: &[String]) -> Result<UnlockOutcome> {
        let mut tx = self.pool.begin().await?;
        let mut outcome = UnlockOutcome {
            locks_cleared: 0,
            counters_cleared: 0,
        };
        for key in keys {
            outcome.locks_cleared += sqlx::query("DELETE FROM login_lockouts WHERE key = ?")
                .bind(key)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            outcome.counters_cleared +=
                sqlx::query("DELETE FROM login_rate_counters WHERE key = ?")
                    .bind(key)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
        }
        tx.commit().await?;
        Ok(outcome)
    }

    /// 严格扫描 `login_lockouts` 全表(锁定状态是访问决策依据,损坏必须 fail-closed)。
    ///
    /// 流式逐行校验(`fetch` + `try_next`),错误 key 固定为 `rowid=<n>`,不回显 `key` 列
    /// (其值含攻击者可控的用户名);reason 为 `invalid_column:<列>`。
    pub async fn scan_login_lockouts(&self) -> Result<usize> {
        use futures_util::TryStreamExt;
        use sqlx::Row;
        let mut scanned: usize = 0;
        let mut rows = sqlx::query(
            "SELECT rowid, key, level, locked_until FROM login_lockouts ORDER BY rowid ASC",
        )
        .fetch(&self.pool);
        while let Some(row) = rows.try_next().await? {
            scanned += 1;
            let key = Self::scan_rowid_key(&row);
            let invalid = |column: &str| DataChainError::DataCorruption {
                category: CorruptionCategory::Authoritative,
                table: "login_lockouts",
                key: key.clone(),
                reason: format!("invalid_column:{}", column),
            };
            row.try_get::<String, _>("key")
                .map_err(|_| invalid("key"))?;
            for column in ["level", "locked_until"] {
                row.try_get::<i64, _>(column).map_err(|_| invalid(column))?;
            }
        }
        Ok(scanned)
    }

    /// 删除 `locked_until < cutoff` 的陈旧锁定行(启动时清理),返回删除行数。
    pub async fn purge_login_lockouts_before(&self, cutoff: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM login_lockouts WHERE locked_until < ?")
            .bind(cutoff)
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
        let actual: Option<(i64,)> = sqlx::query_as(&count_sql).fetch_one(&self.pool).await.ok();
        let actual = match actual {
            Some((n,)) => n,
            None => return true,
        };
        if actual != expected {
            return true;
        }

        // 数量一致时再抽样校验可解析性:逐行尝试反序列化 data 列。
        let data_sql = format!("SELECT data FROM {}", table);
        let rows: Option<Vec<(String,)>> =
            sqlx::query_as(&data_sql).fetch_all(&self.pool).await.ok();
        match rows {
            None => true,
            Some(rows) => rows
                .iter()
                .any(|(data,)| serde_json::from_str::<serde_json::Value>(data).is_err()),
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

        storage.commit_block(&block, &[]).await.unwrap();

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

        storage.commit_block(&block, &[]).await.unwrap();

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

    fn pending_identity_entry(target_key: &str) -> crate::core::KeyTransactionEntry {
        crate::core::KeyTransactionEntry {
            tx_type: "register".to_string(),
            target_key: target_key.to_string(),
            role: "node".to_string(),
            label: "pending".to_string(),
            signed_by: target_key.to_string(),
            signature: "signature".to_string(),
            timestamp: 10,
            reason: String::new(),
        }
    }

    #[tokio::test]
    async fn identity_transaction_is_durable_idempotent_and_committed_with_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let entry = pending_identity_entry("key-a");

        let first = storage
            .create_or_get_identity_transaction(
                "user-a",
                Some("idempotency-a"),
                "fingerprint-a",
                &entry,
                10,
            )
            .await
            .unwrap();
        assert!(first.created, "首次提交必须创建 pending 账本行");
        assert_eq!(first.transaction.status, "pending");

        let replay = storage
            .create_or_get_identity_transaction(
                "user-a",
                Some("idempotency-a"),
                "fingerprint-a",
                &entry,
                20,
            )
            .await
            .unwrap();
        assert!(!replay.created, "相同用户与幂等键重试不得创建第二行");
        assert_eq!(
            replay.transaction.transaction_id,
            first.transaction.transaction_id
        );
        assert_eq!(
            storage
                .get_pending_identity_transactions()
                .await
                .unwrap()
                .len(),
            1
        );

        let mismatch = storage
            .create_or_get_identity_transaction(
                "user-a",
                Some("idempotency-a"),
                "fingerprint-b",
                &entry,
                20,
            )
            .await;
        assert!(matches!(
            mismatch,
            Err(DataChainError::IdentityTransactionConflict)
        ));

        let unmapped = storage
            .create_or_get_identity_transaction(
                "user-a",
                Some("idempotency-unmapped"),
                "fingerprint-unmapped",
                &pending_identity_entry("key-unmapped"),
                30,
            )
            .await
            .unwrap()
            .transaction;

        let mut block = Block::new(1, "0".repeat(64), 2);
        block.key_transactions = vec![pending_identity_entry("legacy-key"), entry];
        block.hash = "h".repeat(16);
        storage
            .commit_block(
                &block,
                &[None, Some(first.transaction.transaction_id.clone())],
            )
            .await
            .unwrap();

        let committed = storage
            .get_identity_transaction(&first.transaction.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(committed.status, "committed");
        assert_eq!(committed.committed_block_index, Some(1));
        let unmapped = storage
            .get_identity_transaction(&unmapped.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unmapped.status, "pending", "None 映射不得更新身份账本");
        assert!(storage
            .get_pending_identity_transactions()
            .await
            .unwrap()
            .iter()
            .any(|transaction| transaction.transaction_id == unmapped.transaction_id));
    }

    #[tokio::test]
    async fn pending_identity_transactions_restore_first_acceptance_order() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let first = storage
            .create_or_get_identity_transaction(
                "user-a",
                Some("idempotency-a"),
                "fingerprint-a",
                &pending_identity_entry("key-a"),
                10,
            )
            .await
            .unwrap();
        let second = storage
            .create_or_get_identity_transaction(
                "user-a",
                Some("idempotency-b"),
                "fingerprint-b",
                &pending_identity_entry("key-b"),
                20,
            )
            .await
            .unwrap();

        let pending = storage.get_pending_identity_transactions().await.unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].transaction_id, first.transaction.transaction_id);
        assert_eq!(pending[1].transaction_id, second.transaction.transaction_id);
    }

    #[tokio::test]
    async fn identity_transaction_commit_failure_rolls_back_block_and_keeps_pending() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let entry = pending_identity_entry("key-a");
        let transaction = storage
            .create_or_get_identity_transaction(
                "user-a",
                Some("idempotency-a"),
                "fingerprint-a",
                &entry,
                10,
            )
            .await
            .unwrap()
            .transaction;
        let mut block = Block::new(1, "0".repeat(64), 2);
        block.key_transactions.push(entry);
        block.hash = "h".repeat(16);

        let error = storage
            .commit_block(&block, &[Some("missing-transaction".to_string())])
            .await
            .unwrap_err();
        assert!(matches!(error, DataChainError::StorageError(_)));
        assert_eq!(
            storage.get_block_count().await.unwrap(),
            0,
            "失败事务不得留下已写入区块"
        );
        let pending = storage
            .get_identity_transaction(&transaction.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.status, "pending", "失败事务不得转换账本状态");
        assert_eq!(pending.committed_block_index, None);
    }

    #[tokio::test]
    async fn commit_block_rejects_cross_instance_sidecars_in_a_different_entry_order() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage_a = Storage::new(path.to_str().unwrap()).await.unwrap();
        let storage_b = Storage::new(path.to_str().unwrap()).await.unwrap();
        let first = storage_a
            .create_or_get_identity_transaction(
                "user-a",
                None,
                "fingerprint-a",
                &pending_identity_entry("key-a"),
                10,
            )
            .await
            .unwrap()
            .transaction;
        let second = storage_a
            .create_or_get_identity_transaction(
                "user-a",
                None,
                "fingerprint-b",
                &pending_identity_entry("key-b"),
                20,
            )
            .await
            .unwrap()
            .transaction;
        let mut block = Block::new(1, "0".repeat(64), 1);
        block.key_transactions = vec![
            pending_identity_entry("key-a"),
            pending_identity_entry("key-b"),
        ];
        block.hash = "h".repeat(16);

        let error = storage_b
            .commit_block(
                &block,
                &[
                    Some(second.transaction_id.clone()),
                    Some(first.transaction_id.clone()),
                ],
            )
            .await
            .unwrap_err();

        assert!(matches!(error, DataChainError::StorageError(_)));
        assert_eq!(storage_a.get_block_count().await.unwrap(), 0);
        for transaction_id in [&first.transaction_id, &second.transaction_id] {
            assert_eq!(
                storage_a
                    .get_identity_transaction(transaction_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                "pending"
            );
        }
    }

    #[tokio::test]
    async fn commit_block_rejects_identity_sidecars_for_metadata_only_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let transaction = storage
            .create_or_get_identity_transaction(
                "user-a",
                None,
                "fingerprint-a",
                &pending_identity_entry("key-a"),
                10,
            )
            .await
            .unwrap()
            .transaction;
        let mut block = Block::new(1, "0".repeat(64), 1);
        block.hash = "h".repeat(16);

        let error = storage
            .commit_block(&block, &[Some(transaction.transaction_id.clone())])
            .await
            .unwrap_err();

        assert!(matches!(error, DataChainError::StorageError(_)));
        assert_eq!(storage.get_block_count().await.unwrap(), 0);
        assert_eq!(
            storage
                .get_identity_transaction(&transaction.transaction_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
    }

    #[tokio::test]
    async fn rebuild_projections_leaves_identity_transaction_ledger_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rebuild-ledger.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let entry = pending_identity_entry("key-a");
        let created = storage
            .create_or_get_identity_transaction("user-a", Some("k"), "fp", &entry, 1)
            .await
            .unwrap();

        storage.rebuild_projections(&[]).await.unwrap();

        let after = storage
            .get_identity_transaction(&created.transaction.transaction_id)
            .await
            .unwrap()
            .expect("identity_transactions 是权威账本,重建投影不得清空");
        assert_eq!(after.status, "pending");
        assert_eq!(
            storage
                .get_pending_identity_transactions()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn rebuild_projections_leaves_committed_identity_transaction_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rebuild-committed-ledger.sqlite");
        let storage = Storage::new(path.to_str().unwrap()).await.unwrap();
        let entry = pending_identity_entry("key-a");
        let created = storage
            .create_or_get_identity_transaction("user-a", Some("k"), "fp", &entry, 1)
            .await
            .unwrap()
            .transaction;

        // 经 commit_block 把 pending 身份交易转为 committed。
        let mut block = Block::new(1, "0".repeat(64), 1);
        block.key_transactions.push(entry);
        block.hash = "h".repeat(16);
        storage
            .commit_block(&block, &[Some(created.transaction_id.clone())])
            .await
            .unwrap();
        let before = storage
            .get_identity_transaction(&created.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.status, "committed");
        assert_eq!(before.committed_block_index, Some(1));

        // 重建投影(重放该区块)不得改动 committed 账本行。
        storage
            .rebuild_projections(std::slice::from_ref(&block))
            .await
            .unwrap();

        let after = storage
            .get_identity_transaction(&created.transaction_id)
            .await
            .unwrap()
            .expect("committed 账本行不得被重建投影清除");
        assert_eq!(after.status, "committed");
        assert_eq!(after.committed_block_index, Some(1));
        assert_eq!(after.submitter_user_id, before.submitter_user_id);
        assert_eq!(after.idempotency_key, before.idempotency_key);
        assert_eq!(after.request_fingerprint, before.request_fingerprint);
        assert_eq!(after.accepted_at, before.accepted_at);
        assert_eq!(
            serde_json::to_value(&after.entry).unwrap(),
            serde_json::to_value(&before.entry).unwrap()
        );
        assert!(
            storage
                .get_pending_identity_transactions()
                .await
                .unwrap()
                .is_empty(),
            "committed 行不应回到 pending 列表"
        );
    }

    #[tokio::test]
    async fn schema_version_six_upgrades_identity_transactions_with_recovery_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("schema-v6.sqlite");
        let dsn = path.to_str().unwrap();
        {
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&format!("sqlite:{}?mode=rwc", dsn))
                .await
                .unwrap();
            sqlx::query(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
            )
            .execute(&pool)
            .await
            .unwrap();
            for version in 1..=6 {
                sqlx::query("INSERT INTO schema_migrations (version) VALUES (?)")
                    .bind(version)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            pool.close().await;
        }

        let storage = Storage::new(dsn).await.unwrap();
        let (version,): (i64,) = sqlx::query_as("SELECT MAX(version) FROM schema_migrations")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(version, 13);
        let index_sql: (String,) = sqlx::query_as(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_identity_transactions_submitter_idempotency'",
        )
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert!(index_sql.0.contains("WHERE idempotency_key IS NOT NULL"));

        let entry = pending_identity_entry("key-a");
        let first = storage
            .create_or_get_identity_transaction("user-a", Some("same-key"), "fp-a", &entry, 1)
            .await
            .unwrap();
        let second = storage
            .create_or_get_identity_transaction("user-b", Some("same-key"), "fp-b", &entry, 2)
            .await
            .unwrap();
        let recovery_state: (String,) = sqlx::query_as(
            "SELECT recovery_state FROM identity_transactions WHERE transaction_id = ?",
        )
        .bind(&first.transaction.transaction_id)
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert_eq!(recovery_state.0, "verified");
        assert_ne!(
            first.transaction.transaction_id, second.transaction.transaction_id,
            "部分唯一索引必须按 submitter_user_id 隔离相同幂等键"
        );
    }
}
