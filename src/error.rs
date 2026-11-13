use thiserror::Error;

/// 数据损坏的分类:权威源数据损坏必须 fail-closed;可重建投影损坏可在校验通过后重放修复。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionCategory {
    Authoritative,
    Rebuildable,
}

impl CorruptionCategory {
    fn as_str(&self) -> &'static str {
        match self {
            CorruptionCategory::Authoritative => "authoritative",
            CorruptionCategory::Rebuildable => "rebuildable",
        }
    }
}

#[derive(Error, Debug)]
pub enum DataChainError {
    #[error("区块未找到: {0}")]
    BlockNotFound(i64),

    #[error("无效的区块: {0}")]
    InvalidBlock(String),

    #[error("链未初始化")]
    ChainNotInitialized,

    #[error("无效的链")]
    InvalidChain,

    #[error("用户未找到: {0}")]
    UserNotFound(String),

    #[error("用户已存在: {0}")]
    UserExists(String),

    #[error("密码错误")]
    InvalidPassword,

    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("too many attempts")]
    TooManyAttempts { retry_after_secs: u64 },
    /// 新密码被策略拒绝;载荷为固定词表,可直接作为 400 响应的 error 文本。
    #[error("{0}")]
    PasswordRejected(&'static str),
    #[error("无效的令牌")]
    InvalidToken,

    #[error("令牌已过期")]
    TokenExpired,

    #[error("检测到刷新令牌复用,该登录会话已被撤销")]
    TokenReuseDetected,

    #[error("权限不足")]
    PermissionDenied,

    #[error("元数据未找到: {0}")]
    MetadataNotFound(String),

    #[error("版本未找到: {0}")]
    VersionNotFound(String),

    #[error("汇总失败: {0}")]
    AggregationFailed(String),

    #[error("存储错误: {0}")]
    StorageError(String),

    #[error("幂等键已用于不同的身份交易请求")]
    IdentityTransactionConflict,

    #[error("配置错误: {0}")]
    ConfigError(String),

    #[error("IO 错误: {0}")]
    IoError(#[from] std::io::Error),

    #[error("序列化错误: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("数据库错误: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("内部错误: {0}")]
    Internal(String),

    /// 结构化数据损坏错误。reason 只允许固定词表(见 corruption_reason 相关 helper),
    /// 禁止包含行内容、password_hash、secret、token 或任意 JSON 片段,防止敏感信息外泄。
    #[error("data corruption [{category}] table={table} key={key}: {reason}")]
    DataCorruption {
        category: CorruptionCategory,
        table: &'static str,
        key: String,
        reason: String,
    },
}

impl std::fmt::Display for CorruptionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 辅助:格式化 `DataCorruption` 的 key 字段(主键缺失/不可解析时用占位)。
pub fn corruption_key(value: Option<&str>) -> String {
    value.unwrap_or("<unknown>").to_string()
}

/// 将 serde_json 反序列化错误转换为固定词表 reason,不泄露被解析的原始内容。
///
/// 仅使用 `serde_json::Error::classify()` + `line()/column()`,不触碰错误的 Display
/// (某些实现可能回显片段)。
pub fn json_corruption_reason(err: &serde_json::Error) -> String {
    use serde_json::error::Category;
    match err.classify() {
        Category::Syntax => format!("json_syntax line={} col={}", err.line(), err.column()),
        Category::Data => "json_data".to_string(),
        Category::Eof => "json_eof".to_string(),
        Category::Io => "json_io".to_string(),
    }
}

/// 构造一条权威源/可重建投影的 `DataCorruption` 错误,reason 取自固定词表 helper。
pub fn corruption_from_json(
    category: CorruptionCategory,
    table: &'static str,
    key: Option<&str>,
    err: &serde_json::Error,
) -> DataChainError {
    DataChainError::DataCorruption {
        category,
        table,
        key: corruption_key(key),
        reason: json_corruption_reason(err),
    }
}

pub type Result<T> = std::result::Result<T, DataChainError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_fixed_format_and_does_not_leak_content() {
        let err = DataChainError::DataCorruption {
            category: CorruptionCategory::Authoritative,
            table: "users",
            key: "user-1".to_string(),
            reason: "json_data".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "data corruption [authoritative] table=users key=user-1: json_data"
        );
    }

    #[test]
    fn json_corruption_reason_never_echoes_value_content() {
        let bad: std::result::Result<serde_json::Value, _> =
            serde_json::from_str("{\"password_hash\":\"SECRET-XYZ\" invalid");
        let err = bad.unwrap_err();
        let reason = json_corruption_reason(&err);
        assert!(!reason.contains("SECRET-XYZ"));
        assert!(reason.starts_with("json_syntax") || reason == "json_data" || reason == "json_eof");
    }
}
