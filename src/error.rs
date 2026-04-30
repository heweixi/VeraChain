use thiserror::Error;

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

    #[error("无效的令牌")]
    InvalidToken,

    #[error("令牌已过期")]
    TokenExpired,

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
}

pub type Result<T> = std::result::Result<T, DataChainError>;
