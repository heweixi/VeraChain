use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub blockchain: BlockchainConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub aggregation: AggregationConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    #[serde(default = "default_difficulty")]
    pub difficulty: u32,
    #[serde(default = "default_block_size")]
    pub block_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_driver")]
    pub driver: String,
    #[serde(default = "default_dsn")]
    pub dsn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    #[serde(default = "default_secret")]
    pub secret: String,
    #[serde(default = "default_expire")]
    pub expire_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    #[serde(default = "default_time_interval")]
    pub time_interval_secs: u64,
    #[serde(default = "default_count_threshold")]
    pub count_threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

// 默认值函数
fn default_port() -> u16 {
    8080
}
fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_difficulty() -> u32 {
    4
}
fn default_block_size() -> usize {
    100
}
fn default_driver() -> String {
    "sqlite".to_string()
}
fn default_dsn() -> String {
    "./data/datachain.db".to_string()
}
fn default_secret() -> String {
    "datachain-secret-key-change-in-production".to_string()
}
fn default_expire() -> u64 {
    24
}
fn default_time_interval() -> u64 {
    3600
}
fn default_count_threshold() -> usize {
    1000
}
fn default_log_level() -> String {
    "info".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: default_port(),
                host: default_host(),
                tls_cert: None,
                tls_key: None,
            },
            blockchain: BlockchainConfig {
                difficulty: default_difficulty(),
                block_size: default_block_size(),
            },
            database: DatabaseConfig {
                driver: default_driver(),
                dsn: default_dsn(),
            },
            jwt: JwtConfig {
                secret: default_secret(),
                expire_hours: default_expire(),
            },
            aggregation: AggregationConfig {
                time_interval_secs: default_time_interval(),
                count_threshold: default_count_threshold(),
            },
            log: LogConfig {
                level: default_log_level(),
            },
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let mut config = if Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str::<AppConfig>(&content)?
        } else {
            Self::default()
        };

        config.apply_environment();
        config.validate()?;
        Ok(config)
    }

    /// 应用部署环境覆盖，避免把生产密钥写入配置文件。
    fn apply_environment(&mut self) {
        if let Ok(secret) = std::env::var("DATACHAIN_JWT_SECRET") {
            self.jwt.secret = secret;
        } else if let Ok(secret) = std::env::var("JWT_SECRET") {
            self.jwt.secret = secret;
        }
        if let Ok(dsn) = std::env::var("DATACHAIN_DATABASE_DSN") {
            self.database.dsn = dsn;
        }
        if let Ok(host) = std::env::var("DATACHAIN_SERVER_HOST") {
            self.server.host = host;
        }
        if let Ok(port) = std::env::var("DATACHAIN_SERVER_PORT") {
            if let Ok(port) = port.parse() {
                self.server.port = port;
            }
        }
        if let Ok(cert) = std::env::var("DATACHAIN_TLS_CERT") {
            self.server.tls_cert = Some(cert);
        }
        if let Ok(key) = std::env::var("DATACHAIN_TLS_KEY") {
            self.server.tls_key = Some(key);
        }
    }

    /// 校验生产安全前置条件。
    pub fn validate(&self) -> anyhow::Result<()> {
        let secret = self.jwt.secret.trim();
        if secret.len() < 32
            || secret == "your-secret-key-change-in-production"
            || secret == "datachain-secret-key-change-in-production"
        {
            anyhow::bail!("JWT secret must be at least 32 characters and not a default placeholder; set DATACHAIN_JWT_SECRET");
        }
        if self.server.port == 0 {
            anyhow::bail!("server port must be greater than zero");
        }
        if self.blockchain.block_size == 0 {
            anyhow::bail!("blockchain block_size must be greater than zero");
        }
        Ok(())
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
