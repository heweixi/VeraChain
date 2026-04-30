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
fn default_port() -> u16 { 8080 }
fn default_host() -> String { "0.0.0.0".to_string() }
fn default_difficulty() -> u32 { 4 }
fn default_block_size() -> usize { 100 }
fn default_driver() -> String { "sqlite".to_string() }
fn default_dsn() -> String { "./data/datachain.db".to_string() }
fn default_secret() -> String { "datachain-secret-key-change-in-production".to_string() }
fn default_expire() -> u64 { 24 }
fn default_time_interval() -> u64 { 3600 }
fn default_count_threshold() -> usize { 1000 }
fn default_log_level() -> String { "info".to_string() }

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: default_port(),
                host: default_host(),
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
        if Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            let config: AppConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
