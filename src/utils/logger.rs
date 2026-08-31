use tracing::Subscriber;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// 日志配置
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: String,
    pub format: LogFormat,
    pub show_target: bool,
    pub show_thread_ids: bool,
    pub show_line_numbers: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Pretty,
            show_target: true,
            show_thread_ids: false,
            show_line_numbers: true,
        }
    }
}

/// 日志格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
    Compact,
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" => Ok(LogFormat::Pretty),
            "json" => Ok(LogFormat::Json),
            "compact" => Ok(LogFormat::Compact),
            _ => Err(format!("Unknown log format: {}", s)),
        }
    }
}

/// 初始化日志系统
pub fn init_logger(config: &LogConfig) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    match config.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json())
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .compact()
                        .with_target(config.show_target)
                        .with_thread_ids(config.show_thread_ids)
                        .with_line_number(config.show_line_numbers),
                )
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .pretty()
                        .with_target(config.show_target)
                        .with_thread_ids(config.show_thread_ids)
                        .with_line_number(config.show_line_numbers)
                        .with_span_events(FmtSpan::CLOSE),
                )
                .init();
        }
    }
}

/// 简单初始化（使用默认配置）
pub fn init_default() {
    init_logger(&LogConfig::default());
}

/// 从环境变量初始化
pub fn init_from_env() {
    let level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let format = std::env::var("LOG_FORMAT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(LogFormat::Pretty);

    let config = LogConfig {
        level,
        format,
        ..Default::default()
    };

    init_logger(&config);
}

/// 日志宏 - 带上下文
#[macro_export]
macro_rules! log_with_context {
    ($level:expr, $ctx:expr, $($arg:tt)*) => {
        match $level {
            tracing::Level::ERROR => tracing::error!(context = %$ctx, $($arg)*),
            tracing::Level::WARN => tracing::warn!(context = %$ctx, $($arg)*),
            tracing::Level::INFO => tracing::info!(context = %$ctx, $($arg)*),
            tracing::Level::DEBUG => tracing::debug!(context = %$ctx, $($arg)*),
            tracing::Level::TRACE => tracing::trace!(context = %$ctx, $($arg)*),
        }
    };
}

/// 请求日志中间件辅助
pub struct RequestLogger {
    request_id: String,
    method: String,
    path: String,
    start_time: std::time::Instant,
}

impl RequestLogger {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            method: method.to_string(),
            path: path.to_string(),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn log_start(&self) {
        tracing::info!(
            request_id = %self.request_id,
            method = %self.method,
            path = %self.path,
            "请求开始"
        );
    }

    pub fn log_end(&self, status: u16) {
        let duration = self.start_time.elapsed();
        tracing::info!(
            request_id = %self.request_id,
            method = %self.method,
            path = %self.path,
            status = status,
            duration_ms = duration.as_millis(),
            "请求完成"
        );
    }

    pub fn log_error(&self, error: &str) {
        let duration = self.start_time.elapsed();
        tracing::error!(
            request_id = %self.request_id,
            method = %self.method,
            path = %self.path,
            error = %error,
            duration_ms = duration.as_millis(),
            "请求错误"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_parse() {
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("compact".parse::<LogFormat>().unwrap(), LogFormat::Compact);
    }
}
