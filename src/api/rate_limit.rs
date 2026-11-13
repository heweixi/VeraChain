use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::AppState;

struct Window {
    started: Instant,
    count: u32,
}

/// 轻量进程内固定窗口限流器。生产多实例部署应换成 Redis/网关级限流。
pub struct RateLimiter {
    windows: Mutex<HashMap<String, Window>>,
    /// 上次淘汰过期 key 的时刻。
    last_sweep: Mutex<Instant>,
    window: Duration,
    normal_limit: u32,
    auth_limit: u32,
}

impl RateLimiter {
    pub fn new(normal_limit: u32, auth_limit: u32, window: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            last_sweep: Mutex::new(Instant::now()),
            window,
            normal_limit,
            auth_limit,
        }
    }

    /// 当前被跟踪的限流 key 数量(用于观察过期淘汰)。
    pub fn tracked_keys(&self) -> usize {
        self.windows.lock().len()
    }

    pub fn allow(&self, key: &str, is_auth: bool) -> bool {
        let limit = if is_auth {
            self.auth_limit
        } else {
            self.normal_limit
        };
        let now = Instant::now();
        let mut windows = self.windows.lock();
        self.evict_expired(&mut windows, now);
        let entry = windows.entry(key.to_string()).or_insert(Window {
            started: now,
            count: 0,
        });
        if now.duration_since(entry.started) >= self.window {
            entry.started = now;
            entry.count = 0;
        }
        if entry.count >= limit {
            return false;
        }
        entry.count += 1;
        true
    }
}

impl RateLimiter {
    /// 淘汰窗口已过期的 key,防止伪造/海量 key 让 map 无限增长。
    /// 每个窗口周期最多全量扫描一次;map 超过 `SWEEP_THRESHOLD` 时也立即扫描。
    fn evict_expired(&self, windows: &mut HashMap<String, Window>, now: Instant) {
        let mut last_sweep = self.last_sweep.lock();
        if now.duration_since(*last_sweep) >= self.window || windows.len() >= SWEEP_THRESHOLD {
            windows.retain(|_, w| now.duration_since(w.started) < self.window);
            *last_sweep = now;
        }
    }
}

/// map 条目数达到该值时,不等窗口周期结束就触发一次过期扫描。
const SWEEP_THRESHOLD: usize = 10_000;

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(120, 20, Duration::from_secs(60))
    }
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/health" {
        return next.run(request).await;
    }
    // 仅信任对端地址;X-Forwarded-For / X-Real-IP 可被客户端任意伪造,不参与限流 key。
    // 无 ConnectInfo(如进程内 oneshot 测试)时回退占位 key。
    let key = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let is_auth = path.starts_with("/api/v1/auth/");
    if !state
        .rate_limiter
        .allow(&format!("{}:{}", key, path), is_auth)
    {
        tracing::warn!("rate limit exceeded: key={} path={}", key, path);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(request).await
}
