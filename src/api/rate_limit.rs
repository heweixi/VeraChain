use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::AppState;
use crate::net::{ClientIp, TrustedProxies};

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
    /// 可信代理列表;默认为空(不信任任何代理,只用对端地址)。
    trusted_proxies: TrustedProxies,
}

impl RateLimiter {
    pub fn new(normal_limit: u32, auth_limit: u32, window: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            last_sweep: Mutex::new(Instant::now()),
            window,
            normal_limit,
            auth_limit,
            trusted_proxies: TrustedProxies::default(),
        }
    }

    /// 设置可信代理列表(builder)。
    pub fn with_trusted_proxies(mut self, trusted_proxies: TrustedProxies) -> Self {
        self.trusted_proxies = trusted_proxies;
        self
    }

    /// 按可信代理配置解析真实客户端 IP。
    pub fn client_ip(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        self.trusted_proxies.resolve_client_ip(peer, headers)
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
    mut request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }
    // 取对端地址后经可信代理配置解析一次真实客户端 IP:仅当对端属于可信代理时才读取
    // X-Forwarded-For(默认空列表即不读取,与此前行为一致)。无 ConnectInfo(如进程内
    // oneshot 测试)时回退占位 key。解析结果写入 ClientIp extension 供 handler 复用。
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let client_ip = state.rate_limiter.client_ip(peer, request.headers());
    request.extensions_mut().insert(ClientIp(client_ip));
    let key = client_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let path = request.uri().path();
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
