use axum::{extract::Request, extract::State, http::StatusCode, middleware::Next, response::{IntoResponse, Response}};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::AppState;

struct Window {
    started: Instant,
    count: u32,
}

/// 轻量进程内固定窗口限流器。生产多实例部署应换成 Redis/网关级限流。
pub struct RateLimiter {
    windows: Mutex<HashMap<String, Window>>,
    window: Duration,
    normal_limit: u32,
    auth_limit: u32,
}

impl RateLimiter {
    pub fn new(normal_limit: u32, auth_limit: u32, window: Duration) -> Self {
        Self { windows: Mutex::new(HashMap::new()), window, normal_limit, auth_limit }
    }

    pub fn allow(&self, key: &str, is_auth: bool) -> bool {
        let limit = if is_auth { self.auth_limit } else { self.normal_limit };
        let now = Instant::now();
        let mut windows = self.windows.lock();
        let entry = windows.entry(key.to_string()).or_insert(Window { started: now, count: 0 });
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
    let key = request
        .headers()
        .get("x-forwarded-for")
        .or_else(|| request.headers().get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim();
    let is_auth = path.starts_with("/api/v1/auth/");
    if !state.rate_limiter.allow(&format!("{}:{}", key, path), is_auth) {
        tracing::warn!("rate limit exceeded: key={} path={}", key, path);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(request).await
}
