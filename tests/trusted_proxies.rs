//! C3(B1):trusted_proxies 的 XFF 取址与 HTTP 接入行为测试。
//! A 组走公开纯函数 `TrustedProxies::resolve_client_ip`;
//! B 组经 `create_router` + oneshot(手动注入 ConnectInfo)驱动,沿用 sessions_api 的构造方式。
mod common;

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use common::*;
use datachain::api::{self, AppState, RateLimiter};
use datachain::auth::Role;
use datachain::net::TrustedProxies;
use serde_json::json;
use tower::ServiceExt;

// ---------------------------------------------------------------- A 组:纯函数

fn proxies(items: &[&str]) -> TrustedProxies {
    let items: Vec<String> = items.iter().map(|s| s.to_string()).collect();
    TrustedProxies::parse(&items).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn xff(values: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for v in values {
        headers.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
    }
    headers
}

#[test]
fn empty_list_returns_peer_and_ignores_xff() {
    let tp = proxies(&[]);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["203.0.113.5"]));
    assert_eq!(got, Some(ip("10.0.0.1")));
}

#[test]
fn untrusted_peer_ignores_forged_xff() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("198.51.100.9")), &xff(&["203.0.113.5"]));
    assert_eq!(got, Some(ip("198.51.100.9")));
}

#[test]
fn trusted_peer_with_single_value_takes_it() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["203.0.113.5"]));
    assert_eq!(got, Some(ip("203.0.113.5")));
}

#[test]
fn walks_right_to_left_and_stops_at_first_untrusted() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(
        Some(ip("10.0.0.1")),
        &xff(&["1.1.1.1, 203.0.113.5, 10.0.0.2"]),
    );
    assert_eq!(
        got,
        Some(ip("203.0.113.5")),
        "左侧 1.1.1.1 是可伪造部分,不应被取用"
    );
}

#[test]
fn all_trusted_returns_leftmost() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(
        Some(ip("10.0.0.1")),
        &xff(&["10.0.0.7, 10.0.0.3, 10.0.0.2"]),
    );
    assert_eq!(got, Some(ip("10.0.0.7")));
}

#[test]
fn unparsable_entry_stops_at_previous_trusted_hop() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["garbage, 10.0.0.2"]));
    assert_eq!(got, Some(ip("10.0.0.2")));
}

#[test]
fn empty_entry_stops_at_previous_trusted_hop() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["203.0.113.5, , 10.0.0.2"]));
    assert_eq!(got, Some(ip("10.0.0.2")));
}

#[test]
fn unparsable_rightmost_entry_returns_peer() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["203.0.113.5, garbage"]));
    assert_eq!(got, Some(ip("10.0.0.1")));
}

#[test]
fn more_than_32_entries_falls_back_to_peer() {
    let tp = proxies(&["10.0.0.0/8"]);
    let at_limit = vec!["10.0.0.2"; 32].join(", ");
    let over = vec!["10.0.0.2"; 33].join(", ");
    assert_eq!(
        tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&[&at_limit])),
        Some(ip("10.0.0.2")),
        "32 条仍在上限内,全可信取最左"
    );
    assert_eq!(
        tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&[&over])),
        Some(ip("10.0.0.1")),
        "33 条超限,返回对端"
    );
}

#[test]
fn oversized_header_falls_back_to_peer() {
    let tp = proxies(&["10.0.0.0/8"]);
    let padding = " ".repeat(2100);
    let value = format!("203.0.113.5,{}, 10.0.0.2", padding);
    assert!(value.len() > 2048);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&[&value]));
    assert_eq!(got, Some(ip("10.0.0.1")));
}

#[test]
fn multiple_header_lines_are_concatenated_in_order() {
    let tp = proxies(&["10.0.0.0/8"]);
    // 等价于 "203.0.113.5, 10.0.0.2"
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["203.0.113.5", "10.0.0.2"]));
    assert_eq!(got, Some(ip("203.0.113.5")));
    // 顺序反过来等价于 "10.0.0.2, 203.0.113.5":最右是 203.0.113.5(不可信)
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["10.0.0.2", "203.0.113.5"]));
    assert_eq!(got, Some(ip("203.0.113.5")));
    let got = tp.resolve_client_ip(
        Some(ip("10.0.0.1")),
        &xff(&["1.1.1.1, 203.0.113.5", "10.0.0.2"]),
    );
    assert_eq!(got, Some(ip("203.0.113.5")));
}

#[test]
fn entries_with_port_and_bracketed_v6_are_parsed() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["1.2.3.4:80, 10.0.0.2"]));
    assert_eq!(got, Some(ip("1.2.3.4")));
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &xff(&["[2001:db8::1]:443, 10.0.0.2"]));
    assert_eq!(got, Some(ip("2001:db8::1")));
}

#[test]
fn v4_mapped_v6_peer_is_judged_as_v4() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("::ffff:10.0.0.1")), &xff(&["203.0.113.5"]));
    assert_eq!(got, Some(ip("203.0.113.5")));
}

#[test]
fn trusted_peer_without_xff_returns_peer() {
    let tp = proxies(&["10.0.0.0/8"]);
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &HeaderMap::new());
    assert_eq!(got, Some(ip("10.0.0.1")));
}

#[test]
fn missing_peer_returns_none() {
    let tp = proxies(&["10.0.0.0/8"]);
    assert_eq!(tp.resolve_client_ip(None, &xff(&["203.0.113.5"])), None);
    assert_eq!(
        proxies(&[]).resolve_client_ip(None, &HeaderMap::new()),
        None
    );
}

#[test]
fn x_real_ip_is_never_consulted() {
    let tp = proxies(&["10.0.0.0/8"]);
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.5"));
    let got = tp.resolve_client_ip(Some(ip("10.0.0.1")), &headers);
    assert_eq!(got, Some(ip("10.0.0.1")));
}

// ---------------------------------------------------------------- B 组:HTTP 层

const TRUSTED_PROXY_PEER: &str = "10.0.0.2:40000";

struct Fixture {
    router: axum::Router,
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn fixture_with_trusted(items: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (mut state, _) = build_state(dsn.to_str().unwrap()).await;
    state.rate_limiter =
        std::sync::Arc::new(RateLimiter::default().with_trusted_proxies(proxies(items)));
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        _dir: dir,
    }
}

fn with_peer_and_xff(mut req: Request<Body>, peer: &str, xff_value: Option<&str>) -> Request<Body> {
    let peer: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    if let Some(v) = xff_value {
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
    }
    req
}

async fn refresh_status(router: &axum::Router, peer: &str, xff_value: Option<&str>) -> StatusCode {
    let req = with_peer_and_xff(
        post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": "garbage"}),
        ),
        peer,
        xff_value,
    );
    router.clone().oneshot(req).await.unwrap().status()
}

async fn login_session_ip_hash(f: &Fixture, peer: &str, xff_value: Option<&str>) -> Option<String> {
    let req = with_peer_and_xff(
        post(
            "/api/v1/auth/login",
            None,
            json!({"username": "alice", "password": "alicepass123"}),
        ),
        peer,
        xff_value,
    );
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let claims = f
        .state
        .auth_service
        .validate_token(body["data"]["token"].as_str().unwrap())
        .unwrap();
    let session = f
        .state
        .storage
        .get_session(&claims.sid.unwrap())
        .await
        .unwrap()
        .unwrap();
    session.ip_hash
}

#[tokio::test]
async fn rate_limiter_client_ip_resolves_via_builder_proxies() {
    let limiter = RateLimiter::default().with_trusted_proxies(proxies(&["10.0.0.0/8"]));
    let got = limiter.client_ip(Some(ip("10.0.0.2")), &xff(&["203.0.113.5"]));
    assert_eq!(got, Some(ip("203.0.113.5")));
    // 默认(未配置)限流器不信任任何代理。
    let default = RateLimiter::default();
    let got = default.client_ip(Some(ip("10.0.0.2")), &xff(&["203.0.113.5"]));
    assert_eq!(got, Some(ip("10.0.0.2")));
}

#[tokio::test]
async fn session_ip_hash_is_digest_of_resolved_client_behind_trusted_proxy() {
    let f = fixture_with_trusted(&["10.0.0.0/8"]).await;
    let got = login_session_ip_hash(&f, TRUSTED_PROXY_PEER, Some("203.0.113.5")).await;
    assert_eq!(
        got.as_deref(),
        Some(f.state.auth_service.hash_client_ip("203.0.113.5").as_str()),
        "经可信代理应记录 XFF 解析出的客户端摘要"
    );
}

#[tokio::test]
async fn session_ip_hash_uses_peer_when_peer_is_untrusted() {
    let f = fixture_with_trusted(&["10.0.0.0/8"]).await;
    let got = login_session_ip_hash(&f, "198.51.100.9:40000", Some("203.0.113.5")).await;
    assert_eq!(
        got.as_deref(),
        Some(f.state.auth_service.hash_client_ip("198.51.100.9").as_str()),
        "不可信对端的 XFF 必须被忽略"
    );
}

#[tokio::test]
async fn clients_behind_same_trusted_proxy_get_independent_buckets() {
    let f = fixture_with_trusted(&["10.0.0.0/8"]).await;
    for i in 0..20 {
        let status = refresh_status(&f.router, TRUSTED_PROXY_PEER, Some("203.0.113.5")).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "A 第 {} 次不应限流",
            i + 1
        );
    }
    // 同一客户端第 21 次被限流。
    let status = refresh_status(&f.router, TRUSTED_PROXY_PEER, Some("203.0.113.5")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // 另一个客户端(同一代理后)拥有独立的桶,不受 A 影响。
    let status = refresh_status(&f.router, TRUSTED_PROXY_PEER, Some("203.0.113.6")).await;
    assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "B 应有独立桶");
}

#[tokio::test]
async fn untrusted_peer_cannot_bypass_rate_limit_by_forging_xff() {
    let f = fixture_with_trusted(&["10.0.0.0/8"]).await;
    let peer = "198.51.100.9:40000";
    for i in 0..20 {
        let forged = format!("203.0.113.{}", i);
        let status = refresh_status(&f.router, peer, Some(&forged)).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "第 {} 次不应限流",
            i + 1
        );
    }
    let status = refresh_status(&f.router, peer, Some("203.0.113.200")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "换 XFF 仍应落入同一对端桶"
    );
}
