//! C2(B2):认证参数配置化与 `TrustedProxies::parse` 的行为测试。
//!
//! 本文件在实现前应编译失败(Red):`datachain::net`、`AppConfig::load_with_env`、
//! `AppConfig::auth_settings`、`AuthConfig`、`AuthSettings`、`LockoutPolicy`、
//! `AuthService::with_settings` 目前都不存在。
//!
//! 环境变量一律经 `AppConfig::load_with_env(path, env_fn)` 注入,不使用 `set_var`,避免并行污染。
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use datachain::auth::{
    AuthService, AuthSettings, JwtHandler, LockoutPolicy, LoginContext, LoginLimits, LoginRequest,
    RegisterRequest,
};
use datachain::config::{AppConfig, AuthConfig};
use datachain::error::DataChainError;
use datachain::net::TrustedProxies;
use datachain::storage::create_storage;

const SECRET: &str = "0123456789abcdef0123456789abcdef-config-test";
/// 已对齐 900 秒固定窗口起点的 epoch 秒。
const ALIGNED_T0: i64 = 1_800_000_000;

// ---------- 辅助 ----------

/// 生成一份最小可加载的 TOML:六个必需表齐全,jwt.secret 合法;
/// `jwt_extra` 追加到 `[jwt]` 表内,`auth` 为 `[auth]` 段整体文本(可为空)。
fn toml_text(jwt_extra: &str, auth: &str) -> String {
    format!(
        "[server]\nport = 8080\n\n\
         [blockchain]\ndifficulty = 1\n\n\
         [database]\ndsn = \"x.db\"\n\n\
         [jwt]\nsecret = \"{secret}\"\n{jwt_extra}\n\n\
         [aggregation]\n\n\
         [log]\n\n\
         {auth}\n",
        secret = SECRET,
        jwt_extra = jwt_extra,
        auth = auth,
    )
}

/// 把 TOML 写入临时文件并经 `load_with_env` 加载;`env` 为注入的环境变量。
fn load(text: &str, env: &[(&str, &str)]) -> anyhow::Result<AppConfig> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, text).unwrap();
    let map: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    AppConfig::load_with_env(path.to_str().unwrap(), move |k| map.get(k).cloned())
}

/// 配置文件不存在 => 全部取默认值;JWT 密钥经注入的环境变量提供以通过 validate。
fn load_defaults() -> AppConfig {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.toml");
    let mut map = HashMap::new();
    map.insert("DATACHAIN_JWT_SECRET".to_string(), SECRET.to_string());
    AppConfig::load_with_env(path.to_str().unwrap(), move |k| map.get(k).cloned())
        .expect("无配置文件时应使用默认值加载成功")
}

fn err_text(r: anyhow::Result<AppConfig>) -> String {
    match r {
        Ok(_) => panic!("期望加载失败,实际成功"),
        Err(e) => format!("{:#}", e).to_lowercase(),
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// ---------- 默认值 ----------

#[test]
fn auth_config_defaults_match_current_hardcoded_values() {
    let a = AuthConfig::default();
    assert_eq!(a.login_user_max_attempts, 5);
    assert_eq!(a.login_ip_max_attempts, 20);
    assert_eq!(a.login_window_secs, 900);
    assert_eq!(a.lockout_base_secs, 900);
    assert_eq!(a.lockout_max_secs, 3600);
    assert_eq!(a.lockout_reset_secs, 86400);
    assert_eq!(a.audit_retention_days, 90);
    assert_eq!(a.active_cache_ttl_secs, 5);
    assert_eq!(a.password_min_length, 8);
    assert!(a.trusted_proxies.is_empty());
}

#[test]
fn app_config_default_and_loaded_defaults_match_current_values() {
    let from_default = AppConfig::default();
    assert_eq!(from_default.jwt.expire_hours, 24);
    assert_eq!(from_default.jwt.refresh_expire_days, 7);
    assert_eq!(from_default.auth.login_user_max_attempts, 5);

    let loaded = load_defaults();
    assert_eq!(loaded.jwt.expire_hours, 24);
    assert_eq!(loaded.jwt.refresh_expire_days, 7);
    assert_eq!(loaded.auth.login_user_max_attempts, 5);
    assert_eq!(loaded.auth.login_ip_max_attempts, 20);
    assert_eq!(loaded.auth.login_window_secs, 900);
    assert_eq!(loaded.auth.lockout_base_secs, 900);
    assert_eq!(loaded.auth.lockout_max_secs, 3600);
    assert_eq!(loaded.auth.lockout_reset_secs, 86400);
    assert_eq!(loaded.auth.audit_retention_days, 90);
    assert_eq!(loaded.auth.active_cache_ttl_secs, 5);
    assert_eq!(loaded.auth.password_min_length, 8);
    assert!(loaded.auth.trusted_proxies.is_empty());
}

#[test]
fn config_without_auth_section_uses_auth_defaults() {
    // 已有部署的 config.toml 没有 [auth] 与 jwt.refresh_expire_days,必须仍可加载。
    let cfg = load(&toml_text("", ""), &[]).expect("缺省 [auth] 应使用默认值");
    assert_eq!(cfg.auth.login_user_max_attempts, 5);
    assert_eq!(cfg.jwt.refresh_expire_days, 7);
}

#[test]
fn auth_settings_default_equals_current_behavior() {
    let s = AuthSettings::default();
    assert_eq!(s.access_expire_hours, 24);
    assert_eq!(s.refresh_expire_days, 7);
    assert_eq!(s.login_limits.user_max_attempts, 5);
    assert_eq!(s.login_limits.ip_max_attempts, 20);
    assert_eq!(s.login_limits.window_secs, 900);
    assert_eq!(s.lockout.base_secs, 900);
    assert_eq!(s.lockout.max_secs, 3600);
    assert_eq!(s.lockout.reset_secs, 86400);
    assert_eq!(s.password_min_length, 8);

    let p = LockoutPolicy::default();
    assert_eq!((p.base_secs, p.max_secs, p.reset_secs), (900, 3600, 86400));
}

#[test]
fn default_app_config_auth_settings_equals_default_auth_settings() {
    let from_cfg = load_defaults().auth_settings();
    let d = AuthSettings::default();
    assert_eq!(from_cfg.access_expire_hours, d.access_expire_hours);
    assert_eq!(from_cfg.refresh_expire_days, d.refresh_expire_days);
    assert_eq!(
        from_cfg.login_limits.user_max_attempts,
        d.login_limits.user_max_attempts
    );
    assert_eq!(
        from_cfg.login_limits.ip_max_attempts,
        d.login_limits.ip_max_attempts
    );
    assert_eq!(
        from_cfg.login_limits.window_secs,
        d.login_limits.window_secs
    );
    assert_eq!(from_cfg.lockout.base_secs, d.lockout.base_secs);
    assert_eq!(from_cfg.lockout.max_secs, d.lockout.max_secs);
    assert_eq!(from_cfg.lockout.reset_secs, d.lockout.reset_secs);
    assert_eq!(from_cfg.password_min_length, d.password_min_length);
}

// ---------- TOML 覆盖 ----------

const FULL_AUTH_TOML: &str = "[auth]\n\
    login_user_max_attempts = 7\n\
    login_ip_max_attempts = 30\n\
    login_window_secs = 600\n\
    lockout_base_secs = 120\n\
    lockout_max_secs = 1200\n\
    lockout_reset_secs = 7200\n\
    audit_retention_days = 30\n\
    active_cache_ttl_secs = 0\n\
    password_min_length = 12\n\
    trusted_proxies = [\"10.0.0.0/8\", \"192.168.1.1\", \"fd00::/8\"]\n";

#[test]
fn toml_overrides_every_auth_and_jwt_key() {
    let cfg = load(
        &toml_text("expire_hours = 48\nrefresh_expire_days = 14\n", FULL_AUTH_TOML),
        &[],
    )
    .expect("合法覆盖应加载成功");

    assert_eq!(cfg.jwt.expire_hours, 48);
    assert_eq!(cfg.jwt.refresh_expire_days, 14);
    assert_eq!(cfg.auth.login_user_max_attempts, 7);
    assert_eq!(cfg.auth.login_ip_max_attempts, 30);
    assert_eq!(cfg.auth.login_window_secs, 600);
    assert_eq!(cfg.auth.lockout_base_secs, 120);
    assert_eq!(cfg.auth.lockout_max_secs, 1200);
    assert_eq!(cfg.auth.lockout_reset_secs, 7200);
    assert_eq!(cfg.auth.audit_retention_days, 30);
    assert_eq!(cfg.auth.active_cache_ttl_secs, 0);
    assert_eq!(cfg.auth.password_min_length, 12);
    assert_eq!(
        cfg.auth.trusted_proxies,
        strings(&["10.0.0.0/8", "192.168.1.1", "fd00::/8"])
    );
}

#[test]
fn auth_settings_reflects_loaded_config() {
    let cfg = load(
        &toml_text("expire_hours = 48\nrefresh_expire_days = 14\n", FULL_AUTH_TOML),
        &[],
    )
    .unwrap();
    let s = cfg.auth_settings();
    assert_eq!(s.access_expire_hours, 48);
    assert_eq!(s.refresh_expire_days, 14);
    assert_eq!(s.login_limits.user_max_attempts, 7);
    assert_eq!(s.login_limits.ip_max_attempts, 30);
    assert_eq!(s.login_limits.window_secs, 600);
    assert_eq!(s.lockout.base_secs, 120);
    assert_eq!(s.lockout.max_secs, 1200);
    assert_eq!(s.lockout.reset_secs, 7200);
    assert_eq!(s.password_min_length, 12);
}

#[test]
fn boundary_values_are_accepted() {
    let max_auth = "[auth]\n\
        login_user_max_attempts = 1000\n\
        login_ip_max_attempts = 10000\n\
        login_window_secs = 86400\n\
        lockout_base_secs = 86400\n\
        lockout_max_secs = 604800\n\
        lockout_reset_secs = 2592000\n\
        audit_retention_days = 3650\n\
        active_cache_ttl_secs = 300\n\
        password_min_length = 72\n";
    load(&toml_text("expire_hours = 720\nrefresh_expire_days = 365\n", max_auth), &[])
        .expect("上边界应被接受");

    let min_auth = "[auth]\n\
        login_user_max_attempts = 1\n\
        login_ip_max_attempts = 1\n\
        login_window_secs = 60\n\
        lockout_base_secs = 60\n\
        lockout_max_secs = 60\n\
        lockout_reset_secs = 60\n\
        audit_retention_days = 1\n\
        active_cache_ttl_secs = 0\n\
        password_min_length = 4\n";
    load(&toml_text("expire_hours = 1\nrefresh_expire_days = 1\n", min_auth), &[])
        .expect("下边界应被接受");
}

// ---------- 环境变量覆盖 TOML ----------

#[test]
fn environment_overrides_toml_for_every_new_key() {
    let toml = toml_text("expire_hours = 48\nrefresh_expire_days = 14\n", FULL_AUTH_TOML);
    let cfg = load(
        &toml,
        &[
            ("DATACHAIN_JWT_EXPIRE_HOURS", "36"),
            ("DATACHAIN_JWT_REFRESH_EXPIRE_DAYS", "10"),
            ("DATACHAIN_AUTH_LOGIN_USER_MAX_ATTEMPTS", "9"),
            ("DATACHAIN_AUTH_LOGIN_IP_MAX_ATTEMPTS", "40"),
            ("DATACHAIN_AUTH_LOGIN_WINDOW_SECS", "300"),
            ("DATACHAIN_AUTH_LOCKOUT_BASE_SECS", "100"),
            ("DATACHAIN_AUTH_LOCKOUT_MAX_SECS", "1000"),
            ("DATACHAIN_AUTH_LOCKOUT_RESET_SECS", "5000"),
            ("DATACHAIN_AUTH_AUDIT_RETENTION_DAYS", "15"),
            ("DATACHAIN_AUTH_ACTIVE_CACHE_TTL_SECS", "20"),
            ("DATACHAIN_AUTH_PASSWORD_MIN_LENGTH", "10"),
            ("DATACHAIN_AUTH_TRUSTED_PROXIES", "172.16.0.0/12,203.0.113.7"),
        ],
    )
    .expect("环境变量覆盖应加载成功");

    assert_eq!(cfg.jwt.expire_hours, 36);
    assert_eq!(cfg.jwt.refresh_expire_days, 10);
    assert_eq!(cfg.auth.login_user_max_attempts, 9);
    assert_eq!(cfg.auth.login_ip_max_attempts, 40);
    assert_eq!(cfg.auth.login_window_secs, 300);
    assert_eq!(cfg.auth.lockout_base_secs, 100);
    assert_eq!(cfg.auth.lockout_max_secs, 1000);
    assert_eq!(cfg.auth.lockout_reset_secs, 5000);
    assert_eq!(cfg.auth.audit_retention_days, 15);
    assert_eq!(cfg.auth.active_cache_ttl_secs, 20);
    assert_eq!(cfg.auth.password_min_length, 10);
    assert_eq!(
        cfg.auth.trusted_proxies,
        strings(&["172.16.0.0/12", "203.0.113.7"])
    );
}

#[test]
fn environment_alone_overrides_defaults_without_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.toml");
    let mut map = HashMap::new();
    map.insert("DATACHAIN_JWT_SECRET".to_string(), SECRET.to_string());
    map.insert(
        "DATACHAIN_AUTH_LOGIN_USER_MAX_ATTEMPTS".to_string(),
        "3".to_string(),
    );
    let cfg = AppConfig::load_with_env(path.to_str().unwrap(), move |k| map.get(k).cloned())
        .unwrap();
    assert_eq!(cfg.auth.login_user_max_attempts, 3);
    assert_eq!(cfg.auth.login_ip_max_attempts, 20, "未设置的键保持默认");
}

// ---------- 非法值(表驱动) ----------

struct Bad {
    name: &'static str,
    jwt_extra: &'static str,
    auth: &'static str,
    env: &'static [(&'static str, &'static str)],
    /// 错误文本(小写化后)必须包含的片段:键名或变量名。
    needle: &'static str,
}

#[test]
fn invalid_values_fail_with_key_or_variable_name() {
    let cases = [
        // ---- jwt.expire_hours / jwt.refresh_expire_days ----
        Bad { name: "expire_hours=0", jwt_extra: "expire_hours = 0", auth: "", env: &[], needle: "expire_hours" },
        Bad { name: "expire_hours=721", jwt_extra: "expire_hours = 721\nrefresh_expire_days = 365", auth: "", env: &[], needle: "expire_hours" },
        Bad { name: "refresh_days=0", jwt_extra: "refresh_expire_days = 0", auth: "", env: &[], needle: "refresh_expire_days" },
        Bad { name: "refresh_days=366", jwt_extra: "refresh_expire_days = 366", auth: "", env: &[], needle: "refresh_expire_days" },
        Bad { name: "refresh<access", jwt_extra: "expire_hours = 48\nrefresh_expire_days = 1", auth: "", env: &[], needle: "refresh_expire_days" },
        // ---- auth 范围 ----
        Bad { name: "user_max=0", jwt_extra: "", auth: "[auth]\nlogin_user_max_attempts = 0", env: &[], needle: "login_user_max_attempts" },
        Bad { name: "user_max=1001", jwt_extra: "", auth: "[auth]\nlogin_user_max_attempts = 1001", env: &[], needle: "login_user_max_attempts" },
        Bad { name: "ip_max=0", jwt_extra: "", auth: "[auth]\nlogin_ip_max_attempts = 0", env: &[], needle: "login_ip_max_attempts" },
        Bad { name: "ip_max=10001", jwt_extra: "", auth: "[auth]\nlogin_ip_max_attempts = 10001", env: &[], needle: "login_ip_max_attempts" },
        Bad { name: "window=59", jwt_extra: "", auth: "[auth]\nlogin_window_secs = 59", env: &[], needle: "login_window_secs" },
        Bad { name: "window=86401", jwt_extra: "", auth: "[auth]\nlogin_window_secs = 86401", env: &[], needle: "login_window_secs" },
        Bad { name: "base=59", jwt_extra: "", auth: "[auth]\nlockout_base_secs = 59", env: &[], needle: "lockout_base_secs" },
        Bad {
            name: "base=86401",
            jwt_extra: "",
            auth: "[auth]\nlockout_base_secs = 86401\nlockout_max_secs = 604800\nlockout_reset_secs = 2592000",
            env: &[],
            needle: "lockout_base_secs",
        },
        Bad { name: "max<base", jwt_extra: "", auth: "[auth]\nlockout_max_secs = 30", env: &[], needle: "lockout_max_secs" },
        Bad {
            name: "max=604801",
            jwt_extra: "",
            auth: "[auth]\nlockout_max_secs = 604801\nlockout_reset_secs = 2592000",
            env: &[],
            needle: "lockout_max_secs",
        },
        Bad { name: "reset<max", jwt_extra: "", auth: "[auth]\nlockout_reset_secs = 100", env: &[], needle: "lockout_reset_secs" },
        Bad { name: "reset=2592001", jwt_extra: "", auth: "[auth]\nlockout_reset_secs = 2592001", env: &[], needle: "lockout_reset_secs" },
        Bad { name: "retention=0", jwt_extra: "", auth: "[auth]\naudit_retention_days = 0", env: &[], needle: "audit_retention_days" },
        Bad { name: "retention=3651", jwt_extra: "", auth: "[auth]\naudit_retention_days = 3651", env: &[], needle: "audit_retention_days" },
        Bad { name: "cache_ttl=301", jwt_extra: "", auth: "[auth]\nactive_cache_ttl_secs = 301", env: &[], needle: "active_cache_ttl_secs" },
        Bad { name: "min_len=3", jwt_extra: "", auth: "[auth]\npassword_min_length = 3", env: &[], needle: "password_min_length" },
        Bad { name: "min_len=73", jwt_extra: "", auth: "[auth]\npassword_min_length = 73", env: &[], needle: "password_min_length" },
        // ---- trusted_proxies ----
        Bad { name: "proxy bad ip", jwt_extra: "", auth: "[auth]\ntrusted_proxies = [\"not-an-ip\"]", env: &[], needle: "trusted_proxies" },
        Bad { name: "proxy /33", jwt_extra: "", auth: "[auth]\ntrusted_proxies = [\"10.0.0.0/33\"]", env: &[], needle: "trusted_proxies" },
        Bad { name: "proxy ::/0", jwt_extra: "", auth: "[auth]\ntrusted_proxies = [\"::/0\"]", env: &[], needle: "trusted_proxies" },
        Bad { name: "proxy 0.0.0.0/0", jwt_extra: "", auth: "[auth]\ntrusted_proxies = [\"0.0.0.0/0\"]", env: &[], needle: "trusted_proxies" },
        Bad { name: "proxy empty item", jwt_extra: "", auth: "[auth]\ntrusted_proxies = [\"\"]", env: &[], needle: "trusted_proxies" },
        // ---- 环境变量:非数字 => 错误含变量名 ----
        Bad { name: "env expire_hours=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_JWT_EXPIRE_HOURS", "abc")], needle: "datachain_jwt_expire_hours" },
        Bad { name: "env refresh_days=x", jwt_extra: "", auth: "", env: &[("DATACHAIN_JWT_REFRESH_EXPIRE_DAYS", "x")], needle: "datachain_jwt_refresh_expire_days" },
        Bad { name: "env user_max=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOGIN_USER_MAX_ATTEMPTS", "abc")], needle: "datachain_auth_login_user_max_attempts" },
        Bad { name: "env ip_max=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOGIN_IP_MAX_ATTEMPTS", "abc")], needle: "datachain_auth_login_ip_max_attempts" },
        Bad { name: "env window=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOGIN_WINDOW_SECS", "abc")], needle: "datachain_auth_login_window_secs" },
        Bad { name: "env base=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOCKOUT_BASE_SECS", "abc")], needle: "datachain_auth_lockout_base_secs" },
        Bad { name: "env max=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOCKOUT_MAX_SECS", "abc")], needle: "datachain_auth_lockout_max_secs" },
        Bad { name: "env reset=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOCKOUT_RESET_SECS", "abc")], needle: "datachain_auth_lockout_reset_secs" },
        Bad { name: "env retention=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_AUDIT_RETENTION_DAYS", "abc")], needle: "datachain_auth_audit_retention_days" },
        Bad { name: "env cache_ttl=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_ACTIVE_CACHE_TTL_SECS", "abc")], needle: "datachain_auth_active_cache_ttl_secs" },
        Bad { name: "env min_len=abc", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_PASSWORD_MIN_LENGTH", "abc")], needle: "datachain_auth_password_min_length" },
        Bad { name: "env min_len=-1", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_PASSWORD_MIN_LENGTH", "-1")], needle: "datachain_auth_password_min_length" },
        Bad { name: "env proxies /33", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_TRUSTED_PROXIES", "10.0.0.0/33")], needle: "datachain_auth_trusted_proxies" },
        Bad { name: "env proxies /0", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_TRUSTED_PROXIES", "0.0.0.0/0")], needle: "datachain_auth_trusted_proxies" },
        Bad { name: "env proxies empty item", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_TRUSTED_PROXIES", "10.0.0.1,,10.0.0.2")], needle: "datachain_auth_trusted_proxies" },
        // ---- 环境变量:越界(来自 validate,键名或变量名皆可,二者都含该片段) ----
        Bad { name: "env window=59", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOGIN_WINDOW_SECS", "59")], needle: "login_window_secs" },
        Bad { name: "env max<base", jwt_extra: "", auth: "", env: &[("DATACHAIN_AUTH_LOCKOUT_MAX_SECS", "30")], needle: "lockout_max_secs" },
    ];

    for case in cases {
        let result = load(&toml_text(case.jwt_extra, case.auth), case.env);
        let text = match result {
            Ok(_) => panic!("[{}] 非法值必须使加载失败", case.name),
            Err(e) => format!("{:#}", e).to_lowercase(),
        };
        assert!(
            text.contains(case.needle),
            "[{}] 错误文本应包含 `{}`,实际: {}",
            case.name,
            case.needle,
            text
        );
    }
}

#[test]
fn unknown_field_in_auth_section_is_rejected() {
    let text = err_text(load(&toml_text("", "[auth]\nbogus_option = 1"), &[]));
    assert!(text.contains("bogus_option"), "实际: {}", text);
}

#[test]
fn duplicate_trusted_proxies_are_accepted() {
    load(
        &toml_text("", "[auth]\ntrusted_proxies = [\"10.0.0.1\", \"10.0.0.1\"]"),
        &[],
    )
    .expect("重复项不报错");
}

// ---------- TrustedProxies::parse ----------

#[test]
fn trusted_proxies_parse_accepts_valid_entries() {
    let tp = TrustedProxies::parse(&strings(&[
        "10.0.0.0/8",
        "192.168.1.1",
        "172.16.0.0/12",
        "fd00::/8",
        "::1",
        "203.0.113.9/32",
        "2001:db8::1/128",
    ]))
    .expect("合法条目应解析成功");
    assert!(!tp.is_empty());

    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert!(tp.contains(ip("10.1.2.3")));
    assert!(tp.contains(ip("192.168.1.1")));
    assert!(!tp.contains(ip("192.168.1.2")));
    assert!(tp.contains(ip("172.31.255.255")));
    assert!(!tp.contains(ip("172.32.0.1")));
    assert!(tp.contains(ip("fd12::1")));
    assert!(tp.contains(ip("::1")));
    assert!(tp.contains(ip("203.0.113.9")));
    assert!(!tp.contains(ip("203.0.113.10")));
    assert!(tp.contains(ip("2001:db8::1")));
    assert!(!tp.contains(ip("2001:db8::2")));
    assert!(!tp.contains(ip("11.0.0.1")));
}

#[test]
fn trusted_proxies_parse_empty_list_is_empty() {
    let tp = TrustedProxies::parse(&[]).expect("空列表合法");
    assert!(tp.is_empty());
    assert!(!tp.contains("10.0.0.1".parse().unwrap()));
}

#[test]
fn trusted_proxies_parse_masks_unaligned_cidr() {
    // 非对齐写法按掩码规整:10.1.2.3/8 等价于 10.0.0.0/8。
    let tp = TrustedProxies::parse(&strings(&["10.1.2.3/8"])).expect("非对齐写法应被规整");
    assert!(tp.contains("10.9.9.9".parse().unwrap()));
    assert!(!tp.contains("11.0.0.1".parse().unwrap()));
}

#[test]
fn trusted_proxies_parse_duplicates_are_accepted() {
    let tp = TrustedProxies::parse(&strings(&["10.0.0.1", "10.0.0.1"])).expect("重复不报错");
    assert!(tp.contains("10.0.0.1".parse().unwrap()));
}

#[test]
fn trusted_proxies_parse_rejects_invalid_entries() {
    for bad in [
        "not-an-ip",
        "10.0.0.0/33",
        "fd00::/129",
        "10.0.0.0/abc",
        "10.0.0.0/",
        "::/0",
        "0.0.0.0/0",
        "10.0.0.0/0",
        "",
        "   ",
        "300.1.1.1",
    ] {
        assert!(
            TrustedProxies::parse(&strings(&[bad])).is_err(),
            "`{}` 应被拒绝",
            bad
        );
    }
    // 一个坏条目即整体失败。
    assert!(TrustedProxies::parse(&strings(&["10.0.0.1", "::/0"])).is_err());
}

// ---------- AuthService::with_settings 行为 ----------

async fn register_and_save(
    service: &AuthService,
    storage: &datachain::storage::Storage,
    name: &str,
) {
    let user = service
        .register(&RegisterRequest {
            username: name.to_string(),
            password: "password123".to_string(),
            email: format!("{}@test.local", name),
            role: None,
        })
        .unwrap();
    storage.save_user(&user).await.unwrap();
}

fn login_req(username: &str, password: &str) -> LoginRequest {
    LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
    }
}

fn ctx(ip: &str) -> LoginContext {
    LoginContext {
        client_ip: Some(ip.to_string()),
        user_agent: None,
    }
}

#[tokio::test]
async fn with_settings_refresh_expire_days_controls_refresh_token_lifetime() {
    let dir = tempfile::tempdir().unwrap();
    let storage = create_storage(dir.path().join("a.db").to_str().unwrap())
        .await
        .unwrap();
    let secret = "with-settings-secret".to_string();
    let settings = AuthSettings {
        refresh_expire_days: 1,
        ..AuthSettings::default()
    };
    let service = AuthService::with_settings(secret.clone(), storage.clone(), settings);
    register_and_save(&service, &storage, "dave").await;

    let resp = service
        .login(&login_req("dave", "password123"), &ctx("198.51.100.1"))
        .await
        .expect("登录应成功");

    // 经公开的 JwtHandler 解码(同一密钥),不依赖 AuthService 内部。
    let claims = JwtHandler::new(secret, 24)
        .parse_refresh_claims(&resp.refresh_token)
        .expect("refresh token 应可解码");
    assert_eq!(
        claims.exp - claims.iat,
        86_400,
        "refresh_expire_days=1 => 有效期 86400 秒"
    );
}

#[tokio::test]
async fn with_settings_login_limits_user_max_two_blocks_third_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let storage = create_storage(dir.path().join("b.db").to_str().unwrap())
        .await
        .unwrap();
    // 固定时钟,保证三次尝试落在同一固定窗口内。
    let now: i64 = ALIGNED_T0 + 10;
    storage.set_clock(Arc::new(move || now));

    let settings = AuthSettings {
        login_limits: LoginLimits {
            user_max_attempts: 2,
            ip_max_attempts: 100,
            window_secs: 900,
        },
        ..AuthSettings::default()
    };
    let service =
        AuthService::with_settings("with-settings-secret".to_string(), storage.clone(), settings);
    register_and_save(&service, &storage, "erin").await;

    for attempt in 1..=2 {
        let err = service
            .login(&login_req("erin", "bad-password"), &ctx("198.51.100.2"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DataChainError::InvalidCredentials),
            "第 {} 次应为 InvalidCredentials: {:?}",
            attempt,
            err
        );
    }
    let err = service
        .login(&login_req("erin", "bad-password"), &ctx("198.51.100.2"))
        .await
        .unwrap_err();
    match err {
        DataChainError::TooManyAttempts { retry_after_secs } => {
            assert!(retry_after_secs >= 1, "retry_after_secs={}", retry_after_secs)
        }
        other => panic!("第 3 次应为 TooManyAttempts,实际 {:?}", other),
    }
}
