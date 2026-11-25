//! C1(B20):WebSocket 定时复核间隔配置 `auth.ws_revalidate_secs` 与 `WsHub` 间隔 seam 的行为测试。
//!
//! 本文件在实现前应编译失败(Red):`AuthConfig` 尚无 `ws_revalidate_secs`,
//! `WsHub` 尚无 `revalidate_interval` / `set_revalidate_interval`。
//!
//! 环境变量一律经 `AppConfig::load_with_env(path, env_fn)` 注入,不使用 `set_var`,避免并行污染。
use std::collections::HashMap;
use std::time::Duration;

use datachain::api::WsHub;
use datachain::config::{AppConfig, AuthConfig};

const SECRET: &str = "0123456789abcdef0123456789abcdef-config-test";
const ENV_NAME: &str = "DATACHAIN_AUTH_WS_REVALIDATE_SECS";
const KEY_NAME: &str = "ws_revalidate_secs";

// ---------- 辅助(复制自 auth_config.rs) ----------

fn toml_text(auth: &str) -> String {
    format!(
        "[server]\nport = 8080\n\n\
         [blockchain]\ndifficulty = 1\n\n\
         [database]\ndsn = \"x.db\"\n\n\
         [jwt]\nsecret = \"{secret}\"\n\n\n\
         [aggregation]\n\n\
         [log]\n\n\
         {auth}\n",
        secret = SECRET,
        auth = auth,
    )
}

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

// ---------- 默认值 ----------

#[test]
fn default_ws_revalidate_secs_is_30() {
    assert_eq!(AuthConfig::default().ws_revalidate_secs, 30);
    assert_eq!(AppConfig::default().auth.ws_revalidate_secs, 30);
    assert_eq!(load_defaults().auth.ws_revalidate_secs, 30);
}

#[test]
fn config_without_auth_section_uses_default_30() {
    let cfg = load(&toml_text(""), &[]).expect("缺省 [auth] 应使用默认值");
    assert_eq!(cfg.auth.ws_revalidate_secs, 30);
}

// ---------- 覆盖 ----------

#[test]
fn toml_overrides_ws_revalidate_secs() {
    let cfg = load(&toml_text("[auth]\nws_revalidate_secs = 5"), &[]).expect("合法值应加载成功");
    assert_eq!(cfg.auth.ws_revalidate_secs, 5);
}

#[test]
fn environment_overrides_toml() {
    let cfg = load(
        &toml_text("[auth]\nws_revalidate_secs = 5"),
        &[(ENV_NAME, "7")],
    )
    .expect("环境变量覆盖应加载成功");
    assert_eq!(cfg.auth.ws_revalidate_secs, 7);
}

#[test]
fn environment_alone_overrides_default_without_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.toml");
    let mut map = HashMap::new();
    map.insert("DATACHAIN_JWT_SECRET".to_string(), SECRET.to_string());
    map.insert(ENV_NAME.to_string(), "9".to_string());
    let cfg =
        AppConfig::load_with_env(path.to_str().unwrap(), move |k| map.get(k).cloned()).unwrap();
    assert_eq!(cfg.auth.ws_revalidate_secs, 9);
}

// ---------- 边界与非法值 ----------

#[test]
fn boundaries_1_and_3600_are_accepted() {
    for v in [1u64, 3600] {
        let cfg = load(
            &toml_text(&format!("[auth]\nws_revalidate_secs = {}", v)),
            &[],
        )
        .unwrap_or_else(|e| panic!("TOML 边界 {} 应合法: {:#}", v, e));
        assert_eq!(cfg.auth.ws_revalidate_secs, v);

        let cfg = load(&toml_text(""), &[(ENV_NAME, &v.to_string())])
            .unwrap_or_else(|e| panic!("环境变量边界 {} 应合法: {:#}", v, e));
        assert_eq!(cfg.auth.ws_revalidate_secs, v);
    }
}

#[test]
fn out_of_range_toml_values_fail_with_key_name_without_echoing_value() {
    // (名称, TOML 值, 不应出现在错误文本中的取值)。0 太短,无法做不回显断言,故为 None。
    let cases: [(&str, &str, Option<&str>); 2] =
        [("zero", "0", None), ("over_max", "3601", Some("3601"))];
    for (name, value, secret) in cases {
        let text = err_text(load(
            &toml_text(&format!("[auth]\nws_revalidate_secs = {}", value)),
            &[],
        ));
        assert!(
            text.contains(KEY_NAME),
            "[{}] 错误应含键名 {},实际: {}",
            name,
            KEY_NAME,
            text
        );
        if let Some(s) = secret {
            assert!(!text.contains(s), "[{}] 错误不应回显取值,实际: {}", name, text);
        }
    }
}

#[test]
fn negative_toml_value_fails_with_key_name() {
    // TOML 解析层可能回显源码行,故此处只要求含键名。
    let text = err_text(load(&toml_text("[auth]\nws_revalidate_secs = -7777"), &[]));
    assert!(text.contains(KEY_NAME), "实际: {}", text);
}

#[test]
fn invalid_environment_values_fail_with_variable_name_without_echoing_value() {
    let env_name_lower = ENV_NAME.to_lowercase();
    // (名称, 环境变量值, 不应回显的取值)
    let cases: [(&str, &str, Option<&str>); 4] = [
        ("zero", "0", None),
        ("over_max", "3601", Some("3601")),
        ("non_numeric", "abc", Some("abc")),
        ("negative", "-7777", Some("-7777")),
    ];
    for (name, value, secret) in cases {
        let text = err_text(load(&toml_text(""), &[(ENV_NAME, value)]));
        assert!(
            text.contains(&env_name_lower) || text.contains(KEY_NAME),
            "[{}] 错误应含变量名或键名,实际: {}",
            name,
            text
        );
        if let Some(s) = secret {
            assert!(!text.contains(s), "[{}] 错误不应回显取值,实际: {}", name, text);
        }
    }
}

#[test]
fn non_numeric_environment_value_names_the_variable() {
    // 与 auth_config.rs 一致:非数字解析失败时错误必须含变量名。
    let text = err_text(load(&toml_text(""), &[(ENV_NAME, "abc")]));
    assert!(text.contains(&ENV_NAME.to_lowercase()), "实际: {}", text);
}

// ---------- WsHub seam ----------

#[test]
fn ws_hub_default_revalidate_interval_is_30_seconds() {
    let hub = WsHub::new();
    assert_eq!(hub.revalidate_interval(), Duration::from_secs(30));
}

#[test]
fn ws_hub_set_revalidate_interval_takes_effect() {
    let hub = WsHub::new();
    hub.set_revalidate_interval(Duration::from_millis(200));
    assert_eq!(hub.revalidate_interval(), Duration::from_millis(200));

    // 可再次修改。
    hub.set_revalidate_interval(Duration::from_secs(3));
    assert_eq!(hub.revalidate_interval(), Duration::from_secs(3));
}
