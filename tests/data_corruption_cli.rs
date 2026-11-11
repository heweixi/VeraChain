//! S5:CLI 统一校验 + 退出码 + Mine 投影一致性。
//!
//! Red 基线(实施前):
//! - metadata/aggregate/status 命令直接 `storage.get_all_blocks().await?` 后
//!   `chain.load_blocks(blocks)`,不调用 validate_loaded_blocks,也不会在数据
//!   损坏时 fail-closed——它们会"成功"跑完并打印基于未经验证数据的结果。
//! - `chain mine` 用 `storage.save_block`(低层,无投影写入),挖矿后 metadata
//!   投影表不会包含新区块的元数据。

use std::process::Command;

use datachain::config::AppConfig;
use datachain::core::Block;
use datachain::storage::create_storage;

fn write_config(path: &std::path::Path, dsn: &str) {
    let mut config = AppConfig::default();
    config.database.dsn = dsn.to_string();
    config.blockchain.difficulty = 1;
    config.jwt.secret = "data-corruption-cli-test-secret-0123456789".to_string();
    config.claim_policy.min_weight = 1;
    std::fs::write(path, toml::to_string(&config).unwrap()).unwrap();
}

async fn write_healthy_genesis(dsn: &str) {
    let storage = create_storage(dsn).await.unwrap();
    let mut genesis = Block::new(0, "0".to_string(), 1);
    genesis.mine();
    storage.save_block(&genesis).await.unwrap();
}

fn run_cli(config_path: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut full_args = vec!["--config", config_path.to_str().unwrap()];
    full_args.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_datachain"))
        .args(full_args)
        .output()
        .unwrap()
}

#[tokio::test]
async fn chain_validate_exits_3_on_block_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let dsn = directory.path().join("datachain.sqlite");
    let dsn_str = dsn.to_str().unwrap();
    let config_path = directory.path().join("config.toml");
    write_healthy_genesis(dsn_str).await;
    write_config(&config_path, dsn_str);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rwc", dsn_str))
        .await
        .unwrap();
    sqlx::query("UPDATE blocks SET data = '{not valid json' WHERE block_index = 0")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let output = run_cli(&config_path, &["chain", "validate"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "数据损坏应退出码 3,stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn metadata_list_fails_closed_with_exit_3_on_corrupt_users_table_via_status() {
    // metadata/aggregate/status 均经 load_verified_chain,这里用 status 命令验证
    // (status 同时读 users,更容易触发非 blocks 的权威源损坏路径)。
    let directory = tempfile::tempdir().unwrap();
    let dsn = directory.path().join("datachain.sqlite");
    let dsn_str = dsn.to_str().unwrap();
    let config_path = directory.path().join("config.toml");
    write_healthy_genesis(dsn_str).await;
    write_config(&config_path, dsn_str);

    let storage = create_storage(dsn_str).await.unwrap();
    let user = datachain::auth::User::new(
        "tester".to_string(),
        "SECRET-XYZ".to_string(),
        "tester@example.com".to_string(),
        datachain::auth::Role::User,
    );
    storage.save_user(&user).await.unwrap();

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rwc", dsn_str))
        .await
        .unwrap();
    sqlx::query("UPDATE users SET metadata = '{not valid json' WHERE user_id = ?")
        .bind(&user.user_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let output = run_cli(&config_path, &["status"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "users 损坏应退出码 3,stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("SECRET-XYZ"), "stderr 不得泄露 password_hash");
}

#[tokio::test]
async fn metadata_list_exits_2_on_invalid_chain() {
    let directory = tempfile::tempdir().unwrap();
    let dsn = directory.path().join("datachain.sqlite");
    let dsn_str = dsn.to_str().unwrap();
    let config_path = directory.path().join("config.toml");

    let storage = create_storage(dsn_str).await.unwrap();
    let mut corrupt = Block::new(0, "tampered-parent".to_string(), 1);
    corrupt.mine();
    storage.save_block(&corrupt).await.unwrap();
    write_config(&config_path, dsn_str);

    let output = run_cli(&config_path, &["metadata", "list"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "链无效应退出码 2,stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn chain_mine_projects_metadata_in_same_commit_as_cli_import() {
    let directory = tempfile::tempdir().unwrap();
    let dsn = directory.path().join("datachain.sqlite");
    let dsn_str = dsn.to_str().unwrap();
    let config_path = directory.path().join("config.toml");
    write_healthy_genesis(dsn_str).await;
    write_config(&config_path, dsn_str);

    // 先用 metadata add 让一条 pending 元数据被打包进下一次 Mine。
    let add_output = run_cli(
        &config_path,
        &["metadata", "add", "--owner", "alice", "--size", "10"],
    );
    assert_eq!(add_output.status.code(), Some(0), "metadata add 应成功");

    let mine_output = run_cli(&config_path, &["chain", "mine"]);
    assert_eq!(
        mine_output.status.code(),
        Some(0),
        "mine 应成功,stderr: {}",
        String::from_utf8_lossy(&mine_output.stderr)
    );

    let storage = create_storage(dsn_str).await.unwrap();
    let blocks = storage.get_all_blocks().await.unwrap();
    let expected_metadata_count: i64 = blocks
        .iter()
        .map(|b| b.metadata_list.len() as i64)
        .sum();
    assert!(expected_metadata_count >= 1, "挖矿区块应至少打包 1 条元数据");
    assert_eq!(
        storage.metadata_projection_count().await.unwrap(),
        expected_metadata_count,
        "Mine 后投影数量应等于区块推导值(commit_block 同事务写投影)"
    );
}
