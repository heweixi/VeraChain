use std::process::Command;

use datachain::config::AppConfig;
use datachain::core::Block;
use datachain::storage::create_storage;

async fn write_chain_database(dsn: &str, invalid_genesis: bool) -> serde_json::Value {
    let storage = create_storage(dsn).await.unwrap();
    let mut genesis = Block::new(
        0,
        if invalid_genesis {
            "tampered-genesis-parent".to_string()
        } else {
            "0".to_string()
        },
        1,
    );
    genesis.mine();
    storage.save_block(&genesis).await.unwrap();
    let blocks = serde_json::to_value(storage.get_all_blocks().await.unwrap()).unwrap();
    drop(storage);
    blocks
}

fn write_config(path: &std::path::Path, dsn: &str) {
    let mut config = AppConfig::default();
    config.database.dsn = dsn.to_string();
    config.blockchain.difficulty = 1;
    config.jwt.secret = "chain-validation-cli-test-secret-0123456789".to_string();
    config.claim_policy.min_weight = 1;
    std::fs::write(path, toml::to_string(&config).unwrap()).unwrap();
}

#[tokio::test]
async fn chain_validate_cli_reports_valid_and_invalid_chains_without_writing_storage() {
    for (invalid_genesis, expected_output) in [(false, "✓ 链验证通过"), (true, "✗ 链验证失败")]
    {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("datachain.sqlite");
        let dsn = database_path.to_str().unwrap();
        let config_path = directory.path().join("config.toml");
        let blocks_before = write_chain_database(dsn, invalid_genesis).await;
        write_config(&config_path, dsn);

        let output = Command::new(env!("CARGO_BIN_EXE_datachain"))
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "chain",
                "validate",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "CLI 应保持成功退出: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(expected_output),
            "stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );

        let storage = create_storage(dsn).await.unwrap();
        let blocks_after = serde_json::to_value(storage.get_all_blocks().await.unwrap()).unwrap();
        assert_eq!(blocks_after, blocks_before, "校验命令不得修改区块数据库");
    }
}
