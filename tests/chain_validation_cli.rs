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

/// 退出码契约(本特性引入的破坏性变更,设计文档"默认决策#1"):
/// 0=链有效,2=链无效,3=数据损坏。此前 `chain validate` 恒返回 0,
/// 调用脚本若依赖旧的"恒 0"行为需要相应调整(见最终报告的破坏性变更说明)。
#[tokio::test]
async fn chain_validate_cli_reports_valid_and_invalid_chains_without_writing_storage() {
    for (invalid_genesis, expected_output, expected_exit_code) in
        [(false, "✓ 链验证通过", 0), (true, "✗ 链验证失败", 2)]
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

        assert_eq!(
            output.status.code(),
            Some(expected_exit_code),
            "退出码契约:0=valid,2=invalid。stderr: {}",
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
