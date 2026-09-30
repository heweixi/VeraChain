use clap::Subcommand;

use crate::aggregation::{create_aggregation_engine, StrategyType};
use crate::config::AppConfig;
use crate::core::create_chain;
use crate::storage::create_storage;

#[derive(Subcommand)]
pub enum AggregateAction {
    /// 触发汇总
    Trigger {
        /// 策略类型
        #[arg(short, long, default_value = "time_based")]
        strategy: String,
    },
    /// 汇总状态
    Status,
    /// 列出汇总
    List,
    /// 汇总统计
    Stats,
}

/// 运行汇总命令
pub async fn run_aggregate(config: &AppConfig, action: AggregateAction) -> anyhow::Result<()> {
    let storage = create_storage(&config.database.dsn).await?;
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);

    // 加载区块
    let blocks = storage.get_all_blocks().await?;
    if !blocks.is_empty() {
        chain.load_blocks(blocks);
    }

    let engine = create_aggregation_engine(
        chain,
        config.aggregation.time_interval_secs,
        config.aggregation.count_threshold,
    );
    for summary in storage.get_all_aggregations().await? {
        engine.load_aggregation(summary);
    }

    match action {
        AggregateAction::Trigger { strategy } => {
            let strategy_type: StrategyType = strategy.parse().unwrap_or(StrategyType::TimeBased);

            match engine.aggregate(strategy_type) {
                Some(summary) => {
                    storage.save_aggregation(&summary).await?;
                    println!("✓ 汇总完成");
                    println!("  汇总 ID: {}", summary.summary_id);
                    println!("  类型: {}", summary.summary_type);
                    println!("  元数据数量: {}", summary.metadata_count);
                    println!("  Merkle 根: {}", summary.merkle_root);
                }
                None => {
                    println!("✗ 汇总失败: 没有可汇总的数据");
                }
            }
        }
        AggregateAction::Status => {
            let (should_agg, strategy) = engine.should_aggregate();

            println!("汇总状态");
            println!("========");
            println!("上次汇总: {}", engine.get_last_aggregation());
            println!("已汇总数量: {}", engine.get_aggregated_count());
            println!("需要汇总: {}", if should_agg { "是" } else { "否" });

            if let Some(s) = strategy {
                println!("触发策略: {}", s);
            }
        }
        AggregateAction::List => {
            let aggregations = engine.get_all_aggregations();
            println!("汇总列表 (共 {} 个)", aggregations.len());
            println!("=========");

            for agg in aggregations {
                println!(
                    "{} | {} | {} 条 | {}",
                    agg.summary_id,
                    agg.summary_type,
                    agg.metadata_count,
                    agg.created_at.format("%Y-%m-%d %H:%M:%S")
                );
            }
        }
        AggregateAction::Stats => {
            let aggregations = engine.get_all_aggregations();

            let total_metadata: usize = aggregations.iter().map(|a| a.metadata_count).sum();
            let by_type: std::collections::HashMap<String, usize> =
                aggregations
                    .iter()
                    .fold(std::collections::HashMap::new(), |mut acc, a| {
                        *acc.entry(a.summary_type.clone()).or_insert(0) += 1;
                        acc
                    });

            println!("汇总统计");
            println!("========");
            println!("总汇总数: {}", aggregations.len());
            println!("总元数据数: {}", total_metadata);

            println!();
            println!("按类型:");
            for (t, count) in &by_type {
                println!("  {}: {}", t, count);
            }
        }
    }

    Ok(())
}
