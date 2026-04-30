//! DataChain 基本使用示例
//!
//! 运行方式: cargo run --example basic_usage

use std::collections::HashMap;

/// 模拟 API 客户端
struct DataChainClient {
    base_url: String,
    token: Option<String>,
}

impl DataChainClient {
    fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            token: None,
        }
    }

    fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }
}

fn main() {
    println!("=== DataChain Rust 基本使用示例 ===\n");

    // 1. 创建客户端
    let mut client = DataChainClient::new("http://localhost:8080");
    println!("1. 创建客户端: {}", client.base_url);

    // 2. 模拟用户注册
    println!("\n2. 用户注册");
    println!("   POST /api/v1/auth/register");
    println!("   Body: {{");
    println!("     \"username\": \"testuser\",");
    println!("     \"password\": \"password123\",");
    println!("     \"email\": \"test@example.com\"");
    println!("   }}");

    // 3. 模拟用户登录
    println!("\n3. 用户登录");
    println!("   POST /api/v1/auth/login");
    println!("   Body: {{");
    println!("     \"username\": \"testuser\",");
    println!("     \"password\": \"password123\"");
    println!("   }}");
    client.set_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...".to_string());
    println!("   获取令牌: {}", client.token.as_ref().unwrap());

    // 4. 创建元数据
    println!("\n4. 创建元数据");
    println!("   POST /api/v1/metadata");
    println!("   Headers: Authorization: Bearer <token>");
    println!("   Body: {{");
    println!("     \"data_size\": 1024,");
    println!("     \"tags\": [\"document\", \"important\"],");
    println!("     \"metadata\": {{\"type\": \"pdf\"}}");
    println!("   }}");

    // 5. 查询元数据
    println!("\n5. 查询元数据");
    println!("   GET /api/v1/metadata?owner=testuser&page=1&page_size=20");

    // 6. 获取区块链信息
    println!("\n6. 获取区块链信息");
    println!("   GET /api/v1/chain/info");
    println!("   响应示例:");
    println!("   {{");
    println!("     \"block_count\": 10,");
    println!("     \"difficulty\": 4,");
    println!("     \"pending_count\": 5");
    println!("   }}");

    // 7. 挖掘新区块
    println!("\n7. 挖掘新区块");
    println!("   POST /api/v1/chain/mine");
    println!("   需要 admin 或 user 角色");

    // 8. 验证链完整性
    println!("\n8. 验证链完整性");
    println!("   POST /api/v1/chain/validate");
    println!("   响应: {{\"valid\": true, \"block_count\": 11}}");

    // 9. 版本追踪
    println!("\n9. 版本追踪");
    println!("   POST /api/v1/versions/track");
    println!("   Body: {{");
    println!("     \"file_path\": \"/path/to/file.txt\",");
    println!("     \"message\": \"Initial version\"");
    println!("   }}");

    // 10. 触发汇总
    println!("\n10. 触发汇总");
    println!("    POST /api/v1/aggregations/trigger");
    println!("    Body: {{\"strategy\": \"time_based\"}}");

    // 11. WebSocket 连接
    println!("\n11. WebSocket 实时事件");
    println!("    ws://localhost:8080/ws          - 通用连接");
    println!("    ws://localhost:8080/ws/chain    - 区块链事件");
    println!("    ws://localhost:8080/ws/metadata - 元数据事件");

    // 12. 获取统计信息
    println!("\n12. 获取统计信息");
    println!("    GET /api/v1/stats");

    println!("\n=== 示例完成 ===");
    println!("\n提示: 启动服务后使用 curl 或 Postman 测试这些 API");
    println!("启动命令: cargo run -- serve --port 8080");
}
