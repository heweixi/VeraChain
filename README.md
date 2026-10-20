# DataChain Rust

> 实现状态与未完成需求见本仓库 `IMPLEMENTATION_STATUS.md`；该文档是独立仓库的回顾入口。
> 最后核实:2026-10-18(进度至 R7 + backlog #4/#3/#6/#5 + 跨链认证网 L1 链上身份含端到端测试,提交 `8b5ecf1`)。
>
> R0-R7 已在 247 服务器 docker `rust:latest` 完成 `cargo check/test/fmt/clippy` 与 HTTP smoke 验证:
> - R1 安全:公开注册固定普通用户、RBAC 路由权限、JWT issuer/audience + refresh jti 一次性撤销、
>   默认/短 JWT secret 启动拒绝、CORS allowlist、10MiB 请求体限制、进程内限流、WebSocket JWT/256 连接/16KiB、可选 TLS。
> - R2 挖矿经 `commit_block` 原子落库(写区块+删 pending 同事务)。
> - R3 递归父聚合(自底向上合并为 level+1 父 summary)。
> - R4 版本内容快照 + 历史 diff + `DATACHAIN_VERSION_ROOT` 路径 allowlist。
> - R5 跨链证明与锚定:完整 Merkle proof、ed25519 节点签名、ChainAnchor/AnchorReceipt、
>   anchor_outbox 重试投递、attestation connector、`/api/v1/crosschain/*` 端点。
> - R6 P2P 区块广播 + 认证 gossip 发现 + 种子 peer(双节点 smoke 验证)。
> - R7 集成测试 `tests/api_integration.rs`(health/401/RBAC 越权/SQLite 重启恢复)。
> - backlog #4 WebSocket 实时事件集成测试 `tests/websocket_integration.rs`(握手鉴权/EventBus 广播/
>   16KiB 消息上限/256 连接上限),`97eeee5` 247 验证 8 passed。
> - backlog #3 refresh token 持久化 + token-family 复用检测 `1124baa`:撤销落 SQLite(重启不失忆)、
>   复用触发整族撤销、并发双花以 jti 主键唯一性收口、启动清理过期撤销行。
> - 共 62 单测 + 12 集成测试(api 4 + websocket 8)通过。
>
> ⚠️ 仍未实现:P2P 共识与同长度分叉选择(单一诚实源假设)、跨链密钥轮换/链上身份注册、
> WebSocket 频道隔离(`/ws/chain` 等当前为全量广播,服务端不按频道过滤)、设备会话管理。
> 具体以 `IMPLEMENTATION_STATUS.md` 为准。

数据追溯区块链系统 - Rust 实现

## 功能特性

- **区块链核心**: 区块、链、Merkle 树
- **多哈希支持**: MD5, SHA-256, SHA-3, bcrypt, scrypt, Argon2, PBKDF2
- **认证系统**: JWT 令牌、RBAC 权限控制
- **元数据管理**: 数据追溯、标签、查询
- **汇总引擎**: 时间/数量策略、递归父聚合(多层合并)
- **版本控制**: 文件追踪、内容快照、历史差异
- **跨链锚定**: 完整 Merkle proof、ed25519 节点签名、ChainAnchor/回执、outbox 重试投递
- **P2P 同步**: 显式注册 + 区块广播 + 认证 gossip 发现 + 最长合法链替换
- **RESTful API**: HTTP 接口(认证/元数据/区块/版本/聚合/跨链/P2P)
- **WebSocket**: 实时事件推送(JWT 认证;当前各频道为全量广播,服务端频道隔离未实现)

## 项目结构

```
datachain-rust/
├── src/
│   ├── main.rs           # 入口点
│   ├── config.rs         # 配置管理
│   ├── error.rs          # 错误类型
│   ├── api/              # HTTP API
│   │   ├── mod.rs
│   │   ├── state.rs      # 应用状态
│   │   ├── routes.rs     # 路由定义
│   │   ├── handlers.rs   # 请求处理器
│   │   ├── middleware.rs # 中间件
│   │   └── websocket.rs  # WebSocket
│   ├── core/             # 区块链核心
│   │   ├── block.rs      # 区块
│   │   ├── chain.rs      # 链
│   │   └── merkle.rs     # Merkle 树
│   ├── crypto/           # 加密模块
│   │   └── hash.rs       # 哈希算法
│   ├── auth/             # 认证模块
│   │   ├── user.rs       # 用户
│   │   ├── jwt.rs        # JWT
│   │   ├── permissions.rs# 权限
│   │   └── service.rs    # 服务
│   ├── metadata/         # 元数据
│   │   ├── models.rs     # 模型
│   │   └── manager.rs    # 管理器
│   ├── aggregation/      # 汇总
│   │   ├── strategies.rs # 策略
│   │   └── engine.rs     # 引擎
│   ├── versioning/       # 版本控制
│   │   ├── tracker.rs    # 追踪器
│   │   └── diff.rs       # 差异
│   ├── storage/          # 存储
│   │   └── database.rs   # SQLite
│   └── cli/              # CLI 命令
├── Cargo.toml
├── Dockerfile
├── docker-compose.yml
├── config.toml
└── README.md
```

## 快速开始

### 本地运行

```bash
# 构建
cargo build --release

# 初始化
./target/release/datachain init

# 启动服务
./target/release/datachain serve --port 8080
```

### Docker 运行

```bash
# 构建镜像
docker build -t datachain-rust .

# 运行容器
docker run -d -p 8004:8080 --name datachain-rust datachain-rust

# 或使用 docker-compose
docker-compose up -d
```

## CLI 命令

```bash
# 查看帮助
datachain --help

# 启动服务
datachain serve --port 8080

# 初始化区块链
datachain init

# 查看状态
datachain status

# 查看版本信息
datachain info --detailed

# 区块链管理
datachain chain list
datachain chain get <index>
datachain chain mine
datachain chain validate

# 元数据管理
datachain metadata create --file <path>
datachain metadata get <id>
datachain metadata list

# 用户管理
datachain user create --username <name> --password <pass>
datachain user list

# 汇总管理
datachain aggregate trigger --strategy time_based
datachain aggregate list

# 版本管理
datachain version track <file>
datachain version history <file>
datachain version diff <v1> <v2>
```

## API 接口

### 认证

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | /api/v1/auth/register | 用户注册 |
| POST | /api/v1/auth/login | 用户登录 |
| POST | /api/v1/auth/refresh | 刷新令牌 |
| GET | /api/v1/auth/profile | 获取用户信息 |

### 元数据

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | /api/v1/metadata | 创建元数据 |
| GET | /api/v1/metadata | 查询元数据 |
| GET | /api/v1/metadata/:id | 获取元数据 |

### 区块链

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/v1/blocks | 获取区块列表 |
| GET | /api/v1/blocks/:index | 获取指定区块 |
| GET | /api/v1/chain/info | 获取链信息 |
| POST | /api/v1/chain/mine | 挖掘新区块 |
| POST | /api/v1/chain/validate | 验证链完整性 |

### 链上身份(认证网 L1)

> 密钥交易经 ed25519 验签后进待打包队列,下次挖矿随区块上链并进入 merkle_root 受 PoW 保护;
> 当前有效密钥集由重放 key_transactions 得出。register 需自签(signed_by==target_key)。

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | /api/v1/identity/key-transaction | 提交密钥交易(register/revoke) |
| GET | /api/v1/identity/keys | 当前有效密钥集 |
| GET | /api/v1/identity/keys/:public_key | 单个公钥状态 |

### 版本

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/v1/versions | 获取版本列表 |
| GET | /api/v1/versions/:id | 获取版本详情 |
| POST | /api/v1/versions/track | 追踪文件版本 |
| GET | /api/v1/versions/history/:path | 获取版本历史 |

### 汇总

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/v1/aggregations | 获取汇总列表 |
| POST | /api/v1/aggregations/trigger | 触发汇总 |

### 统计

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/v1/stats | 获取统计信息 |

### WebSocket

> 注意:以下频道当前均订阅同一 Hub 的**全量广播**,服务端不按频道过滤;
> 订阅 `/ws/chain` 仍会收到 metadata/aggregation 等全部事件。频道隔离为已知遗留(见 `IMPLEMENTATION_STATUS.md`)。

| 路径 | 描述 |
|------|------|
| /ws | 通用 WebSocket(JWT 认证,全量事件) |
| /ws/chain | 区块链事件(当前实为全量广播) |
| /ws/metadata | 元数据事件(当前实为全量广播) |
| /ws/aggregation | 汇总事件(当前实为全量广播) |

## 配置说明

```toml
[server]
host = "0.0.0.0"      # 监听地址
port = 8080           # 监听端口
mode = "release"      # 运行模式

[database]
dsn = "./data/datachain.db"  # SQLite 数据库路径

[blockchain]
difficulty = 4        # 挖矿难度
block_size = 100      # 区块大小

[jwt]
secret = "..."        # JWT 密钥
expire_hours = 24     # 令牌过期时间

[aggregation]
time_interval_secs = 3600  # 时间汇总间隔
count_threshold = 100      # 数量汇总阈值
```

## 技术栈

- **Web 框架**: Axum
- **异步运行时**: Tokio
- **数据库**: SQLx + SQLite
- **序列化**: Serde
- **加密**: sha2, sha3, bcrypt, argon2, scrypt
- **JWT**: jsonwebtoken
- **CLI**: Clap
- **日志**: Tracing

## 许可证

MIT License
