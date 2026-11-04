# DataChain Rust

> 实现状态与未完成需求见本仓库 `IMPLEMENTATION_STATUS.md`；该文档是独立仓库的回顾入口。
> 基于现有代码的完整流程图(模块级 + 带数据字段)见 `docs/FLOW.md`。
> 跨链认证网、可验证语义目录与后续路线图见 `docs/CERTIFICATION_NETWORK.md`。
> 最后核实:2026-11-05。本次 WebSocket 频道隔离:静态事件映射已实现；验证证据为本次提交 + 247 docker `rust:latest` `cargo test`（97 passed）。
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
> - WebSocket 频道隔离 `tests/websocket_integration.rs`：`/ws` 接收全部业务事件；`/ws/chain` 仅接收 `block_added`、`chain_validated`；`/ws/metadata` 仅接收 `metadata_added`；`/ws/aggregation` 仅接收 `aggregation`；`version_tracked` 与未来未映射事件仅进入 `/ws`。本次提交 + 247 docker `rust:latest` `cargo test`（97 passed）。
> - backlog #3 refresh token 持久化 + token-family 复用检测 `1124baa`:撤销落 SQLite(重启不失忆)、
>   复用触发整族撤销、并发双花以 jti 主键唯一性收口、启动清理过期撤销行。
> - 跨链认证网 L1 链上身份:公钥登记/撤销、ed25519 验签、身份快照摘要，身份交易进入 Merkle 根。
> - 可验证语义目录 `d97cd94`:Subject→Revision→Artifact + 带签名/证据/时间范围/覆盖关系的 Claim；
>   完整语义进入区块 Merkle 根，持久化待打包队列与查询投影；`/api/v1/catalog/*` 端点。
> - 共 78 单测 + 19 集成测试(api 10 + websocket 9)，合计 97 passed/0 failed。
>
> ⚠️ 当前仍未实现:多外链批次认证、外链认证阶段回写本链、外链失信切换、人工封存后新链启用、
> Claim 集中分类字典与认证机构治理、设备会话管理。
> Claim 当前有效结论已按配置的可信认证者、分类授权、权重、有效时间和覆盖关系解析；未配置可信认证者时默认不产生可信结论。
> P2P 内部不做去中心化共识是有意设计，可信根逐步由外部认证链锚定提供。
> 具体以 `IMPLEMENTATION_STATUS.md` 为准。

数据追溯区块链系统 - Rust 实现

## 功能特性

- **区块链核心**: 区块、链、Merkle 树
- **多哈希支持**: MD5, SHA-256, SHA-3, bcrypt, scrypt, Argon2, PBKDF2
- **认证系统**: JWT 令牌、RBAC 权限控制
- **元数据管理**: 数据追溯、标签、查询
- **可验证语义目录**: Subject→Revision→Artifact、带签名/证据/时间范围的 Claim、风险与长期支持等可追溯声明
- **汇总引擎**: 时间/数量策略、递归父聚合(多层合并)
- **版本控制**: 文件追踪、内容快照、历史差异
- **跨链锚定**: 完整 Merkle proof、ed25519 节点签名、ChainAnchor/回执、outbox 重试投递
- **P2P 同步**: 显式注册 + 区块广播 + 认证 gossip 发现 + 最长合法链替换
- **RESTful API**: HTTP 接口(认证/元数据/区块/版本/聚合/跨链/P2P)
- **WebSocket**: 实时事件推送(JWT 认证；静态频道映射；`/ws` 接收全部业务事件，专用频道仅接收各自映射的事件；不提供动态订阅或频道级授权)

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

### 可验证语义目录

> Subject 表示长期逻辑对象，Revision 表示不可变内容版本，Artifact 表示构建或配置变体。
> Claim 是带签名、证据、时间范围和覆盖关系的认证、支持、质量或风险声明；记录进入普通新区块并纳入 Merkle 根。

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | /api/v1/catalog/records | 提交已签名 Subject、Revision、Artifact 或 Claim |
| GET | /api/v1/catalog/subjects/:subject_id | 查询对象登记记录 |
| GET | /api/v1/catalog/subjects/:subject_id/revisions | 查询对象版本历史 |
| GET | /api/v1/catalog/revisions/:revision_id/artifacts | 查询版本的构建/配置变体 |
| GET | /api/v1/catalog/subjects/:subject_id/claims | 查询对象全部认证声明历史 |
| GET | /api/v1/catalog/subjects/:subject_id/effective-claims | 按可信认证者策略解析指定时间点的有效声明与冲突 |

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

> 频道按静态事件映射过滤，不是动态订阅，也不提供频道级授权。`/ws` 保持接收全部业务事件；
> `version_tracked` 和未来未映射事件仅投递到 `/ws`。URL、JWT、全局 256 连接上限、16KiB 行为及 `WsMessage` JSON schema 均未改变。
> 验证证据:本次提交 + 247 docker `rust:latest` `cargo test`（97 passed）。

| 路径 | 描述 |
|------|------|
| /ws | 通用 WebSocket(JWT 认证，全部业务事件) |
| /ws/chain | 静态映射：`block_added`、`chain_validated` |
| /ws/metadata | 静态映射：`metadata_added` |
| /ws/aggregation | 静态映射：`aggregation` |

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

# 未配置可信认证者时，Claim 历史仍可查询，但不会生成可信“有效结论”。
[claim_policy]
min_weight = 1

[[claim_policy.trusted_issuers]]
issuer_identity = "security-lab"
issuer_key = "<base64-ed25519-public-key>"
weight = 10
categories = ["risk.*", "quality.verified"]
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
