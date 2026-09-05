# DataChain Rust

> 项目级实现状态与已知差异见仓库根 `PROJECT_STATUS_OVERVIEW.md`。

数据追溯区块链系统 - Rust 实现

## 功能特性

- **区块链核心**: 区块、链、Merkle 树
- **多哈希支持**: MD5, SHA-256, SHA-3, bcrypt, scrypt, Argon2, PBKDF2
- **认证系统**: JWT 令牌、RBAC 权限控制
- **元数据管理**: 数据追溯、标签、查询
- **汇总引擎**: 时间/数量策略、递归汇总
- **版本控制**: 文件追踪、差异计算
- **RESTful API**: 完整的 HTTP 接口
- **WebSocket**: 实时事件推送

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

| 路径 | 描述 |
|------|------|
| /ws | 通用 WebSocket |
| /ws/chain | 区块链事件 |
| /ws/metadata | 元数据事件 |
| /ws/aggregation | 汇总事件 |

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
