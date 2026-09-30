# DataChain Rust 实现状态与未完成需求

> 核实日期:2026-08-31。本文档是独立仓库的实现状态入口。
> 状态标记:✅已实现 / ⚠️部分实现 / 🔺设计与实现有差异 / ⏳未实现 / 🧩预留能力 / 🗑️已废弃。
> 本文档基于源码、README、配置、Docker/Compose 和原 monorepo 的设计基线核查；未在本次拆分操作中重新执行 cargo、Docker 或运行时 smoke test。

## 一、总体结论

DataChain Rust 已具备真实的 Axum HTTP 服务、SQLite/SQLx 基础存储、JWT 登录、区块/PoW/Merkle 核心、版本追踪、聚合策略、CLI 和 Docker 构建骨架。

但 README 中“完整 REST、WebSocket、RBAC、递归汇总”等表述高于当前实现。当前仍有以下实质差异：

- P0：公开注册可自行指定 `admin`；RBAC 权限表没有真正接入 API 路由；默认 JWT secret 不会阻止生产启动。
- P0：注册/挖矿/版本写库失败时部分 handler 仍返回成功；pending 元数据、聚合结果和事件没有完整持久化。
- P1：WebSocket Hub/EventBus 已定义但没有接入 AppState 和业务 handler；Scheduler 已定义但 server 没启动。
- P1：没有 SQLx migrations；启动恢复不会完整验证链；没有区块同步/P2P。
- P1：版本内容寻址存储没有接入 HTTP 主流程，文件路径存在越权读取风险。
- P2：递归汇总目前只有单层 summary；API/数据库/调度/越权测试不足；Docker 和运行时行为需要重新验证。

## 二、需求/设计与实现对照

### 2.1 HTTP API 与 WebSocket

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| 健康检查 | ✅ | `src/api/handlers.rs` 的 `health_check`；Docker healthcheck 请求 `/health` |
| 注册/登录/刷新 token | ⚠️ | 基础路径存在；注册失败写库只记日志仍返回 201；refresh token 无轮换、撤销和设备会话管理 |
| 元数据创建/查询 | ⚠️ | `src/api/handlers.rs` 只把新元数据加入内存 pending；查询主要扫描已加载区块，没有独立 metadata 表 |
| 区块列表/详情/挖矿/验证 | ⚠️ | 路由存在；挖矿写库失败仍返回成功，链恢复/验证完整性不足 |
| Merkle proof | 🔺 | `get_proof` 只返回命中区块、root 等信息，不返回 sibling/path，也没有真正调用 Merkle proof 验证流程；不能视为完整 Merkle proof |
| 版本 API | ⚠️ | 元数据写入 SQLite，但文件内容快照未接入主流程；历史文件被覆盖或删除后不能可靠还原 |
| WebSocket 实时事件 | 🧩/⚠️ | `src/api/websocket.rs` 定义了 `WsHub` 和频道处理，但 `AppState` 没有 Hub，业务 handler 也未发布事件；当前主要是连接确认、Ping/Pong 和占位频道 |
| EventBus/通知 | 🧩 | `src/api/notification.rs` 已定义 EventBus/NotificationService，但创建元数据、挖矿、聚合、版本追踪没有调用它 |

### 2.2 认证、授权与安全

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| JWT access/refresh | ⚠️ | `src/auth/jwt.rs` 可生成/验证；缺 issuer/audience 强校验、撤销、轮换和账户实时状态检查 |
| 用户持久化 | ⚠️ | 启动可从 SQLite 加载；运行中注册写库失败仍成功返回，运行中资料/密码管理 API 未完整提供 |
| 公开注册 | 🔺 | `RegisterRequest.role` 可由客户端指定，公开注册可注册 `admin`；应强制普通用户或仅管理员可分配高权限角色 |
| RBAC | 🔺 | `src/auth/permissions.rs` 定义了权限矩阵，但路由只做“有 JWT 即可”；挖矿 handler 的角色判断还允许普通 `user`，与权限表的 `BlockMine` 定义冲突 |
| 密码哈希 | ⚠️ | 实际认证使用 bcrypt；多算法 API 存在，但部分算法的 salt/dispatch 设计不适合作为统一生产密码方案 |
| 默认 JWT secret | 🔺 | `config.rs`、`config.toml`、`config/config.toml` 含可预测占位 secret，启动不拒绝默认值，也没有环境变量/secret-file 覆盖 |
| CORS/TLS/限流 | ⏳ | CORS 当前 `allow_origin(Any)` 等全开放；没有 TLS 强制、请求体限制、登录限速/锁定、审计日志 |
| WebSocket 认证 | ⏳ | WebSocket 路由未经过 JWT middleware，连接和频道没有认证/授权 |

### 2.3 区块链核心与数据完整性

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| Block/Chain/PoW/Merkle | ✅核心 | `src/core/` 已有真实实现；跨语言哈希和 metadata leaf 规则已对齐 |
| 启动恢复 | ⚠️ | `src/cli/server.rs` 恢复 blocks/users/versions，但恢复时没有完整验证索引、previous hash、PoW、Merkle root |
| 链验证 | ⚠️ | `Chain::validate_chain` 验证大部分链接和 PoW，但不重新验证创世块、Merkle root 与 metadata 的对应关系 |
| pending 原子性 | ⏳ | pending metadata 只在内存；进入 pending 后进程退出、尚未挖矿时数据会丢失 |
| attestation/identity/key transactions | 🧩 | Block 字段存在，但签名验证、身份注册、密钥轮换、交易处理和持久化业务流程未接入 |
| P2P/节点同步/冲突解决 | ⏳ | 未发现 peer、发现、连接、广播、同步协议或共识同步模块；WebSocket 不等同于 P2P 区块同步 |

### 2.4 存储、迁移与恢复

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| SQLite + SQLx | ✅基础 | `src/storage/database.rs` 创建 SQLite pool、blocks/users/versions 表及基础 CRUD |
| 独立 metadata/aggregation/events 表 | ⏳ | 当前没有对应表；相关数据主要留在内存或 block JSON 中 |
| SQLx 版本迁移 | ⏳ | 没有 `migrations/`、schema version 表、`sqlx::migrate!`、回滚或数据回填机制 |
| 数据损坏处理 | ⚠️ | JSON 反序列化失败的记录会被 `filter_map` 静默丢弃，查询错误也有统一误映射为“未找到”的情况 |
| 聚合持久化 | ⏳ | `AggregationEngine` 的 summaries 只在 `RwLock<Vec<_>>`，重启后列表和计数丢失 |
| Scheduler 运行 | 🧩 | `src/aggregation/scheduler.rs` 已定义，但 `src/cli/server.rs` 没有创建/启动 Scheduler |
| 配置环境变量 | ⏳ | 应用配置主要来自 TOML；JWT、数据库、聚合参数没有统一 env 覆盖和启动校验 |

### 2.5 聚合与版本控制

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| 时间/数量策略 | ⚠️ | 策略和 engine 存在，但聚合通常扫描所有历史 metadata，不区分未聚合部分 |
| 递归汇总 | 🔺 | `RecursiveStrategy` 有阈值判断，但 engine 始终生成 `level: 1`、空 `parent_summaries` 的单层 summary，没有父汇总合并 |
| 内容寻址存储 | 🧩 | `src/versioning/storage.rs` 功能较完整，但 server/HTTP track 使用 VersionTracker，未接入 ContentStorage |
| 版本差异 | ⚠️ | diff 读取当前路径文件，不是版本快照；文件被覆盖/删除后无法可靠比较历史内容 |
| 文件路径安全 | 🔺 | HTTP track 接受任意 `file_path`，缺根目录 allowlist、大小限制、符号链接限制和内容类型限制 |

## 三、测试与验证状态

- ✅ 核心算法已有单元测试：Block、Chain、Merkle/canonical、密码哈希、JWT、权限、版本 diff/content storage 等。
- ⏳ 没有独立 `tests/` 集成测试目录；API handler、Router、注册落库失败、角色越权、refresh token、WebSocket 收发、SQLx schema/重启恢复、Scheduler、聚合递归等缺少系统测试。
- ⚠️ 本次拆分只读核查，没有重新执行 `cargo test`、`cargo check`、Docker build、容器启动或 HTTP/WS smoke test。此前 monorepo 环境曾对默认 Rust 构建和 release 构建做过验证，但独立仓库应重新建立自己的 CI 证据。

## 四、建议开发顺序

1. **P0 安全**：禁止公开注册指定 admin；接入真实 Permission middleware；拒绝默认 JWT secret；限制 CORS；给 WebSocket 加认证、连接数和消息大小限制。
2. **P0 数据可靠性**：注册/挖矿/版本写库失败必须返回错误；pending、metadata、aggregation 纳入持久化和事务；启动恢复时验证整条链和 Merkle。
3. **P1 运行闭环**：把 WsHub/EventBus 放入 AppState 并在 metadata/mine/aggregate/version handler 发布事件；启动并管理 Scheduler；聚合结果持久化并恢复。
4. **P1 数据库演进**：引入 SQLx migrations、schema version、唯一约束/索引测试、坏记录告警和回滚策略。
5. **P1 版本安全**：接入 ContentStorage 或明确只做元数据追踪；限制 file_path 根目录；diff 读取内容快照。
6. **P1/P2 网络与测试**：若产品需要多节点，设计并实现 P2P/节点同步协议；补 API/SQLite/越权/WebSocket/Docker 集成测试和独立 CI。

## 五、独立仓库维护约定

- 本仓库不再依赖 monorepo 根的 `PROJECT_STATUS_OVERVIEW.md`；状态以本文档和 README 为准。
- 每次需求、设计或代码行为变化，都要同步本文档对应表格、README 和任务记录，并在状态项后附 commit 与验证方式。
- 远程仓库地址尚未配置；当前 Git 历史由原 monorepo 的 `datachain-rust` subtree 提取而来，提交消息和演进路径保留，commit hash 因 subtree 拆分而重新生成。
