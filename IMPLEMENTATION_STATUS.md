# DataChain Rust 实现状态与未完成需求

> 核实日期:2026-10-18，代码进度更新至提交 `4cf84f8`(R5 跨链证明与锚定)。
> R0/R1/R5 已在 247 服务器 docker `rust:latest` 完成 cargo check/test/fmt/clippy 验证并做 HTTP smoke；R2/R3/R4/R6/R7/R8 待推进。
> 状态标记:✅已实现 / ⚠️部分实现 / 🔺设计与实现有差异 / ⏳未实现 / 🧩预留能力 / 🗑️已废弃。
> 本文档基于源码、README、配置、Docker/Compose 和原 monorepo 的设计基线核查。

## 一、总体结论

DataChain Rust 已具备真实的 Axum HTTP 服务、SQLite/SQLx 基础存储、JWT 登录、区块/PoW/Merkle 核心、版本追踪、聚合策略、CLI 和 Docker 构建骨架。

但 README 中“完整 REST、WebSocket、RBAC、递归汇总”等表述高于当前实现。当前已完成 P0-A 安全代码接入、P0-B 数据可靠性基础、P1-A 事件/调度闭环基础、P1-B 版本化迁移基础、P1-C 版本快照安全基础，以及 P2 的最小认证 HTTP 区块同步；所有新代码仍待 Rust/Docker 验证。当前仍有以下实质差异：

- ✅ P0-A 安全代码已接入：公开注册固定普通用户；认证中间件接入账户状态、角色新鲜度和路由权限；JWT secret 环境覆盖/默认拒绝；CORS allowlist；WebSocket JWT/连接数/消息大小保护。
- ✅ P0-B 数据可靠性基础已接入：pending metadata/aggregation SQLite 持久化、写库错误传播、启动恢复和区块/Merkle 校验；区块保存与 pending 删除仍不是同一事务。
- ✅ P1-A 运行闭环基础已接入：WsHub/EventBus/Scheduler 进入 AppState；业务 handler 发布事件；WebSocket 订阅广播；Scheduler 自动启动并异步持久化聚合。
- ✅ P1-B 已有版本化 SQL migration 和坏记录显式报错；旧 init_tables 仍保留幂等建表兼容逻辑，尚未完全重构为纯 migration 驱动。
- ✅ P1-C 已接入内容快照、基于快照 diff 和版本路径 allowlist/大小/符号链接校验。
- ⚠️ P2 区块同步已实现基础方案：显式注册 peer、认证拉取/导入、完整链校验、最长合法链替换和 60 秒定时同步；没有自动发现、广播网络、共识或同长度分叉选择。
- P2：API/数据库/调度/越权测试不足；Cargo.lock 尚未生成 reqwest 新依赖的最终锁定变更；Docker 和运行时行为需要重新验证。

## 二、需求/设计与实现对照

### 2.1 HTTP API 与 WebSocket

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| 健康检查 | ✅ | `src/api/handlers.rs` 的 `health_check`；Docker healthcheck 请求 `/health` |
| 注册/登录/刷新 token | ⚠️ | 基础路径存在；注册失败写库只记日志仍返回 201；refresh token 无轮换、撤销和设备会话管理 |
| 元数据创建/查询 | ⚠️ | `src/api/handlers.rs` 只把新元数据加入内存 pending；查询主要扫描已加载区块，没有独立 metadata 表 |
| 区块列表/详情/挖矿/验证 | ⚠️ | 路由存在；挖矿经 `commit_block` 原子落库(写库失败回滚并返回错误);链恢复/验证完整性仍待加强(见启动恢复项) |
| Merkle proof | ✅ `4cf84f8`/247 已验证 | 旧 `get_proof` 保留;新增 `GET /api/v1/crosschain/proof/:data_id`,经 `MerkleTree::get_structured_proof` 返回 leaf/index/siblings/sibling_is_left/root,服务端校验 `root==block.merkle_root` 且 `verify_structured_proof`;目标链可独立验证 data→root。处理奇数叶子自配对 |
| 跨链锚定(ChainAnchor/AnchorReceipt) | ✅ `4cf84f8`/247 已验证 | `src/crosschain.rs`:`POST /api/v1/crosschain/anchor/:data_id` 由 Merkle proof 生成 ed25519 签名锚定并写入 `anchor_outbox`(pending);后台 worker 带重试投递(`HttpAttestationConnector`),成功记录 `AnchorReceipt`;`GET /crosschain/anchor/status/:id` 查状态;`GET /crosschain/identity` 返回节点公钥。进程重启可从 outbox 恢复未投递锚定 |
| 节点签名身份 | ✅ `4cf84f8`/247 已验证 | `src/node_signing.rs`:ed25519 密钥对(生成/base64 种子恢复/签名/验签);配置 `DATACHAIN_NODE_SECRET` 持久化,未配置则启动随机生成并打印公钥 |
| 版本 API | ✅ 247 已验证 | `track_version` 经 `validate_version_path`(DATACHAIN_VERSION_ROOT allowlist+路径遍历/目录/符号链接防护)后保存不可变内容快照(ContentStorage);`get_version_diff` 用两版本历史快照计算,`get_version_content` 读快照不读当前文件;历史文件被覆盖/删除仍可还原。单测覆盖 track/diff/快照缺失/路径校验 |
| WebSocket 实时事件 | ⚠️代码已接线/待验证 | `AppState` 持有 `WsHub`，连接有 JWT/连接数/消息大小保护；业务事件现在可经 EventBus 广播，但频道过滤和运行时 smoke test仍待验证 |
| EventBus/通知 | ✅代码已接线/待验证 | `src/api/notification.rs` 已由 server 创建并注入；注册、元数据、挖矿、校验、版本、聚合 handler 会发布事件 |

### 2.2 认证、授权与安全

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| JWT access/refresh | ⚠️ | `src/auth/jwt.rs` 可生成/验证；缺 issuer/audience 强校验、撤销、轮换和设备会话管理；secret 安全前置已在 `fe93939` 接入，待编译验证 |
| 用户持久化 | ⚠️ | 启动可从 SQLite 加载；运行中注册写库失败仍成功返回，运行中资料/密码管理 API 未完整提供 |
| 公开注册 | ✅代码已修复/待验证 | `AuthService::register` 现在固定 `Role::User`；CLI 使用受信的 `register_with_role` 创建指定角色 |
| RBAC | ✅基础代码已接入/待验证 | `auth_middleware` 现在按 HTTP 方法/路径映射 `Permission` 并校验 claims 角色；用户管理/更细资源级授权仍未覆盖 |
| 密码哈希 | ⚠️ | 实际认证使用 bcrypt；多算法 API 存在，但部分算法的 salt/dispatch 设计不适合作为统一生产密码方案 |
| 默认 JWT secret | ✅代码已修复/待验证 | `AppConfig::load` 支持 `DATACHAIN_JWT_SECRET`/`JWT_SECRET` 覆盖，并拒绝短密钥和默认占位值 |
| CORS/TLS/限流 | ⚠️ | CORS 已改为 `DATACHAIN_CORS_ORIGINS` 显式 allowlist（未配置时本地开发来源）；TLS、请求体限制、登录限速/锁定、审计日志仍未实现 |
| WebSocket 认证 | ✅基础代码已接入/待验证 | WebSocket 路由现在经过 JWT 认证；Hub 限制 256 连接、单条文本 16 KiB；事件授权/广播接线仍待 P1 |

### 2.3 区块链核心与数据完整性

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| Block/Chain/PoW/Merkle | ✅核心 | `src/core/` 已有真实实现；跨语言哈希和 metadata leaf 规则已对齐 |
| 启动恢复 | ⚠️ | `src/cli/server.rs` 恢复 blocks/users/versions，但恢复时没有完整验证索引、previous hash、PoW、Merkle root |
| 链验证 | ⚠️ | `Chain::validate_chain` 验证大部分链接和 PoW，但不重新验证创世块、Merkle root 与 metadata 的对应关系 |
| pending 原子性 | ✅ 247 已验证 | pending metadata 已 SQLite 持久化(进程退出不丢);挖矿经 `Storage::commit_block` 在同一事务内原子写区块+删对应 pending,失败回滚内存区块与 pending 队列,消除两步之间崩溃的不一致窗口。单测 `commit_block_atomically_removes_pending` |
| attestation/identity/key transactions | ⚠️ `4cf84f8` | 节点 ed25519 身份 + 跨链锚定签名/验签已接入(见 2.1 跨链锚定);密钥轮换、链上身份注册交易、密钥撤销仍未实现 |
| P2P/节点同步/冲突解决 | ⚠️基础同步已实现/仍不完整 | `src/p2p.rs` + `/api/v1/peers`、`/api/v1/sync/blocks` 提供显式 peer 注册、认证拉取/导入、最长合法链选择和定时同步；没有自动发现、广播网络、共识或同长度分叉选择 |

### 2.4 存储、迁移与恢复

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| SQLite + SQLx | ✅基础 | `src/storage/database.rs` 创建 SQLite pool、blocks/users/versions 表及基础 CRUD |
| 独立 metadata/aggregation/events 表 | ⏳ | 当前没有对应表；相关数据主要留在内存或 block JSON 中 |
| SQLx 版本迁移 | ⚠️基础已实现/待验证 | `migrations/001_base.sql`、`002_pending_aggregations.sql` + `schema_migrations` 已接入；旧 `IF NOT EXISTS` 初始化仍保留为兼容兜底，尚无回滚/数据回填迁移 |
| 数据损坏处理 | ⚠️已改善/待验证 | block/user/version/新 pending/aggregation JSON 解析错误会返回错误；旧用户/版本表的字段兼容迁移和坏数据恢复策略仍需补充 |
| 聚合持久化 | ⏳ | `AggregationEngine` 的 summaries 只在 `RwLock<Vec<_>>`，重启后列表和计数丢失 |
| Scheduler 运行 | ✅代码已启动/待验证 | `src/cli/server.rs` 创建、注册回调并启动 Scheduler；自动聚合结果异步写入 SQLite 并发布 EventBus 事件 |
| 配置环境变量 | ✅基础已实现/待验证 | JWT、数据库 DSN、host、port 支持环境变量覆盖；默认 JWT secret/短 secret 启动拒绝；聚合等配置仍主要来自 TOML |

### 2.5 聚合与版本控制

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| 时间/数量策略 | ⚠️ | 策略和 engine 存在，但聚合通常扫描所有历史 metadata，不区分未聚合部分 |
| 递归汇总 | ✅ `4cf84f8`/247 已验证 | `aggregate(Recursive)` 走 `aggregate_recursive`:自底向上,未合并 summary 数达 `recursive_threshold`(min(count_threshold,8)≥2)即合并为 level+1 父 summary;父 `merkle_root=build_merkle_root(子 root)`、`metadata_count/total_size` 累加、`parent_summaries` 记子 id、子标记 `is_merged`。`should_aggregate` 按每 level 未合并数触发递归。单测覆盖单层合并/阈值不足/多层(level1→2→3) |
| 内容寻址存储 | ✅ 247 已验证 | `VersionTracker` 内置 `ContentStorage`(快照目录由 DATACHAIN_VERSION_CONTENT_DIR 配置);HTTP/CLI track 均保存内容快照并校验快照哈希==内容哈希 |
| 版本差异 | ✅ 247 已验证 | `get_version_diff` 从两版本的不可变快照读取内容再 diff,不依赖当前文件;文件被覆盖/删除仍可比较历史 |
| 文件路径安全 | ✅ 247 已验证 | `validate_version_path`:拒绝空/绝对/`..` 遍历,canonical 后必须位于 `DATACHAIN_VERSION_ROOT` 内,拒绝目录与越界符号链接。单测 `rejects_path_traversal_before_filesystem_access` 等 |

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
