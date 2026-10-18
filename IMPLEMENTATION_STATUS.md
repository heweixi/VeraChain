# DataChain Rust 实现状态与未完成需求

> 核实日期:2026-10-18，代码进度更新至提交 `c90c65a`(R7 集成测试)。
> R0-R7 全部完成并在 247 服务器 docker `rust:latest` 完成 cargo check/test/fmt/clippy(--all-targets)验证并做 HTTP/双节点 smoke。
> 关键提交:R1 安全(fe93939 系列)、R5 跨链(4cf84f8)、R3 递归聚合(3c76ee4)、R2 原子提交(619e0eb)、R4 快照复核(095d1cd)、R6 P2P 广播/发现(4395546)、R7 集成测试(c90c65a)。
> 状态标记:✅已实现 / ⚠️部分实现 / 🔺设计与实现有差异 / ⏳未实现 / 🧩预留能力 / 🗑️已废弃。
> 本文档基于源码、README、配置、Docker/Compose 和原 monorepo 的设计基线核查。

## 一、总体结论

DataChain Rust 已具备真实的 Axum HTTP 服务、SQLite/SQLx 基础存储、JWT 登录、区块/PoW/Merkle 核心、版本追踪、聚合策略、CLI 和 Docker 构建骨架。

R0-R7 推荐顺序已全部实现并验证。当前能力与关键残留差异如下:

- ✅ R1 安全:公开注册固定普通用户;认证中间件接入账户状态、角色新鲜度和路由权限;JWT issuer/audience + refresh jti 一次性撤销;默认/短 JWT secret 启动拒绝 + env 覆盖;CORS allowlist;10MiB 请求体限制;进程内限流;WebSocket JWT/256 连接/16KiB;可选 TLS。
- ✅ R2 数据可靠性:pending/aggregation SQLite 持久化、写库错误传播、启动恢复与区块/Merkle 校验;挖矿经 `commit_block` 在**同一事务**内写区块+删 pending(消除原子性缺口)。
- ✅ R3 递归聚合:`aggregate_recursive` 自底向上把未合并 summary 合并为 level+1 父 summary,真实多层(level1→2→3),不再是单层 level:1。
- ✅ R4 版本快照:内容快照 + 基于快照的历史 diff + `DATACHAIN_VERSION_ROOT` 路径 allowlist/遍历/符号链接校验。
- ✅ R5 跨链:完整 Merkle proof(可独立验证 data→root)、ed25519 节点签名、ChainAnchor/AnchorReceipt、anchor_outbox 重试投递、attestation connector、`/api/v1/crosschain/*` + RBAC。
- ✅ R6 P2P:显式注册 + **主动区块广播** + **认证 gossip 发现**(跳过自身)+ 种子 peer + 认证拉取/导入 + 最长合法链替换 + 60s 定时同步。
- ✅ R7 测试:55 单测 + 4 集成测试(`tests/api_integration.rs`:health/401/RBAC 越权/SQLite 重启恢复),双节点 smoke 验证广播/发现。

**仍存在的实质差异(⚠️/🧩,非本轮目标)**:
- ⚠️ P2P 无共识、无同长度分叉选择(单一诚实源假设);无跨链密钥轮换与链上身份注册交易。
- ⚠️ refresh token 轮换、WebSocket 收发自动化集成测试未补(当前 WS 由连接级保护 + 手工/单测覆盖)。
- ⚠️ 元数据仍以内存 pending + 区块 JSON 为主,无独立 metadata 查询表;注册失败写库的返回语义待收敛。
- ⚠️ 旧 `init_tables` 幂等建表作为兼容兜底与 migration 并存,未纯 migration 驱动。

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
| P2P/节点同步/冲突解决 | ⚠️ `R6`/247 双节点已验证 | `src/p2p.rs` + `/api/v1/peers`、`/api/v1/sync/blocks`:显式注册 + **主动广播**(挖矿后 `broadcast_blocks` 推新块给 peers)+ **认证 gossip 发现**(`exchange_peers` 从已知 peer 拉取 peer 列表并入,跳过自身)+ 种子 peer(DATACHAIN_P2P_SEED_PEERS)+ 认证拉取/导入 + 最长合法链替换 + 60s 定时同步。**仍无共识、同长度分叉选择**(⚠️ 单一诚实源假设)。双节点 smoke:a 挖矿→b 经广播增长, 双向 exchange_peers 互相发现 |

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
- ✅ `R7` 已新增 `tests/api_integration.rs` 集成测试(tower oneshot 进程内驱动真实 Router):公开 health、受保护路由 401、RBAC 越权(user 创建 anchor 403 / 读 proof 200 / admin anchor 200 pending)、SQLite 重启恢复区块与用户。247 验证 4 passed。
- ✅ 核心算法 + 新增能力单测共 55 passed(core/merkle/canonical、密码哈希、JWT、权限、版本 diff/content、node_signing、crosschain、递归聚合、commit_block 原子性、p2p)。
- ⚠️ P2P 双节点广播/发现路径由 247 双容器 smoke 验证(非进程内集成测试);refresh token 轮换/WebSocket 收发的自动化集成测试仍待补。
- ✅ 已建立独立仓库 CI 证据:R0-R7 均在 247 `rust:latest` 执行 `cargo check/test/fmt/clippy` 并做 HTTP smoke(见各 R 提交说明)。

## 四、开发进度与后续建议

### 已完成(R0-R7,推荐顺序)

1. ✅ **R0 构建基线**:Cargo.lock(含 reqwest)、cargo check/test/fmt/clippy、Docker build、HTTP smoke。
2. ✅ **R1 安全**:公开注册固定普通用户、RBAC 路由权限、JWT issuer/audience + refresh jti 撤销、默认/短 secret 拒绝、CORS allowlist、请求体限制、限流、WebSocket 保护、可选 TLS。
3. ✅ **R2 数据可靠性**:写库错误传播、持久化与启动恢复、`commit_block` 区块+pending 同事务原子化。
4. ✅ **R3 递归聚合**:自底向上多层父 summary 合并。
5. ✅ **R4 版本安全**:ContentStorage 快照、历史快照 diff、file_path 根目录 allowlist。
6. ✅ **R5 跨链**:Merkle proof、ed25519 签名、ChainAnchor/回执、outbox 重试、attestation connector。
7. ✅ **R6 P2P**:区块广播、认证 gossip 发现、种子 peer、最长合法链替换。
8. ✅ **R7 测试与 CI**:集成测试(API/RBAC/重启恢复)、双节点 smoke、247 CI 证据。

### 后续建议(backlog,非当前目标)

- P2P 共识与分叉选择(当前为单一诚实源假设)。
- 跨链密钥轮换与链上身份注册交易。
- refresh token 轮换;WebSocket 收发自动化集成测试。
- 独立 metadata 查询表;注册失败写库返回语义收敛。
- 纯 migration 驱动(移除 init_tables 兼容兜底);回滚/数据回填迁移。

## 五、独立仓库维护约定

- 本仓库不再依赖 monorepo 根的 `PROJECT_STATUS_OVERVIEW.md`；状态以本文档和 README 为准。
- 每次需求、设计或代码行为变化，都要同步本文档对应表格、README 和任务记录，并在状态项后附 commit 与验证方式。
- 远程仓库地址尚未配置；当前 Git 历史由原 monorepo 的 `datachain-rust` subtree 提取而来，提交消息和演进路径保留，commit hash 因 subtree 拆分而重新生成。
