# DataChain Rust 实现状态与未完成需求

> 核实日期:2026-10-18，代码进度更新至提交 `d97cd94`(可验证语义目录与完整 Claim 承诺基础)。
> R0-R7、backlog #3/#4/#5/#6、认证网 L1 与可验证语义目录基础已在 247 服务器 docker `rust:latest` 完成 cargo test/fmt/clippy(--all-targets)验证。
>
> **跨链认证网主线(基调)**:DataChain 内部**有意不做拜占庭共识**(受信节点 + 最长合法链),
> 可信根逐步来自把数据、身份及完整语义目录记录锚定到多个外部去中心化公共链。外链→本链的认证走正常上链路径(无特殊逻辑)。分层:L0 单链锚定(R5✅)
> → L1 链上身份(✅ `8b5ecf1`)→ 语义目录基础(✅ `d97cd94`)→ L2 多外链批次锚定 → L3 回执回写 → L4 失信切换 → L5 自身失信封存重启(人工触发)。
> 关键提交:R1 安全(fe93939 系列)、R5 跨链(4cf84f8)、R3 递归聚合(3c76ee4)、R2 原子提交(619e0eb)、R4 快照复核(095d1cd)、R6 P2P 广播/发现(4395546)、R7 集成测试(c90c65a)、backlog #4 WebSocket 集成测试(97eeee5)、backlog #3 refresh 持久化(1124baa)、语义目录(d97cd94)。
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
- ✅ 可验证语义目录:Subject→Revision→Artifact + 有签名/证据/时间范围/覆盖关系的 Claim；完整规范化语义成为 Merkle 叶子，目录 pending、区块提交与查询投影同链路持久化。

**仍存在的实质差异(⚠️/🧩,非本轮目标)**:
- ⚠️ P2P 内部无共识、无同长度分叉选择——这是**有意设计**(见认证网主线:可信根在外链锚定,非内部自证),非缺陷。链上身份注册/撤销已由 L1 接入(`5bf05c8`);密钥轮换状态机、多外链锚定(L2)、回执回写(L3)、失信切换(L4)、自身封存重启(L5)待后续。
- ✅ refresh token 持久化 + token-family 复用检测已补(见 `1124baa`/247 lib 62+集成 12 passed):撤销落 SQLite(重启不失忆)、复用触发整族撤销、并发双花以 jti 主键唯一性收口、启动清理过期撤销行。WebSocket 收发自动化集成测试已补(`97eeee5`/8 passed)。
- 🔺 WebSocket 频道(`/ws/chain`、`/ws/metadata`、`/ws/aggregation`)当前都订阅同一 `WsHub` 的**全量广播**,服务端 `handle_channel_socket` 不按频道过滤;任何 EventBus 事件会推给所有频道客户端。真正的频道隔离(如 `/ws/chain` 只收 chain 事件)未实现,属已知遗留(非 backlog #4 范围,#4 只验证"频道客户端能收到广播")。
- ✅ metadata 查询投影表已接入(`b239df6`):独立 `metadata` 表作为只读查询投影(权威源仍是区块 metadata_list),commit_block 同事务 upsert、启动/CLI 代码级回填,读路径走 SQL 不再扫链。注册失败写库返回语义已在 #3 收敛为 500。仍未做:tag 关联表、pending 联合查询(最小版有意不做)。
- ✅ 建表已纯 migration 驱动(`13ded24`):移除 init_tables 与 migration 重叠的兜底,事实源唯一收敛到 migrations/;旧库升级安全性有回归测试。回滚为 up-only 约定(无自动 down)、backfill 推迟到首个真实场景,属有意的范围收敛而非遗漏。

## 二、需求/设计与实现对照

### 2.1 HTTP API 与 WebSocket

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| 健康检查 | ✅ | `src/api/handlers.rs` 的 `health_check`；Docker healthcheck 请求 `/health` |
| 注册/登录/刷新 token | ✅ `1124baa`/247 已验证 | 注册失败写库回滚并返回 500(非旧述 201);refresh token 轮换 + 持久化撤销(SQLite)+ token-family 复用检测(复用触发整族撤销)+ 并发双花主键收口。设备会话管理仍未做(单 family 不区分设备) |
| 元数据创建/查询 | ✅ `b239df6`/247 已验证 | 创建(写路径)仍入链 pending(权威源);查询(读路径)走独立 `metadata` 投影表(migration 005),owner/时间下推 SQL、tag/分页应用层过滤,不再扫链。投影由 commit_block 同事务 upsert + 启动/CLI 代码级回填保证与区块一致。边界:只覆盖已上链元数据,pending 不出现在查询结果 |
| 可验证语义目录 | ✅ `d97cd94`/247 端到端已验证 | `POST /api/v1/catalog/records` 提交由已上链有效身份公钥签名的 Subject/Revision/Artifact/Claim；校验对象关系、主标识唯一性与 Claim 证据/时间范围，记录进入普通新区块的 `catalog_records` 并作为完整语义 Merkle 叶子。提供对象、版本、构建物、Claim 历史查询。边界:Claim 当前返回完整历史，尚未按认证者信任策略/覆盖关系计算单一有效结论 |
| 区块列表/详情/挖矿/验证 | ⚠️ | 路由存在；挖矿经 `commit_block` 原子落库(写库失败回滚并返回错误);链恢复/验证完整性仍待加强(见启动恢复项) |
| Merkle proof | ✅ `4cf84f8`/247 已验证 | 旧 `get_proof` 保留;新增 `GET /api/v1/crosschain/proof/:data_id`,经 `MerkleTree::get_structured_proof` 返回 leaf/index/siblings/sibling_is_left/root,服务端校验 `root==block.merkle_root` 且 `verify_structured_proof`;目标链可独立验证 data→root。处理奇数叶子自配对 |
| 跨链锚定(ChainAnchor/AnchorReceipt) | ✅ `4cf84f8`/247 已验证 | `src/crosschain.rs`:`POST /api/v1/crosschain/anchor/:data_id` 由 Merkle proof 生成 ed25519 签名锚定并写入 `anchor_outbox`(pending);后台 worker 带重试投递(`HttpAttestationConnector`),成功记录 `AnchorReceipt`;`GET /crosschain/anchor/status/:id` 查状态;`GET /crosschain/identity` 返回节点公钥。进程重启可从 outbox 恢复未投递锚定 |
| 节点签名身份 | ✅ `4cf84f8`/247 已验证 | `src/node_signing.rs`:ed25519 密钥对(生成/base64 种子恢复/签名/验签);配置 `DATACHAIN_NODE_SECRET` 持久化,未配置则启动随机生成并打印公钥 |
| 版本 API | ✅ 247 已验证 | `track_version` 经 `validate_version_path`(DATACHAIN_VERSION_ROOT allowlist+路径遍历/目录/符号链接防护)后保存不可变内容快照(ContentStorage);`get_version_diff` 用两版本历史快照计算,`get_version_content` 读快照不读当前文件;历史文件被覆盖/删除仍可还原。单测覆盖 track/diff/快照缺失/路径校验 |
| WebSocket 实时事件 | ⚠️ 已接线+集成测试已验证(频道隔离未实现) `97eeee5`/247 | `AppState` 持有 `WsHub`,连接有 JWT/连接数(256)/消息大小(16KiB)保护;业务事件经 EventBus 广播,已由 `tests/websocket_integration.rs` 自动化验证(8 passed):握手鉴权(无/无效 token 401、合法 101+welcome)、EventBus 广播(block_mined→block_added、metadata_created→metadata_added、aggregation_done→aggregation)、16KiB 上限(`/ws` 回 error 后断开、`/ws/chain` 只断开不回 error)、256 连接上限(第 257 个 503,释放后恢复)。**频道过滤未实现**:三频道共享全量广播,见下 🔺 频道隔离 |
| WebSocket 频道隔离 | 🔺 未实现 `97eeee5` | `/ws/chain`、`/ws/metadata`、`/ws/aggregation` 均 `hub.subscribe()` 订阅同一 `WsHub` 全量广播,`handle_channel_socket` 不做任何按频道过滤;所有 EventBus 事件推给所有频道客户端。差异影响:客户端订阅特定频道并不能只收到该类事件;原因:服务端尚未实现频道级路由,属已知遗留,后续若做需另起 backlog |
| EventBus/通知 | ✅ 247 已验证 `97eeee5` | `src/api/notification.rs` 已由 server 创建并注入;注册、元数据、挖矿、校验、版本、聚合 handler 会发布事件;广播链路已由 WS 集成测试覆盖(block/metadata/aggregation 三类事件实际收到) |

### 2.2 认证、授权与安全

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| JWT access/refresh | ✅ `1124baa`/247 已验证 | `src/auth/jwt.rs` 生成/验证含 issuer/audience 校验;refresh 轮换 + 持久化撤销(`revoked_refresh_tokens` 表)+ token-family 复用检测;JwtHandler 退为纯编解码,撤销状态由 `AuthService`+`Storage` 管理。仍缺:设备会话管理、access token 即时吊销(受 JWT 无状态固有限制,整族撤销对已签发 access 有最长一个 access 有效期的滞后) |
| 用户持久化 | ⚠️ | 启动可从 SQLite 加载；运行中注册写库失败仍成功返回，运行中资料/密码管理 API 未完整提供 |
| 公开注册 | ✅代码已修复/待验证 | `AuthService::register` 现在固定 `Role::User`；CLI 使用受信的 `register_with_role` 创建指定角色 |
| RBAC | ✅基础代码已接入/待验证 | `auth_middleware` 现在按 HTTP 方法/路径映射 `Permission` 并校验 claims 角色；用户管理/更细资源级授权仍未覆盖 |
| 密码哈希 | ⚠️ | 实际认证使用 bcrypt；多算法 API 存在，但部分算法的 salt/dispatch 设计不适合作为统一生产密码方案 |
| 默认 JWT secret | ✅代码已修复/待验证 | `AppConfig::load` 支持 `DATACHAIN_JWT_SECRET`/`JWT_SECRET` 覆盖，并拒绝短密钥和默认占位值 |
| CORS/TLS/限流 | ⚠️ | CORS 已改为 `DATACHAIN_CORS_ORIGINS` 显式 allowlist（未配置时本地开发来源）；TLS、请求体限制、登录限速/锁定、审计日志仍未实现 |
| WebSocket 认证 | ✅ 247 集成测试已验证 `97eeee5` | WebSocket 路由经 JWT 认证(无/无效 token 401、合法 token 101+welcome);Hub 限制 256 连接、单条文本 16 KiB;广播接线已由 `tests/websocket_integration.rs` 验证。按频道的事件授权/过滤仍未实现(见 2.1 WebSocket 频道隔离 🔺) |

### 2.3 区块链核心与数据完整性

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| Block/Chain/PoW/Merkle | ✅ `d97cd94` | 现有 metadata 叶子保持 `SHA256(data_id)` 兼容旧链；L1 key_tx 与新目录记录(`catalog_records`)的完整规范化语义均进入 merkle_root，受区块哈希/PoW 保护。旧 metadata 的完整字段仍非 Merkle 语义承诺，历史区块不重写 |
| 启动恢复 | ⚠️ | `src/cli/server.rs` 恢复 blocks/users/versions，但恢复时没有完整验证索引、previous hash、PoW、Merkle root |
| 链验证 | ⚠️ | `Chain::validate_chain` 验证大部分链接和 PoW，但不重新验证创世块、Merkle root 与 metadata 的对应关系 |
| pending 原子性 | ✅ 247 已验证 | pending metadata 已 SQLite 持久化(进程退出不丢);挖矿经 `Storage::commit_block` 在同一事务内原子写区块+删对应 pending,失败回滚内存区块与 pending 队列,消除两步之间崩溃的不一致窗口。单测 `commit_block_atomically_removes_pending` |
| attestation/identity/key transactions | ⚠️ `8b5ecf1`/247 端到端已验证 | 链上身份最小版(L1)已接入并经端到端集成测试(register→挖矿→查询→撤销链路真实可用):`POST /api/v1/identity/key-transaction`(register/revoke,ed25519 验签,register 自签)、`GET /identity/keys[/:pk]`(重放 key_transactions 得当前有效密钥集);key_transactions 进 merkle_root 受 PoW 保护(Block::calculate_merkle_root 选项 X);挖矿写 identity_snapshot_hash。签名负载不含 timestamp(服务端独立盖,`8b5ecf1` 修复)。**仍未做**:密钥轮换状态机、Merkle 身份树、pending key_tx 持久化(仅内存,重启丢未打包交易,幂等可重提);attestation 仍只在 verify_content 读、无专门提交流程 |
| P2P/节点同步/冲突解决 | ⚠️ `R6`/247 双节点已验证 | `src/p2p.rs` + `/api/v1/peers`、`/api/v1/sync/blocks`:显式注册 + **主动广播**(挖矿后 `broadcast_blocks` 推新块给 peers)+ **认证 gossip 发现**(`exchange_peers` 从已知 peer 拉取 peer 列表并入,跳过自身)+ 种子 peer(DATACHAIN_P2P_SEED_PEERS)+ 认证拉取/导入 + 最长合法链替换 + 60s 定时同步。**仍无共识、同长度分叉选择**(⚠️ 单一诚实源假设)。双节点 smoke:a 挖矿→b 经广播增长, 双向 exchange_peers 互相发现 |

### 2.4 存储、迁移与恢复

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| SQLite + SQLx | ✅基础 | `src/storage/database.rs` 创建 SQLite pool、blocks/users/versions 表及基础 CRUD |
| 独立 metadata/aggregation/events 表 | ⚠️ `d97cd94` | metadata 查询投影表已建(migration 005);aggregation 已持久化(`aggregations` 表);语义目录新增 pending_catalog_records 与 catalog_subjects/catalog_revisions/catalog_artifacts/catalog_claims 查询投影(migration 006);事件通知仍无独立表(经 EventBus 内存广播,不落库) |
| SQLx 版本迁移 | ✅ `13ded24`/247 已验证 | `migrations/001~006` + `schema_migrations` 版本表为建表唯一事实源;`apply_migrations` 按版本顺序执行幂等 DDL;`init_tables` 已移除重叠兜底,仅调 `apply_migrations`。旧库(无 schema_migrations)升级经回归测试 `legacy_db_without_schema_migrations_upgrades_safely` 验证不丢表、数据保留。**仍无自动 down 回滚**(有意收敛,up-only + 手动回滚约定)。数据回填在 #5(`b239df6`)落地为**代码级 reconcile**(启动/CLI 从已反序列化 Block 幂等 upsert 投影),而非纯 SQL migration——因 apply_migrations 的 `split(';')` 对复杂 SQL/JSON 解析脆弱,代码侧回填更稳 |
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
- ✅ 集成测试共 17 passed:`tests/api_integration.rs`(9,tower oneshot 进程内驱动 Router:公开 health、受保护路由 401、RBAC 越权 anchor、SQLite 重启恢复、L1 链上身份端到端 3 个、**语义目录端到端** Subject→Revision→Artifact→风险 Claim→上链查询、未登记签发公钥 403)+ `tests/websocket_integration.rs`(8,真实 axum 服务 + tokio-tungstenite 客户端:握手鉴权、EventBus 广播、16KiB 上限、256 连接上限,`97eeee5`)。247 验证 `d97cd94`。
- ✅ 核心算法 + 新增能力单测共 75 passed(core/merkle/canonical、密码哈希、JWT、权限、版本 diff/content、node_signing、crosschain、递归聚合、commit_block 原子性、p2p、链上身份、语义目录与 Merkle 语义承诺)。
- ⚠️ P2P 双节点广播/发现路径由 247 双容器 smoke 验证(非进程内集成测试)。refresh token 持久化/复用检测/并发双花已由单测覆盖(`1124baa`:正常轮换/复用整族撤销/并发双花 tokio::join 恰一成功/跨实例重启撤销持久化/revoke_refresh 抢占/purge 边界)。WebSocket 收发自动化集成测试已补(`97eeee5`),但只验证"频道客户端能收到广播",**不覆盖频道隔离**(服务端全量广播,频道过滤未实现,见 2.1 🔺)。
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

- ✅ #4 WebSocket 收发自动化集成测试 — `97eeee5` 247 `cargo test --test websocket_integration` 8 passed。
- ✅ #3 refresh token 持久化 + token-family 复用检测 — `1124baa` 247 lib 62 + 集成 12 passed(撤销落 SQLite/复用整族撤销/并发双花主键收口/启动清理)。
- ✅ 可验证语义目录 — `d97cd94` Subject→Revision→Artifact + 完整语义 Merkle 承诺 + signed Claim + pending 持久化/查询投影，247 lib 75 + 集成 17 passed。
- P2P 内部去中心化共识与自动分叉裁决：有意不实现，可信根由外部认证链锚定提供。
- 跨链认证网后续: L2 多外链批次锚定 / L3 锚定回执回写本链 / L4 外链失信切换 / L5 自身失信封存重启(人工触发,涉创世块语义单独设计)。
- Claim 信任策略与有效状态 resolver：按认证者信任、观察/生效时间与 supersedes/withdrawn 链计算当前结论；分类字典与认证者治理策略。
- 🔺 WebSocket 频道隔离:服务端按 `/ws/chain`、`/ws/metadata`、`/ws/aggregation` 过滤事件(当前为全量广播,见 2.1)。
- ✅ #6 纯 migration 驱动 — `13ded24` 移除 init_tables 兜底,建表事实源唯一化,旧库升级回归测试通过。回滚(自动 down)/数据回填按用户确认有意推迟。
- ✅ #5 独立 metadata 查询表 — `b239df6` migration 005 投影表 + commit_block 同事务 upsert + 代码级回填 reconcile,读路径走 SQL(lib 64 含投影测试)。tag 关联表/pending 联合查询为最小版有意不做。
- (可选)自动 down 回滚机制:当前 up-only + 手动回滚约定,无真实场景暂不实现。

## 五、独立仓库维护约定

- 本仓库不再依赖 monorepo 根的 `PROJECT_STATUS_OVERVIEW.md`；状态以本文档和 README 为准。
- 每次需求、设计或代码行为变化，都要同步本文档对应表格、README 和任务记录，并在状态项后附 commit 与验证方式。
- 远程仓库地址尚未配置；当前 Git 历史由原 monorepo 的 `datachain-rust` subtree 提取而来，提交消息和演进路径保留，commit hash 因 subtree 拆分而重新生成。
