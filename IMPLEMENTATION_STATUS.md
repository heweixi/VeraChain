# DataChain Rust 实现状态与未完成需求

> 最后核实:2026-11-11。本次新增「身份交易 Idempotency-Key + pending 身份交易 SQLite 持久化」，**当前精确代码尚未完成 cargo test/fmt/clippy 验证**（本机无 Rust 工具链、247 磁盘满），详见 §2.3 与 §三。
> 其余条目沿用 2026-11-10 核实：WebSocket 频道隔离已实现；验证证据为 247 docker `rust:latest` `cargo test`（97 passed，**旧版本历史结果，不代表本次改动**）。
> R0-R7、backlog #3/#4/#5/#6、认证网 L1、可验证语义目录与 Claim resolver 已在 247 服务器 docker `rust:latest` 完成 cargo test/fmt/clippy(--all-targets)验证。
>
> **跨链认证网主线(基调)**:DataChain 内部**有意不做拜占庭共识**(受信节点 + 最长合法链),
> 可信根逐步来自把数据、身份及完整语义目录记录锚定到多个外部去中心化公共链。外链→本链的认证走正常上链路径(无特殊逻辑)。分层:L0 单链锚定(R5✅)
> → L1 链上身份(✅ `8b5ecf1`)→ 语义目录基础(✅ `d97cd94`)→ Claim resolver(✅ 本次提交)→ L2 多外链批次锚定 → L3 回执回写 → L4 失信切换 → L5 自身失信封存重启(人工触发)。
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
- ✅ R7 测试:78 单测 + 19 集成测试（API 10 + WebSocket 9），共 97 passed；API 覆盖 health、401、RBAC 越权、SQLite 重启恢复及语义目录/Claim resolver 端到端路径，WebSocket 覆盖握手鉴权、EventBus 广播、16KiB 消息上限、256 连接上限和四路静态频道隔离；另有双节点 smoke 验证广播/发现。
- ✅ 可验证语义目录:Subject→Revision→Artifact + 有签名/证据/时间范围/覆盖关系的 Claim；完整规范化语义成为 Merkle 叶子，目录 pending、区块提交与查询投影同链路持久化。

**仍存在的实质差异(⚠️/🧩,非本轮目标)**:
- ⚠️ P2P 内部无共识、无同长度分叉选择——这是**有意设计**(见认证网主线:可信根在外链锚定,非内部自证),非缺陷。链上身份注册/撤销已由 L1 接入(`5bf05c8`);密钥轮换状态机、多外链锚定(L2)、回执回写(L3)、失信切换(L4)、自身封存重启(L5)待后续。
- ✅ refresh token 持久化 + token-family 复用检测已补(见 `1124baa`/247 lib 62+集成 12 passed):撤销落 SQLite(重启不失忆)、复用触发整族撤销、并发双花以 jti 主键唯一性收口、启动清理过期撤销行。WebSocket 收发自动化集成测试已补(`97eeee5`/8 passed)。
- ✅ WebSocket 频道隔离:服务端按静态事件映射过滤。`/ws` 接收全部业务事件；`/ws/chain` 仅接收 `block_added`、`chain_validated`；`/ws/metadata` 仅接收 `metadata_added`；`/ws/aggregation` 仅接收 `aggregation`；`version_tracked` 和未来未映射事件仅进入 `/ws`。这不是动态订阅或频道级授权。本次提交 + 247 docker `rust:latest` `cargo test`（97 passed）。
- ✅ metadata 查询投影表已接入(`b239df6`):独立 `metadata` 表作为只读查询投影(权威源仍是区块 metadata_list),commit_block 同事务 upsert、启动/CLI 代码级回填,读路径走 SQL 不再扫链。注册失败写库返回语义已在 #3 收敛为 500。仍未做:tag 关联表、pending 联合查询(最小版有意不做)。
- ✅ 建表已纯 migration 驱动(`13ded24`):移除 init_tables 与 migration 重叠的兜底,事实源唯一收敛到 migrations/;旧库升级安全性有回归测试。回滚为 up-only 约定(无自动 down)、backfill 推迟到首个真实场景,属有意的范围收敛而非遗漏。

## 二、需求/设计与实现对照

### 2.1 HTTP API 与 WebSocket

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| 健康检查 | ✅ | `src/api/handlers.rs` 的 `health_check`；Docker healthcheck 请求 `/health` |
| 注册/登录/刷新 token | ✅ `1124baa`/247 已验证 | 注册失败写库回滚并返回 500(非旧述 201);refresh token 轮换 + 持久化撤销(SQLite)+ token-family 复用检测(复用触发整族撤销)+ 并发双花主键收口。设备会话管理仍未做(单 family 不区分设备) |
| 元数据创建/查询 | ✅ `b239df6`/247 已验证 | 创建(写路径)仍入链 pending(权威源);查询(读路径)走独立 `metadata` 投影表(migration 005),owner/时间下推 SQL、tag/分页应用层过滤,不再扫链。投影由 commit_block 同事务 upsert + 启动/CLI 代码级回填保证与区块一致。边界:只覆盖已上链元数据,pending 不出现在查询结果 |
| 可验证语义目录 | ✅ 本次提交/247 端到端已验证 | `POST /api/v1/catalog/records` 提交由已上链有效身份公钥签名的 Subject/Revision/Artifact/Claim；校验对象关系、主标识唯一性与 Claim 证据/时间范围，记录进入普通新区块的 `catalog_records` 并作为完整语义 Merkle 叶子。原始 Claim 历史可查；`GET /catalog/subjects/:id/effective-claims` 按配置可信认证者、分类授权、权重、有效时间和覆盖关系解析有效结论，同权重不同状态返回 conflicts，未配可信认证者默认 fail-closed。边界:无集中分类字典和动态认证机构治理 |
| 区块列表/详情/挖矿/验证 | ⚠️ | 路由存在；挖矿经 `commit_block` 原子落库(写库失败回滚并返回错误);链恢复/验证完整性仍待加强(见启动恢复项) |
| Merkle proof | ✅ `4cf84f8`/247 已验证 | 旧 `get_proof` 保留;新增 `GET /api/v1/crosschain/proof/:data_id`,经 `MerkleTree::get_structured_proof` 返回 leaf/index/siblings/sibling_is_left/root,服务端校验 `root==block.merkle_root` 且 `verify_structured_proof`;目标链可独立验证 data→root。处理奇数叶子自配对 |
| 跨链锚定(ChainAnchor/AnchorReceipt) | ✅ `4cf84f8`/247 已验证 | `src/crosschain.rs`:`POST /api/v1/crosschain/anchor/:data_id` 由 Merkle proof 生成 ed25519 签名锚定并写入 `anchor_outbox`(pending);后台 worker 带重试投递(`HttpAttestationConnector`),成功记录 `AnchorReceipt`;`GET /crosschain/anchor/status/:id` 查状态;`GET /crosschain/identity` 返回节点公钥。进程重启可从 outbox 恢复未投递锚定 |
| 节点签名身份 | ✅ `4cf84f8`/247 已验证 | `src/node_signing.rs`:ed25519 密钥对(生成/base64 种子恢复/签名/验签);配置 `DATACHAIN_NODE_SECRET` 持久化,未配置则启动随机生成并打印公钥 |
| 版本 API | ✅ 247 已验证 | `track_version` 经 `validate_version_path`(DATACHAIN_VERSION_ROOT allowlist+路径遍历/目录/符号链接防护)后保存不可变内容快照(ContentStorage);`get_version_diff` 用两版本历史快照计算,`get_version_content` 读快照不读当前文件;历史文件被覆盖/删除仍可还原。单测覆盖 track/diff/快照缺失/路径校验 |
| WebSocket 实时事件 | ✅ 本次提交 + 247 docker `rust:latest` `cargo test`（97 passed） | `AppState` 持有 `WsHub`，连接保留 JWT、全局 256 连接与 16KiB 保护；`WsMessage` JSON schema 未变。业务事件经 EventBus 广播，`tests/websocket_integration.rs` 的 9 个测试覆盖握手鉴权、消息/连接上限及四路连接接收五种事件。`/ws` 接收全部业务事件；专用频道按静态映射投递，未映射事件仅进入 `/ws`。 |
| WebSocket 频道隔离 | ✅ 本次提交 + 247 docker `rust:latest` `cargo test`（97 passed） | 服务端采用静态映射：`/ws/chain` 仅投递 `block_added`、`chain_validated`；`/ws/metadata` 仅投递 `metadata_added`；`/ws/aggregation` 仅投递 `aggregation`。通用 `/ws` 保持全部业务事件；`version_tracked` 和未来未映射事件只投递到 `/ws`。新增端到端测试以四路连接发布五种事件，验证正向投递及非归属频道不投递。该功能不包含动态订阅或频道级授权。 |
| EventBus/通知 | ✅ 247 已验证 `97eeee5` | `src/api/notification.rs` 已由 server 创建并注入;注册、元数据、挖矿、校验、版本、聚合 handler 会发布事件;广播链路已由 WS 集成测试覆盖(block/metadata/aggregation 三类事件实际收到) |

### 2.2 认证、授权与安全

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| JWT access/refresh | ✅ `1124baa`/247 已验证 | `src/auth/jwt.rs` 生成/验证含 issuer/audience 校验;refresh 轮换 + 持久化撤销(`revoked_refresh_tokens` 表)+ token-family 复用检测;JwtHandler 退为纯编解码,撤销状态由 `AuthService`+`Storage` 管理。仍缺:设备会话管理、access token 即时吊销(受 JWT 无状态固有限制,整族撤销对已签发 access 有最长一个 access 有效期的滞后) |
| 用户持久化 | ⚠️ | 注册时若 `save_user` 失败，服务会回滚已写入内存的用户并返回 500；启动可从 SQLite 加载用户。仍缺运行时资料管理与密码管理 API。 |
| 公开注册 | ✅代码已修复/待验证 | `AuthService::register` 现在固定 `Role::User`；CLI 使用受信的 `register_with_role` 创建指定角色 |
| RBAC | ✅基础代码已接入/待验证 | `auth_middleware` 现在按 HTTP 方法/路径映射 `Permission` 并校验 claims 角色；用户管理/更细资源级授权仍未覆盖 |
| Claim 信任策略 | ✅ 本次提交/247 已验证 | `[claim_policy]` 配置可信认证者身份/公钥、分类授权和权重；resolver 仅接受满足最小权重及有效时间的声明，覆盖关系生效，同权重冲突不强行裁决。默认无可信认证者时 fail-closed |
| 密码哈希 | ⚠️ | 实际认证使用 bcrypt；多算法 API 存在，但部分算法的 salt/dispatch 设计不适合作为统一生产密码方案 |
| 默认 JWT secret | ✅代码已修复/待验证 | `AppConfig::load` 支持 `DATACHAIN_JWT_SECRET`/`JWT_SECRET` 覆盖，并拒绝短密钥和默认占位值 |
| CORS/TLS/限流 | ⚠️ | CORS 使用 `DATACHAIN_CORS_ORIGINS` 显式 allowlist（未配置时仅本地开发来源）；可选 TLS、10MiB 全局请求体限制与进程内全局限流已实现。仍缺登录专属限速/锁定和审计日志。 |
| WebSocket 认证 | ✅ 本次提交 + 247 docker `rust:latest` `cargo test`（97 passed） | WebSocket 路由经 JWT 认证(无/无效 token 401、合法 token 101+welcome)；Hub 保留全局 256 连接和单条文本 16 KiB 限制。频道按静态事件映射过滤，但不实施频道级授权；验证覆盖四路连接、五种事件的正向投递和非归属频道不投递。 |

### 2.3 区块链核心与数据完整性

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| Block/Chain/PoW/Merkle | ✅ `d97cd94` | 现有 metadata 叶子保持 `SHA256(data_id)` 兼容旧链；L1 key_tx 与新目录记录(`catalog_records`)的完整规范化语义均进入 merkle_root，受区块哈希/PoW 保护。旧 metadata 的完整字段仍非 Merkle 语义承诺，历史区块不重写 |
| 启动恢复 | ⚠️ | `src/cli/server.rs` 恢复 blocks/users/versions，但恢复时没有完整验证索引、previous hash、PoW、Merkle root |
| 链验证 | ⚠️ | `Chain::validate_chain` 验证大部分链接和 PoW，但不重新验证创世块、Merkle root 与 metadata 的对应关系 |
| pending 原子性 | ✅ 247 已验证 | pending metadata 已 SQLite 持久化(进程退出不丢);挖矿经 `Storage::commit_block` 在同一事务内原子写区块+删对应 pending,失败回滚内存区块与 pending 队列,消除两步之间崩溃的不一致窗口。单测 `commit_block_atomically_removes_pending` |
| attestation/identity/key transactions | ⚠️ `8b5ecf1`/247 端到端已验证 | 链上身份最小版(L1)已接入并经端到端集成测试(register→挖矿→查询→撤销链路真实可用):`POST /api/v1/identity/key-transaction`(register/revoke,ed25519 验签,register 自签)、`GET /identity/keys[/:pk]`(重放 key_transactions 得当前有效密钥集);key_transactions 进 merkle_root 受 PoW 保护(Block::calculate_merkle_root 选项 X);挖矿写 identity_snapshot_hash。签名负载不含 timestamp(服务端独立盖,`8b5ecf1` 修复)。**仍未做**:密钥轮换状态机、Merkle 身份树;attestation 仍只在 verify_content 读、无专门提交流程。(「pending key_tx 仅内存」的旧限制已由下一行的身份交易账本取代,见 §2.3.1) |
| 身份交易幂等与 pending 持久化(`Idempotency-Key`) | ⚠️ 代码已实现 / **本次提交当前代码未完成 Rust 验证** | 见 §2.3.1 |
| P2P/节点同步/冲突解决 | ⚠️ `R6`/247 双节点已验证 | `src/p2p.rs` + `/api/v1/peers`、`/api/v1/sync/blocks`:显式注册 + **主动广播**(挖矿后 `broadcast_blocks` 推新块给 peers)+ **认证 gossip 发现**(`exchange_peers` 从已知 peer 拉取 peer 列表并入,跳过自身)+ 种子 peer(DATACHAIN_P2P_SEED_PEERS)+ 认证拉取/导入 + 最长合法链替换 + 60s 定时同步。**仍无共识、同长度分叉选择**(⚠️ 单一诚实源假设)。双节点 smoke:a 挖矿→b 经广播增长, 双向 exchange_peers 互相发现 |

### 2.3.1 身份交易幂等与 pending 持久化(本次提交,⚠️ 代码已实现、验证未完成)

依据:`src/api/handlers.rs`(`submit_key_transaction`、`mine_block`)、`src/api/routes.rs`(CORS)、`src/storage/database.rs`(`create_or_get_identity_transaction`、`commit_block`、`get_pending_identity_transactions`)、`src/cli/server.rs`(`recover_pending_identity_transactions`)、`src/cli/chain.rs`、`migrations/007`、`008`。

**行为(读代码核实)**:

| 项 | 状态 | 说明 |
|---|---|---|
| `POST /api/v1/identity/key-transaction` 可选 `Idempotency-Key` 头 | ⚠️ 代码已实现/未验证 | 同用户 + 同键 + 同指纹 → 返回原事务:仍 pending 返回 `202`,已 committed 返回 `200`;同键但指纹不同 → `409`(`IdentityTransactionConflict`)。响应新增 `transaction_id`、`status` 字段 |
| 键的解析 | ⚠️ 代码已实现/未验证 | 去首尾空白后为空,或请求头非 UTF-8(`to_str()` 失败),均视为未提供(按无幂等键处理,每次生成新事务) |
| 用户隔离 | ⚠️ 代码已实现/未验证 | 唯一索引 `(submitter_user_id, idempotency_key) WHERE idempotency_key IS NOT NULL`,键按 JWT `claims.sub` 隔离,不同用户可使用相同键 |
| sidecar `transaction_id` | ⚠️ 代码已实现/未验证 | `transaction_id` 仅存于 SQLite 账本与内存队列的 sidecar,**不进入区块 JSON、Merkle 叶子或签名负载**;`KeyTransactionEntry` 与区块协议未变 |
| CORS | ⚠️ 代码已实现/未验证 | `allow_headers` 增加 `idempotency-key` |
| pending 持久化与重启恢复 | ⚠️ 代码已实现/未验证 | 身份交易先落 `identity_transactions` 表(`pending`),服务启动经 `recover_pending_identity_transactions` 按 `accepted_at, transaction_id` 恢复入队;`commit_block` 同事务把对应行置 `committed` 并记录 `committed_block_index` |
| 串行化 | ⚠️ 代码已实现/未验证 | `AppState.identity_tx_gate`(进程内 `tokio::Mutex`)串行化「身份提交」与「HTTP 挖矿」 |
| `Storage::commit_block` 签名 | 🔺 破坏性变更 | 由 `commit_block(&block)` 变为 `commit_block(&block, &[Option<String>])`(须与 `block.key_transactions` 逐项对齐,`None` 表示普通交易)。公开库 API 的调用方需适配;README 已声明库 API 不承诺稳定 |

**迁移与升级(007/008)**:

- `007_identity_transactions.sql`:新建 `identity_transactions` 表(状态 `pending`/`committed`)、幂等唯一索引、pending 顺序索引。
- `008_identity_transaction_recovery_state.sql`:新增 `recovery_state`(`legacy_unverified`/`verified`),列默认值为 `legacy_unverified`。新提交的身份交易写入 `verified`。
- 🔺 **升级前遗留 pending 行**(007 已部署、008 之前产生)会被标为 `legacy_unverified`:因区块 JSON 不含 `transaction_id`,无法证明其是否已被打包。**服务启动与 CLI `chain mine` 均 fail-closed**(报错 `refusing to recover N unverifiable legacy pending identity transaction(s)`),**不自动修复**。
- 人工处置思路(⚠️ 需谨慎,以下仅为示意,执行前务必按实际库核对):
  1. 停止服务,**先完整备份** SQLite 文件(含 `-wal`/`-shm`)。
  2. 查看遗留行:`SELECT transaction_id, submitter_user_id, entry, accepted_at FROM identity_transactions WHERE status='pending' AND recovery_state!='verified';`
  3. 人工把每条 `entry` 与 `blocks.data` 中的 `key_transactions` 比对,判断是否已入块。注意同内容条目可能合法重复,内容相同不等于同一交易。
  4. 已确认入块的:示意性改为已提交(`UPDATE identity_transactions SET status='committed', committed_block_index=<块号> WHERE transaction_id='<id>';`);确认未入块且确需继续打包的:示意性标为已核实(`UPDATE identity_transactions SET recovery_state='verified' WHERE transaction_id='<id>';`);确认应丢弃的再决定是否删除。以上 SQL **未经本项目验证**,不是内置恢复流程。
  5. 处理完毕再启动服务。

**已知限制(登记)**:

- ⚠️ (a) **服务运行时不要用 CLI `chain mine` 对同一数据库挖矿**:CLI 进程与服务进程各有内存队列且不共享 `identity_tx_gate`,可能使内存队列与账本漂移,导致服务后续挖矿持续失败,直到重启服务重新加载账本。
- ⚠️ (b) `legacy_unverified` **没有内置恢复命令**,只能人工处置(见上)。
- ⚠️ (c) `Idempotency-Key` **无长度上限**。请求指纹为 `SHA256(signing_payload)`,仅覆盖 `tx_type|target_key|role|label|signed_by` 5 个字段,**不含 `reason`、`timestamp`、`signature`**:同键下仅这三项不同的请求会被视为同一请求并返回原事务。
- ⚠️ (d) 同步导入区块(P2P/sync)**不会清理**本地内容相同的 pending(既有行为,本次未改变)。

**验证证据(如实)**:

- 本次提交的**当前精确代码未完成** `cargo test` / `cargo fmt --check` / `cargo clippy`:本机无 Rust 工具链,247 服务器磁盘已满无法运行 docker 验证。
- 仅有**旧版本**历史结果(87 lib + 19 API + 9 WS 通过)可供参考,**不代表本次代码**;本次未编造或推算任何新的测试计数。
- 代码中含相关新增测试(`tests/api_integration.rs`、`src/storage/database.rs`、`src/cli/server.rs`、`src/cli/chain.rs`),但**均未在本次代码上运行**。
- reviewer 复审结论:无 Important 级问题(基于读代码,非运行结果)。
- 因此上表各项不标 ✅;待 247 磁盘恢复并通过 cargo test/fmt/clippy 后再升级。

### 2.4 存储、迁移与恢复

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| SQLite + SQLx | ✅基础 | `src/storage/database.rs` 创建 SQLite pool、blocks/users/versions 表及基础 CRUD |
| 独立 metadata/aggregation/events 表 | ⚠️ `d97cd94` | metadata 查询投影表已建(migration 005);aggregation 已持久化(`aggregations` 表);语义目录新增 pending_catalog_records 与 catalog_subjects/catalog_revisions/catalog_artifacts/catalog_claims 查询投影(migration 006);事件通知仍无独立表(经 EventBus 内存广播,不落库) |
| SQLx 版本迁移 | ✅ `13ded24`/247 已验证 | `migrations/001~008`(007/008 为本次新增,见 §2.3.1,未在本次代码上验证) + `schema_migrations` 版本表为建表唯一事实源;`apply_migrations` 按版本顺序执行幂等 DDL;`init_tables` 已移除重叠兜底,仅调 `apply_migrations`。旧库(无 schema_migrations)升级经回归测试 `legacy_db_without_schema_migrations_upgrades_safely` 验证不丢表、数据保留。**仍无自动 down 回滚**(有意收敛,up-only + 手动回滚约定)。数据回填在 #5(`b239df6`)落地为**代码级 reconcile**(启动/CLI 从已反序列化 Block 幂等 upsert 投影),而非纯 SQL migration——因 apply_migrations 的 `split(';')` 对复杂 SQL/JSON 解析脆弱,代码侧回填更稳 |
| 数据损坏处理 | ⚠️已改善/待验证 | block/user/version/新 pending/aggregation JSON 解析错误会返回错误；旧用户/版本表的字段兼容迁移和坏数据恢复策略仍需补充 |
| 聚合持久化 | ✅ | aggregation summaries 已写入 SQLite 的 `aggregations` 表，server 启动时加载并恢复查询结果和聚合计数。仍有的边界：时间/数量策略通常扫描全部历史 metadata，不区分未聚合部分。 |
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
- ✅ 集成测试共 19 passed:`tests/api_integration.rs`(10，含语义目录端到端 Subject→Revision→Artifact→风险 Claim→上链查询、未登记签发公钥拒绝、**可信 Claim resolver 端到端**)+ `tests/websocket_integration.rs`(9，真实 axum 服务 + tokio-tungstenite 客户端：握手鉴权、EventBus 广播、16KiB 上限、256 连接上限，以及四路连接接收五种事件的频道隔离)。本次提交 + 247 docker `rust:latest` `cargo test`（97 passed）。
- ✅ 核心算法 + 新增能力单测共 78 passed(含 Claim resolver 的可信签发者/分类授权/覆盖关系/冲突/fail-closed 覆盖)。
- ⚠️ P2P 双节点广播/发现路径由 247 双容器 smoke 验证(非进程内集成测试)。refresh token 持久化/复用检测/并发双花已由单测覆盖(`1124baa`:正常轮换/复用整族撤销/并发双花 tokio::join 恰一成功/跨实例重启撤销持久化/revoke_refresh 抢占/purge 边界)。WebSocket 频道隔离已由端到端测试覆盖：专用频道只收到映射事件，`version_tracked` 仅进入 `/ws`；该功能不提供动态订阅或频道级授权。
- ✅ 已建立独立仓库 CI 证据:R0-R7 均在 247 `rust:latest` 执行 `cargo check/test/fmt/clippy` 并做 HTTP smoke(见各 R 提交说明)。

- ⚠️ **本次(身份交易幂等 + pending 持久化)验证状态**:当前精确代码在本机无 Rust 工具链、247 磁盘满的条件下**未完成** cargo test/fmt/clippy。上面的 97 passed / 87 lib + 19 API + 9 WS 均为**旧版本历史结果**,仅供参考,不代表本次提交。reviewer 复审(读代码)无 Important。

### 登记项(本次提交时登记,编号沿用本节顺序)

| 编号 | 状态 | 内容 |
|---|---|---|
| R-1 | 🔺 | `Storage::commit_block` 公开签名变更(breaking):新增 `identity_transaction_ids: &[Option<String>]` 参数 |
| R-2 | 🔺 协议既有 | `KeyTransactionEntry::signing_payload` 以 `|` 拼接字段,字段含 `|` 时可能碰撞;属协议既有问题,本次未改,计划在协议 v2 迁移时修复 |
| R-3 | ⚠️ | clippy 基线警告:既有代码存在 clippy 警告(基线问题),本次未清理,也未在本次代码上重跑 clippy |
| R-4 | ⚠️ 环境 | 247 验证服务器磁盘长期处于满状态,导致 docker 验证无法执行;须先清理磁盘,才能补做本次验证 |
| R-5 | ⚠️ | 见 §2.3.1 已知限制 (a)-(d):CLI 与运行中服务同库挖矿漂移、`legacy_unverified` 无内置恢复、幂等键无长度上限且指纹仅 5 字段、同步导入不清理本地 pending |

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

- ⏳ 补做本次身份交易幂等改动的 Rust 验证(247 磁盘恢复后跑 cargo test/fmt/clippy);提供 `legacy_unverified` 的内置恢复命令;为 `Idempotency-Key` 增加长度上限;指纹覆盖 reason/timestamp/signature 的取舍评估;`signing_payload` v2 分隔方案。

- ✅ #4 WebSocket 收发自动化集成测试 — 历史握手/广播/消息与连接上限覆盖已扩展为频道隔离端到端覆盖：四路连接、五种事件、正向投递和非归属频道不投递。本次提交 + 247 docker `rust:latest` `cargo test`（97 passed）。
- ✅ #3 refresh token 持久化 + token-family 复用检测 — `1124baa` 247 lib 62 + 集成 12 passed(撤销落 SQLite/复用整族撤销/并发双花主键收口/启动清理)。
- ✅ 可验证语义目录 — `d97cd94` Subject→Revision→Artifact + 完整语义 Merkle 承诺 + signed Claim + pending 持久化/查询投影，247 lib 75 + 集成 17 passed。
- P2P 内部去中心化共识与自动分叉裁决：有意不实现，可信根由外部认证链锚定提供。
- 跨链认证网后续: L2 多外链批次锚定 / L3 锚定回执回写本链 / L4 外链失信切换 / L5 自身失信封存重启(人工触发,涉创世块语义单独设计)。
- ✅ Claim 信任策略与有效状态 resolver — 本次提交:按可信认证者、分类授权、权重、观察/生效时间与 supersedes/withdrawn 链解析；同权重状态冲突显式返回，默认无可信认证者 fail-closed。
- Claim 集中分类字典与认证机构治理：动态信任权重、认证机构变更、跨机构争议裁决仍待实现。
- ✅ WebSocket 频道隔离 — 静态事件映射已实现：`/ws/chain`→`block_added`、`chain_validated`，`/ws/metadata`→`metadata_added`，`/ws/aggregation`→`aggregation`；`/ws` 保持全量，`version_tracked` 和未映射事件仅进入 `/ws`。本次提交 + 247 docker `rust:latest` `cargo test`（97 passed）。不包含动态订阅或频道级授权。
- ✅ #6 纯 migration 驱动 — `13ded24` 移除 init_tables 兜底,建表事实源唯一化,旧库升级回归测试通过。回滚(自动 down)/数据回填按用户确认有意推迟。
- ✅ #5 独立 metadata 查询表 — `b239df6` migration 005 投影表 + commit_block 同事务 upsert + 代码级回填 reconcile,读路径走 SQL(lib 64 含投影测试)。tag 关联表/pending 联合查询为最小版有意不做。
- (可选)自动 down 回滚机制:当前 up-only + 手动回滚约定,无真实场景暂不实现。

## 五、独立仓库维护约定

- 本仓库不再依赖 monorepo 根的 `PROJECT_STATUS_OVERVIEW.md`；状态以本文档和 README 为准。
- 每次需求、设计或代码行为变化，都要同步本文档对应表格、README 和任务记录，并在状态项后附 commit 与验证方式。
- 远程仓库已配置为 `https://github.com/heweixi/datachain-rust.git`；当前 Git 历史由原 monorepo 的 `datachain-rust` subtree 提取而来，提交消息和演进路径保留，commit hash 因 subtree 拆分而重新生成。
