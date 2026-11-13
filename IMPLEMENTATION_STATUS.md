# DataChain Rust 实现状态与未完成需求

> ✅ **合并后验证声明(以此为准)**:本分支 `feat/pending-identity-transactions-local`(身份交易 `Idempotency-Key` + pending 身份交易持久化,§2.3.1)已合并 `main`(`ecae5e0`:数据损坏处置 §2.6 + 认证加固 §2.7),HEAD `65c7c4c`(= `a5b6f80` 迁移改名 007/008→010/011 + `6bc1d9d` `git merge main` + `65c7c4c` 回归测试)。最后核实:2026-11-13。本次提交 + 验证机 `deploy@192.168.3.7` docker `rust:latest`(作业 pimergeo,orchestrator 亲自复跑,避开登录限速测试的 15 分钟窗口边界):`cargo fmt --check` rc=0;`cargo test --no-fail-fast` 19 个测试目标全部 ok,共 **234 passed、0 failed**(lib 110、bin 0、api_integration 21、auth_audit 13、auth_claims 5、auth_middleware_session 12、chain_validation_cli 1、cli_user_status 3、connect_info_rate_limit 5、data_corruption_authoritative 4、data_corruption_cli 4、data_corruption_outbox 9、data_corruption_projection 3、data_corruption_startup 5、login_rate_limit 8、sessions_api 16、storage_sessions 4、websocket_integration 11、doctest 0);`cargo clippy --all-targets`(无 `-D warnings`)无 error,lib 22 条警告(与 main 基线持平,无新增),`tests/common/corrupt.rs` 的 `dead_code` 告警为遗留共享 helper(未处理)。reviewer 对合并做了行为级审查,无 Important。设计文档:`docs/superpowers/specs/2026-11-13-auth-hardening-design.md`、`docs/superpowers/specs/2026-11-11-data-corruption-policy-design.md`。
> **历史数字说明**:**210 passed**(main `ecae5e0`,数据损坏 + 认证加固合并后,作业 authmergeo,不含本分支身份交易)是上一层历史数字;**139 passed**(数据损坏分支 `d3614f6` 单独)、**168 passed**(认证加固分支单独)、**120 passed**(本分支 `734f1a2` 合并前单独)是**合并前各分支的历史数字**,均不适用于当前合并结果。下文及各行中的 107 / 97 / 78 / 75+17 / 62+12 等也是各自提交当时在 247 验证机上的历史基线,仅供追溯。下文各行标注的测试文件分项(如 `auth_audit 13`、`sessions_api 16`)均包含在合并后 234 passed 中。
> 以下为 2026-11-10 的历史说明:WebSocket 频道隔离已实现；验证证据为当时提交 + 247 docker `rust:latest` `cargo test`（97 passed,历史基线）。
> 统一显式链完整性校验已实现；其历史验证证据为基线 `96d08e8` + 247 docker `rust:latest` `cargo test`（107 passed，**旧基线计数**）。
> **验证环境变更**:主验证机已从 247 迁到 `deploy@192.168.3.7`(局域网,docker `rust:latest`);247 根分区长期 100% 满,降为备用。下文"247 …已验证"的历史条目是迁移前在 247 上取得的证据,保持原样。
> 历史（pending identity 分支合并 main 前的单独结果，120 passed 为历史数字，不适用于合并后；合并后以顶部 234 passed 为准）：2026-11-11。新增「身份交易 Idempotency-Key + pending 身份交易 SQLite 持久化」，提交 `734f1a2` 已在验证机 192.168.3.7 docker `rust:latest` 验证：`cargo fmt --check` rc=0；`cargo test --no-fail-fast` rc=0，120 passed / 0 failed（lib 91、bin 0、api_integration 20、websocket_integration 9、doctest 0）；`cargo clippy --all-targets` rc=0，本分支无新增告警（基线告警仍在）。详见 §2.3.1 与 §三。
> 其余条目沿用 2026-11-10 核实：WebSocket 频道隔离已实现；其下标注的 97 passed 是各自功能提交当时的历史结果，不是当前总数。
> R0-R7、backlog #3/#4/#5/#6、认证网 L1、可验证语义目录与 Claim resolver 已在 247 服务器 docker `rust:latest` 完成 cargo test/fmt/clippy(--all-targets)验证。
>
> **跨链认证网主线(基调)**:DataChain 内部**有意不做拜占庭共识**(受信节点 + 最长合法链),
> 可信根逐步来自把数据、身份及完整语义目录记录锚定到多个外部去中心化公共链。外链→本链的认证走正常上链路径(无特殊逻辑)。分层:L0 单链锚定(R5✅)
> → L1 链上身份(✅ `8b5ecf1`)→ 语义目录基础(✅ `d97cd94`)→ Claim resolver(✅ 本次提交)→ L2 多外链批次锚定 → L3 回执回写 → L4 失信切换 → L5 自身失信封存重启(人工触发)。
> 关键提交:R1 安全(fe93939 系列)、R5 跨链(4cf84f8)、R3 递归聚合(3c76ee4)、R2 原子提交(619e0eb)、R4 快照复核(095d1cd)、R6 P2P 广播/发现(4395546)、R7 集成测试(c90c65a)、backlog #4 WebSocket 集成测试(97eeee5)、backlog #3 refresh 持久化(1124baa)、语义目录(d97cd94)。
> **✅ 数据损坏分支(`feat/data-corruption-policy`,HEAD `d3614f6`,基于 `fix/chain-integrity-validation` `96d08e8`)合并前单独验证记录(2026-11-13,历史数字;合并后以顶部 234 passed 为准)**:数据损坏处置策略(见 §2.4「数据损坏处理」与 §2.6)当时在验证机 `deploy@192.168.3.7` docker `rust:latest` 真实验证。当时 `cargo test`(139 passed,合并前单独):`cargo fmt --check` rc=0;`cargo test --no-fail-fast` TEST_RC=0,139 passed / 0 failed(lib 93、bin 0、api_integration 11、chain_validation_cli 1、data_corruption_authoritative 4、data_corruption_cli 4、data_corruption_outbox 9、data_corruption_projection 3、data_corruption_startup 5、websocket_integration 9、doctest 0);`cargo clippy --all-targets`(未加 `-D warnings`)无 error,lib 22 条 warning(既有基线约 23 条,本分支新增的 `anchor_outbox` type_complexity 已消除),`tests/common/corrupt.rs` 3 条 `dead_code`(共享测试 helper,未处理)。首次真实运行发现并已修复:2 个 `/chain/validate` HTTP 测试漏带 Bearer token(返回 401,**测试缺陷,路由鉴权未改**)、rustfmt 格式差异(修复提交 `e63c66a`、`1a8b4b6`、`d3614f6`)。reviewer 两轮读代码审查最终无 Important。文档中各处"107 passed"是 `96d08e8` 及更早基线的**旧计数**。**仍未覆盖(保持 ⚠️/⏳)**:`login`/`refresh` 遇损坏返回 500(body `internal error`)无集成测试;已知限制见 §2.6。设计见 `docs/superpowers/specs/2026-11-11-data-corruption-policy-design.md`。
> 状态标记:✅已实现 / ⚠️部分实现 / 🔺设计与实现有差异 / ⏳未实现 / 🧩预留能力 / 🗑️已废弃。
> 本文档基于源码、README、配置、Docker/Compose 和原 monorepo 的设计基线核查。

## 一、总体结论

DataChain Rust 已具备真实的 Axum HTTP 服务、SQLite/SQLx 基础存储、JWT 登录、区块/PoW/Merkle 核心、版本追踪、聚合策略、CLI 和 Docker 构建骨架。

R0-R7 推荐顺序已全部实现并验证。当前能力与关键残留差异如下:

- ✅ R1 安全:公开注册固定普通用户;认证中间件接入账户状态、角色新鲜度和路由权限;JWT issuer/audience + refresh jti 一次性撤销;默认/短 JWT secret 启动拒绝 + env 覆盖;CORS allowlist;10MiB 请求体限制;进程内限流;WebSocket JWT/256 连接/16KiB;可选 TLS。
- ✅ R2 数据可靠性:pending/aggregation SQLite 持久化、写库错误传播、启动恢复时 `validate_loaded_blocks` 与 `validate_chain` 复用统一显式链完整性校验；恢复发现损坏区块会失败关闭，不加载、修复或写回该库。挖矿经 `commit_block` 在**同一事务**内写区块+删 pending(消除原子性缺口)。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。
- ✅ R3 递归聚合:`aggregate_recursive` 自底向上把未合并 summary 合并为 level+1 父 summary,真实多层(level1→2→3),不再是单层 level:1。
- ✅ R4 版本快照:内容快照 + 基于快照的历史 diff + `DATACHAIN_VERSION_ROOT` 路径 allowlist/遍历/符号链接校验。
- ✅ R5 跨链:完整 Merkle proof(可独立验证 data→root)、ed25519 节点签名、ChainAnchor/AnchorReceipt、anchor_outbox 重试投递、attestation connector、`/api/v1/crosschain/*` + RBAC。
- ✅ R6 P2P:显式注册 + **主动区块广播** + **认证 gossip 发现**(跳过自身)+ 种子 peer + 认证拉取/导入 + 最长合法链替换 + 60s 定时同步。
- ✅ R7 测试:86 单测 + 21 集成测试（API 11 + CLI 1 + WebSocket 9），共 107 passed；API 覆盖 health、401、RBAC 越权、SQLite 重启恢复及语义目录/Claim resolver 端到端路径，CLI 覆盖 `chain validate` 的有效/无效输出与无效成功退出，WebSocket 覆盖握手鉴权、EventBus 广播、16KiB 消息上限、256 连接上限和四路静态频道隔离。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。
- ✅ 可验证语义目录:Subject→Revision→Artifact + 有签名/证据/时间范围/覆盖关系的 Claim；完整规范化语义成为 Merkle 叶子，目录 pending、区块提交与查询投影同链路持久化。

**仍存在的实质差异(⚠️/🧩,非本轮目标)**:
- ⚠️ P2P 内部无共识、无同长度分叉选择——这是**有意设计**(见认证网主线:可信根在外链锚定,非内部自证),非缺陷。链上身份注册/撤销已由 L1 接入(`5bf05c8`);密钥轮换状态机、多外链锚定(L2)、回执回写(L3)、失信切换(L4)、自身封存重启(L5)待后续。
- ✅ refresh token 持久化 + token-family 复用检测已补(见 `1124baa`/247 lib 62+集成 12 passed):撤销落 SQLite(重启不失忆)、复用触发整族撤销、并发双花以 jti 主键唯一性收口、启动清理过期撤销行。WebSocket 收发自动化集成测试已补(`97eeee5`/8 passed)。
- ✅ WebSocket 频道隔离:服务端按静态事件映射过滤。`/ws` 接收全部业务事件；`/ws/chain` 仅接收 `block_added`、`chain_validated`；`/ws/metadata` 仅接收 `metadata_added`；`/ws/aggregation` 仅接收 `aggregation`；`version_tracked` 和未来未映射事件仅进入 `/ws`。这不是动态订阅或频道级授权。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。
- ✅ metadata 查询投影表已接入(`b239df6`):独立 `metadata` 表作为只读查询投影(权威源仍是区块 metadata_list),commit_block 同事务 upsert、启动/CLI 代码级回填,读路径走 SQL 不再扫链。注册失败写库返回语义已在 #3 收敛为 500。仍未做:tag 关联表、pending 联合查询(最小版有意不做)。
- ✅ 建表已纯 migration 驱动(`13ded24`):移除 init_tables 与 migration 重叠的兜底,事实源唯一收敛到 migrations/;旧库升级安全性有回归测试。回滚为 up-only 约定(无自动 down)、backfill 推迟到首个真实场景,属有意的范围收敛而非遗漏。

## 二、需求/设计与实现对照

### 2.1 HTTP API 与 WebSocket

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| 健康检查 | ✅ | `src/api/handlers.rs` 的 `health_check`；Docker healthcheck 请求 `/health` |
| 注册/登录/刷新 token | ✅ `1124baa`/247 已验证(历史);本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed) | 注册失败写库回滚并返回 500(非旧述 201);refresh token 轮换 + 持久化撤销(SQLite)+ token-family 复用检测(复用触发整族撤销)+ 并发双花主键收口。**本次**:登录创建会话(会话 id 即 refresh family,access 携带 `sid`),refresh 校验 is_active 与会话有效并更新 `last_seen_at`、新 access 带 `sid`,旧 refresh(空 family)补建会话。🔺 登录失败统一返回 401 `invalid credentials`(原可区分用户不存在/密码错),超限 429 + `Retry-After`;`login`/`refresh` 遇 `DataCorruption`/`DatabaseError`/`StorageError` 返回 500 + 固定 `internal error`(⚠️ 无集成测试,见 §2.6)。⚠️ refresh 失败(停用/会话失效)未写审计事件;「`touch_session` 失败且为复用时返回 TokenReuseDetected」分支无专门测试 |
| 会话与登出接口 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:sessions_api 16、auth_middleware_session 12) | `POST /api/v1/auth/logout`(撤销当前会话,幂等,204)、`POST /api/v1/auth/logout-all`(撤销本人全部会话,幂等,204);`GET /api/v1/auth/sessions`(含 `current`、脱敏 `ip_hint`,不返回 token/jti/ip_hash/refresh family);`DELETE /api/v1/auth/sessions/{id}`(204;非本人/不存在/已失效统一 404)。四条均为受保护路由,CORS 放行 DELETE。⚠️ 无 `sid` 的旧 access token 登出无效(无会话可撤销),最长保持到自然过期(默认 24h) |
| 登录限速与统一失败响应 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:login_rate_limit 8) | 固定窗口,用户名维度 5 次、IP 维度 20 次 / 15 分钟,超限 429 + `Retry-After`;不存在用户同样计数且执行 dummy bcrypt 抹平时序;计数持久化 SQLite(`login_rate_counters`,重启不丢);**成功登录只归还本次名额,不清零**(reviewer 发现的 I1:原"成功即清零"可被大小写变体账户重置受害者计数,已修复并有回归测试)。⚠️ 纯固定窗口:窗口边界约 2 倍突发;指数退避与 `locked_until` 未实现(列保留未用,见 §2.7) |
| 元数据创建/查询 | ✅ `b239df6`/247 已验证 | 创建(写路径)仍入链 pending(权威源);查询(读路径)走独立 `metadata` 投影表(migration 005),owner/时间下推 SQL、tag/分页应用层过滤,不再扫链。投影由 commit_block 同事务 upsert + 启动/CLI 代码级回填保证与区块一致。边界:只覆盖已上链元数据,pending 不出现在查询结果 |
| 可验证语义目录 | ✅ 本次提交/247 端到端已验证 | `POST /api/v1/catalog/records` 提交由已上链有效身份公钥签名的 Subject/Revision/Artifact/Claim；校验对象关系、主标识唯一性与 Claim 证据/时间范围，记录进入普通新区块的 `catalog_records` 并作为完整语义 Merkle 叶子。原始 Claim 历史可查；`GET /catalog/subjects/:id/effective-claims` 按配置可信认证者、分类授权、权重、有效时间和覆盖关系解析有效结论，同权重不同状态返回 conflicts，未配可信认证者默认 fail-closed。边界:无集中分类字典和动态认证机构治理 |
| 区块列表/详情/挖矿/验证 | ✅ | 路由存在；挖矿经 `commit_block` 原子落库(写库失败回滚并返回错误)。`validate_chain` 与 `validate_loaded_blocks` 复用同一私有完整性门禁：非空链校验创世 index/previous_hash、连续 index、每块保存 hash、块自身 difficulty PoW、previous hash 及按既有 metadata/key transaction/catalog record 规则计算的 Merkle root；空内存链校验返回 `false`。HTTP validate 保持 200/success/data.valid bool，缺 token 为 401；CLI `chain validate` 保持有效/无效输出(基线无效仍成功退出;**本分支起无效退出码为 2、损坏为 3,见 §2.3/§2.6;本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed)**)。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。 |
| Merkle proof | ✅ `4cf84f8`/247 已验证 | 旧 `get_proof` 保留;新增 `GET /api/v1/crosschain/proof/:data_id`,经 `MerkleTree::get_structured_proof` 返回 leaf/index/siblings/sibling_is_left/root,服务端校验 `root==block.merkle_root` 且 `verify_structured_proof`;目标链可独立验证 data→root。处理奇数叶子自配对 |
| 跨链锚定(ChainAnchor/AnchorReceipt) | ✅ `4cf84f8`/247 已验证 | `src/crosschain.rs`:`POST /api/v1/crosschain/anchor/:data_id` 由 Merkle proof 生成 ed25519 签名锚定并写入 `anchor_outbox`(pending);后台 worker 带重试投递(`HttpAttestationConnector`),成功记录 `AnchorReceipt`;`GET /crosschain/anchor/status/:id` 查状态;`GET /crosschain/identity` 返回节点公钥。进程重启可从 outbox 恢复未投递锚定 |
| 节点签名身份 | ✅ `4cf84f8`/247 已验证 | `src/node_signing.rs`:ed25519 密钥对(生成/base64 种子恢复/签名/验签);配置 `DATACHAIN_NODE_SECRET` 持久化,未配置则启动随机生成并打印公钥 |
| 版本 API | ✅ 247 已验证 | `track_version` 经 `validate_version_path`(DATACHAIN_VERSION_ROOT allowlist+路径遍历/目录/符号链接防护)后保存不可变内容快照(ContentStorage);`get_version_diff` 用两版本历史快照计算,`get_version_content` 读快照不读当前文件;历史文件被覆盖/删除仍可还原。单测覆盖 track/diff/快照缺失/路径校验 |
| WebSocket 实时事件 | ✅ 本次提交 + 247 docker `rust:latest` `cargo test`（107 passed） | `AppState` 持有 `WsHub`，连接保留 JWT、全局 256 连接与 16KiB 保护；`WsMessage` JSON schema 未变。业务事件经 EventBus 广播，`tests/websocket_integration.rs` 的 9 个测试覆盖握手鉴权、消息/连接上限及四路连接接收五种事件。`/ws` 接收全部业务事件；专用频道按静态映射投递，未映射事件仅进入 `/ws`。 |
| WebSocket 频道隔离 | ✅ 本次提交 + 247 docker `rust:latest` `cargo test`（107 passed） | 服务端采用静态映射：`/ws/chain` 仅投递 `block_added`、`chain_validated`；`/ws/metadata` 仅投递 `metadata_added`；`/ws/aggregation` 仅投递 `aggregation`。通用 `/ws` 保持全部业务事件；`version_tracked` 和未来未映射事件只投递到 `/ws`。新增端到端测试以四路连接发布五种事件，验证正向投递及非归属频道不投递。该功能不包含动态订阅或频道级授权。 |
| EventBus/通知 | ✅ 247 已验证 `97eeee5` | `src/api/notification.rs` 已由 server 创建并注入;注册、元数据、挖矿、校验、版本、聚合 handler 会发布事件;广播链路已由 WS 集成测试覆盖(block/metadata/aggregation 三类事件实际收到) |

### 2.2 认证、授权与安全

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| JWT access/refresh | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:auth_claims 5、auth_middleware_session 12、storage_sessions 4);refresh 轮换/复用检测基线 `1124baa`/247(历史) | `src/auth/jwt.rs` 生成/验证含 issuer/audience 校验;refresh 轮换 + 持久化撤销(`revoked_refresh_tokens` 表)+ token-family 复用检测;JwtHandler 退为纯编解码,撤销状态由 `AuthService`+`Storage` 管理。**本次**:原"仍缺:设备会话管理、access token 即时吊销"已实现(access 携带 `sid`,受保护路由经 `authenticate_access_token` 统一校验:JWT → 会话存在/属于该用户/未撤销/未过期 → SQLite `is_active`(进程内缓存 TTL 默认 5s,写路径清缓存)→ 内存用户存在且 role 与 claims 一致;查库失败 fail-closed 返回 401;WS 握手共用同一校验;`optional_auth_middleware` 对被撤销 token 按匿名)。🔺 `generate_access_token`/`generate_token_pair` 新增 `sid` 参数(库 API 变更)。⚠️ 残余限制:无 `sid` 的旧 token 仅查 `is_active`、不受登出影响,最长到自然过期(默认 24h 未改);跨进程停用/撤销最长滞后缓存 TTL(5s,TTL 目前仅代码 API `set_active_cache_ttl` 可调,无配置项);已建立的 WS 连接不会因撤销/禁用被主动断开(仅新握手被拒);refresh 与 access 仍共用同一 JWT 密钥(既有债务) |
| 用户持久化 | ⚠️ | 注册时若 `save_user` 失败，服务会回滚已写入内存的用户并返回 500；启动可从 SQLite 加载用户。**本次**:启用/禁用状态以 SQLite 为权威(✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:cli_user_status 3、auth_middleware_session 12)):CLI `user deactivate\|activate <username>`;停用在同事务内撤销该用户全部会话与 refresh family,激活**不**恢复旧会话;登录/refresh/鉴权均以 SQLite `is_active` 为准;运行时 `deactivate_user`/`activate_user` 落库并清缓存、同步内存副本。🔺 `AuthService::deactivate_user`/`activate_user` 改 async(返回类型变化)。仍缺运行时资料管理、密码管理(改密 API,F9)与管理员用户禁用接口(F8),均为第二批 ⏳。 |
| 公开注册 | ✅代码已修复/待验证 | `AuthService::register` 现在固定 `Role::User`；CLI 使用受信的 `register_with_role` 创建指定角色 |
| RBAC | ✅基础代码已接入/待验证 | `auth_middleware` 现在按 HTTP 方法/路径映射 `Permission` 并校验 claims 角色；用户管理/更细资源级授权仍未覆盖 |
| Claim 信任策略 | ✅ 本次提交/247 已验证 | `[claim_policy]` 配置可信认证者身份/公钥、分类授权和权重；resolver 仅接受满足最小权重及有效时间的声明，覆盖关系生效，同权重冲突不强行裁决。默认无可信认证者时 fail-closed |
| 密码哈希 | ⚠️ | 实际认证使用 bcrypt；多算法 API 存在，但部分算法的 salt/dispatch 设计不适合作为统一生产密码方案 |
| 默认 JWT secret | ✅代码已修复/待验证 | `AppConfig::load` 支持 `DATACHAIN_JWT_SECRET`/`JWT_SECRET` 覆盖，并拒绝短密钥和默认占位值 |
| CORS/TLS/限流 | ⚠️ | CORS 使用 `DATACHAIN_CORS_ORIGINS` 显式 allowlist（未配置时仅本地开发来源;本次放行 `DELETE`）；可选 TLS、10MiB 全局请求体限制与进程内全局限流已实现。**本次**:全局限流 IP 来源改为 `ConnectInfo` 对端地址(TLS 与非 TLS 两条 serve 路径均经 `make_service` 注入),不再信任 `X-Forwarded-For`/`X-Real-IP`,限流 map 增加过期淘汰(✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:connect_info_rate_limit 5))。🔺 **反向代理后所有客户端共享一个全局限流桶**(对端地址是代理 IP);`trusted_proxies` 留第二批(⏳)。⚠️ TLS 路径无真实握手测试(两条 serve 路径均改用 `make_service`,但 TLS 分支无测试覆盖)。登录专属限速已实现(见 §2.1「登录限速与统一失败响应」);**认证审计日志已实现**(✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:auth_audit 13),见 §2.7);**登录锁定**中的指数退避/`locked_until` 为 ⏳ 未实现,当前仅固定窗口限速。 |
| 认证审计日志 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:auth_audit 13) | 表 `auth_audit_log`;事件类型以代码为准,当前为 `login_success`、`login_failure`、`login_locked`、`refresh_success`、`refresh_reuse_detected`、`logout`、`logout_all`、`session_revoked`、`user_deactivated`、`user_activated`。不存密码/token/jti/明文 IP(仅 HMAC `ip_hash`),文本字段脱敏并转义控制字符、限长;写入失败只记 error 日志,不阻塞也不改变认证结果;启动时清理 90 天前的行。⚠️ refresh 失败(停用/会话失效等)不写事件 |
| WebSocket 认证 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(234 passed:websocket_integration 11,其中本次新增 2 个握手测试;频道隔离基线为历史 97 passed/247) | **本次**:握手与 HTTP 共用 `authenticate_access_token`(被撤销会话/已停用用户的 token 握手被拒 401)。⚠️ 已建立的连接不会因撤销/禁用被主动断开,仅新握手被拒。WebSocket 路由经 JWT 认证(无/无效 token 401、合法 token 101+welcome)；Hub 保留全局 256 连接和单条文本 16 KiB 限制。频道按静态事件映射过滤，但不实施频道级授权；验证覆盖四路连接、五种事件的正向投递和非归属频道不投递。 |

### 2.3 区块链核心与数据完整性

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| Block/Chain/PoW/Merkle | ✅ `d97cd94` | 现有 metadata 叶子保持 `SHA256(data_id)` 兼容旧链；L1 key_tx 与新目录记录(`catalog_records`)的完整规范化语义均进入 merkle_root，受区块哈希/PoW 保护。旧 metadata 的完整字段仍非 Merkle 语义承诺，历史区块不重写 |
| 启动恢复(本分支时序重排) | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) | 本分支(`d3614f6`)把启动时序改为:打开 DB+migrations → `get_all_blocks` 严格解析 → `validate_loaded_blocks` → **权威源只读扫描**(users→versions→pending metadata→pending catalog→identity_transactions→anchor_outbox→aggregations,任一损坏 fail-closed)→ pending 去重 → `ensure_projections`(投影检测与重建)→ backfill 等后续写。扫描发生在去重、投影重建、backfill、purge 等**写操作之前**,损坏时不改库。例外:空库首次启动会先写创世块。入口 `scan_authoritative_sources_and_ensure_projections`(`src/cli/server.rs`)。验证:`tests/data_corruption_startup.rs` 5 个测试(含 users/aggregations 损坏在任何投影或 pending 写之前 fail-closed、仅 metadata 表损坏时重建)随 210 passed 通过;另有 reviewer 读代码审查。 |
| 启动恢复(基线) | ✅(`fix/chain-integrity-validation`,本分支基于它) | server 从 SQLite 恢复 blocks/users/versions；对已加载的非空 blocks 在恢复前由 `validate_loaded_blocks` 复用 `validate_chain` 的私有完整性门禁，校验创世 index/previous_hash、连续 index、保存 hash、块自身 difficulty PoW、previous hash 与既有 metadata/key transaction/catalog record 叶子规则下的 Merkle root。损坏块会使启动失败关闭，不加载、修复或写回数据库；空库首次启动仍初始化创世块。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。 |
| 链验证(CLI 统一校验,本分支) | 🔺 破坏性变更 / ✅ 已验证 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) | `chain`/`metadata`/`aggregate`/`status` 等链相关命令统一经 `load_verified_chain`(读区块→`validate_loaded_blocks`→加载),此前除 `chain validate` 外均不校验直接 `load_blocks`。退出码约定:0 成功 / 1 其他错误 / 2 链无效 / 3 数据损坏。**🔺 `chain validate` 链无效原退出码为 0,现为 2;损坏为 3**(依赖旧行为的脚本需调整)。CLI `chain mine` 由 `save_block` 改为 `commit_block`,在同事务写 metadata/catalog 投影。验证:`tests/data_corruption_cli.rs`(4:损坏退出 3、无效链退出 2、`status` 经完整校验对损坏 fail-closed、`chain mine` 同事务写投影)与随退出码变更修改的 `tests/chain_validation_cli.rs`(1)均已运行并通过(210 passed 之内)。 |
| 链验证(基线) | ✅ | `Chain::validate_chain` 与加载区块验证复用同一私有完整性门禁。非空链校验创世 index/previous_hash、连续 index、保存 hash、块自身 difficulty PoW、previous hash 及按既有 metadata/key transaction/catalog record 叶子规则计算的 Merkle root；不改变当前 Chain difficulty 比较、Hash/Merkle 协议、P2P、路由或自动修复。空内存链返回 `false`。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。 |
| pending 原子性 | ✅ 247 已验证 | pending metadata 已 SQLite 持久化(进程退出不丢);挖矿经 `Storage::commit_block` 在同一事务内原子写区块+删对应 pending,失败回滚内存区块与 pending 队列,消除两步之间崩溃的不一致窗口。单测 `commit_block_atomically_removes_pending` |
| attestation/identity/key transactions | ⚠️ `8b5ecf1`/247 端到端已验证 | 链上身份最小版(L1)已接入并经端到端集成测试(register→挖矿→查询→撤销链路真实可用):`POST /api/v1/identity/key-transaction`(register/revoke,ed25519 验签,register 自签)、`GET /identity/keys[/:pk]`(重放 key_transactions 得当前有效密钥集);key_transactions 进 merkle_root 受 PoW 保护(Block::calculate_merkle_root 选项 X);挖矿写 identity_snapshot_hash。签名负载不含 timestamp(服务端独立盖,`8b5ecf1` 修复)。**仍未做**:密钥轮换状态机、Merkle 身份树;attestation 仍只在 verify_content 读、无专门提交流程。(「pending key_tx 仅内存」的旧限制已由下一行的身份交易账本取代,见 §2.3.1) |
| 身份交易幂等与 pending 持久化(`Idempotency-Key`) | ⚠️ 主体行为 ✅ 已测试(功能提交 `734f1a2`,合并前 120 passed 历史;合并后 `65c7c4c` + 192.168.3.7 docker `rust:latest` cargo test 234 passed);仍含 🔺、⚠️ 升级风险与无测试覆盖项 | 见 §2.3.1 |
| P2P/节点同步/冲突解决 | ⚠️ `R6`/247 双节点已验证 | `src/p2p.rs` + `/api/v1/peers`、`/api/v1/sync/blocks`:显式注册 + **主动广播**(挖矿后 `broadcast_blocks` 推新块给 peers)+ **认证 gossip 发现**(`exchange_peers` 从已知 peer 拉取 peer 列表并入,跳过自身)+ 种子 peer(DATACHAIN_P2P_SEED_PEERS)+ 认证拉取/导入 + 最长合法链替换 + 60s 定时同步。**仍无共识、同长度分叉选择**(⚠️ 单一诚实源假设)。双节点 smoke:a 挖矿→b 经广播增长, 双向 exchange_peers 互相发现 |

### 2.3.1 身份交易幂等与 pending 持久化(功能提交 `734f1a2`,已合并 main 于 `65c7c4c`;主体行为 ✅ 已验证,个别项 ⚠️ 无测试覆盖)

最后核实:2026-11-13(合并后重新读代码核实)。依据:`src/api/handlers.rs`(`submit_key_transaction`、`mine_block`)、`src/api/routes.rs`(CORS)、`src/storage/database.rs`(`create_or_get_identity_transaction`、`commit_block`、`get_pending_identity_transactions`)、`src/cli/server.rs`(`recover_pending_identity_transactions`)、`src/cli/chain.rs`、`migrations/010`、`011`(原 007/008,合并 main 后顺延)。

**行为(读代码 + 对照测试核实;✅ 均指"本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`:功能提交 `734f1a2` 合并前 120 passed(历史),合并后 `65c7c4c` 234 passed,这些测试均包含其中")**:

| 项 | 状态 | 说明 |
|---|---|---|
| `POST /api/v1/identity/key-transaction` 可选 `Idempotency-Key` 头 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(合并后 234 passed;合并前 `734f1a2` 为 120 passed,历史) | 同用户 + 同键 + 同指纹 → 返回原事务:仍 pending 返回 `202`,已 committed 返回 `200`;同键但指纹不同 → `409`(`IdentityTransactionConflict`)。响应新增 `transaction_id`、`status` 字段。测试:`identity_key_transaction_idempotency_key_replays_pending_then_committed`、`..._reused_key_with_different_request_returns_conflict`、`..._concurrent_same_key_creates_one_pending_transaction`、`..._idempotency_ignores_unsigned_reason`、`..._without_idempotency_key_retains_accepted_pending_behavior`(均在 `tests/api_integration.rs`),及 storage 单测 `identity_transaction_is_durable_idempotent_and_committed_with_block` |
| 键的解析 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(合并后 234 passed;合并前 `734f1a2` 为 120 passed,历史) | 去首尾空白后为空,或请求头非 UTF-8(`to_str()` 失败),均视为未提供(按无幂等键处理,每次生成新事务)。测试:`idempotency_key_is_scoped_to_user_and_blank_values_do_not_deduplicate`(空白)、`non_ascii_idempotency_key_is_treated_as_missing_and_cors_preflight_allows_the_header`(非 ASCII 字节 0xff) |
| 用户隔离 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(合并后 234 passed;合并前 `734f1a2` 为 120 passed,历史) | 唯一索引 `(submitter_user_id, idempotency_key) WHERE idempotency_key IS NOT NULL`,键按 JWT `claims.sub` 隔离,不同用户可使用相同键。测试:`idempotency_key_is_scoped_to_user_and_blank_values_do_not_deduplicate`、`schema_version_six_upgrades_identity_transactions_with_recovery_state`(含索引 SQL 与按用户隔离断言) |
| sidecar `transaction_id` | ⚠️ 实现为读代码核实;sidecar 对齐/回滚已测试,"不进入区块 JSON/Merkle/签名"**无直接断言测试** | `transaction_id` 仅存于 SQLite 账本与内存队列的 sidecar,**不进入区块 JSON、Merkle 叶子或签名负载**;区块协议未变。唯一的类型改动是 `KeyTransactionEntry`(`src/core/block.rs`)新增派生 `PartialEq, Eq`(加性变更,不影响序列化/签名/Merkle),原因是 `src/core/chain.rs` 测试比较 `Vec<KeyTransactionEntry>`,首次真实运行(`5b2ad61`)lib 测试编译失败 E0369,已在 `734f1a2` 修复。已测试部分:`src/core/chain.rs` 的 `sidecar_mining_keeps_an_aligned_mapping_...`、`sidecar_rollback_rejects_misaligned_sidecars_...`、`legacy_*` 兼容测试 |
| CORS | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(合并后 234 passed;合并前 `734f1a2` 为 120 passed,历史) | `allow_headers` 增加 `idempotency-key`。测试:`non_ascii_idempotency_key_is_treated_as_missing_and_cors_preflight_allows_the_header`(OPTIONS 预检断言 `access-control-allow-headers` 含该头) |
| pending 持久化与重启恢复 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(合并后 234 passed;合并前 `734f1a2` 为 120 passed,历史) | 测试:`identity_key_transaction_restart_recovers_pending_for_mining`、`identity_transaction_remains_pending_when_another_app_state_mines_only_metadata`、`failed_identity_transaction_commit_rolls_back_the_mined_block_and_pending_queue`(API);storage 单测 `pending_identity_transactions_restore_first_acceptance_order`、`identity_transaction_commit_failure_rolls_back_block_and_keeps_pending`、`commit_block_rejects_*sidecars*`;`src/cli/server.rs` 的 `startup_recovery_keeps_distinct_verified_no_key_transaction_...`;`src/cli/chain.rs` 的 `mine_recovers_persisted_pending_identity_transactions_before_mining`。机制:身份交易先落 `identity_transactions` 表(`pending`),服务启动经 `recover_pending_identity_transactions` 按 `accepted_at, transaction_id` 恢复入队;`commit_block` 同事务把对应行置 `committed` 并记录 `committed_block_index` |
| 串行化 | ⚠️ 代码已实现;**无测试覆盖**(无针对 gate 互斥的专门测试;并发同键测试只验证账本层去重,不能证明 gate 生效) | `AppState.identity_tx_gate`(进程内 `tokio::Mutex`)串行化「身份提交」与「HTTP 挖矿」 |
| `Storage::commit_block` 签名 | 🔺 破坏性变更 | 由 `commit_block(&block)` 变为 `commit_block(&block, &[Option<String>])`(须与 `block.key_transactions` 逐项对齐,`None` 表示普通交易)。公开库 API 的调用方需适配;README 已声明库 API 不承诺稳定 |

**迁移与升级(010/011;原 007/008,与 main 认证加固的 007/008/009 合并时已顺延为 010/011,`a5b6f80`)**:

- `010_identity_transactions.sql`:新建 `identity_transactions` 表(状态 `pending`/`committed`)、幂等唯一索引、pending 顺序索引。
- `011_identity_transaction_recovery_state.sql`:新增 `recovery_state`(`legacy_unverified`/`verified`),列默认值为 `legacy_unverified`。新提交的身份交易写入 `verified`。
- 🔺 **升级前遗留 pending 行**(身份交易表已部署、`recovery_state` 列之前产生)会被标为 `legacy_unverified`:因区块 JSON 不含 `transaction_id`,无法证明其是否已被打包。**服务启动与 CLI `chain mine` 均 fail-closed**(报错 `refusing to recover N unverifiable legacy pending identity transaction(s)`),**不自动修复**。测试覆盖:启动恢复路径由 `src/cli/server.rs` 的 `startup_recovery_fails_closed_for_unverifiable_legacy_pending_in_history` 验证(合并后 234 passed 包含;功能提交 `734f1a2` + 192.168.3.7 docker `rust:latest` cargo test 120 passed 历史;合并后 234 passed);CLI `chain mine` 对 `legacy_unverified` 的拒绝**无专门测试**(`src/cli/chain.rs` 的测试仅覆盖已核实 pending 的恢复与挖矿)。
- **错误类型与退出码(有意选择)**:`legacy_unverified` 保持 `DataChainError::StorageError`(文案 `refusing to recover N unverifiable legacy pending identity transaction(s)`),CLI 退出码为 **1**(不是数据损坏的 3):它表达"无法证明是否已入块",不是 JSON 损坏。身份账本读取 `get_pending_identity_transactions` 已并入启动权威源只读扫描(`scan_authoritative_sources_and_ensure_projections`),顺序为 users → versions → pending metadata → pending catalog → **identity_transactions** → anchor_outbox → aggregations,仍在任何写操作之前;CLI `chain mine` 经 `recover_pending_identity_transactions` 同样 fail-closed。(读代码核实;启动路径有 `startup_recovery_fails_closed_for_unverifiable_legacy_pending_in_history`,CLI 路径无专门测试。)
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
- ⚠️ (e) **旧版 pending 分支开发库的升级风险**(读代码推导,**未在真实旧库上实跑**):曾运行过**旧版 pending 分支**迁移(identity 迁移占用版本 7/8)的开发库,升级到合并后版本时 `MAX(version)=8`,会跳过 main 的 007/008(`sessions`、`login_rate_counters_and_audit`);009(`ALTER TABLE sessions ADD COLUMN ip_hint`)因 `sessions` 表不存在而失败,迁移事务回滚、启动失败,**不损坏数据**。直观的手工修复 `DELETE FROM schema_migrations WHERE version IN (7,8)` 会在 011(`ALTER TABLE ... ADD COLUMN recovery_state`)因列已存在报 `duplicate column name`。建议:这类开发库直接重建;或先完整备份,手工创建 main 的 007/008 表并把 `schema_migrations` 调整为 10,同时保留 `recovery_state` 列。main 现网库(`MAX=9`)升级只会执行 010/011,新行显式 `verified`,不会误触发 legacy fail-closed。
- ⚠️ (f) **「已接受即承诺」**:幂等键按提交用户(JWT `sub`)隔离;提交者之后被禁用或会话被撤销,其 token 立即失效、不能再提交,但**此前已接受并落账本的 pending 身份交易仍会被后续挖矿打包**(挖矿不重新检查提交者状态)。现状不修复,仅登记。
- ✅ (g) 重建投影不触碰 `identity_transactions` 账本:回归测试 `rebuild_projections_leaves_identity_transaction_ledger_untouched`(`65c7c4c`,仅覆盖 pending 行,committed 行未覆盖;`REBUILDABLE_TABLES` 白名单只含 metadata 与 catalog 四表,是结构性保证)。
- ⚠️ (h) 迁移 `011` 的 SQL 注释与 `get_pending_identity_transactions` 文档注释仍写"007"(改名前编号残留,仅注释,不影响行为);代码未改,留待下次改代码时顺手修正。

**验证证据(如实)**:

- 提交 `734f1a2`,验证机 `deploy@192.168.3.7`,docker `rust:latest`,target 卷 `dc-rust-target-pi`(orchestrator 复核原始日志):
  - `cargo fmt --check`:rc=0。
  - `cargo test --no-fail-fast`:rc=0,**120 passed、0 failed**——lib 91、bin 0、api_integration 20、websocket_integration 9、doctest 0。
  - `cargo clippy --all-targets`(未加 `-D warnings`):rc=0,无 error;完整输出共 25 处告警位置,其中落在本分支改动文件的 5 处(`src/api/state.rs:36`、`src/storage/database.rs:581/672/808/887`)经 git blame 均来自 main 既有提交(`cd38ef1`、`4cf84f8`),**本分支无新增 clippy 告警**。
- 首次真实运行(`5b2ad61`)发现并已修复:lib 测试编译失败 E0369——`KeyTransactionEntry`(`src/core/block.rs`)未派生 `PartialEq`,而 `src/core/chain.rs` 测试比较 `Vec<KeyTransactionEntry>`;`734f1a2` 改为派生 `PartialEq, Eq`(加性变更,不影响序列化/签名/Merkle)并经 rustfmt。
- reviewer 复审(读代码)无 Important 级问题。
- 状态判定:上表有对应测试的行为项标 ✅(逐项列出测试名);无直接测试的(`identity_tx_gate` 串行化、"`transaction_id` 不进入区块 JSON/Merkle/签名"的直接断言、CLI `chain mine` 对 `legacy_unverified` 的拒绝)保持 ⚠️ 并注明"无测试覆盖";🔺 项与已知限制 (a)-(d) 不因测试通过而取消。

### 2.4 存储、迁移与恢复

| 需求/设计 | 状态 | 证据与差异 |
|---|---|---|
| SQLite + SQLx | ✅基础 | `src/storage/database.rs` 创建 SQLite pool、blocks/users/versions 表及基础 CRUD |
| 独立 metadata/aggregation/events 表 | ⚠️ `d97cd94` | metadata 查询投影表已建(migration 005);aggregation 已持久化(`aggregations` 表);语义目录新增 pending_catalog_records 与 catalog_subjects/catalog_revisions/catalog_artifacts/catalog_claims 查询投影(migration 006);事件通知仍无独立表(经 EventBus 内存广播,不落库) |
| SQLx 版本迁移 | ✅ `13ded24`/247 已验证(历史);认证加固 007-009 与 pending identity 迁移 010/011 经 192.168.3.7 cargo test(合并后 234 passed)覆盖 | **本次**:新增 `007_sessions`、`008_login_rate_counters_and_audit`、`009_session_ip_hint`(`ALTER TABLE sessions ADD COLUMN ip_hint`),详见 §2.7。⚠️ 已执行较大版本号的库因 `MAX(version)` 会跳过较小版本号。**pending identity 分支**:`010_identity_transactions`、`011_identity_transaction_recovery_state`(原为 007/008,**本分支已顺延为 010/011**;详见 §2.3.1;升级回归测试 `schema_version_six_upgrades_identity_transactions_with_recovery_state` 现断言 v6→v11 并包含在 234 passed 中)。⚠️ 曾运行旧版 pending 分支迁移(占用 7/8)的开发库升级会失败,见 §2.3.1 限制 (e)(读代码推导,未实跑)。以下为此前 `migrations/001~006` + `schema_migrations` 版本表为建表唯一事实源;`apply_migrations` 按版本顺序执行幂等 DDL;`init_tables` 已移除重叠兜底,仅调 `apply_migrations`。旧库(无 schema_migrations)升级经回归测试 `legacy_db_without_schema_migrations_upgrades_safely` 验证不丢表、数据保留。**仍无自动 down 回滚**(有意收敛,up-only + 手动回滚约定)。数据回填在 #5(`b239df6`)落地为**代码级 reconcile**(启动/CLI 从已反序列化 Block 幂等 upsert 投影),而非纯 SQL migration——因 apply_migrations 的 `split(';')` 对复杂 SQL/JSON 解析脆弱,代码侧回填更稳 |
| 数据损坏处理 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed)(`d3614f6`,reviewer 两轮读代码审查最终无 Important;已知限制见 §2.6) | 新增 `DataChainError::DataCorruption{category,table,key,reason}`(`CorruptionCategory::{Authoritative,Rebuildable}`),Display 固定为 `data corruption [authoritative] table=users key=<id>: <reason>`。`reason` 取固定词表(`json_syntax line=L col=C`/`json_data`/`json_eof`/`json_io`/`unknown_status` 等),**不回显行内容、password_hash 或 JSON 片段**。详见下方 §2.6。 |
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

### 2.6 数据损坏处置策略(`feat/data-corruption-policy` `d3614f6`,已合入 main;本分支合并 main 后已验证:234 passed;main 侧合并后 210 passed、合并前单独 139 passed 均为历史数字)

> 核实日期:2026-11-13(读代码 + 验证机 `deploy@192.168.3.7` docker `rust:latest` 真实运行 fmt/test/clippy)。设计:`docs/superpowers/specs/2026-11-11-data-corruption-policy-design.md`。

| 项 | 状态 | 说明与证据 |
|---|---|---|
| `DataCorruption` 结构化错误 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) | `src/error.rs`:`{category,table,key,reason}`;reason 固定词表,不含行内容/password_hash/JSON 片段;blocks 的 key 为区块索引,其余用主键,主键不可解析时用占位。验证:`tests/data_corruption_authoritative.rs`(4,含 users 不泄露 password_hash、blocks/versions key 断言)+ lib 单测 |
| 权威源 fail-closed | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) | 测试覆盖 blocks/users/versions(authoritative 4)、pending metadata/catalog 与 anchor_outbox(outbox 9,含未知 status、坏 signed/receipt JSON、健康行计数)、aggregations 启动 fail-closed(startup 5)。范围:blocks、users、versions、pending metadata、pending catalog、anchor_outbox、aggregations。anchor_outbox 启动时**全表扫描**(`scan_anchor_outbox`),未知 status 报 `DataCorruption{anchor_outbox,unknown_status}`,不再当 Pending(`crosschain.rs` `parse_status` 改返回 `Result`)。aggregations 因由调度器写入、含递归合并状态而非纯区块导出,定为权威源,**不重建**。refresh 撤销表无 JSON 列,不做专门扫描 |
| 可重建投影 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) | 测试:`tests/data_corruption_projection.rs`(3:metadata 行删除后重建、catalog 行损坏后重建、一致时幂等)+ startup 中仅 metadata 表损坏的重建。范围:metadata、catalog_subjects/revisions/artifacts/claims。启动在链完整校验通过后检测(行数与期望值比对 + `data` 列可解析),任一不一致则在**单事务**内清表并按区块高度升序重放 `project_block_tx`(失败整体回滚),保持 catalog 首写者胜(`DO NOTHING`)/metadata 后写者胜(`DO UPDATE`)语义。`commit_block` 与重建共用 `project_block_tx`。`metadata_projection_count` 出错不再 `unwrap_or(-1)`,改为传播错误 |
| 启动时序 | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) | 链校验 → 权威源只读扫描(先于 pending 去重、投影重建、backfill、purge 等写)→ 投影检测重建 → 继续。例外:空库先写创世块 |
| CLI 退出码 | 🔺 破坏性 / ✅ 已验证 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) | 0/1/2/3,见 §2.3。`main.rs` 改返回 `ExitCode`,错误一行输出到 stderr。`data_corruption_cli.rs` 覆盖退出 2/3 与 `chain mine` 投影 |
| HTTP `/api/v1/chain/validate` | ✅ 本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed)(仅限该端点) | 保留 `valid`/`block_count`,新增可选 `corruption`、`invalid_block`(仅异常时出现);状态码仍 200。测试:`data_corruption_startup.rs` 验证损坏时返回 `corruption.table=blocks`/`category=authoritative` 且不泄露敏感字段、健康时字段不变(首次真实运行发现这 2 个测试漏带 Bearer token 返回 401,属测试缺陷,已修,路由鉴权未改)。 |
| `login`/`refresh` 遇 `DataCorruption`/`DatabaseError`/`StorageError` 返回 500 | ⚠️ 已写/无集成测试 | 原 `login` 对所有错误返回 401。合并后(`src/api/handlers.rs`,已读代码核实):`login` 对 `TooManyAttempts`→429、`InvalidCredentials`→401,**其余错误一律 500**;`refresh_token` 对 `DatabaseError`/`StorageError`/`DataCorruption`→500,其余→401。两者 500 的 body **固定为 `internal error`**,table/key/错误文本只写 `tracing::error!` 日志,不回显客户端(这是 login/refresh 相对其他业务端点的例外,其他端点见下方已知限制)。合并后 210 个测试(含 login_rate_limit 8、auth_audit 13、sessions_api 16 等)均未注入 DataCorruption,仅 reviewer 读代码审查,不标 ✅。**后续项**:补集成测试——注入 DataCorruption,断言 500、body 为 `internal error` 且不含 table/key |
| 新增测试文件 | ✅ 已运行,全部通过 | `tests/data_corruption_authoritative.rs`(4)、`data_corruption_outbox.rs`(9)、`data_corruption_projection.rs`(3)、`data_corruption_startup.rs`(5)、`data_corruption_cli.rs`(4),辅助 `tests/common/corrupt.rs`(3 条 `dead_code` clippy warning,未处理);并修改 `tests/chain_validation_cli.rs`(1)。本次提交 + 192.168.3.7 docker `rust:latest` `cargo test`(234 passed) |

**已知限制 / 遗留登记(本分支)**:
- 🔺 投影检测只看行数与 JSON 可解析性;**合法但被篡改的内容检测不到**(例如字段值被改但仍是合法 JSON 且行数一致)。
- ⚠️ p2p `import_blocks`(`handlers.rs` 区块同步导入)仍用 `save_block`,**不写投影**,依赖下次启动的数量不一致检测重建兜底;运行期间查询投影可能落后。
- 🔺 **其他**业务端点遇 `DataCorruption` 仍返回 500,body 含 table/key(无行内容),**未按设计收窄**为仅 `{"error":"data_corruption","table":..}`。**例外**:`login`/`refresh` 合并后返回 500 + 固定 `internal error`,不带 table/key(见上表);`/chain/validate` 的 `corruption` 字段仍只在该端点出现。
- ⏳ 未提供 `storage check` / `storage rebuild-projections` 命令(设计 S6,已裁剪)。
- ⚠️ `/chain/validate` 的 `corruption` 目前只来自 blocks 读取;其他权威源损坏在启动时 fail-closed,不经此端点报告。
- ⚠️ 合并后新增的认证表(`sessions`、`login_rate_counters`、`auth_audit_log`)**未纳入**启动权威源只读扫描(`scan_authoritative_sources_and_ensure_projections` 只扫 users、versions、pending metadata/catalog、identity_transactions、anchor_outbox、aggregations);其清理(`purge_expired_sessions`/`purge_audit_before`)在扫描之后执行且失败仅告警,这些表损坏不会触发 fail-closed(读代码核实,无测试)。
- ⚠️ `updated_at` 读取仍为当前时间(既有行为,未改)。
- ⏳ 旧用户/版本表的字段兼容迁移不做。
- ✅ 与 `legacy_unverified` 的对接已完成(本分支合并后):`identity_transactions` 账本经 `get_pending_identity_transactions` 并入启动权威源只读扫描(pending catalog 之后、anchor_outbox 之前,任何写之前);`legacy_unverified` 以 `StorageError` fail-closed、CLI 退出码 1(非数据损坏的 3,有意选择),见 §2.3.1。

### 2.7 认证加固(第一批 F1-F7,分支 `feat/auth-hardening`)

最后核实:2026-11-13。设计:`docs/superpowers/specs/2026-11-13-auth-hardening-design.md`。验证:本次提交 + 192.168.3.7 docker `rust:latest` cargo test(本分支合并后 234 passed,见顶部验证声明与 §三;main 侧合并后 210 passed 为历史数字)。合并前单独验证(历史数字,作业 authfinal2,HEAD `ce889bb`):`cargo test --no-fail-fast` 168 passed、0 failed,lib 24 条警告与当时 main 基线(4cc5646)持平;合并后 lib 22 条,无新增。代码审查(reviewer)发现 1 个 Important(I1:用户名限速可被"成功登录重置"绕过),已修复并有回归测试。

#### 能力

| 编号 | 能力 | 状态 | 证据与差异 |
|---|---|---|---|
| F1 | 会话(设备)模型 | ✅ | `sessions` 表;登录创建会话行(会话 id 即 refresh family),access 带 `sid`;记录截断/去控制字符的 `user_agent` 与 `ip_hash`(HMAC,不存明文 IP);refresh 更新 `last_seen_at`、新 access 带 `sid`;旧 refresh(空 family)补建会话。测试:storage_sessions 4、auth_claims 5、auth_middleware_session 12。⚠️ 无「`touch_session` 失败且为复用 → TokenReuseDetected」分支的专门测试 |
| F2 | 会话接口 | ✅ | `logout`、`logout-all`、`GET sessions`、`DELETE sessions/{id}`,契约见下表。测试:sessions_api 16 |
| F3 | access 即时吊销 | ⚠️ | 统一校验链路见 §2.2「JWT access/refresh」。测试:auth_middleware_session 12 + websocket_integration 新增 2。限制:无 `sid` 旧 token 不受登出影响;跨进程滞后 ≤ 缓存 TTL(5s);已建立 WS 连接不主动断开 |
| F4 | 登录限速 | ⚠️ | 见 §2.1。测试:login_rate_limit 8。限制:纯固定窗口(边界约 2 倍突发);指数退避、`locked_until` ⏳ 未实现 |
| F5 | 全局限流 IP 来源 | ⚠️ | 见 §2.2「CORS/TLS/限流」。测试:connect_info_rate_limit 5。🔺 反代后共享单桶;TLS 路径无真实握手测试 |
| F6 | 认证审计日志 | ✅ | 见 §2.2「认证审计日志」。测试:auth_audit 13。⚠️ refresh 失败未写事件 |
| F7 | 用户禁用(SQLite 权威)与 CLI | ✅ | 见 §2.2「用户持久化」。测试:cli_user_status 3 |

#### 接口契约

| 方法 + 路径 | 认证 | 成功响应 | 失败/边界 |
|---|---|---|---|
| `POST /api/v1/auth/login` | 公开 | 200 + token 对 | 401 `invalid credentials`(用户不存在/密码错/账户禁用同一消息);429 + `Retry-After`(秒);内部故障(含 `DataCorruption`/`DatabaseError`/`StorageError`)500 + 固定 `internal error`(细节只写日志;⚠️ 数据损坏路径无集成测试) |
| `POST /api/v1/auth/logout` | Bearer | 204(幂等) | 无 `sid` 旧 token 视为成功但无会话可撤销 |
| `POST /api/v1/auth/logout-all` | Bearer | 204(幂等) | — |
| `GET /api/v1/auth/sessions` | Bearer | 200,会话列表(`id`、`created_at`、`last_seen_at`、`expires_at`、`user_agent`、`ip_hint`、`current`) | 不返回 token/jti/ip_hash/refresh family |
| `DELETE /api/v1/auth/sessions/{id}` | Bearer | 204 | 非本人/不存在/已失效统一 404 |

#### 迁移

| 迁移 | 内容 |
|---|---|
| `007_sessions` | `sessions` 表(id、user_id、refresh_family、created_at/last_seen_at/expires_at、revoked_at/revoke_reason、ip_hash、user_agent)+ 索引 |
| `008_login_rate_counters_and_audit` | `login_rate_counters`(key、window_start、count、`locked_until` 预留未用)与 `auth_audit_log` + `idx_audit_ts` |
| `009_session_ip_hint` | `ALTER TABLE sessions ADD COLUMN ip_hint TEXT`(会话列表脱敏 IP 提示) |

up-only,无自动 down。与 pending identity 分支的编号冲突已解决(pending 迁移已顺延为 010/011),见 §2.4「SQLx 版本迁移」与 §2.3.1。

#### 破坏性变更(🔺)

- 🔺 登录失败消息统一为 `invalid credentials`(原可区分用户不存在/密码错误);新增 429 与 `Retry-After`。
- 🔺 `AuthService::login` 改 async 并新增 `&LoginContext` 参数。
- 🔺 `generate_access_token` / `generate_token_pair` 新增 `sid` 参数。
- 🔺 `AuthService::deactivate_user` / `activate_user` 改 async。
- 🔺 全局限流 key 改为 TCP 对端地址(不再读 `X-Forwarded-For`/`X-Real-IP`):反向代理后所有客户端共享一个桶;`trusted_proxies` 留第二批。
- 🔺 新增 4 条受保护路由,CORS 放行 `DELETE`。
- ✅ 顺带修复预先存在的缺陷:`ClaimPolicyConfig` 的 `#[derive(Default)]` 把 `min_weight` 置 0,使用不存在的配置文件启动时 `AppConfig::validate` 失败;已改为手写 `Default`(取 `default_min_claim_weight()`)。⚠️ 无专门回归测试(未核实现有测试是否间接覆盖该启动路径,故不标 ✅ 已覆盖)。

#### 已知限制与偏离(未做项登记)

- ⏳ 指数退避与 `locked_until`:未实现,`locked_until` 为预留死列。
- ⚠️ 无 `sid` 的旧 access token 登出无效,最长保持到自然过期(默认 24h,未改)。
- ⚠️ 跨进程停用/撤销最长滞后缓存 TTL(默认 5s)。
- ⚠️ 已建立的 WS 连接不会因撤销/禁用主动断开,仅新握手被拒。
- ⏳ 第二批:`trusted_proxies` 与认证参数完整配置化(F10)、改密 API(F9)、管理员会话/用户禁用接口(F8)。
- ⚠️ refresh 失败(停用/会话失效)未写审计事件;`touch_session` 失败复用分支无专门测试;TLS 路径无真实握手测试。
- ⚠️ refresh 与 access 仍共用同一 JWT 密钥(既有债务)。
- ✅ 迁移编号顺延已完成:pending identity 分支(原迁移 007/008)已在本分支合并 main 时顺延为 010/011(007/008/009 由认证加固占用);⚠️ 曾运行旧版 pending 迁移的开发库升级风险见 §2.3.1 限制 (e)。

#### 登记项(差异清单,本仓库以本文档为登记处)

| 编号 | 项 | 状态 |
|---|---|---|
| A-1 | 反向代理后共享全局限流桶 / `trusted_proxies` | 🔺/⏳ 第二批 |
| A-2 | 指数退避与 `locked_until` | ⏳ |
| A-3 | 无 `sid` 旧 token 登出无效、WS 连接不主动断开、跨进程 ≤5s 滞后 | ⚠️ |
| A-4 | 认证参数完整配置化(F10)、改密 API(F9)、管理员接口(F8) | ⏳ 第二批 |
| A-5 | 迁移 007/008/009 已被认证加固占用;pending identity 分支(原 007/008)已在合并 main 时顺延为 010/011 | ✅ 已处理(`a5b6f80`;合并后 234 passed)。⚠️ 旧版 pending 迁移开发库升级风险见 §2.3.1 (e) |
| A-6 | refresh/access 共用 JWT 密钥;access 默认 24h | ⚠️ 既有债务 |

#### 新增测试(均在本次提交,192.168.3.7 docker `rust:latest` cargo test,包含在合并后 234 passed 中;main 侧合并后 210 passed、认证加固分支单独 168 passed 均为历史数字)

| 测试文件 | 通过数 |
|---|---|
| `tests/storage_sessions.rs` | 4 |
| `tests/auth_claims.rs` | 5 |
| `tests/login_rate_limit.rs` | 8 |
| `tests/connect_info_rate_limit.rs` | 5 |
| `tests/auth_middleware_session.rs` | 12 |
| `tests/sessions_api.rs` | 16 |
| `tests/auth_audit.rs` | 13 |
| `tests/cli_user_status.rs` | 3 |
| `tests/websocket_integration.rs`(新增 2 个握手测试,现共 11) | 11 |

## 三、测试与验证状态

- ✅ **合并后验证总览(权威,`65c7c4c`)**:本次提交 + 192.168.3.7 docker `rust:latest`(作业 pimergeo,orchestrator 亲自复跑),`cargo fmt --check` rc=0;`cargo test --no-fail-fast` 19 个测试目标全部 ok,**234 passed、0 failed**——lib 110、bin 0、api_integration 21、auth_audit 13、auth_claims 5、auth_middleware_session 12、chain_validation_cli 1、cli_user_status 3、connect_info_rate_limit 5、data_corruption_authoritative 4、data_corruption_cli 4、data_corruption_outbox 9、data_corruption_projection 3、data_corruption_startup 5、login_rate_limit 8、sessions_api 16、storage_sessions 4、websocket_integration 11、doctest 0;`cargo clippy --all-targets`(无 `-D warnings`)无 error,lib 22 条警告(与 main 基线持平,无新增)。reviewer 对合并做行为级审查,无 Important。
- 上一层历史数字:main 侧合并后 **210 passed**(`ecae5e0`,作业 authmergeo:lib 96、api_integration 11、其余同上),不含本分支身份交易(lib +14、api_integration +10 来自本分支)。
- ⚠️ 已知测试时序问题(main 既有,与合并无关):`tests/login_rate_limit.rs` 与固定窗口按 epoch 对齐(`window_start = now - now % 900`),跨 :00/:15/:30/:45 边界运行时偶发失败(首跑曾 2 个失败,单独重跑 8/8 通过);本次复跑已避开边界。见 §四后续项。
- **以下 168 / 139 / 120 为合并前各分支单独的历史数字,不适用于合并后。**
- 历史:认证加固分支合并前验证总览:192.168.3.7 docker `rust:latest`,`cargo test --no-fail-fast` 共 168 passed、0 failed——lib 81、bin 0、api_integration 10、auth_audit 13、auth_claims 5、auth_middleware_session 12、cli_user_status 3、connect_info_rate_limit 5、login_rate_limit 8、sessions_api 16、storage_sessions 4、websocket_integration 11、doctest 0;`cargo fmt --check` rc=0;`cargo clippy --all-targets` 无 error。下面各条中的 97 / 78 / 19 等数字为**历史基线**(各自提交时 247 验证机结果),仅供追溯。
> 历史:数据损坏分支(`feat/data-corruption-policy` `d3614f6`)合并前单独计数:当时 + 192.168.3.7 docker `rust:latest` `cargo test --no-fail-fast`,**139 passed、0 failed**(lib 93、bin 0、api_integration 11、chain_validation_cli 1、data_corruption_authoritative 4、data_corruption_cli 4、data_corruption_outbox 9、data_corruption_projection 3、data_corruption_startup 5、websocket_integration 9、doctest 0);`cargo fmt --check` rc=0;`cargo clippy --all-targets`(无 `-D warnings`)无 error,lib 22 条 warning、`tests/common/corrupt.rs` 3 条 dead_code。
> 下文各处"86 单测 + 21 集成 = 107 passed"是**旧基线**(`96d08e8` 及更早,247 docker 验证)的计数,仅作历史参考,已不适用。
> 验证机说明:主验证机已从 247 迁到 `deploy@192.168.3.7`;247 磁盘满,降为备用。

- ✅ 核心算法与链完整性单元测试共 86 passed：覆盖 Block、Chain、Merkle/canonical、密码哈希、JWT、权限、版本 diff/content storage，以及非法单块创世、metadata Merkle 篡改等完整性门禁回归。
- ✅ 集成测试共 21 passed：`tests/api_integration.rs`（11，含语义目录端到端 Subject→Revision→Artifact→风险 Claim→上链查询、未登记签发公钥拒绝、**可信 Claim resolver 端到端**、HTTP validate 的 200/success/data.valid bool 与缺 token 401）、CLI 集成测试（1，`chain validate` 的有效/无效输出和无效成功退出），以及 `tests/websocket_integration.rs`（9，真实 axum 服务 + tokio-tungstenite 客户端：握手鉴权、EventBus 广播、16KiB 上限、256 连接上限，以及四路连接接收五种事件的频道隔离）。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。
- ✅ 启动恢复 helper 覆盖损坏已加载区块时失败关闭、不加载、修复或写回，以及空库仍初始化创世块。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。
- ⚠️ P2P 双节点广播/发现路径由 247 双容器 smoke 验证（非进程内集成测试）。refresh token 持久化/复用检测/并发双花已由单测覆盖(`1124baa`:正常轮换/复用整族撤销/并发双花 tokio::join 恰一成功/跨实例重启撤销持久化/revoke_refresh 抢占/purge 边界)。WebSocket 频道隔离已由端到端测试覆盖：专用频道只收到映射事件，`version_tracked` 仅进入 `/ws`；该功能不提供动态订阅或频道级授权。
- ✅ 已建立独立仓库 CI 证据：本次完整回归在 247 `rust:latest` 执行 `cargo test`，107 passed；`cargo fmt --check` 通过，`cargo clippy --all-targets` 无本次警告但保留现有基线 warning。

- ✅ **身份交易幂等 + pending 持久化验证状态**:功能提交 `734f1a2` 合并前单独验证(历史数字):`cargo fmt --check` rc=0;`cargo test --no-fail-fast` rc=0,120 passed / 0 failed(lib 91、bin 0、api_integration 20、websocket_integration 9、doctest 0);`cargo clippy --all-targets` rc=0,本分支无新增告警。合并 main 后(`65c7c4c`)重新验证为 234 passed(见上方总览);其中本分支新增回归测试 `rebuild_projections_leaves_identity_transaction_ledger_untouched`(lib)。上面各行的 97 passed / 19 集成等为各自功能提交当时的历史结果,当前总数以 234 passed 为准。reviewer 复审(读代码)无 Important。

### 登记项(本次提交时登记,编号沿用本节顺序)

| 编号 | 状态 | 内容 |
|---|---|---|
| R-1 | 🔺 | `Storage::commit_block` 公开签名变更(breaking):新增 `identity_transaction_ids: &[Option<String>]` 参数 |
| R-2 | 🔺 协议既有 | `KeyTransactionEntry::signing_payload` 以 `|` 拼接字段,字段含 `|` 时可能碰撞;属协议既有问题,本次未改,计划在协议 v2 迁移时修复 |
| R-3 | ⚠️ | clippy 基线警告:`734f1a2` 上 `cargo clippy --all-targets` rc=0,**本分支无新增告警**,但 main 既有基线告警仍然存在(落在本分支改动文件的 5 处:`src/api/state.rs:36`、`src/storage/database.rs:581/672/808/887`,均来自 `cd38ef1`/`4cf84f8`),本次未清理;未验证 `-D warnings` 是否通过 |
| R-4 | ⚠️ 环境 | 主验证机已迁至 192.168.3.7(本次验证在该机完成);247 磁盘长期满,降为备用,不再依赖 |
| R-5 | ⚠️ | 见 §2.3.1 已知限制 (a)-(d):CLI 与运行中服务同库挖矿漂移、`legacy_unverified` 无内置恢复、幂等键无长度上限且指纹仅 5 字段、同步导入不清理本地 pending |
| R-6 | ⚠️ | 旧版 pending 分支迁移(占用 7/8)开发库升级会失败(跳过 main 007/008,009 因表不存在而失败,回滚、不损坏数据);读代码推导,未实跑。见 §2.3.1 (e) |
| R-7 | ⚠️ | 「已接受即承诺」:提交者被禁用/会话撤销后,已落账本的 pending 身份交易仍会被挖矿打包。见 §2.3.1 (f) |

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

- ✅ #4 WebSocket 收发自动化集成测试 — 历史握手/广播/消息与连接上限覆盖已扩展为频道隔离端到端覆盖：四路连接、五种事件、正向投递和非归属频道不投递。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。
- ✅ 补做本次身份交易幂等改动的 Rust 验证:`734f1a2` + 192.168.3.7 docker `rust:latest`,fmt/clippy rc=0、cargo test 120 passed(合并前该分支单独结果,历史数字);合并 main 后 `65c7c4c` 为 234 passed。
- ⏳ 为 `identity_tx_gate` 串行化、"`transaction_id` 不入区块 JSON/Merkle/签名"、CLI `chain mine` 拒绝 `legacy_unverified` 补直接测试;提供 `legacy_unverified` 的内置恢复命令;为 `Idempotency-Key` 增加长度上限;指纹覆盖 reason/timestamp/signature 的取舍评估;`signing_payload` v2 分隔方案。
- ✅ #3 refresh token 持久化 + token-family 复用检测 — `1124baa` 247 lib 62 + 集成 12 passed(撤销落 SQLite/复用整族撤销/并发双花主键收口/启动清理)。
- ✅ 可验证语义目录 — `d97cd94` Subject→Revision→Artifact + 完整语义 Merkle 承诺 + signed Claim + pending 持久化/查询投影，247 lib 75 + 集成 17 passed。
- ✅ 认证加固第一批 F1-F7 — 本次提交 + 192.168.3.7 docker `rust:latest` cargo test(本分支合并后 234 passed;main 侧合并后 210 passed、认证加固分支 `1d16004` 合并前单独 168 passed 均为历史数字),详见 §2.7。
- ⏳ 后续(测试缺口):补 `login`/`refresh` 遇 `DataCorruption` 的集成测试——注入 DataCorruption,断言 500、body 为 `internal error` 且不含 table/key;当前仅有代码审查,状态保持 ⚠️。
- ✅ 与 pending identity 分支的迁移编号冲突已解决:pending 迁移已顺延为 010/011(`a5b6f80`),合并后 234 passed。
- ⏳ 后续项(本次合并登记):
  - (a) `login_rate_limit` 测试与固定窗口按 epoch 对齐(`window_start = now - now % 900`),跨 :00/:15/:30/:45 边界运行时偶发失败(首跑 2 个失败,单独重跑 8/8 通过;main 既有问题,与合并无关);建议给限速器注入可控时钟,或让测试对齐窗口起点。
  - (b) 补 `login`/`refresh` 遇 `DataCorruption` 的集成测试(main 已登记,保持)。
  - (c) 认证三张新表(`sessions`、`login_rate_counters`、`auth_audit_log`)未纳入启动权威源扫描(main 已登记,保持)。
  - (d) 可选:补 committed 身份交易行在重建投影后保持不变的测试(现仅覆盖 pending 行)。
  - (e) 曾跑旧版 pending 迁移(版本 7/8)的开发库升级演练(§2.3.1 限制 (e),现为读代码推导,未实跑)。
- ⏳ 认证加固第二批:`trusted_proxies`(解决反代共享桶)与认证参数完整配置化(F10)、改密 API(F9)、管理员会话/用户禁用接口(F8);指数退避与 `locked_until`;refresh 失败审计事件;TLS 真实握手测试;refresh/access 分密钥;主动断开被撤销用户的 WS 连接;缩短 access 默认有效期。
- P2P 内部去中心化共识与自动分叉裁决：有意不实现，可信根由外部认证链锚定提供。
- 跨链认证网后续: L2 多外链批次锚定 / L3 锚定回执回写本链 / L4 外链失信切换 / L5 自身失信封存重启(人工触发,涉创世块语义单独设计)。
- ✅ Claim 信任策略与有效状态 resolver — 本次提交:按可信认证者、分类授权、权重、观察/生效时间与 supersedes/withdrawn 链解析；同权重状态冲突显式返回，默认无可信认证者 fail-closed。
- Claim 集中分类字典与认证机构治理：动态信任权重、认证机构变更、跨机构争议裁决仍待实现。
- ✅ WebSocket 频道隔离 — 静态事件映射已实现：`/ws/chain`→`block_added`、`chain_validated`，`/ws/metadata`→`metadata_added`，`/ws/aggregation`→`aggregation`；`/ws` 保持全量，`version_tracked` 和未映射事件仅进入 `/ws`。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。不包含动态订阅或频道级授权。
- ✅ #6 纯 migration 驱动 — `13ded24` 移除 init_tables 兜底,建表事实源唯一化,旧库升级回归测试通过。回滚(自动 down)/数据回填按用户确认有意推迟。
- ✅ #5 独立 metadata 查询表 — `b239df6` migration 005 投影表 + commit_block 同事务 upsert + 代码级回填 reconcile,读路径走 SQL(lib 64 含投影测试)。tag 关联表/pending 联合查询为最小版有意不做。
- (可选)自动 down 回滚机制:当前 up-only + 手动回滚约定,无真实场景暂不实现。

## 五、独立仓库维护约定

- 本仓库不再依赖 monorepo 根的 `PROJECT_STATUS_OVERVIEW.md`；状态以本文档和 README 为准。
- 每次需求、设计或代码行为变化，都要同步本文档对应表格、README 和任务记录，并在状态项后附 commit 与验证方式。
- 远程仓库已重命名为 `VeraChain`，地址为 `https://github.com/heweixi/VeraChain.git`（SSH：`git@github.com:heweixi/VeraChain.git`；旧地址 `heweixi/datachain-rust` 由 GitHub 重定向，各分支提交号与新地址一致）；当前 Git 历史由原 monorepo 的 `datachain-rust` subtree 提取而来，提交消息和演进路径保留，commit hash 因 subtree 拆分而重新生成。
