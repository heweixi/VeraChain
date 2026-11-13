# DataChain Rust

DataChain Rust 是一个面向数据追溯与可验证记录的 Rust 项目：既可作为可嵌入的 Rust 模块使用，也可独立运行 Axum HTTP + WebSocket 服务。

> **最后核实：2026-11-11**
>
> - ✅ 身份交易 `Idempotency-Key` 与 pending 身份交易持久化：本次提交 `734f1a2` + 验证机 192.168.3.7 docker `rust:latest` 验证：`cargo fmt --check` rc=0；`cargo test --no-fail-fast` rc=0，**120 passed / 0 failed**（lib 91、bin 0、api_integration 20、websocket_integration 9、doctest 0）；`cargo clippy --all-targets` rc=0 无 error，本分支无新增告警（既有基线告警仍在，未加 `-D warnings`）。reviewer 复审（读代码）无 Important。仍有 ⚠️/🔺 项（如无直接测试覆盖的 `identity_tx_gate`、`Storage::commit_block` 破坏性签名、`legacy_unverified` fail-closed），详见 [IMPLEMENTATION_STATUS.md §2.3.1](IMPLEMENTATION_STATUS.md)。
> - 下方 WebSocket 的 97 passed 是该功能提交 `b20cbc4` 当时的历史结果，不是当前总数。
> - ✅ 已验证的 WebSocket 静态频道隔离：已提交 `b20cbc4`；247 docker `rust:latest` `cargo test`，97 passed。
> - 实现状态与未完成需求见 [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)。该文档是本独立仓库的状态入口。

## 适用场景

- 为文件、数据集或业务对象保存可追溯的元数据，并在挖矿后写入本地链。
- 使用 JWT 认证的 HTTP API 集成数据登记、查询、区块信息和实时事件。
- 在 Rust 应用中复用区块、Merkle、认证、元数据、版本与存储模块。
- 试验可验证语义目录、链上身份和单外链锚定的实现方式。

## 核心能力

- Axum HTTP 服务，包含健康检查、认证、元数据、区块、版本、聚合、身份、目录和跨链相关路由。
- SQLite/SQLx 存储，元数据先进入待打包队列，挖矿时与区块提交原子写入。
- JWT access/refresh token、公开注册普通用户和基于路由的 RBAC。
- Block、PoW、Merkle 树、版本内容快照和递归汇总等基础模块。
- WebSocket 实时事件：`/ws` 接收全部业务事件，专用频道按固定映射过滤。
- P2P 广播/发现、单条 `data_id` 的 Merkle proof 与外链锚定基础能力。

## 明确边界

- ⚠️ **库 API 尚未承诺稳定。** 项目可以作为 Rust 模块嵌入，但当前没有稳定 API 兼容性承诺，也没有 crates.io 发布计划。
- ⚠️ **不是生产级去中心化共识系统。** P2P 使用受信节点与最长合法链，不实现拜占庭共识或同长度分叉自动裁决。
- ⚠️ **WebSocket 不是动态订阅系统。** 它不支持动态订阅或频道级授权；专用频道是服务端固定事件映射。
- ⚠️ **跨链认证网仍处于演进中。** 当前是单条数据、单外链锚定；多外链批次认证、回执回写、失信切换和封存重启尚未实现。
- ⚠️ **公开注册账号不能挖矿。** `POST /api/v1/auth/register` 固定创建普通 `user`，该角色可创建和读取 metadata，但没有 `BlockMine` 权限；使用其 Bearer token 请求 `POST /api/v1/chain/mine` 会被认证中间件拒绝并返回 `403`。管理员账户须由部署者在受信运维流程中预先创建并保管；请严格按[新手指南的 Docker Compose 或 Cargo 管理员初始化路径](docs/GETTING_STARTED.md#8-受信管理员打包-pending-元数据)操作，以复用运行服务的数据库和 JWT secret。`docker-compose.yml` 与 `config.toml` 不定义或自动生成管理员账户、管理员 Bearer token。
- ✅ **身份交易幂等与升级注意（`734f1a2`，192.168.3.7 docker `rust:latest` `cargo test` 120 passed；`identity_tx_gate` 串行化、`transaction_id` 不入区块的直接断言无测试覆盖，仍为 ⚠️）。** `POST /api/v1/identity/key-transaction` 支持可选 `Idempotency-Key` 请求头：同一用户、同键、同指纹返回原事务（pending `202` / committed `200`），同键不同请求返回 `409`；空白或非 UTF-8 的键视为未提供；键按提交用户隔离；CORS 已允许该头。`transaction_id` 只存在于 SQLite 账本与内存队列，不进入区块、Merkle 或签名。新增迁移 `007_identity_transactions.sql`、`008_identity_transaction_recovery_state.sql`。
  - 🔺 升级前遗留的 pending 身份交易会被标记为 `legacy_unverified`，**服务启动与 CLI `chain mine` 将 fail-closed 拒绝运行，不自动修复**。须先备份数据库，人工核对这些交易是否已入块后再处理；示意 SQL 与步骤见 [IMPLEMENTATION_STATUS.md §2.3.1](IMPLEMENTATION_STATUS.md)，执行需谨慎，项目无内置恢复命令。
  - 限制：服务运行时不要用 CLI `chain mine` 对同一数据库挖矿（内存队列与账本可能漂移，导致挖矿持续失败直至重启）；`Idempotency-Key` 无长度上限，指纹仅覆盖 `signing_payload` 的 5 个字段（不含 `reason`/`timestamp`/`signature`）；同步导入区块不清理本地同内容 pending（既有行为）。
  - 🔺 `Storage::commit_block` 公开签名变更（breaking），新增 `identity_transaction_ids` 参数。
- ⚠️ **语义目录的治理能力未完成。** Claim 集中分类字典、动态认证机构治理与跨机构争议裁决尚未实现。

完整限制、证据和后续项以 [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) 为准。

## 架构与模块入口

| 入口 | 内容 |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | 可嵌入模块的库入口。 |
| [`src/api/routes.rs`](src/api/routes.rs) | Axum HTTP 与 WebSocket 路由。 |
| [`src/core/`](src/core/) | 区块、链和 Merkle 核心。 |
| [`src/auth/`](src/auth/) | 用户、JWT 和权限。 |
| [`src/metadata/`](src/metadata/) | 元数据请求、待打包与查询。 |
| [`src/storage/`](src/storage/) | SQLite/SQLx 存储与迁移。 |
| [`src/main.rs`](src/main.rs) | `datachain` 可执行程序入口。 |

## 快速开始

按照 [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) 完成本地启动、公开注册/登录、元数据写入与读取、由受信管理员打包 pending 元数据、链查询和 WebSocket 连接。公开注册账号没有挖矿权限；该指南要求在启动前通过 `DATACHAIN_JWT_SECRET` 注入至少 32 字符的非默认随机值。

```bash
# Cargo CLI 路径；先按 GETTING_STARTED.md 设置 DATACHAIN_JWT_SECRET
cargo run -- serve --port 8080
```

Docker Compose 路径、请求示例和端口说明见新手指南。

## 运行与验证

- 启动方式：`cargo run -- serve --port 8080`，或 `docker compose up --build`。
- 健康检查：`GET /health`。
- Rust 测试：`cargo test`。
- 当前 WebSocket 测试证据：已提交 `b20cbc4`；247 docker `rust:latest` `cargo test`，97 passed。此证据描述实现验证，不代表本轮文档已运行 Rust 验证。
- 身份交易幂等改动（提交 `734f1a2`，验证机 192.168.3.7 docker `rust:latest`，target 卷 `dc-rust-target-pi`）：`cargo fmt --check` rc=0；`cargo test --no-fail-fast` rc=0，120 passed、0 failed（lib 91、bin 0、api_integration 20、websocket_integration 9、doctest 0）；`cargo clippy --all-targets`（未加 `-D warnings`）rc=0 无 error，落在本分支改动文件的 5 处告警（`src/api/state.rs:36`、`src/storage/database.rs:581/672/808/887`）经 git blame 均来自 main 既有提交，本分支无新增。首次真实运行（`5b2ad61`）曾因 `KeyTransactionEntry` 未派生 `PartialEq` 导致 lib 测试编译失败（E0369），已在 `734f1a2` 修复（见 IMPLEMENTATION_STATUS.md §2.3.1）。reviewer 复审（读代码）无 Important。

## 文档导航

- [新手指南](docs/GETTING_STARTED.md)：本地运行与最小 API 操作。
- [实现状态与未完成需求](IMPLEMENTATION_STATUS.md)：能力状态、验证证据和已知差异。
- [流程图与模块数据流](docs/FLOW.md)：架构与关键链路。
- [跨链认证网与可验证语义目录](docs/CERTIFICATION_NETWORK.md)：设计方向、当前边界和路线图。
- [基本使用示例](examples/basic_usage.rs)：输出 API 操作示意的 Rust 演示程序。

## 当前成熟度与路线图

- ✅ 已实现：本地 Axum 服务、SQLite 持久化、JWT/RBAC 基础、区块/PoW/Merkle、元数据上链、版本快照、聚合、WebSocket 固定频道映射，以及部分 P2P 和跨链能力。验证证据见 [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)。
- ⚠️ 适合：本地开发、集成验证和面向受信环境的原型。
- ⏳ 后续：多外链批次认证、外链阶段回写、失信切换、人工封存后的新链启用，以及语义目录治理能力。

## 许可现状

项目当前声明为 **MIT**，但仓库尚未包含 `LICENSE` 文件。因此法律许可材料尚未完备；正式分发前应补齐 `LICENSE`，并由项目维护者确认适用许可文本。
