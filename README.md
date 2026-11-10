# DataChain Rust

DataChain Rust 是一个面向数据追溯与可验证记录的 Rust 项目：既可作为可嵌入的 Rust 模块使用，也可独立运行 Axum HTTP + WebSocket 服务。

> **最后核实：2026-11-10**
>
> - ✅ 链完整性校验：`validate_chain` 与 `validate_loaded_blocks` 共用同一显式门禁；恢复遇到损坏区块会失败关闭，不加载、修复或写回该库。本次提交 + 247 docker `rust:latest` `cargo test`（107 passed）。
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
- Block、PoW、Merkle 树、版本内容快照和递归汇总等基础模块；内存链的 `validate_chain` 与已加载区块的 `validate_loaded_blocks` 复用同一完整性门禁，覆盖创世块、连续索引、保存 hash、难度 PoW、previous hash 及既有 Merkle 叶子规则。
- WebSocket 实时事件：`/ws` 接收全部业务事件，专用频道按固定映射过滤。
- P2P 广播/发现、单条 `data_id` 的 Merkle proof 与外链锚定基础能力。

## 明确边界

- ⚠️ **库 API 尚未承诺稳定。** 项目可以作为 Rust 模块嵌入，但当前没有稳定 API 兼容性承诺，也没有 crates.io 发布计划。
- ⚠️ **不是生产级去中心化共识系统。** P2P 使用受信节点与最长合法链，不实现拜占庭共识或同长度分叉自动裁决。
- ⚠️ **完整性校验遵循现有数据协议。** Merkle root 仅覆盖既有 metadata、key transaction 和 catalog record 叶子规则，不承诺所有序列化字段均被 Merkle 绑定；本轮不迁移 Hash/Merkle 协议、不改变难度比较、P2P 或路由，也不提供自动修复。空内存链的 `validate_chain` 返回 `false`，但空库首次启动仍会创建创世块。
- ⚠️ **WebSocket 不是动态订阅系统。** 它不支持动态订阅或频道级授权；专用频道是服务端固定事件映射。
- ⚠️ **跨链认证网仍处于演进中。** 当前是单条数据、单外链锚定；多外链批次认证、回执回写、失信切换和封存重启尚未实现。
- ⚠️ **公开注册账号不能挖矿。** `POST /api/v1/auth/register` 固定创建普通 `user`，该角色可创建和读取 metadata，但没有 `BlockMine` 权限；使用其 Bearer token 请求 `POST /api/v1/chain/mine` 会被认证中间件拒绝并返回 `403`。管理员账户须由部署者在受信运维流程中预先创建并保管；请严格按[新手指南的 Docker Compose 或 Cargo 管理员初始化路径](docs/GETTING_STARTED.md#8-受信管理员打包-pending-元数据)操作，以复用运行服务的数据库和 JWT secret。`docker-compose.yml` 与 `config.toml` 不定义或自动生成管理员账户、管理员 Bearer token。
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
- ✅ 链完整性验证：本次提交 + 247 docker `rust:latest` `cargo test`（86 单测 + 21 集成测试：API 11、CLI 1、WebSocket 9，107 passed）；`cargo fmt --check` 通过，`cargo clippy --all-targets` 无本次警告，现有基线 warning 保留。

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
