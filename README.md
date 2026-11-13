# DataChain Rust

DataChain Rust 是一个面向数据追溯与可验证记录的 Rust 项目：既可作为可嵌入的 Rust 模块使用，也可独立运行 Axum HTTP + WebSocket 服务。

> **最后核实：2026-11-13**
>
> - ✅ 认证加固第一批（F1-F7：设备会话、access 即时吊销、登录限速、ConnectInfo 全局限流、审计日志、用户禁用持久化）：本次提交 + 验证机 `deploy@192.168.3.7` docker `rust:latest`：`cargo fmt --check` 通过；`cargo test --no-fail-fast` **168 passed、0 failed**（lib 81、api_integration 10、auth_audit 13、auth_claims 5、auth_middleware_session 12、cli_user_status 3、connect_info_rate_limit 5、login_rate_limit 8、sessions_api 16、storage_sessions 4、websocket_integration 11）；`cargo clippy --all-targets`（未加 `-D warnings`）无 error，lib 警告 24 条，与 main 基线持平（本分支无新增）。设计见 [docs/superpowers/specs/2026-11-13-auth-hardening-design.md](docs/superpowers/specs/2026-11-13-auth-hardening-design.md)。
> - 历史基线：此前文档中的「97 passed」（WebSocket 频道隔离，`b20cbc4`）等数字是各自提交时在 247 验证机上的历史基线，**不适用于本次**；本次以上述 168 passed 为准。验证机已由 247 迁至 192.168.3.7（247 磁盘满，降为备用）。
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
- 认证加固（第一批）：设备会话（`sessions`）与 access token 即时吊销、`logout` / `logout-all` / 会话列表与撤销接口、登录限速（用户名 5 次 + IP 20 次 / 15 分钟，429 + `Retry-After`）、认证审计日志（保留 90 天）、用户禁用以 SQLite 为权威（CLI `user deactivate|activate`）。
- Block、PoW、Merkle 树、版本内容快照和递归汇总等基础模块。
- WebSocket 实时事件：`/ws` 接收全部业务事件，专用频道按固定映射过滤。
- P2P 广播/发现、单条 `data_id` 的 Merkle proof 与外链锚定基础能力。

## 明确边界

- ⚠️ **库 API 尚未承诺稳定。** 项目可以作为 Rust 模块嵌入，但当前没有稳定 API 兼容性承诺，也没有 crates.io 发布计划。
- ⚠️ **不是生产级去中心化共识系统。** P2P 使用受信节点与最长合法链，不实现拜占庭共识或同长度分叉自动裁决。
- ⚠️ **WebSocket 不是动态订阅系统。** 它不支持动态订阅或频道级授权；专用频道是服务端固定事件映射。
- ⚠️ **跨链认证网仍处于演进中。** 当前是单条数据、单外链锚定；多外链批次认证、回执回写、失信切换和封存重启尚未实现。
- ⚠️ **公开注册账号不能挖矿。** `POST /api/v1/auth/register` 固定创建普通 `user`，该角色可创建和读取 metadata，但没有 `BlockMine` 权限；使用其 Bearer token 请求 `POST /api/v1/chain/mine` 会被认证中间件拒绝并返回 `403`。管理员账户须由部署者在受信运维流程中预先创建并保管；请严格按[新手指南的 Docker Compose 或 Cargo 管理员初始化路径](docs/GETTING_STARTED.md#8-受信管理员打包-pending-元数据)操作，以复用运行服务的数据库和 JWT secret。`docker-compose.yml` 与 `config.toml` 不定义或自动生成管理员账户、管理员 Bearer token。
- 🔺 **反向代理后所有客户端共享一个全局限流桶。** 全局限流与登录 IP 维度现在只使用 TCP 对端地址（`ConnectInfo`），不再信任 `X-Forwarded-For` / `X-Real-IP`（可被客户端伪造）。部署在反向代理/负载均衡之后时，对端地址是代理 IP，所有客户端共享同一个桶；`trusted_proxies` 配置留待第二批。
- 🔺 **登录失败消息统一为 `invalid credentials`。** 不再区分用户不存在/密码错误/账户禁用；登录超限返回 `429` + `Retry-After`。依赖旧错误文案的客户端需要调整。
- ⚠️ **登录限速是纯固定窗口。** 窗口边界附近最多约 2 倍突发；指数退避与 `locked_until` 列未实现（列为预留，当前不使用）。
- ⚠️ **撤销/禁用的生效有边界。** 无 `sid` 的旧 access token 登出无效，最长保持到自然过期（默认 24h）；多进程场景下跨进程停用/撤销最长滞后 is_active 缓存 TTL（默认 5s）；已建立的 WebSocket 连接不会因撤销/禁用被主动断开，仅新握手被拒绝。
- ⏳ **第二批未做：** `trusted_proxies` 与认证参数完整配置化（F10）、改密 API（F9）、管理员会话/用户禁用接口（F8）；目前停用用户只能走 CLI。
- ⚠️ **其他遗留：** refresh 与 access 仍共用同一 JWT 密钥；access 默认有效期仍为 24h；refresh 失败（停用/会话失效）未写审计事件；TLS 路径无真实握手测试。
- ⚠️ **与其他分支合并须注意迁移编号。** 本分支新增 `007_sessions`、`008_login_rate_counters_and_audit`、`009_session_ip_hint`；若与同样占用 007/008 的分支合并，须把本分支三个迁移顺延编号（已执行较大版本号的库按 `MAX(version)` 会跳过较小版本号）。
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
- Rust 测试：`cargo test --no-fail-fast`（本地无 Rust 工具链，验证在验证机 `deploy@192.168.3.7` 的 docker `rust:latest` 中执行；247 为备用）。
- 当前验证证据：本次提交 + 192.168.3.7 docker `rust:latest` `cargo test --no-fail-fast`，168 passed、0 failed；`cargo fmt --check` 通过；`cargo clippy --all-targets` 无 error（lib 24 条警告与 main 基线持平）。「97 passed」「107 passed」等为历史基线，不适用于本次。
- 停用/启用用户（CLI，状态以 SQLite 为权威）：`datachain user deactivate <username>` / `datachain user activate <username>`；停用同事务撤销该用户全部会话与 refresh family，激活不恢复旧会话。

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
