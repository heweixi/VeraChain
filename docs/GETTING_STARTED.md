# DataChain Rust 新手指南

本指南演示如何在本地启动 DataChain Rust，并完成公开注册、登录、元数据写入与读取、由受信管理员打包 pending 元数据、链查询和 WebSocket 连接。

> **最后核实：2026-11-10**
>
> 本指南依据当前源码、`docker-compose.yml`、`config.toml` 和 `README.md` 编写。WebSocket 静态频道隔离的实现验证证据为：已提交 `b20cbc4`；247 docker `rust:latest` `cargo test`，97 passed。本指南本身不声称已运行这些命令。

## 1. 前置条件

任选一种启动路径：

- **Docker Compose 路径**：Docker Engine 与 Docker Compose v2（`docker compose`）。
- **Cargo CLI 路径**：Rust stable 工具链（含 `cargo`）和 SQLite 可用的本地环境。

以下 HTTP 示例使用 `curl` 和 `jq`。测试 WebSocket 的示例使用 `npx wscat`，因此还需要 Node.js；也可以换成任何支持在 WebSocket 握手中设置 HTTP Header 的客户端。

## 2. 克隆与构建

仓库当前远程地址为：

```bash
git clone https://github.com/heweixi/datachain-rust.git
cd datachain-rust
```

使用 Cargo 构建：

```bash
cargo build
```

Docker Compose 会在启动时构建镜像，无需单独执行 `cargo build`。

## 3. 设置 JWT secret

服务会拒绝默认、占位或少于 32 个字符的 JWT secret。启动前必须通过 `DATACHAIN_JWT_SECRET` 提供新的随机值，不能依赖 `config.toml` 中的默认占位值。

在 POSIX shell 中生成并注入临时本地 secret：

```bash
export DATACHAIN_JWT_SECRET="$(openssl rand -base64 48)"
```

如果使用 Docker Compose，请写入仓库根目录的 `.env`。该文件已被 Git 忽略，不应提交：

```bash
printf 'DATACHAIN_JWT_SECRET=%s\n' "$(openssl rand -base64 48)" > .env
```

不要把实际 secret、access token 或 refresh token 写入代码、文档、终端记录或版本库。

## 4. 选择一种本地启动路径

### 路径 A：Docker Compose

先完成上一节的 `.env` 设置，然后启动：

```bash
docker compose up --build
```

Compose 将主机的 `8004` 映射到容器的 `8080`，因此后续命令使用：

```bash
export BASE_URL="http://localhost:8004"
export WS_BASE_URL="ws://localhost:8004"
```

停止服务时按 `Ctrl+C`；若使用 detached 模式启动，请执行 `docker compose down`。本地数据位于 `./data` 的 SQLite 文件中。

### 路径 B：Cargo CLI

在一个终端中设置环境变量并启动服务：

```bash
export DATACHAIN_JWT_SECRET="$(openssl rand -base64 48)"
cargo run -- serve --port 8080
```

另开一个终端执行后续请求：

```bash
export BASE_URL="http://localhost:8080"
export WS_BASE_URL="ws://localhost:8080"
```

默认 SQLite 路径为 `./data/datachain.db`。如需覆盖数据库、监听地址或端口，可使用 `DATACHAIN_DATABASE_DSN`、`DATACHAIN_SERVER_HOST`、`DATACHAIN_SERVER_PORT`；`--port` 会覆盖配置文件中的端口。

## 5. 健康检查

服务就绪后运行：

```bash
curl -fsS "$BASE_URL/health"
```

响应含 `status: "ok"` 和构建时的版本号。该路由无需 token。

## 6. 注册与登录

公开注册始终创建普通 `user` 角色，客户端传入的 `role` 不会提升权限。下面的账号仅用于本地演示，请在共享环境中换成自己的强密码。

```bash
curl -sS -X POST "$BASE_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "guide-user",
    "password": "local-demo-password-change-me",
    "email": "guide-user@example.invalid"
  }'
```

登录并仅在当前 shell 会话中保存 access token：

```bash
export TOKEN="$(curl -sS -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"guide-user","password":"local-demo-password-change-me"}' \
  | jq -r '.data.token')"
```

不要默认输出、记录或复制 access token。若登录排障需要检查响应，请在受控调试环境中检查响应，并避免把 token 写入终端记录、日志或版本库。后续保护路由均使用：

```text
Authorization: Bearer <access-token>
```

其中 `<access-token>` 是运行时取得的 token，例如 shell 中的 `$TOKEN`，不是可复制的固定值。

## 7. 公开账号：写入最小元数据

公开注册始终得到普通 `user` 角色。该角色可以创建和读取 metadata，但没有 `BlockMine` 权限。创建请求会先把元数据写入待打包队列；在管理员挖矿前，查询投影不会包含该记录。以下请求省略 `owner`，服务会使用已认证用户 `guide-user` 作为所有者：

```bash
curl -sS -X POST "$BASE_URL/api/v1/metadata" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_size": 12,
    "hashes": {"sha256": "example-sha256-value"},
    "metadata": {"media_type": "text/plain"},
    "parent_id": null,
    "tags": ["getting-started"]
  }'
```

## 8. 受信管理员：打包 pending 元数据

`POST /api/v1/chain/mine` 需要 `BlockMine` 权限。公开注册的普通 `user` 没有该权限，使用其 Bearer token 调用此端点会被认证中间件拒绝并返回 `403`。

管理员账户必须由部署者在受信运维流程中预先创建并保管。`docker-compose.yml` 与 `config.toml` 不定义或自动生成管理员账户或管理员 Bearer token。不得在公开注册流程中创建管理员，也不得将真实密码、JWT secret 或 token 写入文档、终端记录、日志或版本库。

`--role` 必须明确传入 `admin`。允许值为 `admin`、`user`、`auditor`、`guest`；未知值会**静默回退**为 `user`。每次创建后都必须检查 CLI 输出中的 `角色: admin`，确认无误后才继续。`read` 可避免密码回显，但该 CLI 仍以命令行参数接收密码，因此以下命令只能在受信、非共享的运维主机上执行。

先在受信 shell 设置本次账户的非敏感字段，并读取密码：

```bash
export ADMIN_USERNAME="local-admin"
export ADMIN_EMAIL="local-admin@example.invalid"
read -rs -p "管理员密码: " ADMIN_PASSWORD; echo
```

### 路径 A：Cargo CLI（与服务共用本地运行时配置）

在**与服务相同的工作目录和配置文件**下执行。管理员创建进程必须继承服务正在使用的同一组 `DATACHAIN_JWT_SECRET` 和 `DATACHAIN_DATABASE_DSN` 环境变量；可在后台运行服务的同一受信 shell 中执行，或在第二个受信 shell 安全地载入完全相同的值。不要因另开终端而落回另一套默认数据库或 JWT secret。

```bash
cargo run -- --config ./config.toml user create \
  --username "$ADMIN_USERNAME" \
  --password "$ADMIN_PASSWORD" \
  --email "$ADMIN_EMAIL" \
  --role admin
```

确认输出为 `角色: admin` 后再继续。

### 路径 B：Docker Compose（复用运行中服务容器）

必须在**运行服务的同一个 Compose 项目**中，并针对 `datachain-rust` 服务执行。此路径会复用服务容器挂载的 `/app/data` 和 Compose 注入的 JWT secret：

```bash
docker compose exec -T datachain-rust /app/datachain \
  --config /app/config/config.toml user create \
  --username "$ADMIN_USERNAME" \
  --password "$ADMIN_PASSWORD" \
  --email "$ADMIN_EMAIL" \
  --role admin
```

确认输出为 `角色: admin` 后再继续。不要在宿主机上将 `/app/datachain` 或 `/app/config/config.toml` 传给本地二进制；这些是容器内路径，只能通过上述 `docker compose exec` 路径使用。

服务仅在启动时把 SQLite 用户加载到内存。若服务已运行，创建管理员后必须先重启该服务再登录：Cargo 路径在保持相同工作目录、配置及 `DATACHAIN_JWT_SECRET`/`DATACHAIN_DATABASE_DSN` 的条件下重启服务；Compose 路径在同一项目中执行 `docker compose restart datachain-rust`。重启会保留同一 SQLite 数据库和 Compose 注入的 JWT secret。

### 管理员登录并打包

使用刚创建的管理员用户名和密码调用既有登录 API，并将 JSON 的 `.data.token` 仅保存到当前 shell 的 `ADMIN_TOKEN`，不要回显该变量：

```bash
export ADMIN_TOKEN="$(curl -sS -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg username "$ADMIN_USERNAME" --arg password "$ADMIN_PASSWORD" \
    '{username: $username, password: $password}')" \
  | jq -er '.data.token')"
unset ADMIN_PASSWORD

curl -sS -X POST "$BASE_URL/api/v1/chain/mine" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

在当前受信会话结束后执行 `unset ADMIN_TOKEN`。挖矿难度来自配置，默认值为 `4`，因此执行时间取决于本机性能。

## 9. 查询链与元数据

获取链信息：

```bash
curl -sS "$BASE_URL/api/v1/chain/info" \
  -H "Authorization: Bearer $TOKEN"
```

查询已经上链的元数据：

```bash
curl -sS "$BASE_URL/api/v1/metadata?owner=guide-user&page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

`GET /api/v1/chain/info`、`GET /api/v1/metadata` 等保护路由没有 token 会返回 `401`。

## 10. 连接 WebSocket

WebSocket 握手也必须带 `Authorization: Bearer <access-token>`。不要把 token 作为 URL 查询参数。以下例子用 `npx wscat` 在握手中设置 Header：

```bash
npx wscat -c "$WS_BASE_URL/ws/metadata" \
  -H "Authorization: Bearer $TOKEN"
```

连接路径决定接收范围，客户端发送 `subscribe` 消息不会改变过滤规则：

| 路径 | 接收的事件 |
| --- | --- |
| `/ws` | 全部业务事件。 |
| `/ws/chain` | `block_added`、`chain_validated`。 |
| `/ws/metadata` | `metadata_added`。 |
| `/ws/aggregation` | `aggregation`。 |

`version_tracked` 和未来未映射的事件仅发送到 `/ws`。专用频道不是动态订阅，也不提供频道级授权。连接数全局上限为 256，单条文本消息上限为 16 KiB。

## 11. 测试

在仓库根目录执行：

```bash
cargo test
```

如需执行常见的静态 Rust 检查：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

历史 WebSocket 实现验证证据为已提交 `b20cbc4` 与 247 docker `rust:latest` `cargo test` 的 97 passed；请在自己的环境中重新运行命令取得当前验证结果。

## 常见问题与安全注意事项

### 启动时报 JWT secret 错误

`config.toml` 和 `config/config.toml` 中的 secret 是会被拒绝的占位值。通过 `DATACHAIN_JWT_SECRET` 注入至少 32 个字符、非默认且随机的值后重新启动。

### Docker 的端口为什么是 8004

Compose 将 `8004:8080` 映射到容器。Docker Compose 路径请用 `http://localhost:8004` 与 `ws://localhost:8004`；Cargo CLI 路径的默认端口是 `8080`。

### 元数据创建成功但查询不到

创建请求只会把元数据放入 pending 队列。请由部署者按[受信管理员初始化与登录步骤](#8-受信管理员打包-pending-元数据)在与服务共用同一数据库和 JWT secret 的 Docker Compose 或 Cargo 路径中创建管理员，并用其登录 API 响应的 `.data.token` 设置 `ADMIN_TOKEN` 后调用 `POST /api/v1/chain/mine`。公开注册的普通 `user` 调用该端点会返回 `403`。`docker-compose.yml` 和 `config.toml` 不会自动生成管理员账户或 token。查询投影只包含已上链元数据。

### 收到 401 或 WebSocket 连接失败

重新登录取得 access token，确认使用 `Authorization: Bearer $TOKEN`。WebSocket 同样要求该 Header，且不能以 URL 查询参数替代。

### 是否可直接用于公开生产网络

不可以据此作出生产级去中心化保证。当前 P2P 没有拜占庭共识或同长度分叉自动裁决；跨链认证网也尚未实现多外链批次认证、回执回写、失信切换和封存重启。完整边界见 [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md)。

### 许可是否已经完备

尚未完备。项目当前声明 MIT，但仓库没有 `LICENSE` 文件。正式分发前应补齐许可文件，并由项目维护者确认适用文本。

## 继续阅读

- [README](../README.md)：项目定位、边界、模块入口与文档导航。
- [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md)：实现状态、验证证据与遗留项。
- [FLOW.md](FLOW.md)：模块和数据流。
- [CERTIFICATION_NETWORK.md](CERTIFICATION_NETWORK.md)：跨链认证网与可验证语义目录。
- [examples/basic_usage.rs](../examples/basic_usage.rs)：输出 API 操作示意的 Rust 演示程序。
