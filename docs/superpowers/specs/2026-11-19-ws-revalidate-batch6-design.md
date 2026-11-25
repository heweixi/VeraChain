# WebSocket 连接定时复核(第六批 B20-B21)

> 来源:IMPLEMENTATION_STATUS 已知限制"已建立的 WebSocket 连接不会因撤销/禁用被主动断开,仅新握手被拒绝"。基线 main `a6f7e61`:429 passed,clippy lib 22,迁移 001-013。**无迁移**。
> 用户决策(2026-11-19,"按建议"):延迟 ≤30 秒可接受;令牌过期也断开;复核时查库出错则关闭(fail-closed);refresh/access 分密钥放弃(现有 `token_type`/`iss`/`aud` 校验已隔离两类令牌)。

## 现状
- 握手经 `auth_middleware`(`authenticate_access_token`:JWT、会话、`is_active`、角色)。握手后连接任务只订阅广播并转发;`WsHub` 只有连接计数器,不记录用户/会话。
- 因此登出、停用、改密、管理员撤销、CLI 停用,以及 access 令牌过期,都不会关闭已建立的连接。

## 设计
- **B20 复核方法**:新增 `AuthService::revalidate_claims(&Claims) -> Result<()>`,与 `authenticate_access_token` 共用同一套检查(拆出 `check_claims`):令牌 `exp` 未过期(用真实时钟)→ 有 `sid` 时会话存在、属于该用户、未撤销、未过期 → 用户 `is_active`(**直接查库,不走缓存**)→ 内存用户存在且角色与 claims 一致。任一步失败或查库出错均返回 `Err`(fail-closed)。
- **B21 连接复核**:`ws_handler` 及三个专用频道 handler 从请求扩展取 `Claims`(中间件已写入);连接循环中加一个 `tokio::time::interval(revalidate_interval)`(首个立即触发的 tick 丢弃),每次 tick 调用 `revalidate_claims`;失败则发送 Close 帧(code 1008,reason `session no longer valid`)并结束循环,同时 `remove_client`。复核期间广播消息照常转发,失败后立即不再转发。
- **配置**:新增 `auth.ws_revalidate_secs`(环境变量 `DATACHAIN_AUTH_WS_REVALIDATE_SECS`,默认 30,范围 1..=3600,**不允许 0**,避免关闭保护)。`WsHub` 持有可调间隔(`AtomicU64` 毫秒,`set_revalidate_interval(Duration)` 作为测试 seam,server.rs 启动时按配置设置)。
- **被否决**:仅在撤销出口推送通知(CLI 跨进程撤销感知不到);按撤销事件精确断开(要把 `WsHub` 接入 `AuthService` 多个出口,本批不做,可后续叠加);复核失败后重试(安全优先,直接关闭)。

## 兼容性
- 🔺 已建立的 WS 连接现在会在最多一个复核间隔内因会话撤销、用户停用、角色变化或令牌过期而被关闭(Close 1008)。客户端需重连并重新认证(用 refresh 换新 access)。
- 新增配置项 `auth.ws_revalidate_secs`。无迁移,无新依赖。

## 已知限制(登记)
- 最长滞后一个复核间隔(默认 30 秒)。
- 每连接每间隔一次主键查询(≤256 连接,约每秒 8 次),可忽略。
- 不做按用户的事件过滤(广播仍对所有已认证连接转发),不在本批范围。

## 切片
- **C1 B20 配置与 seam**:`tests/ws_revalidate_config.rs`(默认 30、TOML/环境变量覆盖、范围 1..=3600、拒绝 0 与越界、`auth_settings`/配置可读)+ `WsHub` 间隔 seam。
- **C2 B20/B21 行为**:`tests/ws_revalidate.rs`(真实 axum 服务 + tokio-tungstenite,沿用 `websocket_integration.rs` 写法;间隔设 200ms):登出后被关(1008);管理员停用用户后被关;`change_password` 撤销其他会话时,其他会话的连接被关而当前会话的连接保持;令牌过期后被关;健康连接跨多个间隔保持并仍能收到事件。
