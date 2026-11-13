# 认证加固设计与实施计划(F1/F2/F3/F4/F5/F6/F7 第一批)

> 来源:analyst 需求 + architect 设计(auto),orchestrator 落盘并修正。基线:`feat/auth-hardening` 基于 main `4cc5646`。
> **重要**:architect 这一轮没能读到源码,文件路径/函数名是按模块角色推断的。developer 开工前必须用 grep 核对实际位置(src/auth/{jwt,service,user,permissions}.rs、src/api/{middleware,rate_limit,handlers,routes,state}.rs、src/storage/database.rs、src/cli/{server,user}.rs、src/config.rs),与事实冲突时以事实为准并在报告里说明。

## 1. 关键决策与被否决备选
| 决策 | 选择 | 否决备选 |
|---|---|---|
| 用户状态权威源 | SQLite 为权威;鉴权关键路径(is_active)查库+进程内短 TTL 缓存(≤5s);内存 HashMap 保留为非鉴权快照 | 仅内存(CLI 独立进程感知不到);每请求纯查库(热路径开销);事件总线推送(CLI 是独立进程做不到) |
| 会话标识 | `Claims.sid: Option<String>` + `#[serde(default)]`;WS 握手与 optional_auth 同样校验 sid | 用 jti 当会话(每次 refresh 都变);强制旧 token 重新登录 |
| 会话与撤销 | `sessions` 表为权威;`revoked_refresh_tokens` 不变;撤销会话时同事务联动写 refresh family 哨兵行;缓存≤5s;查库失败 fail-closed 返回 401 | 并入 revoked_refresh_tokens(语义混杂);fail-open |
| 登录限速 | `login_rate_counters` 固定窗口;IP 与用户名双维度;不存在的用户也跑 dummy bcrypt;ConnectInfo 取对端 IP,oneshot 测试无 ConnectInfo 时回退占位 key;默认不信任 XFF | 滑动窗口/令牌桶;纯内存计数 |
| CLI | 本期新增 `user deactivate <username>` / `user activate <username>`,直接写 SQLite,服务靠短 TTL 缓存感知 | 经 HTTP 管理接口(需先有管理员 token) |

## 2. 默认参数(可配置,缺省如下)
账户+IP 维度 5 次失败 / 15 分钟窗口,锁定 15 分钟,连续锁定指数退避上限 1 小时;IP 维度 20 次 / 15 分钟;会话撤销缓存 TTL ≤ 5s;审计保留 90 天;可信代理默认不信任 XFF。第一批只做必要的最小配置,完整配置化(F10)留第二批。

## 3. 数据模型(迁移编号)
**编号修正(orchestrator)**:main 最新迁移是 006。本特性使用 **007、008**(连续编号,不留空档)。原因:`apply_migrations` 按 `MAX(version)` 判断是否已执行,留空档会导致日后合并 pending identity 分支(它也使用 007/008)时,已执行较大版本号的库跳过较小版本号迁移。pending identity 分支合并时需顺延编号(记入登记项)。`apply_migrations` 用 `split(';')`,SQL 字符串与注释里**不得出现分号**,注释用 `--` 且内容不含分号;最后一条语句不带分号。迁移列表在 `src/storage/database.rs` 的 `migrations: &[(i64, &str)]` 里手工登记。

```sql
-- 007_sessions.sql
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  refresh_family TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revoke_reason TEXT,
  ip_hash TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_sessions_family ON sessions(refresh_family)
```
```sql
-- 008_login_rate_counters_and_audit.sql
CREATE TABLE IF NOT EXISTS login_rate_counters (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  locked_until INTEGER,
  PRIMARY KEY (key, window_start)
);
CREATE TABLE IF NOT EXISTS auth_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  user_id TEXT,
  username_attempted TEXT,
  session_id TEXT,
  ip_hash TEXT,
  user_agent TEXT,
  result TEXT NOT NULL,
  reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON auth_audit_log(ts)
```
- `users` 表的 `is_active` 已存在则复用;若 CLI 当前不写库,需补 `Storage::set_user_active`(核对现有 users 表列)。
- `ip_hash`:`HMAC(server_secret, ip)` 取前 16 字节十六进制,不存明文 IP;响应只给脱敏 `ip_hint`(如 203.0.x.x)。`user_agent` 入库前截断 200 字符并去控制字符。限流 key 带前缀 `ip:<hash>` / `user:<lower(username)>`。

## 4. API 契约
- `POST /api/v1/auth/login`:200 返回原有 token 字段,access 带 `sid`;401 统一 `{"error":"invalid credentials"}`(用户不存在/密码错/账户禁用同一消息同一形态);429 带 `Retry-After` 秒,body `{"error":"too many attempts"}`。
- `POST /api/v1/auth/refresh`:成功沿用轮换,sid 不变,更新 last_seen_at;**校验 is_active 与会话未撤销**,否则 401;复用检测仍整族撤销并同步撤销 session。
- `POST /api/v1/auth/logout`(当前会话)与 `POST /api/v1/auth/logout-all`:幂等,撤销 session 并联动 refresh family(同事务)。
- `GET /api/v1/auth/sessions`:当前用户未撤销未过期会话 `[{id, created_at, last_seen_at, expires_at, user_agent, ip_hint, current}]`;不返回 token/jti/ip_hash。
- `DELETE /api/v1/auth/sessions/{id}`:204;不属于自己或不存在均 404。
- 受保护接口:sid 已撤销/会话过期/用户禁用 → 401;查库出错 → 401(fail-closed)。无 sid 的旧 access 只做 is_active 检查,自然过期,不强制下线。`required_permission` 对新路由默认已认证即可,logout/sessions 需 auth_middleware。

## 5. 关键流程
- 登录:取对端 IP → 事务内原子递增 IP 与用户名两个计数器,超阈值 429 → 查用户(不存在则对固定 dummy hash 跑一次 bcrypt,cost 与真实一致)→ 失败统一 401(**禁用账户也先验证密码再返回统一消息,避免耗时差**)→ 成功同事务创建 session 并签发 access(sid)/refresh(family=session.refresh_family)→ 清零/忽略失败计数 → 写审计。
- Refresh:校验 refresh → family 是否已撤销 → session 有效且用户 is_active → 事务内轮换 jti(沿用 jti 主键抢占)→ 更新 last_seen_at;复用检测撤销整族及 session。旧 refresh(空 family)补建 session 后签发带 sid 的新 access。
- 受保护请求:验 JWT → 有 sid 则查缓存(未命中查库)得会话状态 → 查 is_active(同缓存,TTL≤5s)→ 无 sid 仅查 is_active → 任一步查库失败 401。WS 握手与 optional_auth 使用同一校验函数(optional_auth 对被撤销 token 的处理保持与现有一致,并在报告中说明)。
- 登出:同事务写 sessions.revoked_at 与 refresh family 哨兵行,立即清本进程缓存;其他进程最迟 5s 感知。
- 禁用(CLI):同事务置 is_active=0 并撤销该用户全部 session 与 refresh family;activate 只置 is_active=1,不恢复已撤销会话。

## 6. 并发与一致性
限流递增用单条 `INSERT ... ON CONFLICT DO UPDATE SET count=count+1 RETURNING count`,不要先读后写;撤销会话与撤销 refresh family 同事务;缓存为进程内 `RwLock<HashMap>`+时间戳,写操作先清本进程缓存;事务使用 immediate 写事务避免读升级死锁(核对 sqlx 用法);过期 session/计数器惰性清理。撤销生效延迟上界=缓存 TTL(跨进程最长 5s)。

## 7. 安全
统一失败消息与近似耗时;dummy hash cost 必须与真实一致;日志里 username/user_agent 转义控制字符并截断;日志不写明文 IP(用 hash 前缀);不记录密码/token/jti;审计写入失败不阻塞认证(记 error 日志);限流双维度,用户名维度阈值高于 IP 维度;ConnectInfo 在反向代理后会共享 IP(风险登记);不信任 XFF。

## 8. 破坏性变更
登录失败消息统一;新增 429;新 access 带 sid;禁用后 token ≤5s 失效;全局限流 key 的 IP 来源由 XFF 首段改为对端地址(含淘汰机制);新增 CLI 子命令(非破坏)。

## 9. 实施计划(垂直切片,TDD:先 Red 再最小实现)
通用:公开 seam 测试(HTTP router oneshot / Storage 公开方法 / AuthService 公开方法);不测私有实现;验证在验证机 deploy@192.168.3.7(先 commit,git archive 到 `~/verify/<名>-<短SHA>`,`~/rv37.sh <名> [target卷]`,日志 `~/.rv37/<名>.log`;**不要 rm**,需删的登记 `~/verify/.cleanup-pending.txt`)。target 卷用 `dc-rust-target`(与其他分支并行时用独立卷)。

- **S1 迁移与 Storage sessions**:Storage 公开方法 create_session / get_session / list_active_sessions / revoke_session(同事务联动 refresh family 哨兵行)/ is_user_active / set_user_active。Red:`no method create_session`,桩后断言"撤销后应已撤销"。文件:migrations/007_sessions.sql、src/storage/database.rs、tests/storage_sessions.rs。
- **S2 Claims.sid 与签发**(依赖 S1):Claims 加 sid(serde default);登录创建 session 并把 sid 放进 access;旧格式 token 仍可解析。seam:AuthService/jwt 公开方法 + HTTP login。文件:src/auth/*、src/api/handlers.rs、tests/auth_claims.rs。
- **S3 登录限速与恒定时间**(依赖 S2):migrations/008;原子递增;登录入口先查限流;dummy bcrypt;统一 401;429+Retry-After;oneshot 无 ConnectInfo 回退占位 key。seam:router oneshot POST /auth/login。Red:第 6 次错误登录期望 429 实得 401;缺 Retry-After。时序测试仅粗粒度宽松断言(重复取中位数)。文件:migrations/008_*.sql、storage、auth service、handlers、tests/login_rate_limit.rs。
- **S4 ConnectInfo 接入与全局限流修正**(依赖 S3):两条 serve 路径(TLS/非 TLS)改用 `into_make_service_with_connect_info::<SocketAddr>()`;全局 rate_limit 的 IP 来源改为对端地址(默认不信任 XFF,可信代理配置留第二批),并加过期淘汰;保持 `/auth/*` 20 次/分钟行为。seam:监听 127.0.0.1:0 的真实请求 + oneshot 回退。
- **S5 鉴权中间件校验会话与 is_active**(依赖 S1、S2):抽出统一校验函数供 auth_middleware/optional_auth/WS 握手使用;TTL≤5s 缓存;fail-closed;无 sid 旧 token 仅查 is_active。Red:撤销会话后旧 token 期望 401 实得 200;禁用用户后期望 401 实得 200。文件:src/api/middleware.rs、WS 握手、src/auth/*、tests/auth_middleware.rs、tests/ws_auth.rs。
- **S6 登出/会话列表/撤销 + refresh 校验**(依赖 S5):三接口 + logout-all + refresh 校验 session/is_active + 复用检测同步撤销 session + 惰性清理。Red:登出后 refresh 期望 401 实得 200;GET /sessions 404;删他人会话期望 404。文件:handlers、routes、service、tests/sessions_api.rs。
- **S7 审计日志与 CLI 启停**(依赖 S1、S5):审计写入(login_success/login_failure/login_locked/refresh_success/refresh_reuse_detected/session_revoked/logout/logout_all/user_deactivated/user_activated),失败不阻塞;保留 90 天启动清理;CLI `user deactivate|activate <username>` 写库并联动撤销会话;用户不存在返回非 0 退出码。测试经 CLI 入口(沿用现有 CLI 测试方式)与审计表内容断言(无 token/密码子串)。文件:src/cli/user.rs、storage、tests/cli_user_status.rs、tests/auth_audit.rs。
- 最终验证:验证机上对整条分支跑 `cargo fmt --check`、`cargo test --no-fail-fast`、`cargo clippy --all-targets`(不加 -D warnings,本分支不得新增告警)。

## 10. QA 验证点
并发(限流递增不漏计;登出与 refresh 并发结果一致;CLI 禁用与请求并发);时序(三种失败耗时,宽松阈值);枚举(三种失败响应一致;他人/不存在会话 DELETE 响应一致);日志泄露(密码、token、明文 IP;换行与 ANSI 控制字符转义);旧 token 兼容(无 sid access 可用且禁用后被拒;旧 refresh 补建 session);WS 鉴权回归(撤销/禁用后新握手被拒;已建立连接不主动断开是已知范围);fail-closed(查库失败 401);缓存延迟上界≤TTL。

## 11. 风险与登记
设计路径未核对源码;反向代理后共享 IP;已建立 WS 连接不主动断开;跨进程撤销延迟≤5s;用户名维度限流可被用来锁定他人账号(已知取舍);时序测试 CI 抖动;**pending identity 分支合并时需把它的 007/008 顺延编号**(本特性占用 007/008);bcrypt dummy hash cost 需取实际值;access 与 refresh 共用同一密钥(已知债务,不在本期);第二批:F9 改密 API、F10 完整配置化与 trusted_proxies、F8 管理员会话/用户禁用接口。
