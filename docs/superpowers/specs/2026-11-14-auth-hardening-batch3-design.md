# 认证加固第三批设计(B8-B12)与实施计划(C1-C7)

> 来源:architect(auto)读 `d:\workbench\VeraChain-auth3` 源码后产出,orchestrator 落盘。基线 main `09fa049`,分支 `feat/auth-hardening-3`。
> 基线验证:357 passed、clippy lib 22 条、迁移 001-013。第二批设计见 `2026-11-14-auth-hardening-batch2-design.md`。
> 标 **⚠核对** 的点是 architect 未能确认的事项,developer 开工前须读代码核对。

## 0. 读源码得到的关键事实
1. `AuthService::login` 用**内存** `User.password_hash` 验密。CLI 在别的进程改库后,运行中的服务仍按旧哈希验密。`change_password` 靠步骤 7 手工同步内存,CLI 没有这条路径。
2. `register_with_role` 是**同步**公开方法,`tests/common::seed_user` 与大量测试调用它。不能改签名。
3. 现有 `register_with_role`:读锁查唯一性 → bcrypt → 写锁插入,检查与插入之间没有持锁复检。并发同名注册会都通过检查,后者覆盖索引。`remove_user` 回滚时又会按名字删掉索引,导致先成功的用户从索引消失。
4. bcrypt(`hash_password`/`verify_password`,cost 12)在 `login`、`change_password`、`register`、`dummy_password_hash` 里同步执行,占用 tokio 工作线程。
5. `Storage::deactivate_user_and_revoke_sessions` 的首条语句是 `UPDATE users SET is_active=0 WHERE user_id=?`,0 行返回 `Ok(None)`。管理员 API 与 CLI 共用它。当前没有任何改角色的接口。
6. 锁定状态全在 SQLite(`login_lockouts`、`login_rate_counters`),`enter_rate_gate` 每次读库。CLI 在别的进程里清锁,服务立即感知。
7. `required_permission` 对 `/api/v1/admin/users/<id>/<action>` 只映射了 `sessions`、`deactivate`、`activate`,其余落到 `SystemAdmin`。
8. CLI `user create` 失败(含 `UserExists`)只 `println!` 后仍返回 `Ok(())`,退出码为 0。
9. CLI 测试使用真实二进制(`CARGO_BIN_EXE_datachain`)+ 同一 SQLite 文件(见 `tests/cli_user_status.rs`)。这是本批 CLI 切片的公开测试 seam。

## 1. 范围取舍(风险降低 / 改动成本 / 破坏性)
| 候选 | 决定 | 理由 |
|---|---|---|
| 解锁入口 | **做 B8** | 风险最高:攻击者可持续锁定任意用户名(含管理员),没有恢复入口。成本小(两个表删行 + CLI + 一个路由)。无破坏性。 |
| bcrypt spawn_blocking | **做 B9** | 单个慢请求即可占满工作线程,影响全部端点。成本中等(4-5 处调用点)。无外部破坏性。 |
| 最后管理员保护 | **做 B10** | 管理员互停后无人能操作,只能靠 CLI。单语句原子判定,成本小。轻微破坏:原来允许的最后管理员停用变为 409。 |
| login 读 SQLite 哈希 + CLI passwd | **做 B11** | CLI 改密后服务仍接受旧密码,且没有 CLI 改密命令,忘记密码无法恢复。成本小。 |
| 密码策略用于注册/CLI 创建 | **做 B12** | 注册与创建是弱口令入口,策略函数已存在。破坏:短密码注册开始被拒。 |
| create_session 原子化 | 推迟 | 要把"密码/停用状态未变"并入建会话的条件写,与已登记的登录/改密并发限制(B-6)联动,需单独设计。 |
| scan_sessions 流式 | 推迟 | 只是启动期内存占用,不降低安全风险。 |
| refresh/access 分密钥 | 推迟 | 升级即让全部已签发 token 失效,或要双密钥过渡期。破坏性大,单独成批。 |
| 主动断开被撤销用户 WS | 推迟 | 要给 `WsHub` 加按 user/sid 的连接注册表和撤销通知,改动面大。 |
| Forwarded / X-Real-IP | 推迟 | 扩大对头部的信任面,配置错误即可被伪造。 |
| IPv6 /64 | 推迟 | 改变限流/会话 IP 粒度,需设计聚合键和存量计数处理。 |
| 全局限流阈值配置化 | 推迟 | 非认证加固,风险低。 |
| 废弃 `locked_until` 列 | 推迟 | SQLite `DROP COLUMN` 依赖版本(≥3.35),迁移不得含分号。只有整洁收益。 |
| bcrypt 并发 Semaphore | 不做 | YAGNI。登录有 IP/用户名限速兜底。 |
| tty 无回显输入 | 不做 | 需新依赖。 |

## 2. 决策与被否决备选
| 决策 | 选择 | 被否决备选及原因 |
|---|---|---|
| 解锁形态 | CLI + 管理员 HTTP | 只做 HTTP:全部管理员被锁时无法恢复。只做 CLI:无法远程运维。 |
| 解锁权限 | 复用 `UserStatusAdmin` | 新增 `Permission::UserUnlockAdmin`:要改 Display、默认角色和所有穷尽 match,为一个动作不值得。 |
| 解锁清除范围 | 删 `login_lockouts` 与 `login_rate_counters` 里该用户的两个 key | 只删锁行:窗口计数若仍超限会立即重新落锁。同时清 IP:IP 维度被多人共享,管理员无法判断是否为攻击。 |
| 解锁 key 来源 | 由目标用户的存储用户名经与 login 相同的规范化函数得出 | 按请求里传来的用户名清:可能与 login 的 key 不一致,且能清任意字符串。 |
| bcrypt 异步化 | 私有 async 辅助,内部 `spawn_blocking` | 改 `hash_password`/`verify_password` 本身为 async:这两个同步函数被其他路径使用。引入 Semaphore:见 §1。 |
| 注册异步化 | 新增 `register_validated`,保留同步 `register*` | 把 `register_with_role` 改 async:破坏 `tests/common` 与所有库调用方。 |
| 最后管理员判定位置 | Storage 层同一条 UPDATE 带子查询条件 | 先 SELECT 计数再 UPDATE:并发互停可都通过(TOCTOU)。只在 service 层判定:CLI 与并发路径绕过。 |
| 最后管理员保护对 CLI | 同样生效,无 `--force` | CLI 豁免:停用最后管理员不是恢复动作,恢复用 `activate`,该操作不受限。 |
| CLI 密码输入 | stdin 一行 | `--password` 参数:进程列表可见。tty 无回显:需新依赖。 |
| CLI passwd 是否验旧密码 | 不验(运维重置) | 验旧密码:忘记密码场景无法使用。 |
| login 验密来源 | 每次从 SQLite 读哈希 | 给内存加 TTL/版本号:引入新的一致性窗口。 |

## 3. 各项设计

### B9 bcrypt 异步化(先做,其余切片复用)
`src/auth/service.rs` 内私有辅助(骨架):
```rust
async fn hash_password_blocking(password: String) -> Result<String>;
// hash 为 None 时对 dummy_password_hash() 验证,抹平不存在用户的耗时
async fn verify_password_blocking(password: String, hash: Option<String>) -> Result<bool>;
```
- 内部 `tokio::task::spawn_blocking`。`JoinError` 与 bcrypt 错误映射为 `DataChainError::Internal`,错误文本不得包含密码或哈希。
- `dummy_password_hash()` 的 `OnceLock` 首次初始化也发生在 blocking 闭包内。
- 调用点改造:`login`(验密)、`change_password`(验旧、哈希新)、`register_validated`(哈希)、新增 `reset_password`(哈希)。
- 行为不变:限速、审计、错误形状、`login`/`change_password` 的顺序均不动。
- `Cargo.toml` 的 tokio 已是 `features = ["full"]`,无需改依赖。

### B11 login 读 SQLite 哈希 + CLI passwd
- `login`:内存 `found` 用户仍用于存在性、角色、`to_public`。验密哈希改为 `storage.get_user_password_hash(&user.user_id)`。SQLite 查无该用户时按"未知用户"处理(`verify_password_blocking(.., None)`,审计 reason `unknown user`)。读库失败走现有 500 路径。
- `User.password_hash` 内存字段保留,不再参与验证。`change_password` 的内存同步保留,无害。
- 新增 Storage:
```rust
// 无条件改哈希并在同一事务撤销该用户全部会话+写 family 哨兵;None=用户不存在
pub async fn set_user_password_and_revoke_all_sessions(
    &self, user_id: &str, new_hash: &str, reason: &str, ttl_secs: i64,
) -> Result<Option<u64>>;
```
  首条语句为写操作(`UPDATE users SET password_hash=? WHERE user_id=?`),随后复用 `revoke_user_sessions_in_tx(.., None)`。
- 新增 Service:
```rust
pub async fn reset_password(&self, target_user_id: &str, new_password: &str, ctx: &LoginContext) -> Result<u64>;
```
  顺序:`validate_new_password(.., self.password_min_length)` → `hash_password_blocking` → storage → 同步内存哈希 → 审计 `password_reset`(result success,reason `cli reset, revoked N sessions`,actor 为 NULL)。用户不存在返回 `UserNotFound`。
- CLI:`user passwd <username>`。从 stdin 读**一行**(最多 1 KiB,去掉末尾 `\n`/`\r\n`,保留其他空白;超长按策略的 too long 处理)。策略失败与用户不存在均返回非 0 退出码,消息只含固定词表或用户名,不回显密码。
- 并发语义:CLI passwd 是无条件覆盖,与 API `change_password`(旧哈希 CAS)并发时后写者胜,且双方都撤销会话。
- 已登记不变:登录与改密并发时,撤销之后才落库的新会话仍可能存活(B-6)。

### B12 密码策略用于注册/CLI 创建
- 新增:
```rust
pub async fn register_validated(&self, req: &RegisterRequest, role: Role) -> Result<User>;
```
  顺序:`validate_new_password` → `hash_password_blocking` → **同时持有 `users`/`username_index`/`email_index` 三把写锁(顺序与 `register_with_role`、`remove_user` 一致)复检用户名与邮箱唯一性并插入**。冲突返回 `UserExists`。
- HTTP `register` handler 改调 `register_validated(&req, Role::User)`。新增分支:`PasswordRejected(msg)` → 400 `{"success":false,"error":<msg>}`。其余错误保持现状。
- CLI `user create` 改调 `register_validated(&req, role)`。任何失败(策略、UserExists)返回 `Err`,退出码非 0(D11)。
- 同步 `register`/`register_with_role` 保持原样,不校验策略;文档注释写明"会阻塞,请求路径请用 `register_validated`"。

### B10 最后一名活跃管理员保护
`Storage::deactivate_user_and_revoke_sessions`(签名不变)首条语句改为单条条件 UPDATE:
```sql
UPDATE users SET is_active = 0
WHERE user_id = ?
  AND NOT (is_active = 1 AND role = 'admin'
           AND (SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1) <= 1)
```
- 影响 0 行时,**同一事务内**再查该 user_id:不存在 → `Ok(None)`;存在 → `Err(DataChainError::LastAdminProtected)`。
- 目标已是停用状态:条件为真,UPDATE 命中 1 行,保持幂等成功。
- 新增 `DataChainError::LastAdminProtected`,Display `cannot deactivate the last active admin`。⚠核对:全仓库对 `DataChainError` 的穷尽 `match`。
- `AuthService::deactivate_user_by`:先判自停用(`SelfDeactivation`,不变)。捕获 `LastAdminProtected` 时写审计 `user_deactivate_denied`(result `denied`,user=目标,actor,reason `last active admin`)后原样返回。
- HTTP:`admin_error` 增加 `LastAdminProtected` → 409 `cannot deactivate the last active admin`。CLI:`Err` → 非 0 退出码。
- ⚠核对:`users.role` 存的是 `Role::to_string()` 小写 `admin`。

### B8 解锁入口
Storage:
```rust
pub struct UnlockOutcome { pub locks_cleared: u64, pub counters_cleared: u64 }
// 单事务:对每个 key 依次 DELETE login_lockouts 与 login_rate_counters
pub async fn clear_login_keys(&self, keys: &[String]) -> Result<UnlockOutcome>;
```
Service:
```rust
// 目标不在内存用户表 => UserNotFound。key 与 login/change_password 共用同一构造函数:
//   user:<normalize_username_key(username)>   pwchg:<user_id>
pub async fn unlock_user(&self, actor: Option<&str>, target_user_id: &str, ctx: &LoginContext)
    -> Result<UnlockOutcome>;
```
- 把现有 `format!("user:{}", normalize_username_key(..))` 与 `format!("pwchg:{}", ..)` 抽成两个私有函数,login、change_password、unlock 共用。
- 审计:`login_unlocked`(result success,user=目标,actor,reason `cleared locks=N counters=M`)。无锁时也写。
- CLI:`user unlock <username>`;未知用户非 0 退出码;成功打印是否清除了锁记录。
- HTTP:`POST /api/v1/admin/users/:user_id/unlock`(`routes.rs` 加路由,`handlers.rs` 加 `admin_unlock_user`,handler 内 `admin_denied(.., UserStatusAdmin)` 二次断言)。
  - 200 `{"success":true,"data":{"user_id":"..","unlocked":<bool>}}`,`unlocked` 表示清除了锁记录。
  - 404 `user not found`、403、401、500 `internal error`。
- 中间件:`required_permission` 的 admin 分支加 `(Some("unlock"), &Method::POST) => UserStatusAdmin`。
- 不清除 IP 维度计数。

## 4. 接口契约汇总
| 接口 | 成功 | 错误 |
|---|---|---|
| `POST /api/v1/auth/register`(行为变更) | 201(同前) | 新增 400 `password too short` / `password too long` / `password contains invalid characters` |
| `POST /api/v1/admin/users/:user_id/unlock`(新) | 200 `{"user_id","unlocked"}` | 401、403、404 `user not found`、500 `internal error` |
| `POST /api/v1/admin/users/:user_id/deactivate`(行为变更) | 200(同前) | 新增 409 `cannot deactivate the last active admin`;自停用 409 `cannot deactivate yourself` 仍先判定 |
| CLI `user passwd <username>`(新,stdin 读密码) | 0 | 非 0:用户不存在、策略拒绝、读 stdin 失败 |
| CLI `user unlock <username>`(新) | 0 | 非 0:用户不存在 |
| CLI `user create`(行为变更) | 0 | 非 0:策略拒绝、UserExists |
| CLI `user deactivate`(行为变更) | 0 | 非 0:最后管理员 |

新增审计事件:`login_unlocked`、`password_reset`、`user_deactivate_denied`。事件均不得含密码、哈希、token。

## 5. 迁移
**无迁移。** 下一迁移号 014 保留不用,迁移登记仍为 001-013。`login_rate_counters.locked_until` 死列继续保留。

## 6. 兼容性与破坏性变更
- 🔺 HTTP 注册与 CLI `user create` 开始校验密码策略,短密码(< `auth.password_min_length`,默认 8)被拒。现有用户不受影响。
- 🔺 CLI `user create` 失败(含用户已存在)退出码由 0 变非 0。
- 🔺 停用最后一名活跃管理员(API 与 CLI)被拒,返回 409 / 非 0。
- 🔺 `DataChainError` 新增变体 `LastAdminProtected`,对穷尽 `match` 的下游源码级不兼容。
- 🔺 `login` 以 SQLite 哈希为准:只改内存、不落库的哈希(仅测试可能这么做)不再生效。
- ✅ 不变:同步 `register`/`register_with_role`、`Storage::deactivate_user_and_revoke_sessions` 签名、`AuthService::deactivate_user`/`activate_user`、`LoginLimits`、`AuthSettings`、`AppState`、迁移 001-013、全部既有错误词表。
- 新增依赖:无。

## 7. 并发与安全分析
- **解锁**:只删行,不改计数语义。解锁与在途登录并发时,最坏是该请求在删除前已计数、删除后用户重新累计,无安全后果。每次解锁必审计。
- **最后管理员保护**:判定与更新是同一条 SQL。SQLite 单写者,两个管理员并发互停必有一个看到另一个已停用而被拒。
- **bcrypt**:验密不再占用 runtime 工作线程。`spawn_blocking` 池默认上限 512,在限速兜底下可接受。密码字符串被移动进闭包,不写日志。
- **枚举与时序**:`login` 对未知用户仍做同 cost 的 bcrypt(dummy)。`unlock_user` 对未知用户返回 404,仅管理员可见。
- **CLI passwd 与会话**:改密同事务撤销全部会话。`login` 读库哈希后,服务立即拒绝旧密码。
- **注册并发同名**:持三把写锁复检,消除覆盖索引与回滚误删。
- **stdin 密码**:不进 argv、不进审计、不进错误输出。缓冲区本批不做 zeroize,登记为已知限制。
- **已知限制(沿用)**:登录与改密/重置并发时,撤销之后才落库的新会话可能存活(B-6);无 `sid` 旧 token;CLI 创建的用户在运行中的服务内存里不存在,服务需重启后才能让其登录(既有限制)。

## 8. 串行 TDD 切片 C1..C7
通用约束:developer 只能用文件工具写测试与实现,**命令由 orchestrator 在验证机跑**(`bash /d/workbench/kiro/.task-logs/fu-run.sh`)。每片:developer 先只提交测试 → orchestrator `submit <名> --test <目标>` 观察 Red → developer 写最小实现 → 重跑为 Green → 下一片。C7 后跑全量。CLI 测试沿用 `tests/cli_user_status.rs` 的 `run_cli`(真实二进制 + 同 DSN),并加带 stdin 的变体。每个用例只建一次 `build_state`(同 DSN 重复建会重复写创世块)。限速相关用例固定存储时钟:取真实当前时间向下对齐到 900 的整数倍再 +10 秒,不要用固定未来时间(会话过期按真实时钟判断)。

### C1 B9 bcrypt 异步化(`tests/bcrypt_async.rs`)
- **公开 seam**:HTTP router `oneshot`,`#[tokio::test]`(默认 current_thread 运行时)。
- **Red**:同一运行时并发启动每 5ms `sleep` 一次的 ticker 任务,与一次 `/api/v1/auth/login`(正确密码)`join!`。断言登录期间 ticker 至少 tick 3 次。同样覆盖 `/api/v1/auth/password` 与不存在用户登录。
- **Green 范围**:`hash_password_blocking`/`verify_password_blocking`,改 `login`、`change_password`、dummy 初始化;不动 `register`(C3 处理)。
- **回归**:`login_rate_limit`、`login_lockout`、`change_password`、`auth_audit`、`auth_internal_errors` 不变。
- 注意:若判定偶发,阈值改为"登录期间最大 tick 间隔 < 登录总耗时的一半"。

### C2 B11a login 读 SQLite 哈希(`tests/login_sqlite_hash.rs`)
- **公开 seam**:HTTP login + 公开的 Storage 方法直接改库(模拟另一进程,内存哈希保持旧值)。
- **Red**:种子用户 alice → 用 `bcrypt` 生成新哈希写库 → 新密码登录应 200、旧密码应 401。库中删除该用户行后登录 401 且审计 reason `unknown user`;既有 `login_*` 测试通过。
- **Green 范围**:`login` 取 `get_user_password_hash`,经 `verify_password_blocking`。

### C3 B12 注册与 CLI 创建密码策略(`tests/password_policy_registration.rs`)
- **公开 seam**:HTTP `/api/v1/auth/register`;CLI `user create`(真实二进制)。
- **Red**:7 字符 → 400 `password too short`,之后登录 401,库里无该用户;73 字节 → 400 `password too long`;含 NUL → 400 `password contains invalid characters`;8 字符 → 201 且可登录;`auth.password_min_length` 经 `AuthSettings` 生效;CLI 创建短密码退出码非 0 且库里无该用户;CLI 创建重复用户名非 0;CLI 创建合法用户 0 且可登录。并发同名:同一用户名 8 个并发 `register`,恰好 1 个 201,其余 400,成功的用户仍可登录。
- **Green 范围**:`register_validated`、handler 的 `PasswordRejected` 分支、CLI create 改调并返回 `Err`。
- **既有测试需改**:⚠核对 `tests/api_integration.rs` 等所有 `/auth/register` 请求,密码 < 8 字符的测试数据改成 ≥ 8 字符。

### C4 B11b CLI passwd(`tests/cli_passwd.rs`)
- **公开 seam**:真实二进制 `user passwd alice`,stdin 管道写入新密码;HTTP 登录/鉴权观察效果。
- **Red**:alice 有两个会话 → CLI 改密成功退出 0 → 旧密码登录 401、新密码 200 → 旧 access/refresh 均 401 → 审计含 `password_reset`,actor 为空,审计与 CLI 输出不含新旧密码。失败路径:新密码过短 → 非 0、哈希未变;未知用户 → 非 0 且信息含用户名;stdin 为空 → 非 0。`\r\n` 结尾去掉换行;密码前后空格保留。
- **Green 范围**:`Storage::set_user_password_and_revoke_all_sessions`、`AuthService::reset_password`、CLI `Passwd` 子命令。

### C5 B10 最后管理员保护(`tests/last_admin.rs`)
- **公开 seam**:`AuthService::deactivate_user_by`、HTTP admin 接口、CLI `user deactivate`。
- **Red**:仅 1 个活跃管理员:CLI 停用 → 非 0,`is_user_active` 仍 true,审计 `user_deactivate_denied`(reason `last active admin`)。2 个管理员 A、B:A 停用 B → 200;A 停用 A → 409 `cannot deactivate yourself`;CLI 停用 A → 非 0;重复停用已停用的 B → 200 幂等。第三方:另一管理员 C 经 HTTP 停用唯一剩余活跃管理员 → 409 `cannot deactivate the last active admin`。并发:`tokio::join!(deactivate_user_by(Some(A),B), deactivate_user_by(Some(B),A))` 重复 10 轮(每轮新建用户),每轮恰好一个 Ok、一个 `LastAdminProtected`,最终活跃管理员恰为 1。非管理员停用不受影响;`activate` 不受限。
- **Green 范围**:条件 UPDATE 与同事务区分、`LastAdminProtected` 变体、service 审计、handler/CLI 映射。
- **既有测试需核对**:`tests/admin_api.rs`(root/root2)中"允许管理员互停"类用例的前提。

### C6 B8a 解锁:storage、service、CLI(`tests/unlock.rs`)
- **公开 seam**:HTTP login/change-password 触发锁定(可注入时钟),真实二进制 `user unlock alice`。
- **Red**:alice 失败触发锁定(429 + Retry-After 900)→ 锁内正确密码也 429 → CLI unlock 退出 0 → 正确密码立即 200。再次触发锁定 Retry-After 为 900(级别已归零)。大小写变体(`ALICE`)的锁同样被 `unlock alice` 清除。`pwchg:` 锁:unlock 后改密可再次进行。unlock 不影响他人。unlock 不清 IP 维度。审计含 `login_unlocked`(actor 空)。未知用户 → 非 0 且含用户名。
- **Green 范围**:`Storage::clear_login_keys`、两个 key 构造函数、`AuthService::unlock_user`、CLI `Unlock` 子命令。

### C7 B8b 管理员 HTTP 解锁(`tests/unlock.rs` 追加)
- **公开 seam**:HTTP `POST /api/v1/admin/users/:user_id/unlock`。
- **Red**:管理员 200,`data.unlocked` 为 true,目标可登录;无锁时 200 且 `unlocked` false;重复调用 200;审计 `login_unlocked` 带 actor;未知用户 404 `user not found`;User/Auditor/Guest 403;无 token 401;其他方法不被误授权;`/api/v1/admin/users/x/unknown` 仍 fail-closed。
- **Green 范围**:路由、`admin_unlock_user`(含二次断言)、`required_permission` 的 unlock 映射。
- **既有测试需核对**:⚠`tests/admin_api.rs` 是否把 `/unlock` 当作"未实现路径"示例,若是改成其他路径。
- 收尾:全量验证,然后 scribe 同步文档。

## 9. 最终验证
- 每片:`fu-run.sh submit <名> --test <目标>`(Red、Green 各一次)。
- 收尾:`fu-run.sh verify`。通过标准:fmt rc=0;全部目标 0 failed,总数 ≥ 357 + 新增;clippy lib ≤ 22 条;迁移仍 001-013。

## 10. QA / Reviewer 验证点
- 并发:条件 UPDATE 为单语句;并发互停恰一成功;注册并发同名恰一成功且索引不被破坏;解锁与登录并发无死锁。
- bcrypt:`login`/`change_password`/`reset_password`/`register_validated` 内不再有同步 `hash_password`/`verify_password` 调用;dummy 初始化在 blocking 闭包内;错误文本不含密码。
- SQLite 哈希:`login` 不读内存 `password_hash`;库中无该用户按未知用户处理。
- 密码泄露:审计表、CLI 输出、日志、HTTP 响应不含新旧密码或哈希;`audit_table_never_contains_secrets` 扩展覆盖三类新事件。
- 权限:unlock 路由 RBAC 矩阵;handler 内二次断言;admin 前缀其他路径仍 fail-closed。
- key 一致性:unlock 与 login、change_password 使用同一 key 构造函数;大小写变体覆盖。
- 兼容:同步 `register*` 签名未变;`deactivate_user_and_revoke_sessions` 签名未变;迁移无新增;`DataChainError` 新变体已核对所有穷尽 match。
- CLI:`create` 失败退出码非 0;`passwd` 读 stdin 一行、保留前后空格、去掉行尾换行;未知用户信息含用户名且转义。
- 已知限制仍登记:B-6、无 `sid` 旧 token、CLI 创建的用户需重启服务才能登录、stdin 密码缓冲未 zeroize。
