# 认证加固第四批设计(B13-B16)与实施计划(C1-C4)

> 来源:orchestrator 依据第三批 review 的建议项(S-2/S-3/S-4/I-2)整理。基线 main `f0a8669`,分支 `feat/auth-hardening-4`。
> 基线验证:402 passed,clippy lib 22 条,迁移 001-013。**无迁移**。范围小,不另请 architect。
> 默认取舍由 orchestrator 按推荐值决定,用户可推翻。

## 范围
| 编号 | 项 | 来源 |
|---|---|---|
| B13 | `POST /api/v1/auth/register` 按客户端 IP 限速 | review S-2 |
| B14 | CLI `user create` 的 `--role` 解析失败即报错(不再静默建普通用户) | review S-4 |
| B15 | unlock 对"库里有、内存无"的用户可用 | review I-2 |
| B16 | CLI `user passwd` 超长/非 UTF-8 输入的错误信息统一 | review S-3 |

## 决策
- **B13**:复用登录限速的 IP 维度参数(`login_ip_max_attempts`、`login_window_secs`),key 为 `reg:<ip_hash>`,与 `ip:`(登录)和 `user:`/`pwchg:` 互不影响。**注册请求不论成败都计数且不归还名额**(防止批量注册);超限 HTTP 429 + `Retry-After`,体 `{"success":false,"error":"too many attempts"}`;限速在策略校验与 bcrypt 之前(超限不耗 CPU)。不新增配置项,不触发指数退避锁定(只用固定窗口计数,不写 `login_lockouts`)。被拒写审计 `register_rate_limited`(denied,reason `rate limit exceeded`,带 ip_hash)。无对端地址时 IP 维度用占位 `unknown`(与登录一致)。CLI `user create` 不受限。
  - 被否决:新增 `[auth] register_ip_max_attempts` 配置(YAGNI);引入 Semaphore(只缓解不限速);成功后归还名额(允许批量注册)。
- **B14**:`role.parse()` 失败返回 `Err`(错误文本含"无效角色"与允许值,不含密码),退出码非 0;缺省 `user` 不变。
- **B15**:新增 `Storage::get_username(user_id) -> Result<Option<String>>`;`unlock_user` 在内存无该用户时回退读库取用户名构造 key,库里也没有才 `UserNotFound`。
- **B16**:CLI `passwd` 读 stdin 改按字节读(最多 1025 字节):超过 1024 字节无换行 → 错误 `password too long`;非 UTF-8 → 错误 `未从 stdin 读取到有效的 UTF-8 密码`;其余行为不变。错误文本不含密码。

## 兼容性
- 🔺 `register` 新增 429;🔺 CLI `create` 对非法 `--role` 由静默降级改为失败(退出码非 0)。
- 新增审计事件 `register_rate_limited`。无迁移,无新依赖。

## 切片(串行 TDD,developer 只用文件工具,命令由 orchestrator 跑)
- **C1 B14** `tests/cli_create_role.rs`:`--role admin` 建管理员成功;`--role adm1n` 非 0 且库里无该用户;缺省为 user;大小写按现有 `Role::from_str` 行为(先读实现,不改它)。
- **C2 B16** 追加到 `tests/cli_passwd.rs` 之外的新文件 `tests/cli_passwd_input.rs`:>1024 字节无换行 → 非 0 且输出含 `too long`;非 UTF-8 字节 → 非 0 且输出含 UTF-8 提示;输出不含密码。
- **C3 B15** `tests/unlock_db_only_user.rs`:用独立连接/`Storage::save_user` 直接写库一个内存没有的用户并制造其锁行(经 `lock_login_key` 或 SQL),HTTP 与 CLI(CLI 本就读库)unlock 均成功;库里也没有 → 404。
- **C4 B13** `tests/register_rate_limit.rs`:固定存储时钟(真实时间对齐窗口 +10 秒);`ip_max_attempts=2` 时第 3 次注册 429 + Retry-After;失败注册(短密码)也计数;不同 IP(ConnectInfo)互不影响;登录的 IP 计数不受注册影响;审计 `register_rate_limited`;CLI create 不受限。
- 收尾:全量验证 → reviewer → 文档(含修正 IMPLEMENTATION_STATUS 过时的"第三批候选"段落)→ 合并 main。
