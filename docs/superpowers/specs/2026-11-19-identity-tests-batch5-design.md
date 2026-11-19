# 身份交易第五批:测试补全与 Idempotency-Key 长度上限(B17-B19)

> 来源:IMPLEMENTATION_STATUS §2.3.1 登记的已知限制 (c) 与"无测试覆盖"项。基线 main `8b5f4ac`:419 passed,clippy lib 22,迁移 001-013。**无迁移**。

## 范围
| 编号 | 项 | 类型 |
|---|---|---|
| B17 | `POST /api/v1/identity/key-transaction` 的 `Idempotency-Key` 增加长度上限 | 行为变更(TDD Red→Green) |
| B18 | 补直接测试:`transaction_id` 不进入区块 JSON、Merkle 根与签名负载 | 特征测试(现有行为,应直接通过) |
| B19 | 补直接测试:CLI `chain mine` 对 `legacy_unverified` pending 身份交易 fail-closed | 特征测试(现有行为,应直接通过) |

## 决策
- **B17**:键经 trim 后若 UTF-8 字节数 > **255** → HTTP 400 `{"success":false,"error":"idempotency key too long"}`;检查发生在取 `identity_tx_gate`、写账本之前,超长请求不落账本也不入队。恰好 255 字节合法。空白/非 UTF-8 仍视为未提供(行为不变)。指纹算法维持现状:指纹只覆盖进入签名的 5 个字段是有意设计(`timestamp` 由服务端盖章,`signature` 对同一 payload 唯一)。
  - 被否决:截断长键(不同键会碰撞);改存哈希(要改表结构,无必要);上限 128(部分客户端用 UUID 加前缀可能更长)。
- **B18/B19**:特征测试,不改 src/。若测试暴露实现与文档描述不符,按 systematic-debugging 记录并回报,不擅自改实现。
- **推迟**:`identity_tx_gate` 串行化的直接测试(无确定性公开 seam,只能靠并发统计,易偶发);`legacy_unverified` 内置恢复命令(需单独设计);`signing_payload` v2 分隔方案(协议变更)。

## 兼容性
- 🔺 超长(>255 字节)`Idempotency-Key` 由接受改为 400。无迁移,无新依赖。

## 切片
- **C1 B17** `tests/identity_idempotency_key_limit.rs`(Red→Green)。
- **C2 B18** `tests/identity_transaction_id_not_in_block.rs`(特征测试)。
- **C3 B19** `tests/cli_mine_legacy_pending.rs`(特征测试)。
