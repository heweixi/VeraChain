# 跨链认证网与可验证语义目录

> 最后核实:2026-10-18，对应代码提交 `d97cd94`。
> 本文描述已确认的认证网方向与当前实现边界。多外链批次认证、外链阶段回写、失信切换、封存重启仍未实现，见文末路线图。

## 设计基调

DataChain 是受信节点维护的数据追溯链，**有意不在内部实现拜占庭去中心化共识**。
本链负责生成、保存、追溯和验证记录；关键数据与身份状态将逐步锚定到多个可信外部认证链，借外链的公开时间戳和不可篡改性提供去中心化背书。

其他链向本链登记认证信息时，走本链正常的记录、验证和区块生成流程，不需要特殊接收协议。

## 已实现：可验证语义目录

### 统一对象关系

```text
Subject（长期逻辑对象）
  └─ Revision（不可变内容版本）
       └─ Artifact（构建或配置变体）

Claim（认证声明）可指向 Subject、Revision 或 Artifact。
```

| 类型 | 用途 | 关键内容 |
|---|---|---|
| Subject | 文章、代码库、软件包或其他长期跟踪对象 | 稳定标识、对象类型、显示名称、来源引用 |
| Revision | 对象的一次不可变内容状态 | 内容哈希、父版本、来源版本引用 |
| Artifact | 同一版本的构建/配置变体 | 构建产物哈希、配置哈希、平台 |
| Claim | 有来源的认证/风险/支持结论 | 分类、状态、证据、认证者身份与公钥、时间范围、覆盖关系 |

Claim 分类采用可扩展命名空间约定，例如：

```text
support.lts
support.mainline
quality.verified
quality.trusted
lifecycle.deprecated
risk.vulnerability
risk.malware
risk.dangerous
```

Claim 不是永久标签。它记录“谁在何时依据什么证据，对哪个对象作出什么结论”。后续修正、撤销或新结论通过新的 Claim 追加，并用 `supersedes_claim_id` 建立覆盖关系，历史不被删除。

### 语义完整性承诺

旧 metadata 的 Merkle 叶子只承诺 `data_id`。新目录记录采用固定字段顺序和长度前缀的规范化语义负载：

```text
catalog-v1 + 记录类型 + 签发身份 + 签发公钥 + 全部业务字段
```

认证者用已登记的 ed25519 公钥签名该负载。记录进入新区块时，其语义哈希作为 Merkle 叶子，与元数据和密钥交易一起受区块哈希与 PoW 保护。

这使后续外链锚定能够证明完整的版本、构建物和 Claim 语义，而非只证明某个 `data_id` 存在。

### 当前提交与查询流程

```text
已上链有效身份公钥
  → 签名 Subject / Revision / Artifact / Claim
  → 记录进入持久化待打包队列
  → 正常挖矿进入 block.catalog_records
  → 语义叶子进入 merkle_root
  → 同事务写入查询投影
  → 按对象、版本、构建物和 Claim 查询
```

提交时会校验：

- 签名数学有效；
- 签发公钥是当前有效的链上身份；
- Subject、Revision、Artifact、Claim 的稳定主标识不重复；
- Revision 引用的 Subject、Artifact 引用的 Revision、Claim 引用的目标对象均存在；
- Claim 有至少一个作用目标、证据引用和合法生效时间范围。

## 已实现 API

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/v1/catalog/records` | 提交已签名的 Subject、Revision、Artifact 或 Claim，进入待打包队列 |
| GET | `/api/v1/catalog/subjects/:subject_id` | 查询逻辑对象登记记录 |
| GET | `/api/v1/catalog/subjects/:subject_id/revisions` | 查询对象的已上链版本历史 |
| GET | `/api/v1/catalog/revisions/:revision_id/artifacts` | 查询版本的构建/配置变体 |
| GET | `/api/v1/catalog/subjects/:subject_id/claims` | 查询对象的全部 Claim 历史 |

提交需要 `BlockMine` 权限，查询需要 `BlockRead` 权限。

## 当前边界与未实现项

- Claim 查询当前返回完整历史，尚未实现按“认证者信任策略、有效时间、撤销/覆盖链”计算单一当前结论的 resolver。
- Claim 分类是命名空间约定，尚未实现集中分类字典、认证者角色治理或不同认证机构的信任权重策略。
- Subject / Revision / Artifact 的稳定标识由提交方提供；当前不做全局命名注册或跨链名称冲突裁决。
- 目录记录已持久化到 pending 队列并可随服务重启恢复；投影是查询加速副本，区块中的 `catalog_records` 才是权威事实。
- 现有 legacy metadata 继续以 `data_id` 承诺，历史区块不重写；新的目录记录从 `catalog-v1` 开始具备完整语义承诺。
- 当前跨链锚定仍是单条 `data_id`、单外链的 R5 模式；目录记录和身份快照尚未进入外链认证批次。

## 后续路线图

1. **L2：批次认证与多外链投递**
   - 覆盖上一次最终认证后产生的新区块；
   - 按区块完整性摘要聚合批次根；
   - 覆盖目录语义记录与身份快照；
   - 多个 HTTP connector 并行投递，互不阻塞本链出块。
2. **L3：外链阶段回写**
   - 将 initiated、submitted、finalized、failed 等语义阶段作为专门锚定事件写入后续区块；
   - 回写事件引用此前本链认证批次记录和外链交易引用。
3. **L4：外链健康与失信切换**
   - 运行故障自动降级；
   - 信任失效由管理员人工停用；
   - 历史外链回执永久保留。
4. **L5：人工封存与新链启用**
   - 封存旧链、保留旧链终态摘要和外链认证历史；
   - 创建新的初始管理密钥；
   - 将旧链摘要作为新链初始认证记录，确保认证历史可追溯而不丢失。
