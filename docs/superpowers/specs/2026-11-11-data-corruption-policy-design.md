# 数据损坏处置策略:设计与实施计划 (F1-F8 + F12)

> 来源:architect 产出(auto),orchestrator 落盘。代码事实基于 orchestrator 清单,实现者须核实标注"待核实"的项。
> 基线:`feat/data-corruption-policy` 基于 `fix/chain-integrity-validation`(96d08e8)。

## 1. 核心策略
| 类别 | 对象 | 策略 |
|---|---|---|
| 权威源 | blocks、users、versions、refresh 撤销、pending metadata、pending catalog、anchor_outbox | fail-closed:返回结构化 `DataCorruption`,启动中止,CLI 非零;不跳过、不 quarantine、不用默认值替代 |
| 可重建投影 | aggregations、metadata、catalog_subjects/revisions/artifacts/claims | 启动检测;仅在区块校验通过后,单事务内从区块重建;日志含计数 |

被否决:复用 StorageError(String)(无结构/无主键);把 catalog `DO NOTHING` 改 `DO UPDATE`(改变增量写语义);pending/outbox quarantine(会静默丢未落链意图);各 CLI 命令自行 load_blocks(现状不校验);直接 `e.to_string()` 作 reason(serde_json 错误可能回显值内容,泄露 password_hash);保持现有"去重→回填→读 users"启动顺序(发现 users 损坏前已改库)。

## 2. 文件级影响面
修改:`src/error.rs`(新增 `DataCorruption{category,table,key,reason}`、`CorruptionCategory{Authoritative,Rebuildable}`,Display 固定 `data corruption [authoritative] table=users key=<id>: <reason>`);`src/storage/database.rs`(get_all_blocks/get_block/get_all_users/get_all_versions/refresh 撤销/pending metadata/pending catalog/anchor_outbox 读取带主键;抽出 `project_block_tx(tx,&Block)` 由 commit_block 与重建共用;新增 `rebuild_projections`/`ensure_projections`/`integrity_report`;`metadata_projection_count().unwrap_or(-1)` 改传播错误);`src/crosschain.rs:43` parse_status 改返回 Result,未知值报 `DataCorruption{anchor_outbox,<anchor_id>,unknown_status}`;`src/cli/server.rs`(启动时序重排);`src/api/handlers.rs:338` /chain/validate 增可选字段;`src/cli/chain.rs`(Validate 退出码;Mine 补投影);`src/cli/metadata.rs`、`aggregate.rs`、`status.rs` 改用 `load_verified_chain`;CLI 入口统一 `DataChainError→ExitCode`。
新增:`src/cli/common.rs`(待核实合适位置):`load_verified_chain`、`exit_code_for`;S6 可选 `src/cli/storage.rs`;测试 `tests/data_corruption_*.rs`、`tests/common/corrupt.rs`。
不改:migrations 001~006 不新增;`validate_chain`/`validate_loaded_blocks` 规则不动。

## 3. 错误契约
`DataCorruption{category,table,key:Option<String>,reason}`;blocks 的 key 用区块索引,其余用主键,主键不可解析用 rowid。reason 只用固定词表:`json_syntax line=L col=C`、`json_data`、`json_eof`、`unknown_status`、`missing_field`、`count_mismatch expected=N actual=M`;JSON 错误只取 `serde_json::Error::classify()`+`line()/column()`。禁止输出行内容、password_hash、secret、token、JSON 片段。users 的 key 用 user_id,不用 email/用户名(待核实主键列)。
CLI 退出码:0 成功;1 其他错误;2 链校验失败(valid=false);3 数据损坏。破坏性:`chain validate` 原恒 0。stderr 一行 `data corruption [..] table=.. key=..: ..`。
HTTP `/chain/validate`:`{valid,block_count}` 不变,新增可选 `corruption{category,table,key,reason}` 与 `invalid_block`,仅非空时出现;状态码保持 200+valid:false;其他业务端点遇 DataCorruption 返回 500,body 仅 `{"error":"data_corruption","table":..}`。

## 4. catalog 兼容性
不改 commit_block 冲突语义(catalog 首写者胜 DO NOTHING;metadata 后写者胜 DO UPDATE)。重建用"事务内清表→按区块高度升序逐块 `project_block_tx`→提交",失败整体回滚。**前置核实**:aggregations 是否纯由区块导出;若含非区块来源,须移出可重建投影改 fail-closed。

## 5. 启动时序
1 打开 DB+migrations → 2 get_all_blocks 严格解析 → 3 validate_loaded_blocks → 4 权威源只读扫描(users→versions→refresh 撤销→pending metadata→pending catalog→anchor_outbox,任一失败即 fail-closed)→ 5 此前无任何写 → 6 pending 去重(现有)→ 7 `ensure_projections(&blocks)`(解析失败或数量不一致即重建;日志 `event=projection_rebuild tables=[..] reason=parse_error|count_mismatch rows_before rows_after blocks`,不含行内容)→ 8 继续启动。重建仅在第 3 步通过后执行。

## 6. 日志与脱敏
统一字段 event/category/table/key/reason/count。测试:损坏 users 行含 `password_hash="SECRET-XYZ"`,断言错误字符串、Debug、日志、HTTP body 均不含该值。

## 7. Mine 与 p2p 的 save_block
保留 save_block 低层接口;CLI Mine 与 p2p 导入同事务追加 `project_block_tx`(或退而调用 commit_block,待核实参数);兜底:下次启动数量不一致检测会重建。p2p 位置待核实,改动面大则本期只做兜底并文档注明。

## 8. F9 (S6,可裁剪)
`storage check`(只读)与 `storage rebuild-projections`(须服务停止;链无效拒绝);退出码沿用 0/2/3。

## 9. 与 legacy_unverified(5b2ad61)
不依赖;对接点仅 `load_verified_chain` 与启动第 3 步;合并时对齐 legacy 区块是否参与重建、是否在 /chain/validate 报告;默认保守。

## 10. 兼容性
无 schema 迁移;破坏性:chain validate 退出码、启动在坏数据上明确失败;加性:HTTP 可选字段、新错误变体(grep 穷举 match 补分支)。

---

## 实施计划(垂直切片,TDD:先 Red 再最小实现)
通用:损坏注入用测试 helper(独立连接直接改库,仅制造故障),断言只经公开入口;验证 247 docker `rust:latest`(`~/rust-verify-async.sh datachain-rust test -- <过滤>`,`~/rust-verify-status.sh`,缓存卷勿删,磁盘问题如实记"未验证")。顺序:S1→S2→S3→S4;S5 依赖 S1、S3;S6 依赖 S2、S3、S5。

**S1 错误类型+blocks/users/versions 严格读取**:seam=`Storage::get_all_blocks/get_block/get_all_users/get_all_versions`;Red=损坏第 N 区块 JSON,断言 `DataCorruption{table:"blocks",key:Some("N")}`(当前为裸 serde/StorageError);users/versions 同理;脱敏断言;实现=error.rs 变体+`corruption_from_json` helper+四函数;文件=src/error.rs、src/storage/database.rs、tests/data_corruption_authoritative.rs、tests/common/corrupt.rs。
**S2 其余权威源+outbox 未知状态**:seam=`list_pending_anchors/get_anchor`+refresh 撤销/pending metadata/catalog 公开读取(名称待核实);Red=`status='bogus'` 断言 `DataCorruption{anchor_outbox,unknown_status}`(当前被当 Pending);其他坏 JSON 带主键;实现=parse_status→Result+统一 helper;依赖 S1。
**S3 投影检测与重建**:seam=`Storage::ensure_projections(&blocks)->Result<ProjectionReport>`+公开读取验证;Red=破坏 aggregations 行/catalog 行/删 metadata 行,重建后等于原值;区块无效返回 Err 且不改投影;`metadata_projection_count` 出错不再 -1;实现=`project_block_tx`(commit_block 改调用,原测试保持绿)+检测(解析+数量)+事务清表重放;文件=database.rs、tests/data_corruption_projection.rs;依赖 S1。
**S4 启动时序+HTTP**:seam=server 启动入口(待核实)+router `/chain/validate`;Red=损坏 users 行→启动返回含 table=users 的 DataCorruption 且去重/回填未执行;损坏 aggregations→启动成功且已修复;/chain/validate 正常字段不变、损坏含 corruption 对象且不含敏感;实现=按第 5 节重排+handlers 可选字段+DataCorruption→500;文件=src/cli/server.rs、src/api/handlers.rs、tests/data_corruption_startup.rs;依赖 S2、S3。
**S5 CLI 统一校验+退出码+Mine 投影**:seam=CLI 命令入口返回值/ExitCode(待核实);Red=损坏区块 `chain validate`→3,链无效→2,无效链上 metadata/aggregate/status 非零,Mine 后投影数量=区块推导;实现=load_verified_chain、exit_code_for、四命令切换、Mine 同事务 project_block_tx;文件=src/cli/{chain,metadata,aggregate,status,common}.rs、src/main.rs、tests/data_corruption_cli.rs;依赖 S1、S3。
**S6(可选)storage check/rebuild-projections**:Red=损坏库 check→3 并列表/key 且不改库;仅投影损坏 rebuild 后 check→0;链无效 rebuild 拒绝;文件=database.rs(integrity_report)、src/cli/storage.rs、cli/mod.rs、tests/data_corruption_storage_cmd.rs;依赖 S2、S3、S5。
**S7 文档(F12)**:更新 IMPLEMENTATION_STATUS 2.4 与"启动恢复/链验证"陈旧描述;README 退出码变更说明;验证证据如实。

## QA 验证点
每张权威表注入语法错误/缺字段/类型错误/未知 status→DataCorruption 表名主键正确;脱敏(错误串/Debug/日志/HTTP body);权威源损坏时去重与回填尚未执行(库未改);重建后投影与全程增量写入逐表一致(含重复 claim/artifact 首写者胜)、中途失败整体回滚、区块无效拒绝、重复重建幂等;commit_block 重构回归、validate 规则不变;CLI 退出码 0/2/3;HTTP 正常响应与旧版一致;Mine/p2p 后投影与区块一致或下次启动可重建。

## 风险与未验证
聚合是否纯区块导出(S3 前核实);database.rs 单文件多片修改须串行;退出码变更影响脚本;大链重建耗时(日志输出耗时,本期不分批);穷举 match 补分支;247 磁盘/同步导致无法验证须如实记"未验证";legacy_unverified 对齐成本。待核实:公开读取函数名、server 启动入口、CLI 测试方式、p2p 导入位置、commit_block 签名、`updated_at` 列、users 主键列、聚合数据来源。

## 默认决策(用户可否决)
1 chain validate 退出码 0→2(无效)/3(损坏);2 /chain/validate 损坏保持 200+valid:false,其他端点 500;3 S6 本期做(可裁剪最后一片)。
