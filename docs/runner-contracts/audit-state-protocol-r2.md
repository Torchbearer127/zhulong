# 审计状态协议 R2

## 目的与权威关系

审计工作区需要让本地 Agent 和人工审核员能检查已记录的流程状态，而不把自然语言、
静态扫描结果或手工修改的状态文件误当成权威事实。R2 固定以下关系：

~~~
audit-events.jsonl
  = 权威的追加式事件日志

stage-status.json
  = 可从事件日志重建的当前状态物化视图
~~~

stage-status.json 不是并列事实来源。手工编辑该文件不能覆盖事件日志，也不能构成
审计完成、漏洞确认、Docker 核验或确认漏洞包有效的证据。

本协议只描述工作流记录。即使一个 event 或 state view 的形状通过校验，也不表示：

- 漏洞有效或已确认；
- Docker 或 Docker Compose 复现成功；
- verified evidence、confirmed bundle 或 DOCX 通过校验；
- workspace 已通过 finalization gate。

## R2 文件与字段

R2 event 使用 assets/schemas/audit-event.schema.json，R2 state view 使用
assets/schemas/stage-status.schema.json。二者均使用 JSON Schema Draft 2020-12，
顶层和所有结构化子对象均拒绝未知字段。

R2 event 必须包含：

- schema_version=2、seq、run_id、ts；
- stage、event_type、event_name、from_status、to_status、reason_code；
- subjects、evidence_refs、next_actions、expected_state_revision、details。

P9.3 新写入还必须作为一个完整集合包含 `from_stage`、`transition_kind`、
`transition_policy_version=1`、`blocker` 与 `resume_step`。`from_stage` 只在新 journal
的首条 `start` event 中为 null；其余值由 writer 在工作区锁内从当前物化视图派生，调用方可用
`--from-stage` / `--from-status` 提供预期值，但只能被交叉检查，不能覆盖锁内事实。
`transition_kind` 的稳定值是 `start`、`observe`、`advance`、`pause`、`block`、`resume`、
`skip`、`return`、`reopen`、`complete`。

P9.4 后的新 R2 writer event 还必须携带非空 `plugin_version`，使后续 state 可只从
journal 重建。该字段在 schema 中保持可选只为接受 P9.1-P9.3 历史记录；恢复逻辑绝不从
当前安装的 Skill/plugin 版本反推历史值。

seq 从 1 开始。run_id、subjects 与 next_actions 的 ID 是可移植逻辑标识，不能使用
文件系统路径。ts 必须是以 Z 结束的 RFC 3339 UTC 时间戳。event_name 使用
lower-snake-case。

stage 的稳定值为 intake、recon、candidate_generation、triage、verification、
severity_escalation、variant_discovery、packaging、finalization、recording。
status 的稳定值为 running、paused、blocked、completed。

event_type 的稳定值为 stage_transition、state_observation、checkpoint、recovery、
recording。skip、return、reopen 和 resume 是事件语义，不是新增状态值。

reason_code 使用有限的类别级枚举；具体说明放在 details.summary、可选的
details.reason_detail 和受限 details.metadata 中。next_actions 仅是可移植的恢复或
复核指导，使用 action_id、action_type、subject_ids、summary 和可选 evidence_refs；
它不携带可执行命令，也不是证据。

### 新 R2 事件的可移植文本边界

在锁内完成 schema 与 transition 校验后、追加 journal 前，canonical writer 会对所有新 R2
event 的可发布文本运行同一份分类器：`subjects[]`、`blocker`、`resume_step`、`details.summary`、
`details.reason_detail`、字符串型 `details.metadata[].value` 和
`next_actions[].summary`。本机绝对路径（含 Unix/macOS、Windows 盘符、UNC 与 `file:` URI）以及
常见 credential/private-key 形态会以 `EVENT_SENSITIVE_TEXT_FORBIDDEN` 拒绝；诊断只给出字段与
类别，绝不回显原值。拒绝发生在 journal append 之前，因此 journal 与 state view 的 bytes 都保持
不变。直接 writer API、CLI 和 stage finalizer 都经过这一个边界，不能各自绕过。

该规则只约束新写入。既有 journal 不会被重写、截断或“清洗”；后续只读消费者遇到历史不安全文本
必须 fail closed 并报告分类，而不是伪造修复后的历史。

evidence_refs 只能是规范化的 workspace-relative POSIX 路径。绝对路径、反斜杠、
父路径遍历、家目录、盘符和 URI/network reference 都会被拒绝。

prev_event_hash 可以作为可选的 SHA-256 完整性提示，但 R2 不生成或校验哈希链。

R2 state view 必须包含：

- schema_version=2、plugin=zhulong、plugin_version、run_id；
- state_revision、last_event_seq、event_log_digest；
- stage、status、last_event_at、last_event_type、last_event_name；
- blocker、resume_step。

event_log_digest 的格式为 sha256: 后接 64 位小写十六进制字符。它仅用于一致性提示，
不是密码学不可抵赖声明，也不替代日志、Docker 证据或 bundle validator。

当 status 为 blocked 或 paused 时，blocker 与 resume_step 必须为非空字符串；当
status 为 running 或 completed 时，二者必须为 null。R2 validator 与转换策略只检查记录
一致性，不把 event name 或 completed 状态解释为完成证明。

## P9.3 转换策略

`scripts/audit_transition_policy.py` 是唯一权威、版本化的转换策略表示；schema、文档和
selftest 只校验或说明它，不能另行定义 edge list。策略只处理 workflow history，不读取或
推断 candidate、verifier verdict、Docker evidence、disposition、confirmed bundle、recording
archive 或 finalization artifacts。

阶段内规则固定为：首条记录只能用 `start` 从 null 到 `intake/running`；同阶段的
`running -> running` 用 `observe`，`running -> paused` 用 `pause`，`running -> blocked`
用 `block`，`running -> completed` 用 `complete`，`paused/blocked -> running` 只能用
`resume`，`completed -> running` 只能用 `reopen`。`observe` 不得改变阶段或状态；
暂停/阻塞需要非空 `blocker` 与 `resume_step`，而 running/completed 不能残留这些字段。

策略支持非线性但保守的工作流：普通前进覆盖 intake、recon、candidate_generation、triage、
verification、severity_escalation、variant_discovery、packaging、finalization 与可选
recording；return 仅能回到策略明确列出的较早或独立复核阶段，variant discovery 可返回
verification。recording 仅可从 completed 的 finalization 前进或跳过。精确的前进、返回与
可选阶段集合以 `audit_transition_policy.py` 为准；这里的叙述不是第二个权威图。

`resume`、`skip`、`return`、`reopen` 都必须有与 intent 匹配的非默认 `reason_code`、
非空 `details.reason_detail`、至少一个可移植 `subject`、至少一个 workspace-relative
`evidence_ref` 和至少一个结构化 `next_action`。例如，恢复 Docker blocker 的 `resume`
应提供新可用前提的证据；`skip` 仅适用于 not_applicable 或 scope_change 的可选阶段；
`return` 应说明验证失败、缺失前提、范围变化或人工复核；`reopen` 应说明新事实、验证失败
或恢复请求。`normal_progress` 不能满足这些四类 intent。

拒绝示例包括：用 `observe` 或 `advance` 将 paused/blocked 变成 running、completed 后
未用 `reopen` 回到 running、从 running/completed 调用 `resume`、从非 completed 调用
`reopen`、将后退动作标为 `advance`、以 `skip` 跨越 verification/packaging/finalization
等必经事实门，以及 `from_stage`/`from_status` 与锁内当前状态不一致。拒绝会返回稳定 issue
code，且不追加 journal 或替换 state view。

为了让无状态变化的 helper 在任意当前 R2 阶段记录观察，writer 对 `observe` 提供受限的
`--stage current --status current` 简写。它不是 event-name 推断：writer 在同一把锁内将其
展开为实际的 stage/status 并写入完整 event；其他跨阶段 intent 不可用该简写。

### 旧 R2 前缀与 R1

P9.3 前的 schema-valid R2 records 没有上述完整 metadata 集合，仍保持可读且在 JSONL
校验输出中显式标为 `pre_policy_r2`。若后面追加 P9.3 event，分类为
`pre_policy_r2_prefix_then_transition_policy_v1`；策略从已接受旧前缀最后一个物化
stage/status 开始，不回填、重写或伪造旧 event 的 intent。P9.4 的 inspector 会保留该
分类并据此判断字段来源。R1 继续以 `legacy_r1` 读写，绝不伪装成已通过 R2/P9.3
转换验证。

## 只读校验与 R1 兼容

使用 scripts/validate_audit_protocol.py 进行只读检查：

~~~
python3 scripts/validate_audit_protocol.py --event path/to/event.json
python3 scripts/validate_audit_protocol.py --events-jsonl path/to/audit-events.jsonl
python3 scripts/validate_audit_protocol.py --state path/to/stage-status.json
~~~

三个输入选项互斥。可选 --json 输出以稳定字段报告 ok、input_kind、mode 和
record_count 和 transition_policy。JSONL 会跳过空行，并对每一条非空记录检查 JSON、对象
形状和 R2 序号；重复或倒序 seq 会报告对应行号。对 R2 journal，它还会报告
`pre_policy_r2`、`transition_policy_v1` 或
`pre_policy_r2_prefix_then_transition_policy_v1`，只读校验从不修复、回填或截断记录。

当前 R1 只以 legacy_r1 模式读取：

- R1 event 没有 schema_version，并包含 ts、event、stage、status、message、details；
- R1 state 的 schema_version=1，并保留当前 workspace、target_repo 等字段。

R1 输入不会被静默重写为 R2。R1/R2 混合 JSONL、未知 schema version、缺失字段和
畸形 R1 数据都会被拒绝。该工具从不创建、迁移、修复、锁定或重写工作区文件，也不会
执行 event 内容、命令、Docker、PoC 或网络活动。

## P9.2 并发写入与物化视图

P9.2 为单个工作区提供持久的 `.audit-state.lock`。支持 POSIX advisory lock 的平台使用
`fcntl.flock`；没有受支持后端时 writer 以 `LOCK_UNSUPPORTED` fail closed，绝不会在未加锁
状态继续。锁文件保留在工作区，避免删除后产生 inode race；锁、journal 与 state path 都必须是
非 symlink 的普通文件。

`write_audit_event.py` 支持 `--protocol-mode auto|r2|legacy-r1`。`auto` 对空工作区建立 R2，
对已验证 R1 工作区只继续 `legacy_r1`，绝不静默迁移。R1/R2 mode mismatch、mixed journal、
未知版本、R2 缺少 state view 或 digest/state 不一致都会在追加前失败。强制 `r2` 不会迁移 R1，
强制 `legacy-r1` 不会降级 R2。

R2 调用者必须明确说明 revision 意图：

- `--expected-state-revision N` 是 compare-and-swap；不匹配返回
  `STATE_REVISION_CONFLICT`，不改变 journal 或 state；
- `--accept-current-revision` 只用于可信的顺序兼容生产者，writer 在锁内读取当前 revision
  并分配下一个值；
- R1 不支持 R2 CAS，成功输出显式 `cas_mode=unavailable`，而不是伪造 revision 保护。

R2 writer 在锁内按如下顺序执行：校验已有 journal/state（包括已有 P9.3 policy suffix）、
检查 CAS 与调用方预期 source、从锁内当前 state 派生 `from_stage`/`from_status`、构造并校验
完整 transition metadata 和 FSM-lite 规则、分配连续 `seq` 与 `state_revision`、追加一条确定性
紧凑 JSON 并 flush/fsync journal、从**精确已提交 bytes**计算
`event_log_digest`、写入同目录受限权限临时 state 文件并 fsync、`os.replace()` state view，最后在
支持的平台尽力 fsync 工作区目录。

这不是两个文件的原子事务。若 journal fsync 成功而 state 临时写入或替换失败，journal 仍是
权威记录，writer 返回 `journal_committed=true` 与 `state_view_updated=false`，不会截断或要求调用者
盲目重试。后续写入会以 `STATE_VIEW_MISSING` 或 `STATE_VIEW_OUT_OF_SYNC` fail closed；通用 replay /
rebuild 必须通过下述 P9.4 显式 CAS 命令完成，writer 本身不会自动修复。

R2 event 使用显式 `--evidence-ref`；writer 不会把任意 `--detail` 值提升为 evidence reference。
兼容 `--detail`/旧 `--details-json` 仅接受有记录的标量 metadata 映射；嵌套或无效值在触碰
journal/state 前失败。既有 stage alias 在 writer 边界确定性映射，未知 alias 被拒绝。
新 R2 write 还必须显式提供 `--transition-kind`；未知 intent 或非法转换在 journal append
之前以稳定 code 拒绝。`--stage current --status current` 仅用于锁内保持同一状态的 `observe`。

成功输出至少包含 `mode`、`seq`、`state_revision`、`journal_committed`、
`state_view_updated` 与 `cas_mode`；失败输出包含稳定 issue code，且部分提交不会给出“重试同一
event”的建议。

## P9.4 一致性诊断与状态重建

`scripts/recover_audit_state.py` 是只读检查和显式 state rebuild 入口。默认及 `--check`
只读取精确 bytes，并报告 journal/state digest、protocol mode、event count、P9.3 policy
分类、字段 drift、rebuildability 和稳定 issue code。统一 inspector 区分：空 journal、
非 UTF-8、缺少最终 newline、不可解析的非 newline 尾部、中间/换行终止损坏、mixed R1/R2、
unsupported schema、duplicate/gap/non-monotonic seq、revision chain、run ID 和 transition
sequence 错误。`JOURNAL_TAIL_INCOMPLETE` 与 `JOURNAL_MIDDLE_CORRUPTION` 都只提供诊断，
绝不授权截断、splice、补写或忽略损坏内容。

state 字段来源固定如下：schema/plugin、seq/revision/digest 与最后事件身份从协议和精确
journal bytes 派生；`plugin_version` 只来自最后 event，或来自与一个精确有效 journal
prefix digest、seq/revision 和事件字段全部匹配的旧 state；`blocker`/`resume_step` 只来自
显式 P9.3 event，或来自同样锚定且指向最后历史 event 的旧 state。缺失来源返回
`STATE_REBUILD_METADATA_UNAVAILABLE`，不使用 wall clock、mtime、机器路径、当前安装版本或
推测文本。对应 rebuildability 是 `complete_from_journal`、
`complete_with_anchored_legacy_metadata`、`blocked_missing_metadata`、
`blocked_journal_invalid` 或 `not_applicable_legacy_r1`。

`--apply` 只允许替换 `stage-status.json`，并要求 prior-check 的
`--expected-journal-digest`，以及互斥的 `--expected-state-digest` 或
`--expect-state-missing`。实现持有 workspace lock 完成重读、双 CAS、derive、schema 校验、
same-directory temp write/fsync、`os.replace`、directory fsync 和 post-validation。任何
pre-replace 失败保持旧 state byte-identical；所有路径保持 `audit-events.jsonl`
byte-identical。finalizer、assertion、handoff renderer、workspace validator 和普通 writer
只使用统一 reader 并 fail closed，绝不自动 apply。

同时提供两个 state-CAS 参数时，`recover_audit_state.py --json` 在取得 lock 或读取/写入
workspace 前返回非零的 `STATE_CAS_INTENT_CONFLICT`。这是调用意图冲突，不是可绕过的 force
模式。journal 使用 LF 或 CRLF 行终止均可读取；digest 永远覆盖原始 bytes，检查和 rebuild
绝不把 CRLF 重写为 LF。CR-only 或混合损坏行终止仍按不完整/损坏 journal fail closed。

当历史 `plugin_version` 只能从锚定旧 state 取得时，诊断保留
`complete_with_anchored_legacy_metadata`，并输出锚定 prefix 的 seq/revision、后续 event 数和
实际使用字段。这是历史 provenance，不表示该版本必然是最后 event 的 plugin version；未锚定或
fabricated 值仍被拒绝。

## P9.5 回归闭包

`scripts/selftest_audit_state_protocol.py` 是独立的标准库回归入口。P9.5-r2 manifest 对 closure fixture
子树采用封闭文件清单与 SHA-256 登记，拒绝符号链接、隐藏工具状态和未登记文件；每个 case 都从实际
journal/state 计算协议模式、journal/transition/rebuild 分类与末端 stage/status，而不是相信标签。
runner 同时输出逐案 ledger 与由 ledger 归约的指标，主 selftest 会校验 fixture、并发、硬退出与终态
执行记录的固定集合。它读取严格 fixture manifest，
只在 tempfile 创建状态工作区，并以有界子进程覆盖并发 lock/revision CAS、journal-first 故障边界、
explicit rebuild、R1/R2 隔离和状态不能替代 bundle/finalization/recording authority 的负例。该 runner
不会执行 Docker、PoC、replay、network、package manager 或 LLM。source、Claude installed、Codex
installed 布局必须对同一 manifest 生成相同的机器可读结论；仅显式声明的 elapsed-time 字段可不同。

`--migration-preflight` 只读报告 R1 source digests、event count、legacy stage/status、可精确
映射字段、必须构造/推断的 R2 字段与 blocker codes；机器本地字段只显示分类或摘要。它不是
R1→R2 migration、状态推进或漏洞确认，也不会创建 R2 event/state。

## 明确延后事项

本协议不实现 R1→R2 migration，也不修复、截断、重写或补写损坏 journal。重建出的
`finalization/completed` state 仍不是 bundle、Docker、disposition、handoff 或 substantive
finalization 证明。runner/scheduler 等后续工作流能力不属于本协议。

## R1 自动检测与 R2 intent 边界

writer 在写入前会根据 journal/state 形状自动区分 R1 和 R2。对已验证的 R1 工作区，若
调用请求携带 `transition-kind`、预期 from stage/status、显式 reason code、subject、evidence
reference、next action、run ID 或 reason detail 等 R2-only intent，自动模式返回稳定的
`R1_R2_INTENT_MISMATCH`，且 journal 和 state view 的 bytes 都保持不变。它不会迁移 R1、伪造
seq/revision、补写历史或重排事件。

确实需要继续写入历史 R1 的生产 caller 必须显式传入
`--protocol-mode legacy-r1`。成功结果会以机器可读字段报告兼容模式、被忽略的 R2-only fields
及诊断；这不是静默丢弃，也不表示该 workspace 已完成 R2 verification。新生产 caller 不得
通过隐含兼容模式表达 R2 transition intent。

## P9 closure security boundary

The state protocol is not an authority escape hatch. A finalization event may
claim Docker cleanliness only when `docker/docker-cleanliness-status.json` is
an exact, current, host-owned regular file with schema version `1`,
`clean=true`, `strict=true`, the current logical workspace name, a valid UTC
`checked_at`, and a recorded SHA-256. The finalization event must repeat those
claims and the shared reader must verify the digest, workspace, ordering, and
the five-minute freshness window. A stale, symlinked, hard-linked, malformed,
or path-only status is rejected before the finalized state can pass.

The wrapper owns evidence files on the host. The evidence tree is mounted
read-only in Docker; only a separate `container-output` directory is writable.
The command oracle reads stdout/stderr through host file descriptors opened
before the container starts, and verifies that the descriptor and pathname
still identify the same regular, single-link, current-user-owned file after
the process exits. Symlink, hard-link, FIFO, directory replacement, ancestor
replacement, and result-path replacement attacks fail closed and cannot alter
the stage state or external marker. A positive Docker oracle therefore remains
necessary but is never sufficient without the normal verifier, disposition,
bundle, and finalization gates.

Structured blocker facts are authoritative for closure. A current
`blocked_missing_image`, timeout, resource, unsafe-sandbox, or unverified
fact blocks completion even if prose looks positive; a later confirmed,
rejected, or false-positive fact for the same case resolves that identity.
Text fallback is used only when no structured facts exist and ignores quoted
examples and explicitly resolved lines. Sensitive host paths, credential URLs,
control characters, and unsafe `tested_ref` values are rejected before any
journal, state, handoff, checkpoint, candidate, or verdict bytes change.
