# 烛龙工作流细节

本文档包含 README 之外的详细运行规则，适合需要深入了解烛龙机制的运行者阅读。

英文版请阅读 [`WORKFLOW_DETAILS.md`](WORKFLOW_DETAILS.md)。

## 人机协同

烛龙将审计工作区视为 Agent 与人工审核员共享的协作平面。关键状态会写入轻量且明确的文件，而不是困在冗长的对话记录或海量的原始扫描日志中。

- **Agent 接力**：Agent 可以通过 `handoff-summary.md`、`stage-status.json` 和 `audit-disposition.json` 快速掌握进度。
- **人工审计**：审核员可以优先查阅 `attack-surface.md`、`candidate-findings.md`、`false-positives.md`、`unverified-leads.md` 和 `SUMMARY.md`，无需手动翻阅全量日志。
- **流程演进**：维护者可以通过优化脚本、参考契约和校验器来演进工作流，而不是不断膨胀启动提示词。
- **结果复核**：审核员可以直接审查已确认漏洞包，无需重新拼接证据、命令、Payload 与报告结论之间的对应关系。

## 审计状态协议 R2

R2 把 `audit-events.jsonl` 定义为权威的追加事件日志，把 `stage-status.json` 定义为
由日志派生的当前状态视图。记录即使通过结构校验，也不能证明漏洞有效、docker 已确认、
漏洞包有效或工作区已完成。新的 R2 写入由带锁的写入器完成，必须明确 CAS/当前 `revision`
意图和转换意图。

权威的 R2 转换策略记录来源阶段，约束阶段内状态变化、保守的前进/返回/可选阶段关系，
以及带证据的 `resume`、`skip`、`return`、`reopen` 动作。较早的 R2 记录会明确保留为转换策略
引入前的历史记录；有效的 R1 工作区继续兼容读写，不会静默迁移。R2 还提供按原始字节检查的
统一检查器、字段差异诊断、只读 R1 迁移预检，以及只能通过双摘要 CAS 原子重建
`stage-status.json` 的显式命令。消费者不会自动修复，`audit-events.jsonl` 也不会被截断、
重写或合成。详见 [`audit-state-protocol-r2.md`](runner-contracts/audit-state-protocol-r2.md)。

每次追加新 R2 事件前，规范的带锁写入器都会检查可发布文本中的本机路径、`file:` URI，
以及常见凭据或私钥形态。拒绝只返回稳定类别，并保持事件日志和状态视图的字节不变。
直接调用写入器和阶段收尾程序共用这一边界；历史事件日志不会被原地“清洗”。如果同时
提供两个 `state-CAS` 意图，恢复 CLI 会在取得锁之前以 JSON 返回
`STATE_CAS_INTENT_CONFLICT`。LF 和 CRLF 日志都能读取，但它们代表不同的精确字节，恢复流程
不会规范化行尾。历史锚定的 `plugin_version` 会明确标为前缀来源，而不是默认当作最后事件
使用的版本。离线协议夹具会验证这些规则，但不会执行 docker、PoC、复现、网络或包管理器。

## 侦察覆盖结果契约

侦察覆盖应使用独立、可携带的 JSON 契约记录。创建或复核
`recon-result.json` 前，请先阅读
[`recon-result-contract-r1.md`](runner-contracts/recon-result-contract-r1.md)。

候选项分诊使用独立的建议性批次契约。创建 `triage-batch.json` 或登记侦察/分诊阶段终点前，
请阅读 [`triage-batch-contract-r1.md`](runner-contracts/triage-batch-contract-r1.md)。分诊不能
更新处置记录，也不能声称已确认。窄范围阶段收尾程序使用结果摘要和 `revision` CAS，只能追加
同阶段的 R2 `complete`/`pause`/`block` 事件；它不会推进阶段，也不会执行后续建议。

R2 候选项契约新增确定性身份、结构化来源信息和仅限候选项的重复关系。升级或去重前应阅读
[`candidate-identity-dedupe-r1.md`](runner-contracts/candidate-identity-dedupe-r1.md)。R1 继续以
`legacy_r1` 可读；升级必须显式写入新文件。相同 `fingerprint` 和建议性去重计划，都不能替代
独立核验器、处置记录、docker 证据、确认漏洞包校验或工作区收尾。

结果必须绑定本次实际读取的 `zhulong-target.yaml` 精确摘要、`tested_ref`，以及工作区根目录
`attack-surface.md` 的精确摘要。结构化观察使用稳定 ID；源码引用必须是仓库相对路径，
证据引用必须是工作区相对路径。`complete` 只表示八类侦察覆盖都已结构化覆盖，或有证据支持
的 `not_applicable`；它不表示“没有漏洞”、审计完成、候选项就绪、漏洞已确认或漏洞包可以生成。
`partial` 和 `blocked` 必须分别记录结构化缺口/阻塞、证据，以及可执行的下一步或恢复条件。

运行只读校验：

```bash
python3 scripts/validate_recon_result.py \
  --repo-root <repo-root> \
  --workspace-dir <audit-workspace> \
  --recon-result <audit-workspace>/recon-result.json \
  --json
```

该校验器离线运行，不写入仓库、工作区、审计状态或证据，也不执行 docker、网络、PoC、
复现、包管理器或 LLM。侦察结果只能通过稳定的 `focus_refs` 为后续复核规划提供入口，不能
创建候选项、核验结论、处置记录、漏洞包或收尾状态。侦察阶段终结登记由后续的独立阶段终结
入口负责；本校验器不会写入该登记。

## 工具副作用与执行边界

严格的 R2 工具注册表由动态规划器、离线校验器和烛龙的窄范围受控封装脚本共同使用。修改工具
元数据或解读计划前，请阅读
[`tool-effects-execution-boundaries-r1.md`](runner-contracts/tool-effects-execution-boundaries-r1.md)。

注册表只约束烛龙自身，无法拦截人工或其他 Agent 的原生工具调用。注册表校验成功只表示元数据
一致，绝不创建候选项、核验结论、处置记录或确认结论。首次扫描输出始终只是候选项材料；初始
探测封装脚本会在规范的 `recon` 阶段登记开始事件。原始 docker CLI、未受控 DAST 或实时目标
工具不会得到规划器的直连命令提示。只有固定的 docker 验证封装脚本可以生成 docker 判定依据
材料，而这些材料仍必须通过现有独立核验结论、处置记录和确认漏洞包门禁。

工具注册表结构定义中的生命周期阶段枚举必须与 `audit_transition_policy.STAGES` 精确一致；
单独删除、改名、重排、新增阶段或把枚举改成错误类型，生产环境的注册表校验器都会从严拒绝。

在 R2 工作区中，验证封装脚本会在每次 docker CLI 调用前校验权威事件日志和状态视图，并且只
接受 `verification/running`，或从 `verification/blocked` 发起的显式重试。它不会自动推进分诊，
也不会为了让结果事件通过而改写工作流状态。docker 后台服务和镜像检查属于非 PoC 前置条件；
实际 PoC 容器命令只有在带 `revision` 绑定的同阶段 `start` 事件提交成功后才会启动。即使 docker
证据已经存在，结果事件提交失败也会令封装脚本以非零状态退出。R1 继续兼容旧格式；没有状态
文件的工作区不会被静默升级为 R2。

## 上下文建议计划

`assets/context-catalog.json` 声明各阶段可建议阅读的稳定本地参考文档。运行
`plan_audit_context.py --target-dir <target-repo> --phase recon --output <audit-workspace>/context-plan.json`
可生成确定性计划；可选漏洞类别只能来自闭合集合的显式输入。规划器只复用工具链规划器的
技术栈与攻击面探测，不解析备注、候选项、交接文本或参考文档内容。

`audit_transition_policy.STAGES` 是十个正式阶段唯一的 Python 词汇源：`intake`、`recon`、
`candidate_generation`、`triage`、`verification`、`severity_escalation`、`variant_discovery`、
`packaging`、`finalization` 和 `recording`。`triage` 与 `recording` 可以直接规划，并选择各自
稳定的阶段参考文档。生产环境的元一致性检查会将该元组与事件/状态结构定义、两份上下文结构定义、
目录映射、规划器选择以及 skill 的命令/阶段声明逐项比较；任何差异都会从严拒绝。

`mandatory` 只表示计划中的阶段基线阅读建议，不是安全门禁；`optional` 记录精确匹配的选择器
事实，`deferred` 表示与阶段相关但没有匹配选择器的模块。该计划仅供建议：它不证明 Agent 已阅读、
理解或使用模块，不执行工具或参考文档，不创建证据，不确认发现，也不替代既有校验器、门禁或根
skill 约束。详见 [`context-planning-r1.md`](runner-contracts/context-planning-r1.md)。

## 交接与状态的机械一致性

`handoff-summary.md` 是运行交接包。它必须描述可机械核验的工作区状态，不能把备注或部分证据解释成
最乐观的结论。

状态生成器和完成门禁共用 `scripts/workspace_state.py` 作为状态检查层：

- `confirmed_bundle_dirs_total` 统计 `confirmed/` 下的非隐藏目录数量。
- `validated_confirmed_bundle_count` 只统计通过
  `validate_all_report_bundles.py` 最终校验的确认漏洞包目录。
- `invalid_or_partial_confirmed_bundle_count` 统计被校验器判定为不完整或校验失败的疑似漏洞包目录。
- `docker_evidence_only_count` 统计工作区证据目录下的 docker 或核验证据；这些证据尚未组成通过
  校验的确认漏洞包。
- `formal_variant_analysis_status` 只有在至少存在一个通过校验的确认漏洞包，且
  `evidence/variant-analysis/seeds.jsonl` 与 `variant-candidates.jsonl` 都通过各自校验器时才是
  `completed`。

没有通过校验的确认漏洞包时，交接摘要必须写 `Confirmed bundles: 0`。如果存在 docker 证据但没有
通过校验的漏洞包，保守状态是 `docker_evidence_collected_but_no_bundle`。此时 docker 证据可以
作为有用的核验材料，但不是确认交付物，不能表示漏洞包已经就绪，也不能表示正式同类漏洞扩展已
完成或就绪。

人工同类备注、种子草稿、候选记录、代码级证据、不完整漏洞包和校验失败目录，都只能保留为人工或
未验证的工作区材料，直到真实的 `confirmed/<bundle>/` 通过最终校验。
`validate_workspace_state.py`、`assert_finalized_workspace.py` 和收尾门禁会拒绝与实际产物矛盾的
过期交接或状态文案。

### 结构化交接与检查点

`handoff-state.json` 是机器可读的继续工作索引，由 `scripts/workspace_state.py` 根据已提交的
事件日志/状态视图，以及现有候选项、独立核验器、处置记录、漏洞包、docker、运行时、录制和收尾
校验结果派生。它记录 `revision`/摘要、`tested_ref` 是否可验证、稳定 ID 与数量、正式同类漏洞
扩展状态、阻塞/恢复上下文和相对路径产物摘要；它不会回写任何权威产物，也不会把 docker 证据、
录制清单或备注变成已确认漏洞。

侦察和分诊的聚合会使用各生产校验器声明的输入契约。尤其是分诊只接收其工作区相对的
`--triage-batch` 输入；摘要绑定的 `recon_binding` 由分诊契约在内部校验，而不是由交接状态伪造
第二个 CLI 参数。

`render_handoff_state.py` 只发布这一个文件，使用同目录临时文件、`fsync` 和原子替换；
`validate_handoff_state.py` 只读并报告 `revision`、`tested_ref`、摘要、数量或 ID 差异。写入
`handoff-summary.md` 前，面向人工阅读的摘要生成器会刷新或校验这份状态；如果存在 `agent-notes.md`，它只能
作为明确标注的建议性指针。

`checkpoints/<revision>.json` 是不可变的轻量快照索引，不是日志、提示文本、聊天内容、凭据或证据副本。
创建前必须存在当前交接状态，文件名采用稳定数字格式；相同 `revision` 的相同字节保持幂等，冲突字节
从严拒绝。检查点的恢复元数据只允许固定安全入口和工作区相对参数。校验器会把结构合法的旧快照
标为 `valid_historical`；输入变化或索引不安全/被篡改时标为 `historical_unverifiable` 或 `tampered`，
不会静默当作当前状态。

### 派生的下一步建议

`next-actions.json` 是从当前 `handoff-state.json` 及其既有结构化权威输入派生的确定性且仅供建议的索引。
`render_next_actions.py` 只会原子写入这一个派生文件；`validate_next_actions.py` 完全只读并重新
派生每个字段。建议使用固定入口允许列表和结构化相对参数，不是命令行命令，也不会自动执行。该索引
不是证据，对候选项、核验结论、处置记录、漏洞包、录制、收尾或审计完成没有任何权限。权威输入缺失
或冲突时必须从严拒绝，不能从备注、摘要、聊天或目录名推断。

### 静态审计时间线

运行 `render_audit_timeline.py --workspace-dir <audit-workspace> --repo-root <repo-root>` 会生成确定性的
离线派生视图 `audit-timeline.json` 和 `audit-timeline.html`。JSON 通过规范的事件日志/状态视图读取器，
以及既有目标、候选项、核验结论、处置记录、docker、漏洞包、交接状态、后续建议和收尾校验器取得
事实；HTML 只从通过校验的 JSON 渲染。离线打开前，先运行
`validate_audit_timeline.py --timeline <audit-workspace>/audit-timeline.json --html <audit-workspace>/audit-timeline.html --workspace-dir <audit-workspace> --repo-root <repo-root>`。

静态审计时间线不会运行审计、docker、PoC、复现、扫描器、网络请求、模型或 Agent，也不包含隐藏推理
或聊天内容。它不具备确认、处置、生成漏洞包、执行或收尾权限；`confirmed` 关系仍须由既有 docker 证据、
独立核验结论、处置记录和确认漏洞包校验器共同证明。项目采用静态文件而不是服务端仪表板，是为了
不增加服务、数据库、后台服务、遥测、网络依赖或新的权限面。

常见凭据和私钥形态会使时间线生成从严拒绝，诊断不会回显命中的值。本机路径也会由与新 R2 写入边界
共用的同一分类器拒绝；历史事件日志中的不安全文本仍按只读、从严拒绝处理。只有既有权威文件能够
证明唯一的候选项到漏洞包关系时才展示确认漏洞包；存在多个 `confirmed` 或其他无法证明一一绑定的工作区
会被拒绝，不会按名称或顺序猜配。经过转义的 URL 可以作为可见审阅文本，可点击资源
仍只允许规范的工作区相对链接。

发布自检只在运行时构造两类受支持的 AWS 访问密钥 ID 前缀正例，并扫描当前待发布源码与
已安装包的真实字节，拒绝完整的服务商格式测试字面量。该夹具卫生门禁不得弱化生产分类器、
删除任一正例或重写历史证据。

## 运行时残留与清理机制

烛龙会把 docker 残留资源和 OMC/PID 运行时残留分开处理。二者都会出现在工作区产物和交接摘要中，但安全策略不同：

| 类型 | 记录位置 | 默认行为 | 用户或 Agent 可做什么 |
| --- | --- | --- | --- |
| docker 容器、镜像、网络、卷、BuildKit cache | `docker/docker-cleanup-plan.json`、`docker/docker-cleanliness-status.json`、`handoff-summary.md` | 先生成清理计划；默认试运行；只自动处理能证明属于当前审计的资源。 | 人工审核计划后，可授权 Agent 使用精确参数和 `--apply` 清理。 |
| OMC 滞留 Socket | `runtime/runtime-hygiene-status.json`、`handoff-summary.md` | 只清理确认为滞留且无活跃 swarm Socket 的 `claude-swarm-*` Socket。 | 可以运行 `--cleanup-stale` 后重新检查。 |
| 可疑 `claude --teammate-mode tmux` PID | `runtime/runtime-hygiene-status.json`、`handoff-summary.md` | 只读复核；烛龙不会发送终止信号或强制结束命令。 | 用户可根据 `pid/ppid/pgid/sess/tty/stat/command` 等信息自行判断；如确认过期，应在烛龙之外手动处理。 |

docker 清理推荐流程是先查看计划，再决定是否授权清理：

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created
```

确认计划中资源属于当前审计后，再允许 Agent 执行精确清理：

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created \
  --apply
```

如果清理计划列出没有烛龙标签但确实属于本次审计的资源，必须使用精确接管参数，例如 `--adopt-compose-project`、`--adopt-image-ref`、`--adopt-network-name`、`--adopt-volume-name` 或 `--adopt-build-cache-id`。不要使用通配符、前缀、正则或“清理全部项目”的语义。

清理后用严格检查确认环境状态：

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --verify-clean \
  --strict
```

如果 `clean=false`，工作区应保持阻塞状态，并在摘要中写明残留资源和安全续跑步骤。烛龙不会通过重写 docker 初始基线来隐藏残留，也不会信任过期的 `docker-cleanliness-status.json` 作为完成依据。

OMC/PID 复核流程只用于判断多 Agent 模式是否安全：

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

如果只存在滞留 Socket，且没有活跃 swarm socket，可清理 Socket 后重查：

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --cleanup-stale --json
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

如果报告可疑 协作进程 PID，烛龙只会展示复核信息，不会杀进程。即使启用 PID 复核或清理相关选项，当前烛龙也不会对 协作进程 PID 发送信号。用户如果确认某个 PID 确实过期，应在烛龙之外手动处理，或在明确了解风险后授权 Agent 使用系统级进程工具处理；不要把 PID 清理并入 docker 清理，也不要使用大范围进程清理。

更多细节见 [`../assets/references/docker-resource-hygiene.md`](../assets/references/docker-resource-hygiene.md) 和 [`../assets/references/omc-runtime-stability.md`](../assets/references/omc-runtime-stability.md)。

## 确认漏洞包生成短路径

烛龙将确认漏洞包生成收束为一条固定、可重复执行的短路径：

```text
生成合同预检
-> 暂存区构建
-> 暂存区最终校验
-> 原子提升
-> 全量校验
-> 同类漏洞扩展
-> 审计收尾
```

生成合同预检只检查被选中的单个漏洞是否具备可移植、已通过 docker 确认、且足以
生成审核材料的最低输入。它只是生成前门禁，不能证明漏洞成立，也不能替代 docker
证据。

源码绑定确认比结构完整性更严格。预检必须接收真实目标仓库的 `--repo-root`，核验
当前 Git 引用，读取目标合同与独立验证结论，并对攻击入口、危险汇聚点或缺失的关键
约束所对应的仓库相对源码范围做 SHA-256 核验。精确入口与组合入口只有在复现入口能
由真实源码标记机械推导时才能通过；无法机械证明的动态入口必须保持阻塞或条件确认。

测试固件制造的角色、会话、密钥、敏感对象、租户归属或部署边界，不能支撑更强的真实
影响声明。普通合成标记只能作为确定性成功判据，并且必须明确它不能支持哪些影响声明。
条件确认的漏洞必须保留全部源码绑定部署条件，按证据收窄严重性，并将条件同步写入
`validity-review.json`、漏洞包内的 `findings.json`、`verification-evidence.json`、
审核证据索引与 DOCX 报告。

生成合同中的每个字段都必须能对应到报告渲染输出、最终校验器或批量门禁，以及确认
漏洞包内的证据产物。无法建立这些对应关系的字段，不应加入生成合同。

生成合同中的 `finding.severity` 使用稳定枚举值：`Critical`、`High`、`Medium`、
`Low`、`Informational`；最终审核材料可以按输出语言显示对应名称。
`finding.bug_class` 和 `impact_tier.bug_class` 保持自由文本，并在检查清单中给出
推荐值，因为真实项目中的漏洞类别可能具有项目特性或属于复合分类。

暂存区构建脚本会先将材料渲染到 `confirmed/.staging/<slug>`，并在该目录运行同一套
最终漏洞包校验；只有校验通过后才会原子提升到 `confirmed/<slug>`。失败的暂存目录
只能作为调试材料，不能称为已确认交付物。提升后还必须运行
`validate_all_report_bundles.py`，再进入同类漏洞扩展与审计收尾。

默认最终校验仍采用遇错即停。`validate_report_bundle.py --all-errors` 只是暂存区或
最终校验失败时的诊断模式，用来一次收集可处理的问题；它不会修复漏洞包、放宽校验
规则或确认漏洞。

复现日志必须包含真实的命令、输出和成功判据。仅含标记的复现日志，或手工追加直接
影响标记的日志都无效。复制已有成功记录时必须提供可移植的来源信息，例如
`bundle-build-manifest.json` 或面向审核员的证据记录。
`attachments/evidence/replay-output.log` 承担历史证明记录角色。生成的复现辅助脚本与
录屏自动化会把新的标准输出/标准错误运行日志写入
`attachments/evidence/replay-runtime-output.log`；这份运行日志是审核材料，但不能覆盖或
替代已登记的首次证明记录。

`bundle-build-manifest.json` 是构建来源记录。新的构建清单会把仅用于构建的输入放在
`build_inputs[]`，把暂存/最终位置放在 `promotion`，并标记为
`delivered=false` 的工作区相对元数据。`status.static_validation` 与
`status.promotion` 只说明静态漏洞包校验和提升状态；目标构建、目标启动、健康检查、
本地复现、干净环境复现都由构建器记录为 `not_executed`。这份清单不验证实际执行，
因此不接受这些阶段的 `passed` 声明，即使附件的 SHA-256 摘要匹配也不例外。
文件完整不等于程序已经成功运行。

构建器将漏洞包移入正式目录前，会检查合同声明的根目录复现脚本和 `files` 中的
每个文件是否已在暂存区内。只填写路径不会自动补齐文件。脚本直接调用 docker compose 时，
包内必须带上编排文件，以及配置中引用的本地构建目录和 Dockerfile。传入多个 `-f`
文件时，相对路径以第一个文件所在的目录为准。读取编排文件需要校验器所在的 Python
环境已安装 PyYAML。

最终校验还会逐项检查 `bundle_root_artifacts` 声明的交付文件，使用 `output_name`
指定的路径；未指定时使用源文件名。缺失文件、符号链接、硬链接和非普通文件都会被拒绝。
移动漏洞包后不要求原始构建路径仍然存在，但包内声明的交付文件必须保留。

生成脚本中的 docker compose 后台启动命令会加上 `up --wait --wait-timeout`，等待服务的
健康检查通过，因此相关服务必须启用健康检查。等待上限由
`ZHULONG_READY_TIMEOUT_SECONDS` 设置，默认 30 秒，可设为 1–600 秒；展示停顿和
快速模式不会改变这个上限。启动或等待失败，脚本就会停止，不再执行后续复现命令。
docker compose 版本不支持这些等待参数时，脚本同样报错停止，不会跳过等待。

静态校验不会运行构建或复现命令，也不能检查 Dockerfile 的全部依赖或任意写法的
脚本封装。手写脚本仍需人工核对。例如，当前编排输入检查无法识别未加引号的
`run_logged_command docker compose ...` 调用；生成的脚本会为完整命令加上引号。
具体交付要求见
[漏洞包格式说明](../assets/references/confirmed-vuln-docx-format.md)。

`assets/fixtures/replay-transcript-corpus/` 中的复现记录样本集通过静态正反例固定这条
信任边界。校验器不要求唯一且僵化的日志格式：只要真实记录包含命令、原始输出、成功
判据、退出或通过状态，以及直接影响证据，不同格式都可以接受；仅含标记、仅含占位符、
内容过薄、缺少成功判据，以及复制后缺少来源信息的记录仍会被拒绝。

基于已确认漏洞的同类扩展始终保持候选态。对于含确认漏洞包的审计，`seeds.jsonl`
与 `variant-candidates.jsonl` 是必需的收尾产物，但候选排序和种子相似度不能作为漏洞
确认依据。

## 报告质量门禁

所有已确认漏洞报告必须清晰说明：

- 攻击者条件
- 服务端条件
- 具体安全影响
- 实际场景中的危害与利用方式：真实使用场景、攻击者可控输入、触发调用链、直接业务或安全后果，以及已验证影响和未声称影响的边界

校验器还会检测常见的逻辑矛盾，例如：

- 标题或正文声称“无需认证”，但 CVSS 评分或复现证据显示需要权限。
- PoC 脚本在没有明确成功判据的情况下直接输出成功结论。
- 在最终确认横幅之前使用 `grep ... || echo ...`、`grep ... || true`、
  `jq ... || true`、`curl ... || true` 或
  `docker logs ... | grep ... || echo ...` 这类 fail-open 成功判据。
- 复现录屏脚本的步骤标签过期或格式异常。
- 漏洞包根录制脚本的 shell 静态语法和可执行位。
- 附件 docker compose 的静态自洽性，包括缺失相对 `env_file`、缺失相对 绑定挂载 源文件，以及最终包中不允许出现的绝对宿主机路径。
- 中文 (zh-CN) 报告中无故出现大段英文自然语言。
- 在存在结构化证据字段时，校验目标与命令一致性。
- 根脚本或附件脚本通过深层 `../../..` 逃出下载后的漏洞包，或挂载提交者本机父级仓库。
- 报告、补充说明、证据 JSON 与根录屏脚本之间的 PoC 标签漂移。
- 录屏视频早于当前报告、补充说明、证据 JSON 或根复现脚本。
- 最短审核复现路径中可能触发生命周期脚本或联网噪音的 `npm install` / `yarn install` / `pnpm install`。
- 复现脚本只展示 PoC/docker 命令却没有实际执行路径。
- 复现脚本没有把 `测试软件名称` 与 `测试版本/分支` 作为独立开场字段展示，或缺少开场身份屏/最终证据汇总屏停顿。
- 复现脚本缺少可覆盖的 `REVIEWER_PAUSE_SHORT` / `REVIEWER_PAUSE_LONG`，
  在 `quick` 模式中改用固定短暂停顿，或缺少代码上下文、代码级分析、影响边界、
  证明命令/输出、最终证据汇总之后的审核停顿。
- 复现脚本把审核暂停变量复用于服务就绪、健康轮询、启动重试或退避；审核暂停只用于
  录屏视觉停留，功能性等待必须使用独立的就绪/退避变量。
- 补充复现说明或证据索引引用了漏洞包中不存在的本地辅助脚本。
- 缺少直接影响复现证据，例如 `DIRECT_IMPACT_CONFIRMED`、`DIRECT_AVAILABILITY_IMPACT_CONFIRMED` 或等价的程序化危害判据。
- DOCX 面向审核人的正文中泄漏 Python/JSON 风格的字典、列表或对象中间结构，而不是正常报告文字。
- 运行时/版本身份只使用 `latest`、浮动镜像标签、`main`、`master` 或含糊的“current version/当前版本”，且没有稳定版本号、提交哈希、镜像摘要或测试日期。
- DOCX、补充说明、复现辅助脚本、`verification-evidence.json`、审核证据索引与已登记的
  复现日志之间，直接影响标记不一致。
- 已登记的复现日志为空、仅含占位符或标记，或缺少命令、原始输出、成功判据等真实
  运行信号；不得通过手工追加直接影响标记让内容过薄的日志通过校验。
- 复制或沿用的历史成功复现记录缺少 `bundle-build-manifest.json` 或审核材料中的可移植
  来源说明。
- `bundle-build-manifest.json` 声称目标构建、目标启动、健康检查、本地复现或干净环境
  复现已经通过；这份构建来源清单不能验证实际执行。
- SSRF 影响层级漂移，例如实际只证明回连或请求可达，却在没有产物级成功判据的情况
  下声称响应内容、配置、凭据或敏感数据泄露。
- 根复现辅助脚本的就绪或健康检查指向与 PoC 证明命令无关的主机或路径。
- 可选 `reviewer-evidence-and-impact.md` 仅为占位，或缺少攻击者边界、影响说明、成功判据和最短复现命令。
- 可选的 `attachments/reviewer-evidence-index.json` 无法解析、引用缺失附件或漏洞包外
  路径、复现命令不是漏洞包根目录本地命令，或列出的成功判据无法在脚本、证据、补充
  说明、审核补充或 `verification-evidence.json` 中找到。
- 测试固件或内嵌源码复现缺少以源码为依据的来源说明，或库与软件包漏洞缺少消费它的
  应用程序边界。
- 严重性与影响声明矛盾，例如高危 CVSS 与正文中危冲突、WebShell 或 HTTP 命令执行
  声明缺少对应成功判据，或容器逃逸、宿主机 RCE、匿名公开触发声明缺少明确的非声明
  边界。

这些检查刻意保持保守，目标是降低误报，并确保已确认漏洞包的契约稳定性。

SSRF 影响过度声明、代码上下文最低质量、复现辅助脚本暂停契约等审核就绪门禁的分类
说明见
[`../assets/references/reviewer-readiness-validator-gates.md`](../assets/references/reviewer-readiness-validator-gates.md)。
该参考文件记录每类门禁的目的、误报边界、接受与拒绝示例、适用的稳定问题代码，
并明确这些门禁只会拒绝薄弱审核材料，不能证明漏洞成立，也不能替代 docker 证据。

`code_level_reproduced`、`entrypoint_reproduced`、
`blocked_entrypoint_verification` 与 `confirmed_in_docker` 等证据等级定义见
[`runner-contracts/finding-contract-r1.md`](runner-contracts/finding-contract-r1.md)。
代码级或函数级复现只能作为辅助证据；漏洞包就绪需要攻击者入口复现、
入口输入形态、入口到危险汇聚点的路径，以及稳定的直接影响判据。

## 基于已确认种子漏洞的同类漏洞扩展

当一份漏洞产出合格的确认漏洞包后，烛龙可将其作为**种子漏洞**，提取根因、攻击者
可控输入、传播路径、危险汇聚点、缺失约束与 docker 成功判据，再依据这些特征在同一
目标仓库中检索相似候选漏洞。该机制只用于安排后续人工复核和 docker 验证的优先级，
不会把相似度本身当作漏洞成立的证据。

同类漏洞扩展流程分为两个离线执行步骤：

1. 执行 `scripts/extract_variant_seed.py`，从已有的确认漏洞包中提取同类漏洞种子卡。
   种子卡记录确认漏洞包路径、漏洞类型、根因、输入与汇聚点匹配模式、触发条件、
   docker 成功判据、检索范围以及排除规则。
2. 执行 `scripts/find_variant_candidates.py`，读取种子卡，在同一目标仓库内扫描本地
   源码并输出按优先级排序的同类候选漏洞。候选结果默认写入
   `<audit-workspace>/evidence/variant-analysis/variant-candidates.jsonl`；每条记录必须
   保持 `status=candidate`，其中的文件路径统一使用仓库相对路径。

本流程设有多条硬性约束边界：

- 最终种子卡只有在 `confirmed_bundle_path` 指向当前审计工作区内真实的
  `confirmed/<bundle>/` 目录，且该漏洞包通过 `validate_report_bundle.py` 时才会被
  接受。候选编号、Markdown 表格行、临时备注、docker 证据目录、不完整漏洞包或校验
  失败的漏洞包都不能作为正式种子；人工同类备注必须留在正式
  `evidence/variant-analysis/seeds.jsonl` 之外。
- 候选检索工具只读取最终种子卡，并在同一仓库内进行本地、可重复的优先级排序。它
  不调用扫描器、`rg`、`grep`、`git`、网络接口、LLM、docker、PoC、DOCX 渲染或确认
  漏洞包生成。
- 种子卡与候选列表仅作为辅助研判资料，无法替代 `verification-evidence.json`、
  `findings.json`、DOCX 报告、补充复现说明、附件索引、复现日志、docker 核验材料
  以及确认漏洞包的校验结果。
- 同类候选漏洞禁止在补充说明、确认漏洞包、审阅备注、最终摘要里标注为已确认漏洞。候选漏洞只有完成独立 docker 或 docker compose 环境复现，且通过确认漏洞包校验流程后，才可升级判定为已确认同类漏洞。
- 候选检索工具仅支持在单一目标仓库内运行。若种子卡配置的检索范围不属于当前仓库、
  工作区路径匹配异常，或确认漏洞包路径无法解析至当前工作区的 `confirmed/` 目录，
  工具必须直接报错终止运行。
- 确认漏洞包禁止将 `variant-candidates.jsonl` 作为核心佐证材料，也不能把候选排序分值、种子匹配相似度、候选记录本身当作漏洞核验通过的依据。
- 对于以 `completed_with_confirmed_bundles` 收尾的新审计，完成门禁会要求 `evidence/variant-analysis/seeds.jsonl` 与 `evidence/variant-analysis/variant-candidates.jsonl` 已存在并通过校验。也就是说，同类扩展不再是审计结束后的人工提醒，而是确认漏洞包流程里的必做收尾步骤。

推荐复核顺序：先校验种子卡是否准确描述已确认漏洞可稳定复现的根因，再核查候选列表
中的所有条目是否都保持候选状态，最后针对有跟进价值的候选漏洞单独搭建 docker 环境
完成复现验证。配套校验命令如下：

```bash
python3 scripts/validate_report_bundle.py --workspace-dir <audit-workspace> --variant-seed-card <seed-card.json>
python3 scripts/validate_report_bundle.py --workspace-dir <audit-workspace> --variant-candidates <variant-candidates.jsonl>
```

若某一条同类候选漏洞最终核验确认成立，它仍需和常规已确认漏洞保持一致标准：具备
独立 docker 复现流程、复现与直接影响佐证文件、`verification-evidence.json`，以及
校验合格的确认漏洞包。

面向审核与录屏的根脚本应从脚本自身位置推导漏洞包根目录，使用相对该目录的
`attachments/`；脚本要么从漏洞包内附件自举 docker 环境，要么在最前面明确失败并
告诉审核员应先运行哪条漏洞包内命令。
脚本在 `docker exec` 前应检查目标容器是否存在且运行；触发漏洞前应尽量做健康/就绪检查。
这些检查只反映脚本当次看到的容器状态；构建清单不验证实际执行，仍将目标启动和
健康检查记录为 `not_executed`。关键 docker、curl 或令牌生成命令失败时应输出捕获到的错误
上下文，而不是裸用 `2>/dev/null` 吞掉原因。
嵌套附件目录内的无害 `../` 可以存在，但最终路径必须仍位于单个漏洞包内；脚本不能
依赖提交者完整的本机仓库布局。

## 示例审计发现形态

```text
状态：已确认
标题：文件导入 URL 获取导致服务端请求伪造（SSRF）
严重性：高
证据：docker 复现中观察到受攻击者控制的回连请求
攻击者条件：具备导入权限的低权限认证用户
服务端条件：默认导入接口启用，且服务端可访问内网/外网
安全影响：机密性风险，可探测内网服务或访问元数据
实际场景中的危害与利用方式：真实部署中导入功能会处理用户提交的 URL；具备导入权限的攻击者控制该 URL；请求链路到达服务端 URL 获取逻辑；直接危害由回连请求或存储响应内容证明；docker 证据验证 SSRF 可达性，但不声称代码执行。
漏洞包路径：confirmed/<vulnerability-slug>/
```

*注意：这仅为已确认记录的形态示例，不代表每次审计都能产出已确认漏洞。*

## 验证与测试

运行插件自检：

```bash
python3 scripts/selftest_plugin.py
```

同步并测试 Claude 安装目录下的 skill 结构：

```bash
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

Codex 用户级 skill 也已支持。它使用同一套布局契约、安装目录自检、平台无关启动入口和仓库根目录 `AGENTS.md` 引导文件；详见
[`CODEX_SKILL_ADAPTATION.md`](CODEX_SKILL_ADAPTATION.md)。同步后，
`~/.agents/skills/zhulong/` 是受支持的 Codex 安装 skill 副本：

```bash
bash scripts/sync_to_codex_skill.sh
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
```

验证单个已确认漏洞包：

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
```

默认最终漏洞包校验采用遇错即停。若暂存区或最终校验失败，需要一次查看常见结构问题，
可显式启用 `--all-errors` 诊断模式：

```bash
python3 scripts/validate_report_bundle.py \
  --bundle-dir <bundle-dir> \
  --all-errors \
  --json \
  --output-errors <bundle-dir>/bundle-validation-errors.json
```

诊断报告只用于定位问题，不会修复漏洞包，也不能确认漏洞。应修正上游生成合同、证据
或审核材料后，再重新运行校验。

生成最终 `confirmed/<slug>/` 产物之前，先根据
`assets/references/bundle-contract-template.json` 填写
`<audit-workspace>/confirmed/.contracts/<slug>.bundle-contract.json`，用
`render` 字段指向被选中的源漏洞，然后运行：

```bash
python3 scripts/validate_bundle_contract.py \
  --repo-root <target-repository> \
  --workspace-dir <audit-workspace> \
  --contract <bundle-contract> \
  --all-errors
```

如果预检失败，应修正生成合同或上游 docker 证据，不要通过创建仅含标记的复现日志，
或临时修改直接影响标记来绕过。预检只负责生成前门禁，最终仍必须运行确认漏洞包校验。

随后通过暂存区构建脚本生成漏洞包：

```bash
python3 scripts/build_confirmed_bundle.py \
  --repo-root <target-repository> \
  --workspace-dir <audit-workspace> \
  --contract <bundle-contract> \
  --language <zh-CN|en-US>
```

不要手写最终 `confirmed/<slug>/` 目录。构建脚本只会把生成合同选中的单个漏洞渲染
到 `confirmed/.staging/<slug>`，通过最终漏洞包校验后才会原子提升，并在提升后运行
批量校验。失败构建只能留在 `confirmed/.staging/`，不得称为已确认交付物。最终审计
完成仍必须通过既有的同类漏洞扩展和审计收尾门禁。
构建脚本默认不执行复现命令。它会在证据存在时记录复现日志的来源信息，最终由漏洞包
校验器判断已注册的复现日志是否属于可信记录。

批量验证工作区下的所有已确认漏洞包：

```bash
python3 scripts/validate_all_report_bundles.py --confirmed-dir <repo>/<audit-workspace>/confirmed
```

发布前运行：

```bash
cat docs/RELEASE_CHECKLIST.md
```

## 限制说明

- 烛龙不保证能发现所有漏洞。
- 烛龙不能替代专家审查，也不能替代人工进行的负责任披露判断。
- 烛龙不会自动登录镜像仓库 (Registry)，也不会静默替换非等效的 docker 镜像。
- 烛龙不会清理归属不确定的 docker 资源或 OMC 多 Agent 工作进程。
- 烛龙不提供托管的后端服务、数据看板、数据库、向量存储或 RAG 服务。

## 可选最终录屏流程

### 原始输入材料

需要交付 PoC 原始输入截图时，在渲染源的 finding 中增加 `original_input`，字段为
`text_path`、`screenshot_path`、`title`、`description`、`caption`。两个路径必须指向
同一 finding 的 `attachments` 已声明文件：原文是非空 UTF-8 文本，最多 32 KiB，
不含终端控制字符；截图是已经取得的 PNG。中文报告的标题、说明和图注必须用中文。
生成器不会从 PoC 脚本推断完整请求，也不会绘制或改写截图；缺少真实材料时应明确记录
未满足交付要求，不能拿合成测试图片代替。

生成器保留原始附件字节，写入 `attachments/original-input-evidence.json`，并在 DOCX
中把原图放在标题、说明、原文路径与图注之间。校验器核对附件摘要、实际嵌入的图片字节
以及这些段落的位置，并与包内 `findings.json` 的同一声明逐字段核对。清单不是第二份
事实来源；声明仍在时删除清单会被拒绝。根脚本在现有 `code_or_trigger_context` 检查点前展示原文；录屏
复核还检查本次运行日志是否包含该原文。最终 ZIP 沿用逐文件字节一致性检查。

旧包可以不声明这组材料，但声明后必须完整有效。要求这项交付时，给报告校验器、录制器
或录屏校验器加 `--require-original-input`；不能靠删除声明把旧包说成已经满足要求。
摘要、DOCX 关联和运行日志只能证明材料一致，不能证明截图采集真实性、输入确实发送，
也不能证明原文在视频中完整可读。仍需检查实际视频；本次没有新增录制阶段或确认权限。

### 独立复现静态资格

`validate_report_bundle.py --require-standalone-replay --bundle-dir <bundle>`
在普通包校验之外检查静态供给条件。合并多个 `-f` 文件后检查全部服务，
包括依赖服务。每个服务必须有包内构建上下文与 Dockerfile，或固定的
`@sha256:<64 位小写十六进制摘要>` 镜像引用。普通包校验仍接受历史合法的仅 tag 附件。

漏洞包根目录的每个 `.sh` 文件都必须符合以下一种形式：

- 最小手写脚本：只接受空行、注释、可选的首行 `#!/bin/sh`、精确的 `set -eu`，以及
  直接的字面 `docker compose` / `docker-compose` 命令。函数定义、赋值、包装调用、
  显示命令、续行、此处文档及其他执行形式均以 `REPLAY_PROVISIONING_UNSUPPORTED`
  拒绝，不取决于文件名或是否出现某个关键词。
- 已声明的生成脚本：从包内 `findings.json` 和该产物的生成选项，调用当前正式渲染器
  重建脚本；完整 UTF-8 内容必须与其中一种支持语言的结果一致。每条复现命令还必须
  单独满足字面命令语法。改写函数、追加命令、代码预览中包含此处文档终止符都会被拒绝；
  仅声明生成器名称或自报摘要不能取得豁免。

字面命令语法允许 ASCII 字母、数字、`_./:@=,+%-`，词间空格或制表符，以及包围字面词
的单引号、双引号（引号内可含空格）。支持的 Compose 动作为 `up`、`run`、`build`、
`pull`、`down`、`ps`、`logs`、`config`、`version` 和 `exec`；不支持 shell 展开或
操作符。至少需要一条动作位置上的 `up`、`run` 或 `build`；`ps up`、`logs up` 中的
参数词不计数。生成脚本自身的显示、日志、检查点和
有界就绪等待代码仅凭完整内容一致而接受，不凭函数名或显示命令前缀放行。旧版本或自定义
脚本可能需要重新生成；普通校验行为不变。

资格检查只支持有限的 Compose 字段和项目自身创建的默认网络、卷；声明的外部资源、
直接 `docker exec` 所依赖的容器，以及未支持的构建输入会被拒绝。这是有限静态资格
检查，不是 shell 解释器或执行沙箱。尤其是，接受 Compose `exec` 并不证明相应服务
已经启动。检查不会解析实际宿主 PATH、docker / Compose 环境或隐式配置，也不验证
命令顺序、镜像可下载、离线可用、构建成功、健康检查成功或复现成功。构建器的五个运行
阶段继续保持 `not_executed`。

### 录制与校验

普通确认漏洞包流程在 docker 和报告校验通过后结束。最终审核录屏需要单独明确启用；
普通漏洞包已经确认，并不代表它已经满足录屏交付或提交要求。

使用仓库内的公共实现：

```bash
python3 scripts/auto_record_bundle.py confirmed/<slug> \
  --repo-root . \
  --mode record \
  --engine docker
```

录制器从漏洞包内的 `findings.json`、`validity-review.json`、
`verification-evidence.json` 以及源码绑定合同材料解析统一录制身份。它要求根脚本实现
`identity`、`code_or_trigger_context`、`final_impact` 三阶段检查点协议。根脚本只向
录制器拥有的临时目录写入事件；适配器校验 OBS 来源和窗口，在漏洞包外临时保存实时
检查点图片，并写入确认文件。缺少协议的手写辅助脚本会在录制模式下拒绝继续；没有录制
环境变量时，普通复现不会等待确认。

确认文件按 JSON 语义解析，而不是匹配固定文本片段。辅助脚本要求该文件是录制器目录
内的普通文件，并且其中的协议版本、`ack` 状态、阶段、整数序号和预期标记都准确匹配。
JSON 使用紧凑或美化格式、包含不同空白或调整键顺序，都不会改变协议判断。

录制证据校验器从最终编码视频中提取帧，检查画面不是纯黑、时间戳和停留时长，并保守
比较它与实时来源图片的相似度。各阶段的 `recording_time_observations` 是录制器提供的
一致性声明，可用于拒绝不合格材料或帮助定位错误，但不是编码视频可见内容的独立证明。
它只生成以下三个截图：

```text
attachments/evidence/screenshots/01-target-identity.png
attachments/evidence/screenshots/02-code-or-trigger-context.png
attachments/evidence/screenshots/03-final-impact.png
```

它会重新计算截图哈希和尺寸，并要求截图同时登记在 `verification-evidence.json`、
`attachments/reviewer-evidence-index.json` 和附件清单中。严格的
`recording-evidence.json` 记录身份、媒体、复现结果、OBS 来源和窗口、检查点、登记
关系及归档就绪状态。

`--finalize` 必须同时给出 `--checkpoint-dir`，并执行完整的录制时校验：在授予提升
权限前，重新计算实时检查点与最终帧之间的关系。之后不提供检查点目录的调用明确属于
`artifact_only` 产物复核；它可以复核哈希、附件清单、截图和归档一致性，但不能重新
建立录制时内容证明。

提升过程采用事务机制：OBS 输出和暂存材料保持在最终漏洞包之外；暂存漏洞包必须同时
通过 `validate_report_bundle.py` 与 `validate_recording_evidence.py`；临时 UTF-8 ZIP
通过 `testzip()` 和必需条目校验后，漏洞包目录与 ZIP 才会原子提升。复现、视频帧、
归档或提升失败时，原漏洞包、视频、截图和 ZIP 必须保持字节不变，并保留带标签的未提升
录制会话。旧的本地录制 skill 仅作兼容包装，不是事实源。

`--keep-unpromoted-archive DIR` 是可选参数，绝不会写入采用最终名称的 ZIP。只有暂存
ZIP 已完整通过校验、随后提升失败时，才会向用户明确指定且位于漏洞包之外的目录复制
未提升诊断归档；它不会覆盖已有诊断副本。旧参数 `--zip-on-fail` 仅输出弃用警告，
不会生成失败归档。

## 根 skill 小内核与阶段参考文档

根 `SKILL.md` 现在只保留产品边界、核心安全不变量、生命周期权限链、阶段参考文档
加载、确认漏洞包路径、规范收尾和可选录屏。各阶段的详细操作放在基线
`audit-phase-*.md` 参考文档与 `audit-continuation-state.md` 中。

`assets/root-skill-rule-inventory.json` 逐条记录原根 skill 规则为何保留或迁移，并把
规则绑定到生产结构定义、校验器、门禁、固定封装脚本、根内核、参考文档和
自检。可运行：

```bash
python3 scripts/validate_root_skill_rule_inventory.py \
  --skill-root . \
  --inventory assets/root-skill-rule-inventory.json \
  --json
```

硬约束迁移必须有真实的生产承载机制；文档、参考文档、规则清单和自检都不是
生产权限门禁。阶段参考文档会作为目录中的基线模块进入计划，但
`mandatory` 仍只表示计划阅读优先级，不证明 Agent 已读、理解、采用或完成参考文档，
也不授予执行、确认、提升、录屏或最终化权限。详见
`docs/runner-contracts/root-skill-kernel-r1.md`。

## 权威边界：完成判定与验证封装脚本

完成状态不是状态字段数量、`confirmed/` 目录数量或手写 Markdown 的自证，而是只读的实质证据链。
确认结果必须满足以下一对一关系：

```text
候选项 -> 独立核验结论 -> 候选项处置记录 -> 确认漏洞包
```

候选项和独立核验器都必须再次通过生产环境校验器；候选项 ID、目标引用、账本状态、核验结论、
`confirmed_in_docker` 以及证据字段必须一致。R2 候选项还必须绑定候选文件的 SHA-256 和
`fingerprint`。每个漏洞包的
`validity-review.json.source_binding.materials.verifier_verdict` 必须是工作区内安全的普通文件，
并且恰好对应一条已通过校验的处置记录；单独通过漏洞包校验器不足以授予完成权限。

在 `completed_no_confirmed_findings` 状态下，每个候选项都必须有生产环境有效的终端处置记录，
且只有 `false_positive` 可以允许不确认。`candidate`、`unverified`、`blocked`、缺失、重复和孤儿记录
都会阻塞。没有候选文件时，R2 必须使用现有且生产环境有效的侦察覆盖结果证明已覆盖、无缺口、无
阻塞项；任意布尔值或手写“没有发现”说明都不构成证明。收尾程序、交接状态、工作区校验器和
收尾断言使用同一个只读谓词。

真实 R1 工作区继续可读，历史完成字段不会被静默迁移。自动检测到 R1 工作区却收到 R2 专用的
转换意图时会拒绝；真实 R1 调用方必须显式传入 `--protocol-mode legacy-r1`，并从写入结果读取
兼容模式及被忽略字段诊断。这不表示 R1 已完成 R2 验证流程。

验证封装脚本会在创建证据、读取权威状态、调用 docker 或执行 PoC 前校验案例 ID 和证据目录。
案例 ID 必须以 ASCII 字母或数字开头，只能包含 ASCII 字母、数字、`.`、`_`、`-`；点组件、分隔符、
空白、控制字符和前导点都会被拒绝。证据路径必须规范化为
`<workspace>/evidence/<case-id>`，不能穿过符号链接或非目录祖先。缺少事件日志和状态视图时，
会在执行前以 `AUTHORITATIVE_STATE_MISSING` 阻塞。生产环境的 docker 清洁检查没有成功旁路；旧的
测试专用跳过变量也不再支持。

### 收尾安全边界

验证封装脚本拥有权威证据控制文件。`verification-result.json`、`command.json`、沙箱状态、
`stdout.log`、`stderr.log` 和权威引用都由宿主机通过拥有者/文件身份检查的文件描述符及同目录
原子发布创建或替换。docker 运行模式挂载 `/workspace/evidence` 时必须只读；容器写出的内容只能
放到固定 64 MiB tmpfs `/workspace/output`，仅作为非权威临时空间。新执行不会导入容器文件或
创建 `container-output`；历史漏洞包仍保持只读兼容。宿主机以前台方式运行显式参数数组，完成状态
只由 docker CLI 的退出、超时和信号结果决定。判定依据只读取宿主持有的捕获描述符字节，容器退出后
不会按可替换的路径名重新打开文件。符号链接、硬链接、FIFO、目录、祖先漂移和运行中的路径名
替换都会从严拒绝，不能写穿 `stage-status.json`，也不能把案例变成 `confirmed_in_docker`。
docker compose 模式使用相同的宿主机捕获模型；覆盖工作区权威路径的可写绑定挂载会被拒绝。

沙箱预检是 docker 或证据副作用发生前必须完成的证明义务。docker compose 服务的相对路径固定从规范化后的
审计工作区解析，不再依赖调用方 CWD；随后按原顺序复制到一次性、宿主机持有的快照集合。清单绑定低敏
逻辑路径、SHA-256、大小和文件身份。预检以及每次 docker compose `config`、`pull`、`run` 都只读取这些快照，
并显式使用工作区作为项目目录。原文件在预检后变化不会改变执行字节；快照身份变化会在
服务命令前从严拒绝。

docker compose 采用封闭子集：顶层只允许 `version` 和 `services`，每个服务都必须声明字面值
`privileged: false`。锚点、别名、合并、插值、未知字段、`build`/`host-file`/`include`、
`pid`/`ipc`/`uts`/`cgroup`/`userns_mode`、能力/设备/安全选项以及命名卷、匿名卷或外部卷均会被拒绝。
如果服务声明 `network_mode`，只能使用精确的静态字符串 `none`；省略是允许的，因为宿主持有的
生命周期覆盖配置会补上 `none`。选定的服务必须
存在；只要出现 `depends_on` 就拒绝；`restart` 只能省略或精确写为 `"no"`。目标定义的标签不得
使用保留的 `org.zhulong.*` 或 `com.docker.compose.*` 命名空间。宿主机绑定挂载只允许三种固定映射：
目标仓库只读映射到 `/workspace/target`、工作区的 `poc/` 只读映射到 `/workspace/poc`。
`/workspace/output` 固定为容器内 64 MiB tmpfs，不再是可写宿主机绑定挂载，仅作为非权威临时空间。新执行
以前台方式运行显式服务参数数组，并强制合并配置中的 `logging.driver=none`；不读取容器文件，不生成
`container-output`。历史漏洞包保持只读兼容。其他宿主机路径即使只读也拒绝。额外 docker 参数不能覆盖
资源或隔离策略；专用的 `--memory`、`--cpus` 和 `--pids-limit` 必须为正数，并受
`docker-case-policy-v2` 硬上限约束：内存 16 MiB 到 2 GiB、CPU 0.1 到 4、PID 1 到 1024；默认值仍为
512 MiB、1 CPU 和 256 PID。docker 运行模式会把静态的 `none`、`bridge` 或非 host 自定义网络写入
schema 2 回执，并拒绝控制字符和不安全名称；docker compose 始终派生 `network_mode: none`，不接受 docker
运行模式的网络值。预检通过只证明配置处于
当前执行边界内，不证明 PoC、判定依据、核验结论、漏洞包或收尾成立。

每次调用都会在宿主机持有的回执中生成随机案例令牌、精确的容器名称和唯一的 docker compose 项目名称。
新回执使用 schema 2 和 `docker-case-policy-v2`。精确的 schema 1 / `docker-case-policy-v1` 历史回执只允许
进入身份安全的清理流程；配置校验、权威事件、结果发布和新的准备流程都会拒绝它们，不会改写历史回执。
docker compose 在输入文件之后追加最后一层宿主机覆盖配置，将选定服务的 `network_mode` 强制设为 `none`，
并把该值绑定到回执策略；服务启动前还会校验生产环境合并配置，缺失或漂移都会拒绝。执行时
显式使用 `-p`、`--name` 和 `--no-deps`，镜像检查及显式请求的 `pull` 也只针对选定服务。正常退出、
失败、超时、`SIGINT`、`SIGTERM`、证据捕获失败、输出超限或其他证据错误共用同一套幂等清理。宿主机
持续流式捕获标准输出和标准错误，每路 16 MiB 到达硬上限就终止整个 docker 进程组，之后才允许发布结果。
清理过程可以枚举资源用于检查，但只删除携带回执精确令牌或唯一项目标签的资源，不使用前缀、通配、标签
选择器或 `prune`。容器、网络和卷残留必须连续三次观察为零后，才允许提交
`verification_case_completed`。结果发布和验证事件之前还必须使用固定快照完成 docker compose 清理；
无法证明清理完成时返回 `DOCKER_CASE_CLEANUP_FAILED`，撤销判定依据的命中状态并保持 `blocked`。

绑定源的身份检查发生在文件系统解析之前。相对源路径按规范化审计工作区做词法解释；父目录组件和
路径别名会被拒绝；目标仓库与 `poc/` 路径中所有已经存在的组件都必须由 `lstat` 证明为真实目录。
`/workspace/output` 不接受任何宿主机绑定挂载，而由容器内固定大小的 tmpfs 提供；宿主机临时目录只能由
安全辅助程序创建，并在访问 docker 前再次检查。引导程序也会在任何工作区写入前执行同样的从严检查，
因此预先存在的符号链接、普通文件、FIFO、套接字、设备或其他非目录条目不会被跟随。

封装脚本会在每一次 docker compose `config`、`pull` 和 `run` 前重复检查宿主机绑定目录，并比较上一次检查记录的
低敏目录身份。版本化身份把每个已有路径组件的稳定 `device`、`inode`、`type`、`mode`、`uid`、`gid` 与叶目录的
修改时间和链接数观察值分开。任何稳定身份变化都会从严拒绝；目标路径与 `poc/` 的观察值也继续严格比较。
这是重新校验，不是宿主机路径的原子固定。当前平台边界假定受信任的工作区所有者不会在宿主机检查到
docker 调用的短暂窗口中并发替换目录。该重新校验并不构成原子固定，实现也没有声称消除操作系统层面的
检查与使用之间的竞态窗口（TOCTOU）。

初始探测仍然只是建议性结果，最多提供候选项材料。没有经过单独审计的固定 docker 封装脚本时，Maven/Gradle
项目求值和可由目标配置的 golangci-lint 插件加载不会在宿主机运行，而会记录为
`skipped_requires_isolation`。该状态不是通过，也不授权 Agent 或操作者手工执行等价宿主命令。npm 调用
禁用生命周期脚本，Go 包加载强制使用只读模块模式。引导程序的工作区名称只能
是安全的 ASCII 单目录组件，并且目标必须是真实目录的直接子级。

`blocked_verification.py` 先消费结构化验证结果、核验结论、处置记录和规范化事件。按案例/候选项身份，
未解决的 `blocked_*`、超时、不安全沙箱、镜像/运行时缺失或权威事件失败会阻止完成；只有同一身份后续的
结构化结果才能解除阻塞项。历史 R1 可以保留保守文本回退，但会跳过文档示例和已解决句子。

可发布的 R1 文本、`tested_ref`、交接状态和检查点使用同一个可移植文本分类器。本机绝对路径、凭据、私钥、
令牌和控制字符在追加/发布前拒绝，错误只返回稳定类别而不回显原值。正常 SHA-1/SHA-256、标签、分支、
不含凭据的 URL 以及工作区相对证据路径仍可通过。新的 R1 状态使用逻辑工作区/仓库标识，不再写入解析后的
宿主机路径。

工具注册表将 `prohibited` 视为唯一边界：工具效果、封装脚本、权限、主动网络和规划器能力必须分别为空或
`prohibited`。收尾必须存在并安全读取当前的 `docker/docker-cleanliness-status.json`，且同时
为 `clean=true`、`strict=true`；`finalization_succeeded` 事件还必须绑定相对路径、SHA-256、工作区
和 `checked_at`。缺失、过期、符号链接、摘要不匹配、工作区不匹配或手写配对都会被断言拒绝。

`audit-disposition.json` 通过宿主机持有的安全输入/输出路径发布。写入器会拒绝不安全祖先，以及非当前用户拥有、
存在多链接或不是普通文件的目标；随后在同一目录写临时文件，依次完成文件 `fsync`、身份 CAS、原子替换和
目录 `fsync`。发布后必须安全重开磁盘对象，按磁盘字节重新校验结构定义、候选项/核验结论绑定及适用的一对一
确认链。写入、`fsync`、替换、CAS 或写后校验失败时恢复旧账本字节；若恢复本身失败，则返回可区分的错误。

成功收尾时，摘要和交接状态会先针对准确的预期终态事件日志/状态快照生成并校验，再追加
`finalization_succeeded`。该终态事件是最后一次权威提交，之后只执行只读断言。若事件日志已追加而状态视图
更新失败，事件日志继续保持权威，诊断要求显式重建状态视图。对全部一致的已完成工作区重跑收尾程序时不会
改写字节、重跑 docker 检查或追加重复终态；权威链或派生产物出现差异会从严拒绝，并要求显式 `recover` 或
`reopen`。
