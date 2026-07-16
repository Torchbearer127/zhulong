# 烛龙工作流细节

本文档包含 README 之外的详细运行规则，适合需要深入了解烛龙机制的运行者阅读。

英文版请阅读 [`WORKFLOW_DETAILS.md`](WORKFLOW_DETAILS.md)。

## 人机协同

烛龙将审计工作区视为 Agent 与人工审核员共享的协作平面。关键状态会写入轻量且明确的文件，而不是困在冗长的对话记录或海量的原始扫描日志中。

- **Agent 接力**：Agent 可以通过 `handoff-summary.md`、`stage-status.json` 和 `audit-disposition.json` 快速掌握进度。
- **人工审计**：审核员可以优先查阅 `attack-surface.md`、`candidate-findings.md`、`false-positives.md`、`unverified-leads.md` 和 `SUMMARY.md`，无需手动翻阅全量日志。
- **流程演进**：维护者可以通过优化脚本、参考契约和校验器来演进工作流，而不是不断膨胀启动提示词。
- **结果复核**：审核员可以直接审查已确认漏洞包，无需重新拼接证据、命令、Payload 与报告结论之间的对应关系。

## 交接与状态的机械一致性

`handoff-summary.md` 是运行接力包。它必须描述机械化工作区状态，而不是把备注或
部分证据解释成最乐观结论。

状态生成器和完成门禁共用 `scripts/workspace_state.py` 作为状态检查层：

- `confirmed_bundle_dirs_total` 统计 `confirmed/` 下非隐藏目录数量。
- `validated_confirmed_bundle_count` 只统计通过
  `validate_all_report_bundles.py` 最终校验的确认漏洞包目录。
- `invalid_or_partial_confirmed_bundle_count` 统计被校验器判定为不完整或校验失败的
  疑似漏洞包目录。
- `docker_evidence_only_count` 统计工作区证据目录下的 Docker 或核验证据；这些证据
  尚未组成通过校验的确认漏洞包。
- `formal_variant_analysis_status` 只有在至少存在一个通过校验的确认漏洞包，且
  `evidence/variant-analysis/seeds.jsonl` 与 `variant-candidates.jsonl`
  都通过各自校验器时才是 `completed`。

当没有通过校验的确认漏洞包时，交接摘要必须写 `Confirmed bundles: 0`。如果存在
Docker 证据但没有通过校验的漏洞包，保守状态是
`docker_evidence_collected_but_no_bundle`。在这个状态下，Docker 证据可以作为
有用核验材料，但它不是已确认交付物，不能表示漏洞包已经就绪，也不能表示正式同类
漏洞扩展已经完成或就绪。

人工同类备注、种子草稿、候选记录、代码级证据、不完整漏洞包和校验失败目录，都只能
保留为人工或未验证的工作区材料，直到真实的 `confirmed/<bundle>/` 通过最终校验。
`validate_workspace_state.py`、`assert_finalized_workspace.py` 和审计收尾门禁会拒绝
与实际产物矛盾的过期交接或状态文案。

## 运行时残留与清理机制

烛龙会把 Docker 残留资源和 OMC/PID 运行时残留分开处理。二者都会出现在工作区产物和交接摘要中，但安全策略不同：

| 类型 | 记录位置 | 默认行为 | 用户或 Agent 可做什么 |
| --- | --- | --- | --- |
| Docker 容器、镜像、网络、卷、BuildKit cache | `docker/docker-cleanup-plan.json`、`docker/docker-cleanliness-status.json`、`handoff-summary.md` | 先生成清理计划；默认试运行；只自动处理能证明属于当前审计的资源。 | 人工审核计划后，可授权 Agent 使用精确参数和 `--apply` 清理。 |
| OMC 滞留 Socket | `runtime/runtime-hygiene-status.json`、`handoff-summary.md` | 只清理确认为滞留且无活跃 swarm Socket 的 `claude-swarm-*` Socket。 | 可以运行 `--cleanup-stale` 后重新检查。 |
| 可疑 `claude --teammate-mode tmux` PID | `runtime/runtime-hygiene-status.json`、`handoff-summary.md` | 只读复核；烛龙不会发送终止信号或强制结束命令。 | 用户可根据 `pid/ppid/pgid/sess/tty/stat/command` 等信息自行判断；如确认过期，应在烛龙之外手动处理。 |

Docker 清理推荐流程是先查看计划，再决定是否授权清理：

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

如果 `clean=false`，工作区应保持阻塞状态，并在摘要中写明残留资源和安全续跑步骤。烛龙不会通过重写 Docker 初始基线来隐藏残留，也不会信任过期的 `docker-cleanliness-status.json` 作为完成依据。

OMC/PID 复核流程只用于判断多 Agent 模式是否安全：

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

如果只存在滞留 Socket，且没有活跃 swarm socket，可清理 Socket 后重查：

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --cleanup-stale --json
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

如果报告可疑 teammate PID，烛龙只会展示复核信息，不会杀进程。即使启用 PID 复核或清理相关选项，当前烛龙也不会对 teammate PID 发送信号。用户如果确认某个 PID 确实过期，应在烛龙之外手动处理，或在明确了解风险后授权 Agent 使用系统级进程工具处理；不要把 PID 清理并入 Docker 清理，也不要使用大范围进程清理。

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

生成合同预检只检查被选中的单个漏洞是否具备可移植、已通过 Docker 确认、且足以
生成审核材料的最低输入。它只是生成前门禁，不能证明漏洞成立，也不能替代 Docker
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
- 附件 Docker Compose 的静态自洽性，包括缺失相对 `env_file`、缺失相对 bind mount 源文件，以及最终包中不允许出现的绝对宿主机路径。
- 中文 (zh-CN) 报告中无故出现大段英文自然语言。
- 在存在结构化证据字段时，校验目标与命令一致性。
- 根脚本或附件脚本通过深层 `../../..` 逃出下载后的漏洞包，或挂载提交者本机父级仓库。
- 报告、补充说明、证据 JSON 与根录屏脚本之间的 PoC 标签漂移。
- 录屏视频早于当前报告、补充说明、证据 JSON 或根复现脚本。
- 最短审核复现路径中可能触发生命周期脚本或联网噪音的 `npm install` / `yarn install` / `pnpm install`。
- 复现脚本只展示 PoC/Docker 命令却没有实际执行路径。
- 复现脚本没有把 `测试软件名称` 与 `测试版本/分支` 作为独立开场字段展示，或缺少开场身份屏/最终证据汇总屏停顿。
- 复现脚本缺少可覆盖的 `REVIEWER_PAUSE_SHORT` / `REVIEWER_PAUSE_LONG`，
  在 quick 模式中改用固定短暂停顿，或缺少代码上下文、代码级分析、影响边界、
  proof 命令/输出、最终证据汇总之后的审核停顿。
- 复现脚本把 reviewer pause 变量复用于服务 readiness、health polling、启动重试或
  backoff；reviewer pause 只用于录屏视觉停留，功能性等待必须使用独立的
  readiness/backoff 变量。
- 补充复现说明或证据索引引用了漏洞包中不存在的本地辅助脚本。
- 缺少直接影响复现证据，例如 `DIRECT_IMPACT_CONFIRMED`、`DIRECT_AVAILABILITY_IMPACT_CONFIRMED` 或等价的程序化危害判据。
- DOCX 面向审核人的正文中泄漏 Python/JSON 风格的 dict/list/object 中间结构，而不是正常报告 prose。
- 运行时/版本身份只使用 `latest`、浮动镜像 tag、`main`、`master` 或含糊的“current version/当前版本”，且没有稳定版本号、commit、digest 或测试日期。
- DOCX、补充说明、复现辅助脚本、`verification-evidence.json`、审核证据索引与已登记的
  复现日志之间，直接影响标记不一致。
- 已登记的复现日志为空、仅含占位符或标记，或缺少命令、原始输出、成功判据等真实
  运行信号；不得通过手工追加直接影响标记让内容过薄的日志通过校验。
- 复制或沿用的历史成功复现记录缺少 `bundle-build-manifest.json` 或审核材料中的可移植
  来源说明。
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
并明确这些门禁只会拒绝薄弱审核材料，不能证明漏洞成立，也不能替代 Docker 证据。

`code_level_reproduced`、`entrypoint_reproduced`、
`blocked_entrypoint_verification` 与 `confirmed_in_docker` 等证据等级定义见
[`runner-contracts/finding-contract-r1.md`](runner-contracts/finding-contract-r1.md)。
代码级或函数级复现只能作为辅助证据；漏洞包就绪需要攻击者入口复现、
入口输入形态、入口到危险汇聚点的路径，以及稳定的直接影响判据。

## 基于已确认种子漏洞的同类漏洞扩展

当一份漏洞产出合格的确认漏洞包后，烛龙可将其作为**种子漏洞**，提取根因、攻击者
可控输入、传播路径、危险汇聚点、缺失约束与 Docker 成功判据，再依据这些特征在同一
目标仓库中检索相似候选漏洞。该机制只用于安排后续人工复核和 Docker 验证的优先级，
不会把相似度本身当作漏洞成立的证据。

同类漏洞扩展流程分为两个离线执行步骤：

1. 执行 `scripts/extract_variant_seed.py`，从已有的确认漏洞包中提取同类漏洞种子卡。
   种子卡记录确认漏洞包路径、漏洞类型、根因、输入与汇聚点匹配模式、触发条件、
   Docker 成功判据、检索范围以及排除规则。
2. 执行 `scripts/find_variant_candidates.py`，读取种子卡，在同一目标仓库内扫描本地
   源码并输出按优先级排序的同类候选漏洞。候选结果默认写入
   `<audit-workspace>/evidence/variant-analysis/variant-candidates.jsonl`；每条记录必须
   保持 `status=candidate`，其中的文件路径统一使用仓库相对路径。

本流程设有多条硬性约束边界：

- 最终种子卡只有在 `confirmed_bundle_path` 指向当前审计工作区内真实的
  `confirmed/<bundle>/` 目录，且该漏洞包通过 `validate_report_bundle.py` 时才会被
  接受。候选编号、Markdown 表格行、临时备注、Docker 证据目录、不完整漏洞包或校验
  失败的漏洞包都不能作为正式种子；人工同类备注必须留在正式
  `evidence/variant-analysis/seeds.jsonl` 之外。
- 候选检索工具只读取最终种子卡，并在同一仓库内进行本地、可重复的优先级排序。它
  不调用扫描器、`rg`、`grep`、`git`、网络接口、LLM、Docker、PoC、DOCX 渲染或确认
  漏洞包生成。
- 种子卡与候选列表仅作为辅助研判资料，无法替代 `verification-evidence.json`、
  `findings.json`、DOCX 报告、补充复现说明、附件索引、复现日志、Docker 核验材料
  以及确认漏洞包的校验结果。
- 同类候选漏洞禁止在补充说明、确认漏洞包、审阅备注、最终摘要里标注为已确认漏洞。候选漏洞只有完成独立 Docker 或 Docker Compose 环境复现，且通过确认漏洞包校验流程后，才可升级判定为已确认同类漏洞。
- 候选检索工具仅支持在单一目标仓库内运行。若种子卡配置的检索范围不属于当前仓库、
  工作区路径匹配异常，或确认漏洞包路径无法解析至当前工作区的 `confirmed/` 目录，
  工具必须直接报错终止运行。
- 确认漏洞包禁止将 `variant-candidates.jsonl` 作为核心佐证材料，也不能把候选排序分值、种子匹配相似度、候选记录本身当作漏洞核验通过的依据。
- 对于以 `completed_with_confirmed_bundles` 收尾的新审计，完成门禁会要求 `evidence/variant-analysis/seeds.jsonl` 与 `evidence/variant-analysis/variant-candidates.jsonl` 已存在并通过校验。也就是说，同类扩展不再是审计结束后的人工提醒，而是确认漏洞包流程里的必做收尾步骤。

推荐复核顺序：先校验种子卡是否准确描述已确认漏洞可稳定复现的根因，再核查候选列表
中的所有条目是否都保持候选状态，最后针对有跟进价值的候选漏洞单独搭建 Docker 环境
完成复现验证。配套校验命令如下：

```bash
python3 scripts/validate_report_bundle.py --workspace-dir <audit-workspace> --variant-seed-card <seed-card.json>
python3 scripts/validate_report_bundle.py --workspace-dir <audit-workspace> --variant-candidates <variant-candidates.jsonl>
```

若某一条同类候选漏洞最终核验确认成立，它仍需和常规已确认漏洞保持一致标准：具备
独立 Docker 复现流程、复现与直接影响佐证文件、`verification-evidence.json`，以及
校验合格的确认漏洞包。

面向审核与录屏的根脚本应从脚本自身位置推导漏洞包根目录，使用相对该目录的
`attachments/`；脚本要么从漏洞包内附件自举 Docker 环境，要么在最前面明确失败并
告诉审核员应先运行哪条漏洞包内命令。
脚本在 `docker exec` 前应检查目标容器是否存在且运行；触发漏洞前应尽量做健康/就绪检查；关键 Docker、curl 或 token 生成命令失败时应输出捕获到的错误上下文，而不是裸用 `2>/dev/null` 吞掉原因。
嵌套附件目录内的无害 `../` 可以存在，但最终路径必须仍位于单个漏洞包内；脚本不能
依赖提交者完整的本机仓库布局。

## 示例审计发现形态

```text
状态：已确认
标题：文件导入 URL 获取导致服务端请求伪造（SSRF）
严重性：高
证据：Docker 复现中观察到受攻击者控制的回连请求
攻击者条件：具备导入权限的低权限认证用户
服务端条件：默认导入接口启用，且服务端可访问内网/外网
安全影响：机密性风险，可探测内网服务或访问元数据
实际场景中的危害与利用方式：真实部署中导入功能会处理用户提交的 URL；具备导入权限的攻击者控制该 URL；请求链路到达服务端 URL 获取逻辑；直接危害由回连请求或存储响应内容证明；Docker 证据验证 SSRF 可达性，但不声称代码执行。
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

Codex 用户级 Skill 也已支持。它使用同一套布局契约、安装目录自检、平台无关启动入口和仓库根目录 `AGENTS.md` 引导文件；详见
[`CODEX_SKILL_ADAPTATION.md`](CODEX_SKILL_ADAPTATION.md)。同步后，
`~/.agents/skills/zhulong/` 是受支持的 Codex 安装 Skill 副本：

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

如果预检失败，应修正生成合同或上游 Docker 证据，不要通过创建仅含标记的复现日志，
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
- 烛龙不会自动登录镜像仓库 (Registry)，也不会静默替换非等效的 Docker 镜像。
- 烛龙不会清理归属不确定的 Docker 资源或 OMC 多 Agent 工作进程。
- 烛龙不提供托管的后端服务、数据看板、数据库、向量存储或 RAG 服务。

## 可选最终录屏流程

普通确认漏洞包流程在 Docker 和报告校验通过后结束。最终审核录屏需要单独明确启用；
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
录制会话。旧的本地录制 Skill 仅作兼容包装，不是事实源。

`--keep-unpromoted-archive DIR` 是可选参数，绝不会写入采用最终名称的 ZIP。只有暂存
ZIP 已完整通过校验、随后提升失败时，才会向用户明确指定且位于漏洞包之外的目录复制
未提升诊断归档；它不会覆盖已有诊断副本。旧参数 `--zip-on-fail` 仅输出弃用警告，
不会生成失败归档。
