# 烛龙工作流细节

本文档包含 README 之外的详细运行规则，适合需要深入了解烛龙机制的运行者阅读。

英文版请阅读 [`WORKFLOW_DETAILS.md`](WORKFLOW_DETAILS.md)。

## 人机协同

烛龙将审计工作区视为 Agent 与人工审核员共享的协作平面。关键状态会写入轻量且明确的文件，而不是困在冗长的对话记录或海量的原始扫描日志中。

- **Agent 接力**：Agent 可以通过 `handoff-summary.md`、`stage-status.json` 和 `audit-disposition.json` 快速掌握进度。
- **人工审计**：审核员可以优先查阅 `attack-surface.md`、`candidate-findings.md`、`false-positives.md`、`unverified-leads.md` 和 `SUMMARY.md`，无需手动翻阅全量日志。
- **流程演进**：维护者可以通过优化脚本、参考契约和校验器来演进工作流，而不是不断膨胀启动提示词。
- **结果复核**：审核员可以直接审查已确认漏洞包，无需重新拼接证据、命令、Payload 与报告结论之间的对应关系。

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

## confirmed bundle 短路径

P8 将 confirmed bundle 生成收束为一条固定短路径：

```text
bundle contract preflight
-> staging build wrapper
-> staging final validation
-> promote
-> validate all
-> seeded variant discovery
-> finalization
```

bundle contract preflight 只检查被选中的单个 finding 是否具备可移植、Docker
已确认、面向审核材料生成所需的最低输入。它只是生成前门禁，不能证明漏洞成立，
也不能替代 Docker 证据。

contract 字段必须能对应到 renderer 输出、final validator 或 batch gate，以及
confirmed bundle 内的证据产物。无法建立这些对应关系的字段，不应加入 contract。

contract 中的 `finding.severity` 使用稳定枚举：`Critical`、`High`、`Medium`、
`Low`、`Informational`；最终审核材料可以按输出语言本地化展示。`finding.bug_class`
和 `impact_tier.bug_class` 保持 free text，并在 checklist 中给出 recommended values，
因为真实项目中的漏洞类别可能是项目特定或复合分类。

staging build wrapper 会先渲染到 `confirmed/.staging/<slug>`，并在该目录运行同一套
最终 bundle validator；只有校验通过后才 promote 到 `confirmed/<slug>`。失败的
staging 目录只能作为调试材料，不是 confirmed deliverable。promote 后还必须运行
`validate_all_report_bundles.py`，再进入 seeded variant discovery 与 finalization。

默认最终校验仍保持 fail-fast。`validate_report_bundle.py --all-errors` 只是 staging
或最终校验失败时的诊断模式，用来一次性收集可处理问题；它不会修复 bundle，
不会放宽 validator，也不能确认漏洞。

replay log 必须是真实的命令、输出、oracle transcript。marker-only replay log
无效，手工追加 direct-impact marker 的薄日志也无效。复制来的成功 transcript
必须有可移植来源说明，例如 `bundle-build-manifest.json` 或面向审核的证据材料。

`assets/fixtures/replay-transcript-corpus/` 中的 replay transcript corpus
用静态正负样本固定这条信任边界。校验器不要求 single rigid log format：只要是真实
命令、原始输出、oracle、退出/通过结果与 direct-impact 证据构成的 transcript，
可以有不同日志形态；marker-only、placeholder-only、thin explanatory、缺少 oracle
的薄日志，以及缺少 provenance 的 copied transcript 仍会被拒绝。

seeded variant discovery 始终保持候选态。`seeds.jsonl` 与
`variant-candidates.jsonl` 是 confirmed bundle 审计的收尾产物，但候选排序与种子相似度
不能作为确认漏洞的证据。

## 报告质量门禁

所有已确认 (Confirmed) 报告必须清晰说明：

- 攻击者条件
- 服务端条件
- 具体安全影响
- 实际场景中的危害与利用方式：真实使用场景、攻击者可控输入、触发调用链、直接业务或安全后果，以及已验证影响和未声称影响的边界

校验器 (Validator) 还会检测常见的逻辑矛盾，例如：

- 标题或正文声称“无需认证 (No-auth)”，但 CVSS 评分或复现证据显示需要权限。
- PoC 脚本在没有明确成功判据 (Success Oracle) 的情况下直接输出成功结论。
- 在最终确认横幅之前使用 `grep ... || echo ...`、`grep ... || true`、
  `jq ... || true`、`curl ... || true` 或
  `docker logs ... | grep ... || echo ...` 这类 fail-open 成功判据。
- 复现录屏脚本的步骤标签 (Step Label) 过期或格式异常。
- bundle 根录制脚本的 shell 静态语法和可执行位。
- 附件 Docker Compose 的静态自洽性，包括缺失相对 `env_file`、缺失相对 bind mount 源文件，以及最终包中不允许出现的绝对宿主机路径。
- 中文 (zh-CN) 报告中无故出现大段英文自然语言。
- 在存在结构化证据字段时，校验目标与命令一致性。
- 根脚本或附件脚本通过深层 `../../..` 逃出下载后的 bundle，或挂载提交者本机父级仓库。
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
- 补充复现说明或证据索引引用了 bundle 中不存在的本地 helper 脚本。
- 缺少 direct-impact replay 证据，例如 `DIRECT_IMPACT_CONFIRMED`、`DIRECT_AVAILABILITY_IMPACT_CONFIRMED` 或等价的程序化危害判据。
- DOCX 面向审核人的正文中泄漏 Python/JSON 风格的 dict/list/object 中间结构，而不是正常报告 prose。
- 运行时/版本身份只使用 `latest`、浮动镜像 tag、`main`、`master` 或含糊的“current version/当前版本”，且没有稳定版本号、commit、digest 或测试日期。
- DOCX、补充说明、replay helper、`verification-evidence.json`、reviewer evidence index 与已注册 replay `.log` 中的 direct-impact marker 不一致。
- 已注册 replay `.log` 为空、占位、仅包含 marker，或缺少命令、原始输出、oracle
  检查等真实转录信号；不得通过手工追加 direct-impact marker 让薄日志通过校验。
- 复制或历史成功 replay transcript 缺少 `bundle-build-manifest.json` 或审核材料中的可移植来源说明。
- SSRF 影响层级漂移，例如实际只证明 callback/请求可达，却在没有产物级
  oracle 的情况下声称响应内容、配置、凭据或敏感数据泄露。
- 根 replay helper 的 readiness/health 检查指向与 PoC/proof 命令无关的 host/path。
- 可选 `reviewer-evidence-and-impact.md` 仅为占位，或缺少攻击者边界、影响说明、成功判据和最短复现命令。
- 可选 `attachments/reviewer-evidence-index.json` JSON 无效、引用缺失附件、引用 bundle 外路径、复现命令不是 bundle 根目录本地命令，或列出的成功判据无法在脚本/证据/补充说明/审核补充/`verification-evidence.json` 中找到。
- fixture 或 vendored source 复现缺少 source-grounded provenance，或库/包漏洞缺少 consuming application boundary。
- severity / claim 矛盾，例如 High CVSS 与正文 Medium 冲突、webshell/HTTP 命令执行声明缺少对应 oracle，或容器逃逸/宿主机 RCE/匿名公开触发声明缺少明确非声明边界。

这些检查刻意保持保守，目标是降低误报，并确保已确认漏洞包的契约稳定性。

SSRF 影响过度声明、代码上下文最低质量、replay helper 暂停契约等
reviewer-readiness gate 的分类说明见
[`../assets/references/reviewer-readiness-validator-gates.md`](../assets/references/reviewer-readiness-validator-gates.md)。
该参考文件记录每类 gate 的目的、误报边界、接受/拒绝示例、适用的稳定
issue code，以及这些 gate 只会拒绝薄弱审核材料，不能证明漏洞成立，也不能替代
Docker 证据。

## 基于已确认种子漏洞的同类漏洞扩展

当一份漏洞产出合规可用的确认漏洞包后，烛龙可将其视作**种子漏洞**，提取根因、攻击者可控输入、传播路径、危险汇聚点、缺失约束与 Docker 成功判据，依托这些特征在同一个目标仓库中检索相似候选漏洞。该机制仅用于提升后续人工复核与 Docker 验证的处理优先级，不会将相似度本身视作漏洞成立的有效凭证。

同类漏洞扩展流程分为两个离线执行步骤：

1. 执行 `scripts/extract_variant_seed.py`，从已有的确认漏洞包中提取同类漏洞种子卡。种子卡会记录确认漏洞包路径、漏洞类型、根因、输入与汇聚点匹配模式、触发条件、Docker 成功判据、检索范围以及排除规则。
2. 执行 `scripts/find_variant_candidates.py`，读取生成完毕的种子卡，在同一目标仓库内扫描本地源码文件，输出完成优先级排序的同类候选漏洞。候选结果默认输出至路径 `<audit-workspace>/evidence/variant-analysis/variant-candidates.jsonl`，每条记录的状态字段必须固定为 `status=candidate`，文件内全部路径统一采用仓库相对路径。

本流程设有多条硬性约束边界：

- P6.1 确立同类漏洞扩展的流程边界。P6.2 定义 Variant Seed Card 字段，但不实现自动种子提取或候选发现。
- P6.4 增加 `scripts/find_variant_candidates.py`，这是一个离线 helper，只读取最终 Variant Seed Card，并在同一目标仓库内对候选进行排序；它仅使用本地 Python 文件系统遍历，不调用扫描器、`rg`、`grep`、`git`、网络 API、LLM、Docker、PoC、DOCX 渲染或确认漏洞包生成。
- 种子卡与候选列表仅作为辅助研判资料，无法替代 `verification-evidence.json`、findings JSON、DOCX 报告、补充复现说明、附件索引、replay 日志、Docker 核验材料以及确认漏洞包的校验结果。
- 同类候选漏洞禁止在补充说明、确认漏洞包、审阅备注、最终摘要里标注为已确认漏洞。候选漏洞只有完成独立 Docker 或 Docker Compose 环境复现，且通过确认漏洞包校验流程后，才可升级判定为已确认同类漏洞。
- 候选漏洞检索工具仅支持在单一目标仓库内运行。若种子卡配置的检索范围不属于当前仓库、工作区路径匹配异常，或是确认漏洞包路径无法解析至当前工作区的 `confirmed/` 目录，工具必须直接报错终止运行。
- 候选检索逻辑不会调用网络 API、LLM、Docker、PoC、扫描器、DOCX 渲染、确认漏洞包生成等能力，仅执行本地、结果可稳定复现的候选优先级排序运算。
- 确认漏洞包禁止将 `variant-candidates.jsonl` 作为核心佐证材料，也不能把候选排序分值、种子匹配相似度、候选记录本身当作漏洞核验通过的依据。
- 对于以 `completed_with_confirmed_bundles` 收尾的新审计，完成门禁会要求 `evidence/variant-analysis/seeds.jsonl` 与 `evidence/variant-analysis/variant-candidates.jsonl` 已存在并通过校验。也就是说，同类扩展不再是审计结束后的人工提醒，而是确认漏洞包流程里的必做收尾步骤。

推荐复核操作顺序：首先校验种子卡是否精准描述已确认漏洞可稳定复现的根因；其次核查候选列表内所有条目是否均维持候选状态；最后针对有跟进价值的候选漏洞，单独搭建 Docker 环境完成复现验证。配套校验命令如下：

```bash
python3 scripts/validate_report_bundle.py --variant-seed-card <seed-card.json>
python3 scripts/validate_report_bundle.py --variant-candidates <variant-candidates.jsonl>
```

若某一条同类候选漏洞最终核验确认成立，它仍需和常规已确认漏洞保持一致标准：具备独立 Docker 复现流程、replay/直接影响佐证文件、`verification-evidence.json` 凭证，以及校验合格的确认漏洞包。

面向审核/录屏的根脚本应从脚本自身位置推导 bundle 根目录，使用相对该目录的
`attachments/`，并且要么从 bundle-local 附件自举 Docker 环境，要么在最前面清晰失败并告诉审核员应先运行哪条 bundle-local 命令。
脚本在 `docker exec` 前应检查目标容器是否存在且运行；触发漏洞前应尽量做健康/就绪检查；关键 Docker、curl 或 token 生成命令失败时应输出捕获到的错误上下文，而不是裸用 `2>/dev/null` 吞掉原因。
嵌套附件目录内的无害 `../` 可以存在，但必须仍解析到单个漏洞 bundle 内；脚本不能依赖提交者完整本机仓库布局。

## 示例审计发现形态

```text
状态：已确认 (Confirmed)
标题：文件导入 URL Fetch 导致服务端请求伪造 (SSRF)
严重性：高 (High)
证据：Docker 复现中观察到受攻击者控制的回连请求 (Callback)
攻击者条件：具备导入权限的低权限认证用户
服务端条件：默认导入接口启用，且服务端可访问内网/外网
安全影响：机密性风险，可探测内网服务或访问元数据 (Metadata)
实际场景中的危害与利用方式：真实部署中导入功能会处理用户提交的 URL；具备导入权限的攻击者控制该 URL；请求链路到达服务端 URL Fetch 逻辑；直接危害由回连请求或存储响应内容证明；Docker 证据验证 SSRF 可达性，但不声称代码执行。
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

默认最终 bundle 校验保持 fail-fast。若 staging 或最终校验失败，需要一次性查看
高频结构问题，可显式启用诊断型 all-errors collector：

```bash
python3 scripts/validate_report_bundle.py \
  --bundle-dir <bundle-dir> \
  --all-errors \
  --json \
  --output-errors <bundle-dir>/bundle-validation-errors.json
```

all-errors 报告只用于诊断，不会修复 bundle，也不能确认漏洞。应修正上游 contract、
证据或审核材料后，再重新运行校验。

生成最终 `confirmed/<slug>/` 产物之前，先根据
`assets/references/bundle-contract-template.json` 填写
`<audit-workspace>/confirmed/.contracts/<slug>.bundle-contract.json`，用
`render` 字段指向被选中的源 finding，然后运行：

```bash
python3 scripts/validate_bundle_contract.py \
  --workspace-dir <audit-workspace> \
  --contract <contract> \
  --all-errors
```

如果 preflight 失败，应修正 contract 或上游 Docker 证据，不要通过创建
marker-only replay log 或反应式改 direct-impact marker 来绕过。这个 preflight
只负责生成前门禁，最终仍必须运行已确认漏洞包校验。

随后通过 staging wrapper 构建：

```bash
python3 scripts/build_confirmed_bundle.py \
  --workspace-dir <audit-workspace> \
  --contract <contract> \
  --language <zh-CN|en-US>
```

不要手写最终 `confirmed/<slug>/` 目录。wrapper 会只渲染被 contract 选中的
单个 finding 到 `confirmed/.staging/<slug>`，通过最终 bundle 校验后才 promote，
并在 promote 后运行批量校验。失败构建只能留在 `confirmed/.staging/`，不得称为
confirmed deliverable。最终审计完成仍必须通过既有的同类漏洞扩展和 finalization
门禁。
wrapper 默认不执行 replay。它会在可用时记录 bundled evidence 中 replay log 的
provenance，最终由 bundle validator 判断已注册 replay log 是否是可信 transcript。

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
