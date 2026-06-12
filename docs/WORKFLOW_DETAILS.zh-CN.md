# 烛龙工作流细节

本文档包含 README 之外的详细运行规则，适合需要深入了解烛龙机制的运行者阅读。

英文版请阅读 [`WORKFLOW_DETAILS.md`](WORKFLOW_DETAILS.md)。

## 人机协同

烛龙将审计工作区 (Workspace) 视为 Agent 与人工审核员共享的协作平面。关键状态会写入轻量且明确的文件，而不是困在冗长的对话记录或海量的原始扫描日志中。

- **Agent 接力**：Agent 可以通过 `handoff-summary.md`、`stage-status.json` 和 `audit-disposition.json` 快速掌握进度。
- **人工审计**：审核员可以优先查阅 `attack-surface.md`、`candidate-findings.md`、`false-positives.md`、`unverified-leads.md` 和 `SUMMARY.md`，无需手动翻阅全量日志。
- **流程演进**：维护者可以通过优化脚本、参考契约和校验器 (Validator) 来演进工作流，而不是不断膨胀启动 Prompt。
- **结果复核**：审核员可以直接审查已确认漏洞包，无需重新拼接证据、命令、Payload 与报告结论之间的对应关系。

## 运行时残留与清理机制

烛龙会把 Docker 残留资源和 OMC/PID 运行时残留分开处理。二者都会出现在工作区产物和交接摘要中，但安全策略不同：

| 类型 | 记录位置 | 默认行为 | 用户或 Agent 可做什么 |
| --- | --- | --- | --- |
| Docker 容器、镜像、网络、卷、BuildKit cache | `docker/docker-cleanup-plan.json`、`docker/docker-cleanliness-status.json`、`handoff-summary.md` | 先生成清理计划；默认试运行；只自动处理能证明属于当前审计的资源。 | 人工审核计划后，可授权 Agent 使用精确参数和 `--apply` 清理。 |
| OMC 滞留 Socket | `runtime/runtime-hygiene-status.json`、`handoff-summary.md` | 只清理确认为滞留且无活跃 swarm socket 的 `claude-swarm-*` Socket。 | 可以运行 `--cleanup-stale` 后重新检查。 |
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
- 补充复现说明或证据索引引用了 bundle 中不存在的本地 helper 脚本。
- 缺少 direct-impact replay 证据，例如 `DIRECT_IMPACT_CONFIRMED`、`DIRECT_AVAILABILITY_IMPACT_CONFIRMED` 或等价的程序化危害判据。
- 可选 `reviewer-evidence-and-impact.md` 仅为占位，或缺少攻击者边界、影响说明、成功判据和最短复现命令。
- 可选 `attachments/reviewer-evidence-index.json` JSON 无效、引用缺失附件、引用 bundle 外路径、复现命令不是 bundle 根目录本地命令，或列出的成功判据无法在脚本/证据/补充说明/审核补充/`verification-evidence.json` 中找到。
- fixture 或 vendored source 复现缺少 source-grounded provenance，或库/包漏洞缺少 consuming application boundary。
- severity / claim 矛盾，例如 High CVSS 与正文 Medium 冲突、webshell/HTTP 命令执行声明缺少对应 oracle，或容器逃逸/宿主机 RCE/匿名公开触发声明缺少明确非声明边界。

这些检查刻意保持保守，目标是降低误报，并确保已确认漏洞包的契约稳定性。

## 基于 confirmed seed 的同类漏洞扩展（P6.1/P6.2）

- confirmed seed（已确认种子）是已产生有效 confirmed bundle、可复现 Docker 证据、且完成严重性升级复核的确认漏洞。
- variant candidate（同类/变体候选）是基于已确认种子产生的候选材料，默认归入候选材料池，不可直接当作已确认。
- confirmed variant（已确认同类）必须拥有独立的 Docker 重现通过与 `verification_status=confirmed_in_docker` 的完整 bundle 验证；与 seed 的相似性只能作为优先级线索。
- 同类候选的路由状态仅为：
  `candidate`、`blocked`、`false_positive`、`unverified`、`confirmed_in_docker`。
- 同类候选不得在补充说明、结论包、审阅说明等面向确认材料中被当作已确认结论直接写出；只有完成独立 Docker 重现和 bundle 验证后才可进入 `confirmed_in_docker`。
- P6.1 建立同类扩展流程边界。P6.2 定义 Variant Seed Card 字段，但不实现自动 seed 抽取或候选发现。
- P6.3 增加 `scripts/extract_variant_seed.py` 离线辅助脚本，用于从一个既有 confirmed bundle 抽取 Variant Seed Card。它不执行 PoC、不运行 Docker、不搜索仓库、不排序候选，也不确认同类漏洞。
- P6.4 增加 `scripts/find_variant_candidates.py` 离线辅助脚本，用于读取一张最终 Variant Seed Card，并在同一目标仓库内排序同类候选。它只使用本地 Python 文件遍历，不调用 scanner、`rg`、`grep`、`git`、网络 API、LLM、Docker、PoC、DOCX 渲染或 confirmed bundle 生成。
- P6.4 候选输出写入 `variant-candidates.jsonl`。每条记录都保持 `status=candidate`，文件路径必须是仓库相对路径，分数和排名必须可复现，并且必须要求独立 Docker 或 Docker Compose 验证后才可做任何确认决策。
- P6.5 增加 `validate_report_bundle.py --variant-candidates`，用于校验候选专用 JSONL/JSON array。该校验独立于 confirmed bundle validation：候选 JSONL 只能指导后续验证，不能证明漏洞已确认。
- confirmed bundle 不得把 `variant-candidates.jsonl` 作为主证据，也不得把候选排名、seed 相似性或候选记录本身写成确认依据。
- Variant Seed Card 是同类漏洞扩展的辅助证据，不替代 `verification-evidence.json`、findings JSON、DOCX 报告、补充复现说明、附件索引、replay 日志、Docker 证据或 confirmed bundle validation。
- 未来 seed-card 产物预期位于 `<audit-workspace>/evidence/variant-analysis/`：
  `seeds.jsonl`、`variant-candidates.jsonl`、`variant-expansion-summary.json`，以及可选的 `seed-<slug>.md` 说明。现有工作区和旧 confirmed bundle 不要求包含这些文件。
- Seed card 使用 `schema_version=1`，字段包括：`seed_id`、`confirmed_bundle_path`、`bug_class`、`root_cause`、`source_pattern`、`propagation_pattern`、`sink_pattern`、`missing_constraint_pattern`、`trigger_condition`、`docker_success_oracle`、`search_scope`、`negative_filters`。
- 最终 seed card 必须引用 bundle-relative 或 workspace-relative 的 confirmed bundle path，并记录 Docker success oracle。`root_cause`、`source_pattern`、`sink_pattern`、`docker_success_oracle` 必须非空，且最终卡片中不得写成 `unknown`。
- extractor 生成的最终 seed 必须通过 `validate_report_bundle.py --variant-seed-card`。抽取信息不足时只能生成 draft note 或可选 draft seed card，不能写入最终 seed。
- `source_pattern` 要描述攻击者可控输入，`sink_pattern` 要描述 sink 家族/API 或危险行为，`search_scope` 默认限定在同一目标仓库内，`negative_filters` 记录要排除或降权的目录、模式、缓解措施或上下文。
- 候选发现必须在 seed scope 不是结构化同一目标仓库、workspace 不在被扫描仓库内，或 seed 的 confirmed bundle path 不能解析到当前 workspace 的 `confirmed/` 目录下时 fail closed。
- Seed card 只能产生 variant candidates。任何同类漏洞仍需独立 Docker 或 Docker Compose 复现和 confirmed-bundle validation 后，才能称为 confirmed。
- 未来若某个同类漏洞真正确认，它仍必须像普通 confirmed bundle 一样拥有独立 Docker 复现、replay/直接影响证据、`verification-evidence.json` 和 confirmed-bundle validation。

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

同步并测试 Claude 安装目录下的 Skill 结构：

```bash
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

验证单个已确认漏洞包：

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
```

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
