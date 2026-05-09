# 使用说明

这份文档说明如何启动烛龙、什么时候使用哪种 Prompt，以及常用启动参数的含义。它面向想要运行授权代码审计的使用者，而不是插件维护者。

## 选择启动方式

| 使用场景 | 推荐方式 |
| --- | --- |
| 你的本地 AI 编程 Agent 已加载烛龙 Skill | 使用下方的短 Prompt。 |
| 你想先从终端准备或克隆仓库 | 使用 `scripts/asr_start.sh` 脚本。 |
| 你想在多个仓库上试运行烛龙 | 使用下方的试运行 Prompt。 |
| 你已经有本地仓库 | 使用本地仓库专用 Prompt，或使用 `--repo-root` 参数。 |

## 标准 Agent Prompt

当你希望通过本地 Agent 审计一个仓库时，使用：

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this repository:
https://github.com/owner/repo

Output language: zh-CN.
```

如果需要英文输出：

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this repository:
https://github.com/owner/repo

Output language: en-US.
```

如果目标是已有本地仓库：

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this local repository:
/path/to/repo

Output language: zh-CN.
```

## 试运行 Prompt

当你需要评估烛龙在真实项目上的表现，且不希望为了“强行产出漏洞”而导致误报时，可以使用：

```text
Please use the zhulong skill to perform an end-to-end trial security-focused code audit on this repository:
https://github.com/owner/repo

Output language: zh-CN.
Preferences:
- 将此视为产品验证运行，而非单纯为了完成指标的漏洞挖掘。
- 不要强行确认审计发现；当 Docker 证据不支持任何候选漏洞时，接受“无确认漏洞”的结果。
- 在生成的 Workspace 文件中记录已确认漏洞、误报、未验证线索、非安全缺陷、加固建议、Docker 阻塞项以及易用性问题。
- 将审计手册 (Playbook) 和清单作为起始参考。如果该仓库有特定的项目框架、数据流、污染汇聚点 (Sink) 或部署假设，请在审计工作区中记录。
- 任务结束时，总结哪些已确认、哪些已驳回、哪些仍未验证，以及生成的证据是否足以让人工审核员接手。
```

## 常用 Prompt 偏好

只在确实有助于当前工作流时添加偏好：

```text
Preferences:
- 如果多 Agent 运行时状态不清洁，请以单 Agent 模式继续运行。
- 优先关注 XML/解析器输入处理以及对象形态变更类的漏洞。
- 将看似合理但未经证实的漏洞保留在审计笔记中，不要将其视为已确认漏洞。
```

不要把很长的规则清单复制到每次启动的 Prompt 里。烛龙已经把可复用的安全规则、报告规范和自动检查集成在 Skill、参考文档和脚本中了。

## 手动终端启动

使用 Agent Prompt 是常规路径。终端启动脚本适合需要预先克隆仓库、准备环境，或者需要机器可读启动摘要的场景。

从远程仓库开始：

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo
```

使用 `owner/repo` 简写：

```bash
bash scripts/asr_start.sh --source owner/repo
```

从已有本地仓库开始：

```bash
bash scripts/asr_start.sh --repo-root /path/to/repo
```

指定分支或 Tag：

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo --ref main
```

输出 JSON 格式的启动信息：

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo --json
```

在终端显示可疑的多 Agent 工作进程，供人工复核：

```bash
bash scripts/asr_start.sh --repo-root /path/to/repo --prompt-runtime-pid-review
```

*注意：此选项仅打印复核信息，不会自动清理或终止进程。*

## 启动参数

| 参数 | 使用场景 | 说明 |
| --- | --- | --- |
| `--source VALUE` | 从 URL、本地路径或 `owner/repo` 简写开始。 | 与 `--repo-root` 二选一，不能同时使用。 |
| `--repo-root DIR` | 从已有本地仓库开始。 | 与 `--source` 二选一，不能同时使用。 |
| `--workspace-root DIR` | 将远程仓库克隆到指定目录。 | 默认是当前目录。 |
| `--workspace-name NAME` | 指定审计工作区的名称。 | 默认格式为 `security-research-YYYYMMDD-HHMMSS`。 |
| `--output-language LANG` | 报告产物语言（zh-CN / en-US）。 | 请使用标准的 Locale 格式。 |
| `--summary-language LANG` | 摘要语言（zh-CN / en-US）。 | 通常与报告语言保持一致。 |
| `--ref REF` | 指定远程分支或 Tag。 | 仅用于远程仓库模式。 |
| `--force` | 在安全前提下强制重建冲突文件。 | 禁止用它隐藏 Docker 残留或覆盖关键证据。 |
| `--skip-plan` | 调试启动阶段，跳过工具规划。 | 普通审计过程中不建议使用。 |
| `--prompt-runtime-pid-review` | 终端显式提醒可疑 Agent 进程。 | 仅供只读复核，不做自动清理。 |
| `--json` | 需要机器可读的启动输出。 | 适合脚本集成或包装器 (Wrapper) 调用。 |
| `-h`, `--help` | 查看内置帮助。 | 打印启动脚本用法。 |

## 启动后会发生什么

烛龙会在目标仓库内创建一个带时间戳的审计工作区 (Workspace)：

```text
<repo>/security-research-YYYYMMDD-HHMMSS/
```

该工作区会完整保存候选漏洞、误报、未验证线索、交接摘要、Docker 状态、运行时状态、证据文件，以及确认存在的漏洞证据包。

如果 Docker 不可用或验证环境不安全，烛龙会记录阻塞原因并暂停验证，**绝不会**回退到宿主机直接运行 PoC 命令。

## 高级续跑命令

大多数用户不需要直接使用这些命令；它们主要用于人工接管、续跑或调试特定的审计工作区：

```bash
bash <audit-workspace>/bin/run-initial-probes.sh --repo-root /path/to/repo
bash <audit-workspace>/bin/check-docker-gate.sh --repo-root /path/to/repo
python3 <audit-workspace>/bin/render-handoff-summary.py --workspace-dir <audit-workspace> --repo-root /path/to/repo
```

## 模板位置

短 Prompt 模板位于：

```text
assets/references/claude-code-invocation-template.md
```

同步脚本默认不会把模板复制到插件包外部。如果需要一份方便编辑的副本，请显式指定输出路径：

```bash
bash scripts/sync_to_claude_skill.sh --prompt-template-output ./claude-code-zhulong-prompt-template.md
```
