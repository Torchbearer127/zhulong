<div align="center">

<img src="assets/branding/zhulong-hero.png" alt="烛龙头图" width="100%" />

<h1>烛龙（Zhulong）</h1>

<p><strong>面向本地 Agent 的模块化安全导向代码审计工作流：<br>
先在 Docker 中复现，再确认报告。</strong></p>

<p><em>是烛九阴，是谓烛龙。</em><br>
<em>That which illumines the nether gloom — the Torch Dragon.</em></p>

<p>
  <a href="#"><img alt="Version" src="https://img.shields.io/badge/version-0.2.0-blue.svg?style=flat-square" /></a>
  <a href="#"><img alt="Status" src="https://img.shields.io/badge/status-release%20candidate-orange.svg?style=flat-square" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" /></a>
  <a href="#快速开始"><img alt="Runtime" src="https://img.shields.io/badge/runtime-Local%20Agent-111111.svg?style=flat-square" /></a>
  <a href="#审计工作流"><img alt="Verification" src="https://img.shields.io/badge/verification-Docker--first-2496ED.svg?style=flat-square" /></a>
</p>

<p>
  <a href="README.md">English</a> •
  <a href="README.zh-CN.md">简体中文</a> •
  <a href="docs/USAGE.zh-CN.md">使用说明</a> •
  <a href="CHANGELOG.md">更新日志</a>
</p>

</div>

---

## ⚡ 核心特性速览

- 🛡️ **Docker 优先验证：** 只有 Docker 或 Docker Compose 证据支持的问题，才会进入已确认报告。
- 🎯 **仅交付已确认结果：** 扫描器告警、依赖提示、静态分析结果和 LLM 推测会先隔离为候选项，不会直接混入已确认漏洞。
- 🔌 **轻量模块化：** 不强制依赖后端服务、数据看板、数据库、向量存储或 RAG 平台；通过本地 Agent 模块和脚本即可运行。
- 🤝 **人机协同易读：** 工作区、交接摘要和机器可读判断记录同时面向 AI 编程 Agent 与人工审核员设计。

---

## 目录

| 分区 | 内容 |
| :--- | :--- |
| [项目概述](#-项目概述) | 说明烛龙的定位、紧凑工作流和“先复现再确认”的核心原则。 |
| [为什么选择烛龙？](#-为什么选择烛龙) | 对照传统审计痛点，解释烛龙的轻量化、低误报和证据导向优势。 |
| [系统架构](#-系统架构) | 展示本地模块化流水线，以及 Agent、脚本、Docker 和产物之间的关系。 |
| [快速开始](#-快速开始) | 给出平台支持、Skill 同步、Agent 提示词和手动脚本启动方式。 |
| [烛龙会产出什么？](#-烛龙会产出什么) | 说明审计工作区结构和已确认漏洞证据包内容。 |
| [审计工作流](#-审计工作流) | 拆解从项目导入到完成交接的主要阶段。 |
| [依赖项与可选集成](#%EF%B8%8F-依赖项与可选集成) | 列出必选运行依赖和可选安全工具族。 |
| [插件项目结构](#-插件项目结构) | 概览插件源码、脚本、资源和文档目录。 |
| [源码开发指南](#-源码开发指南) | 说明如何使用 Agent 辅助维护烛龙，以及不可破坏的安全边界。 |
| [重要安全声明](#%EF%B8%8F-重要安全声明) | 明确授权使用范围、禁止用途和责任边界。 |
| [贡献与社区](#-贡献与社区) | 提供贡献入口、联系方式、开发计划和致谢。 |
| [项目文档](#-项目文档) | 汇总安装、使用、维护、发布和安全相关文档。 |
| [许可证](#-许可证) | 指向项目许可证。 |

---

## 🔭 项目概述

烛龙是一个面向授权审计的模块化、适合 Agent 操作的安全代码审计工作流。它不是单纯的漏洞扫描器，也不是需要部署的重型审计平台，而是给本地 AI 编程 Agent 一条从理解仓库到 Docker 验证、再到可复核交付的严谨路径。

工作流刻意保持紧凑：

> `导入项目` → `建模攻击面` → `生成候选项` → `Docker 复现` →
> `打包证据` → `交接结果`

烛龙主要解决代码安全审计中的四类痛点：

- **误报负担高：** 未验证的扫描器或 LLM 结论会消耗大量人工复核时间。
- **复现断层：** 源码层面看似可疑，并不等于运行时真的有安全影响。
- **证据碎片化：** 证据、脚本、报告和漏洞研判记录经常彼此脱节。
- **交接脆弱：** 长对话上下文很难让另一个 Agent 或人工审核员可靠接续。

> **💡 核心理念：** 烛龙只有在漏洞可以通过 Docker 或 Docker Compose 复现，并且报告证据包通过自动一致性检查后，才会把它标记为“已确认”。其他结果会保留为候选项、误报、未验证线索或阻塞项。

---

## ⚖️ 为什么选择烛龙？

烛龙面向的是希望引入安全审计自动化、但不想部署重平台，也不想被大量未验证发现淹没的团队。

| 传统审计痛点 | 烛龙解决方案 |
| :--- | :--- |
| **扫描器或 LLM 输出噪声高** | 烛龙用机器可读的判断记录 `audit-disposition.json` 管理每条线索，避免未验证内容悄悄混入已确认报告。 |
| **人工复核要反复重建证据链** | 每个已确认漏洞都会打包报告、复现说明、附件索引、证据 JSON、日志、截图和一个根目录运行脚本。 |
| **源码层面的结论难以信任** | 如果问题可以在运行时验证，烛龙会要求 Agent 先在 Docker 或 Docker Compose 中复现，再把它报告为已确认。 |
| **重型平台部署和维护成本高** | 烛龙以本地 Agent 模块和脚本运行，不要求后端服务、数据看板、数据库、向量存储或 RAG 平台。 |
| **完成状态容易只靠文字描述** | 自动检查会验证报告文件、证据文件、判断记录和 Docker 清理状态，再允许审计标记为完成。 |
| **Docker 残留和环境漂移会隐藏风险** | 烛龙记录 Docker 初始状态，检查新产生的容器、镜像、网络和卷，并拒绝可能误删用户资源的粗暴清理。 |
| **Agent 工作难以被人工接手** | 工作区文件、交接摘要和确定性输出同时面向 AI 编程 Agent 与人工审核员设计。 |

---

## 🧩 系统架构

### 整体架构图

烛龙采用本地模块化工作流，核心路径由 Agent 运行时、本地脚本、自动检查、参考文档、Docker 安全门禁和工作区产物驱动。

<div align="center">
  <img src="assets/branding/zhulong-pipeline.png" alt="烛龙流水线图" width="92%" />
  <p><em>烛龙流水线：把源码转化为可复核证据包。</em></p>
</div>

上面的流水线图就是烛龙的核心心智模型：用小而稳定的本地模块，把仓库、Docker 运行时环境和项目安全策略转化为隔离的候选项，或通过验证的证据包。持久规则沉淀在脚本、自动检查、参考文档和工作区产物里，因此工作流不会变成只存在于长对话里的隐形流程，也更容易迁移到不同的本地 Agent 环境。

---

## 🚀 快速开始

烛龙会通过本地 Agent、Docker、仓库内脚本和可选安全工具协同运行。完整依赖清单见后文“依赖项与可选集成”部分；完整启动 Prompt、手动启动方式和 `asr_start.sh` 参数见 [`docs/USAGE.zh-CN.md`](docs/USAGE.zh-CN.md)。

### 平台支持

下面的命令默认使用类 Unix shell，因为烛龙的运行时辅助脚本主要是 Bash/Python 脚本，验证路径也以 Docker 中复现为核心。

| 平台 | 推荐路径 | 说明 |
| :--- | :--- | :--- |
| **macOS** | ✅ 已支持并完成发布候选测试 | 使用 Docker Desktop 或其他 Docker Engine、Python 3.11+、Bash 和本地 Agent Skill 同步路径。 |
| **Linux** | ✅ 支持路径 | 使用 Docker Engine、Docker Compose、Python 3.11+、Bash，并使用下方同一组命令。如果你的 Agent 使用非默认 Skill 目录，可覆盖 `CLAUDE_SKILLS_DIR`。 |
| **Windows** | ⚠️ 推荐使用 WSL2 | 在 WSL2 内运行烛龙，尽量把 audit workspace 放在 WSL 文件系统中，并启用 Docker Desktop WSL integration。原生 PowerShell/CMD 执行目前还不是一等支持路径。 |

### 方式一：本地 Agent Skill 同步（推荐）

从插件包根目录运行自检，并把稳定的 Skill 目录结构同步到本地 Agent 环境：

```bash
# 1. 测试并同步
python3 scripts/selftest_plugin.py
bash scripts/sync_to_claude_skill.sh

# 2. 验证安装后的目录结构
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

同步后重启本地 Agent 会话。当前稳定的 Claude 兼容运行时路径是：

```text
~/.claude/skills/zhulong/
```

然后在受支持的本地 Agent 中使用短 Prompt：

> **🤖 给 Agent 的 Prompt**
>
> Please use the zhulong skill to perform an end-to-end security-focused code
> audit on this repository:
> `https://github.com/owner/repo`
>
> Output language: zh-CN.

> 这是发布候选验证和真实项目测试推荐使用的路径。

### 方式二：手动脚本启动

如果你希望不依赖 Agent 技能发现机制，直接从终端启动：

```bash
# 远程仓库
bash scripts/asr_start.sh --source https://github.com/owner/repo

# 已有本地仓库
bash scripts/asr_start.sh --repo-root /path/to/repo
```

---

### 预期结果

烛龙会在目标仓库内创建 `security-research-YYYYMMDD-HHMMSS/` 时间戳工作区。如果存在已确认漏洞，会把完整证据包写入 `confirmed/` 目录；如果没有确认漏洞，也可以正常完成，并保留候选项、误报、未验证线索、交接说明和完成检查记录。

## 🌟 烛龙会产出什么？

每次审计会在目标仓库内创建独立的时间戳工作区：

```text
<repo>/security-research-YYYYMMDD-HHMMSS/
├── 📊 audit-disposition.json     # 机器可读的线索判断记录
├── 🗺️ attack-surface.md          # 仓库特定攻击面笔记
├── 🔍 candidate-findings.md      # 仍在复核的候选问题
├── ❌ false-positives.md         # 已复核并排除的问题
├── ❓ unverified-leads.md        # 有价值但未 Docker 确认的线索
├── 📝 handoff-summary.md         # 面向人工和 Agent 的接续说明
├── 🏁 SUMMARY.md                 # 工作区最终摘要
├── 🧭 runtime/                   # 运行时状态
├── 🐳 docker/                    # Docker 初始基线与清理状态
├── 🔎 evidence/                  # 支撑证据
└── 🎯 confirmed/                 # 已确认漏洞证据包，如存在
```

已确认漏洞按“一漏洞一目录”交付：

```text
confirmed/<vulnerability-slug>/
├── 📄 <finding-specific-report>.docx
├── 🔗 <finding-specific-attachment-index>.md
├── 🛠️ <finding-specific-reproduction-supplement>.md
├── 🧾 verification-evidence.json
├── 🚀 run-<slug>-recording.sh
└── 📂 attachments/
```

只有当 Docker 或 Docker Compose 中的运行时证据存在，并且烛龙的报告证据包自动检查通过时，一个发现才算完成态的已确认交付物。

人机协同细节、报告质量门禁、验证命令、示例审计发现形态和限制请阅读 [`docs/WORKFLOW_DETAILS.zh-CN.md`](docs/WORKFLOW_DETAILS.zh-CN.md)。

---

## 🔄 审计工作流

| 步骤 | 阶段 | 负责模块 | 主要动作 |
| :---: | :--- | :--- | :--- |
| 1 | 项目导入 | 本地 Agent + 启动脚本 | 接收目标仓库，创建时间戳工作区，记录 Docker 初始状态，加载参考规则。 |
| 2 | 信息收集与建模 | Agent + 审计手册 (Playbook) | 识别仓库技术栈、入口、信任边界、污染汇聚点 (Sink)、部署假设和项目安全策略。 |
| 3 | 候选发现 | Agent + 本地工具 | 把扫描器、审计手册、依赖提示、静态推理和 LLM 推理作为候选生成器，而不是确认来源。 |
| 4 | Docker 验证 | 安全前置检查 + 验证脚本 | 拒绝危险验证容器，在 Docker 或 Compose 中复现候选项，并收集具体证据。 |
| 5 | 判断与打包 | 判断记录 + 证据包检查 | 把每条线索归类为已确认、误报、未验证、阻塞或仍为候选，并为已确认漏洞生成可复核证据包。 |
| 6 | 完成检查与交接 | 完成检查 + 完整性脚本 | 重新检查 Docker 清理状态，校验判断记录和证据包，然后写入最终摘要与交接文件。 |

---

## 🖥️ 依赖项与可选集成

烛龙刻意保持轻量：核心工作流由本地 Agent 入口、仓库内脚本和自动检查组成。需要在运行时复现漏洞时，Docker 是必选项；大多数安全工具只是用于发现线索的可选组件。

| 依赖项 / 集成 | 是否必选 | 在烛龙中的作用 | 链接 |
| :--- | :---: | :--- | :--- |
| **本地 AI 编程 Agent 运行时** | 预期工作流必选 | 读取烛龙 Skill 和文档，协调仓库审计，并运行本地脚本。当前稳定路径是 Claude 兼容的 Skill 同步方式；也保留脚本方式的手动启动。 | [Claude Code docs](https://docs.anthropic.com/en/docs/claude-code/overview) |
| **Python 3.11+** | 必选 | 运行自动检查、完成检查、自检、报告渲染辅助脚本和工作区完整性检查。 | [python.org](https://www.python.org/) |
| **Docker Engine / Docker Desktop** | 已确认漏洞必选 | 提供隔离复现运行时。Docker 不可用时，烛龙会暂停或记录验证受阻，不回退到宿主机执行。 | [Docker docs](https://docs.docker.com/engine/) |
| **Docker Compose** | 目标验证使用 Compose 时必选 | 使用项目原生或生成的 Compose 文件启动目标应用和验证栈。 | [Docker Compose docs](https://docs.docker.com/compose/) |
| **Git** | 远程目标必选 | 克隆目标仓库并保留源码上下文。 | [git-scm.com](https://git-scm.com/) |
| **POSIX shell / Bash** | 必选 | 运行 Workspace 辅助脚本、Docker 环境卫生检查、初始探测任务和复现脚本。 | [GNU Bash](https://www.gnu.org/software/bash/) |
| **GitHub CLI (`gh`)** | 可选 | 可用于 GitHub clone/auth 流程和仓库元数据查询。 | [GitHub CLI](https://cli.github.com/) |
| **oh-my-claudecode (OMC)** | 可选多 Agent 增强 | 只有在你主动使用 OMC `/team`、`/ultrawork` 等多 Agent 模式时才需要。正常审计不依赖 OMC；烛龙对 OMC 多 Agent worker PID 始终只读复核。 | [OMC GitHub](https://github.com/Yeachan-Heo/oh-my-claudecode) |

可选安全工具会在运行时探测并写入工作区。缺失工具会被记录为被跳过的探测任务，而不是审计阻塞。

<details>
<summary><b>点击展开：可选安全工具族</b></summary>
<br>

| 可选工具族 | 示例 | 作用 | 确认规则 |
| :--- | :--- | :--- | :--- |
| **SAST / 模式匹配扫描** | [Semgrep](https://github.com/semgrep/semgrep), [CodeQL](https://codeql.github.com/) | 广泛代码模式发现和自定义规则探索。 | 结果必须先作为候选，不能绕过 Docker 证据和报告证据包检查。 |
| **依赖与 OSV 扫描** | [OSV-Scanner](https://github.com/google/osv-scanner), [`npm audit`](https://docs.npmjs.com/cli/commands/npm-audit), [pip-audit](https://github.com/pypa/pip-audit), [govulncheck](https://go.dev/doc/security/vuln/) | 依赖公告发现和语言生态漏洞提示。 | 仅有依赖扫描结果不能被报告为已确认漏洞。 |
| **SBOM 与镜像分析** | [Syft](https://github.com/anchore/syft), [Grype](https://github.com/anchore/grype), [Trivy](https://github.com/aquasecurity/trivy) | 生成 SBOM，扫描 filesystem/image，提供容器漏洞线索。 | 扫描器输出只是线索证据，仍需复核和复现。 |
| **敏感信息泄露扫描** | [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog) | 发现疑似敏感信息泄露，生成脱敏摘要并保留本地原始日志。 | 凭据发现披露前仍需人工漏洞研判和范围确认。 |
| **聚焦 DAST 辅助工具** | [Nuclei](https://github.com/projectdiscovery/nuclei), [ffuf](https://github.com/ffuf/ffuf), [sqlmap](https://github.com/sqlmapproject/sqlmap), [OWASP ZAP](https://www.zaproxy.org/) | 仅对授权的本地 Docker 目标做聚焦动态检查。 | 未明确授权时不得进行激进或外部测试。 |
| **语言专用分析器** | [gosec](https://github.com/securego/gosec), [SpotBugs](https://spotbugs.github.io/), [FindSecBugs](https://find-sec-bugs.github.io/), Maven, Gradle | 为 Java、Go 等生态提供静态或依赖上下文。 | 结果用于漏洞研判，不能单独成为已确认漏洞。 |
| **文档 QA 辅助** | [LibreOffice](https://www.libreoffice.org/), [MarkItDown](https://github.com/microsoft/markitdown) | 可选 DOCX 转换和可读性冒烟测试。 | 不影响漏洞确认。 |

</details>

规范依赖清单维护在 [`assets/tool-registry.json`](assets/tool-registry.json)。

---

## 📁 插件项目结构

```text
zhulong/
├── .claude-plugin/plugin.json          # Claude plugin-style 发现元数据
├── .codex-plugin/plugin.json           # 跨 Agent / Codex 元数据
├── skills/zhulong/SKILL.md             # Agent Skill 入口
├── templates/claude-skill/SKILL.md     # 已安装 Skill 模板
├── scripts/                            # 运行时辅助脚本和自动检查
│   ├── asr_start.sh                    # 创建或复用审计工作区
│   ├── manage_docker_resources.py      # Docker 初始基线、精确清理、严格环境卫生检查
│   ├── check_sandbox_preflight.py      # 危险验证容器前置拒绝
│   ├── audit_disposition.py            # 工作区级线索判断记录
│   ├── finalize_audit_workspace.py     # 交接前完成检查
│   ├── assert_finalized_workspace.py   # 已完成工作区完整性检查
│   ├── validate_report_bundle.py       # 已确认漏洞证据包检查
│   └── selftest_plugin.py              # 发布 / 打包自检
├── assets/
│   ├── branding/                       # README 视觉与 logo 资源
│   ├── attacker-container/             # 可选本地 attacker container 模板
│   ├── references/                     # 审计手册、安全契约、输出模板
│   └── examples/                       # 示例结构化输入
├── docs/                               # 使用、工作流、安装、维护和发布文档
│   ├── INSTALL.md
│   ├── USAGE.md
│   ├── USAGE.zh-CN.md
│   ├── WORKFLOW_DETAILS.md
│   ├── WORKFLOW_DETAILS.zh-CN.md
│   ├── AGENTS.md
│   └── RELEASE_CHECKLIST.md
├── SECURITY.md                         # 负责任披露与安全政策
├── DISCLAIMER.md                       # 授权使用与免责声明
├── CONTRIBUTING.md
├── CHANGELOG.md
├── README.md
└── README.zh-CN.md
```

生成的审计工作区会写入目标仓库，而不是写入插件源码目录。

---

## 🔧 源码开发指南

本节面向想修改烛龙本身的贡献者。推荐的维护方式是 Agent 辅助开发：开发者只需理解产品意图和边界，然后让 Codex、Claude Code、Cursor、Gemini CLI 或其他本地 AI 编程 Agent 先读取项目规则，再执行小范围的精准补丁。

完整规则请阅读：

- [`docs/AGENTS.md`](docs/AGENTS.md)：面向 AI 编程 Agent 的烛龙维护规则
- [`CONTRIBUTING.md`](CONTRIBUTING.md)：贡献者原则
- [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md)：发布前门禁

### 环境要求

- Python 3.11+
- Docker 和 Docker Compose
- 可加载 `skills/zhulong` 入口的本地 Agent 运行时
- `assets/tool-registry.json` 中列出的可选安全工具

### 开发调试循环

先把这组项目规则交给 AI 编程 Agent：

```text
Read docs/AGENTS.md, CONTRIBUTING.md, and docs/RELEASE_CHECKLIST.md before editing.
Keep the change narrow.
不要削弱以下规则：未验证问题不能进入已确认报告；适用时必须在 Docker 中复现；Docker 清理必须安全；OMC 多 Agent 工作进程只允许人工复核；危险验证容器必须提前拒绝；已确认漏洞证据包必须先通过检查再交付。
```

```bash
# 1. 运行源码目录自检
python3 scripts/selftest_plugin.py

# 2. 如果修改了 skill-facing 文件，同步并测试 installed layout
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py

# 3. 如果修改了报告输出，验证受影响的已确认漏洞证据包
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
python3 scripts/validate_all_report_bundles.py --confirmed-dir <confirmed-dir>
```

### 维护规则摘要

- PoC 和验证必须在 Docker 或 Docker Compose 中执行，不新增宿主机执行作为验证替代路径。
- 扫描器、依赖、静态分析和 LLM 输出必须先作为候选，不能绕过 Docker 证据和报告证据包检查。
- 修改报告输出时，报告生成逻辑和自动检查要一起更新。
- Docker 残留资源和 OMC/运行时残留必须保持分离。
- 不新增大范围的 Docker prune 清理、广泛进程清理、PID 信号发送、通配符接管或机器本地绝对路径。
- 可选工具必须保持可选；不要把第三方服务、MCP server、RAG 平台、数据看板或数据库变成必需运行依赖。
- 工作流行为变化时，需要同步更新脚本、参考文档、自检和发布检查。

---

## ⚠️ 重要安全声明

烛龙仅用于授权的安全导向代码审查，且本项目仅供网络空间安全学术研究、教学和学习使用。最关键的边界是：

- 只在你拥有或已明确获得授权的仓库、系统、容器、账号、网络和基础设施上使用。
- 禁止用于未授权扫描、漏洞利用、凭据窃取、数据外传、持久化、拒绝服务或绕过访问控制。
- 遵守所选 Agent 运行时、模型提供方、IDE、代码托管平台、Bug Bounty 计划、雇主、客户和所在司法辖区的政策。
- 生成的审计发现仍是证据包，需要合格人工复核和负责任披露。
- 使用者需自行承担使用行为产生的法律、合规、运营和数据处理后果。

完整的授权使用说明、免责声明和漏洞报告建议见：[`DISCLAIMER.md`](DISCLAIMER.md) 与 [`SECURITY.md`](SECURITY.md)。

---

## 🫶 贡献与社区

欢迎贡献，尤其欢迎小而清晰、不会破坏烛龙轻量化、本地 Agent 设计、已确认报告纪律和 Docker 复现模型的改动。Issue、PR、文档完善、测试用例、自动检查补强和真实项目发布候选测试报告都很有价值。

提交 PR 前请先阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。如果你使用 AI 编程 Agent 维护烛龙，请先让它阅读 [`docs/AGENTS.md`](docs/AGENTS.md)。

### 联系方式

技术问题、功能建议、合作交流或安全敏感沟通，可以通过以下方式联系：

| 渠道 | 联系方式 |
| --- | --- |
| 邮箱 | [torchbearer127@qq.com](mailto:torchbearer127@qq.com) |
| GitHub | [@Torchbearer127](https://github.com/Torchbearer127) |
| 小红书 | `1103633904` |

### 命名哲学：衔火照九阴

> 名取自上古神祇“烛龙”。于《山海经》之记，烛龙口衔火精以照九阴，使无日之极暗之地，亦有光明。
>
> 凡未经验证之告警、浮于源码之扫描，皆如幽冥中之虚妄魅影，明灭不定，难辨真伪。烛龙不捕风，不捉影，唯“执炬”而已。藉由隔离之坞匣秘境复现攻伐，将暗藏于代码深处之诡道悉数洞照，使真相无所遁形。
>
> 传云：烛龙视为昼，瞑为夜。于审计之道，其“视”也，旨在揭示运行时确凿无疑之真凭实据，使漏洞如白昼般昭彰；其“瞑”也，旨在封存严丝合缝之证据闭环，使审计如夜色般沉静收网。
>
> 自九阴之极暗，达万物之昭彰：一视一瞑，方为一次确凿之审计。

### 开发计划

烛龙当前已经可以作为轻量级本地 Agent 审计工作流使用，但后续会继续克制演进。优先级是可靠性、清晰证据和易维护性。

已完成：

- [x] 本地 Agent Skill 打包，并保留脚本方式的手动启动。
- [x] 已确认漏洞报告前，先在 Docker 或 Docker Compose 中复现。
- [x] 已确认漏洞证据包，包含报告、复现说明、证据 JSON、日志/截图和运行脚本。
- [x] 机器可读的线索判断记录，以及便于人机协同接续的交接摘要。
- [x] 针对危险验证容器、Docker 残留和 OMC 多 Agent worker 进程的安全检查与只读复核边界。

后续计划：

- [ ] 优化 Linux 和 WSL2 用户的安装说明与示例。
- [ ] 增加更清晰的示例工作区和脱敏输出样例。
- [ ] 补充更多本地 Agent 环境的兼容说明，例如 Codex 和 Cursor。
- [ ] 基于真实项目测试继续收紧报告一致性检查。

### 致谢

烛龙建立在本地 Agent 和开源安全工具社区之上。特别感谢：

- Docker 与 Docker Compose，让本地可复现验证变得可行。
- Claude Code 以及更广泛的本地 AI 编程 Agent 生态，为烛龙提供可维护的 Agent 工作流表达面。
- OMC 社区带来的多 Agent 工作流启发，也促使烛龙明确强化滞留的多 Agent worker 进程和运行时状态边界。
- Semgrep、OSV-Scanner、Syft、Grype、Trivy、Gitleaks、TruffleHog、Nuclei、ffuf、sqlmap、OWASP ZAP、各语言生态安全工具、DeepAudit 以及其他安全审计工具带来的能力启发。
- 所有在真实项目中测试烛龙、反馈混乱输出、帮助把工作流保持在证据导向而非营销导向的人。

---

## 📖 项目文档

| 文档 | 面向读者 | 主要内容 |
| --- | --- | --- |
| [`docs/INSTALL.md`](docs/INSTALL.md) | 新用户 | 安装路径、本地 skill sync 和环境准备说明。 |
| [`docs/USAGE.zh-CN.md`](docs/USAGE.zh-CN.md) | 运行者 | 启动 Prompt、试运行 Prompt、手动启动命令和 `asr_start.sh` 参数。 |
| [`docs/AGENTS.md`](docs/AGENTS.md) | AI 编程 Agent 与维护者 | 开发规则、不可破坏的工作流契约和安全补丁边界。 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | 贡献者 | 贡献预期、测试纪律和范围控制。 |
| [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) | 维护者 | 发布前打包、安全、文档和回归检查。 |
| [`SECURITY.md`](SECURITY.md) | 用户与漏洞报告者 | 负责任使用、烛龙自身安全问题报告和披露建议。 |
| [`DISCLAIMER.md`](DISCLAIMER.md) | 所有用户 | 授权使用边界、禁止用途、Agent / 模型提供方政策遵从和责任限制。 |
| [`CHANGELOG.md`](CHANGELOG.md) | 版本读者 | 版本历史和重要行为变化。 |
| [`docs/WORKFLOW_DETAILS.zh-CN.md`](docs/WORKFLOW_DETAILS.zh-CN.md) | 运行者与人工审核员 | 人机协同、报告质量门禁、验证命令、示例审计发现形态和限制。 |
| [`assets/references/docker-resource-hygiene.md`](assets/references/docker-resource-hygiene.md) | 运行者与维护者 | Docker 初始基线、精确清理、残留资源处置和禁止大范围 Docker prune 清理规则。 |
| [`assets/references/omc-runtime-stability.md`](assets/references/omc-runtime-stability.md) | 多 Agent 用户 | OMC 运行状态、滞留的 Socket 和只供人工复核的多 Agent 工作进程处理。 |
| [`assets/references/confirmed-vuln-docx-format.md`](assets/references/confirmed-vuln-docx-format.md) | 报告作者与维护者 | 已确认漏洞报告格式、DOCX 要求和附件说明。 |

---

## 📄 许可证

MIT — 见 [`LICENSE`](LICENSE)。
