# 静态审计时间线 R1

## 定位

`audit-timeline.json` 是从已校验工作区事实生成的离线、只读、确定性派生视图；
`audit-timeline.html` 只渲染已通过同一 JSON contract 与语义校验的内容。二者都不是新的
事实真源，不会运行审计、Docker、PoC、replay、scanner、网络、模型或 Agent，也不能授予
确认、处置、执行、promotion 或 finalization 权限。

权威关系固定为：

```text
validated workspace facts
  -> canonical audit-timeline.json
  -> validate_audit_timeline.py
  -> static audit-timeline.html
```

HTML 不维护第二套事实计算器。confirmed 关系仍只能来自通过生产 validator 的 candidate、
verifier verdict、`audit-disposition.json` 和确认漏洞包；事件名称、目录存在、静态分析、
Docker-only evidence 或自然语言说明都不能提升为 confirmed。

## 字段到权威文件映射

| Timeline 部分 | 权威输入 | 生产校验入口 |
| --- | --- | --- |
| `events`、`current_state` | `audit-events.jsonl`、`stage-status.json` | `audit_state_io.py`、`audit_transition_policy.py` |
| `target` | `zhulong-target.yaml` | `validate_target_contract.py` |
| `candidate_flows[].candidate` | `candidate.json` | `validate_candidate.py` |
| `candidate_flows[].verdict` | `verifier-verdict.json` | `validate_verifier_verdict.py` 及 candidate cross-check |
| `candidate_flows[].disposition` | `audit-disposition.json` | `audit_disposition.py` |
| `bundles` | `confirmed/` 中逐 bundle 文件 | `validate_all_report_bundles.py`、`validate_report_bundle.py` |
| `docker` | 既有 Docker verification/hygiene 文件 | `workspace_state.py` 的保守聚合 |
| `finalization` | canonical finalization event | `workspace_state.py` |
| `handoff` | `handoff-state.json` | `validate_handoff_state.py` 的当前事实重算 |
| `next_actions` | `next-actions.json` | `validate_next_actions.py` 的当前事实重算 |

`agent-notes.md`、Markdown 摘要、聊天记录、prompt 和隐藏推理不属于 timeline 输入。R2
必须保留真实 `seq`、revision 和 transition；`legacy_r1` 只显示旧协议能够证明的事实，
不得补造 R2 identity、恢复链或 confirmed 关系。

### Confirmed 绑定边界

当前生产账本分别校验 candidate disposition、confirmed ledger item 和 bundle，但没有提供可证明的
逐候选 bundle ID。时间线因此只在一个 confirmed candidate disposition、一个 confirmed ledger item
和一个 production-validated bundle 同时存在，且 ledger path 精确对应该 bundle 时显示完整 confirmed
flow。只要存在多个 confirmed candidate、多个 confirmed item、多个 validated bundle、orphan 或路径
不一致，生成器就拒绝输出，不能根据 slug、标题、数组顺序、目录顺序或数量猜配。

## 生成与验证

在插件或已安装 Skill 的根目录运行：

```bash
python3 scripts/render_audit_timeline.py \
  --workspace-dir <audit-workspace> \
  --repo-root <target-repository> \
  --json

python3 scripts/validate_audit_timeline.py \
  --workspace-dir <audit-workspace> \
  --repo-root <target-repository> \
  --json
```

默认输出是工作区根下的 `audit-timeline.json` 和 `audit-timeline.html`。相同权威输入重复生成
必须得到相同 bytes；若现有合法输出不同，默认 fail closed，只有显式 `--overwrite` 才能
替换这两个派生文件。生成器不修改 journal、state、candidate、verdict、disposition、
Docker 状态、bundle、handoff、next-actions、finalization 或 recording 文件。

JSON 与 HTML 先在同目录 staging 文件中写入、`fsync` 并分别验证，再按固定顺序替换。
两个文件不能获得真正的跨文件系统原子事务，因此实现使用旧 bytes rollback：第二次 replace
失败时恢复第一个文件；测试会注入 staging、validation 和两次 replace 故障。文档不把这描述
为“双文件原子提交”。

## 静态 HTML 安全

HTML 使用严格 CSP、单个 inline `<style>` 和 workspace-relative evidence link。它没有
JavaScript、event handler、外部 stylesheet/font/image、iframe、object、embed、audio、
video、form、meta refresh、CSS `url()` 或 `@import`。所有文本先统一 HTML escape；
href 只接受工作区内现存普通、非 symlink 文件，并进行 URL encoding。页面只显示相对路径和
SHA-256，不嵌入 evidence 内容、截图、录屏或 replay transcript。

时间线、JSON/HTML validator 与新 R2 writer 共用一份窄的可移植性/敏感值分类器。它覆盖常见
access-key、authorization token、平台 token、credential label/value、private-key header，以及
Unix/macOS、Windows、UNC 和 `file:` 本机路径形态。新 event 在 writer 边界先被拒绝；只读时间线
仍会对历史 journal 复查并 fail closed。诊断只报告字段与类别，不回显原值；该分类器不声称识别
所有秘密，也不会重写历史 journal。

URI 安全检查只作用于真实 URI-bearing attribute。经过 escaping 的 `https://`、`file:` 或 `data:`
说明可以作为可见文本出现；可点击链接仍只允许 canonical URL-encoded workspace-relative `href`，
外部 scheme、active scheme、protocol-relative、fragment-only 和 encoded traversal 均被拒绝。

之所以不提供服务端 dashboard，是因为该视图只需要本地离线审阅；服务、数据库、后台进程或
遥测会扩大攻击面和状态一致性负担，却不会增加任何审计确认权限。
