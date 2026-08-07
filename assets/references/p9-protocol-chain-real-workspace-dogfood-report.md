# Real-Workspace Protocol-Chain Dogfood Report

## 结论

本次 P9.12.1 结果为 **passed**。新的真实 R2 pilot 在公开仓库固定提交的独立副本上由当前生产 bootstrap 建立；同一 pilot 的两个独立副本分别完成了真实 CAS 冲突和 digest-CAS rebuild；fresh-context Agent B 通过平台 sub-agent 机制完成了无父对话历史的结构化恢复，并由 Agent A 使用生产只读 validator 独立核对。原始工作区和三份历史 R1 样本的文件、大小、类型、SHA-256 与 symlink manifest 均保持一致，full regression 通过，因此满足本阶段的 closure eligibility。

这份报告只完成证据闭环，不把空 scope、manual-blocked 或 not-executed verification 解释成漏洞结论。先前 P9.12 报告中“缺少真实 R2 CAS/rebuild”的 blocked 结论在当时是正确的；本报告新增 P9.12.1 证据后，仅 supersede 那个阶段性资格判定。旧实现报告与旧 cross-audit 文档仍作为历史记录保留，没有被回写成 R2 证据。

## 边界与 Non-Claims

本次仅执行本地文件协议、生产状态 writer、validator、handoff/checkpoint/next-actions 派生和受限 Agent B 观察。没有执行 Docker、Docker Compose、PoC、replay、scanner、DAST、目标应用、网络或包管理器；bootstrap 的 Docker baseline 只是只读环境观察，创建的 Docker 资源数为 0。没有确认或重新确认漏洞，没有实现自动漏洞确认 runner，也没有测量 token 使用量、吞吐量或生产效率。

公开材料只使用中性 sample ID、提交 digest、计数、状态码和哈希；不包含本地路径、原始 agent ID、PID、原始聊天、隐藏推理、凭据或攻击 payload。详细路径、进程号和原始工具输出只留在本地私有 ledger，不参与 shipped artifacts。

## 历史 R1 样本保留

三份 P9.12 历史样本原样保留为 `legacy_r1`，不做 R1→R2 migration，也不把它们计入真实 R2 acceptance：

| Sample | Category | Protocol | Validator ledger | Counts toward real R2? |
| --- | --- | --- | --- | --- |
| `sample-no-confirmed` | no confirmed | `legacy_r1` | 12 calls, 0 validated, 0 partial/failed | No |
| `sample-blocked-verification` | structured runtime blocker | `legacy_r1` | 14 calls, 0 validated, 2 partial/failed | No |
| `sample-validated-bundle` | validated confirmed bundle | `legacy_r1` | 17 calls, 1 validated, 0 partial/failed | No |

历史记录中的 43 次 validator invocation、7 次 derived-artifact write、0 次 sanitization 和 2 个 contradiction 由样本 ledger 汇总；它们用于保留 R1 回归基线，不替代 R2 证据。

## 真实 R2 Pilot：目标、Bootstrap 与协议链

真实 pilot 的公开标识为 `sample-real-r2-pilot`。目标是公开仓库固定提交的完整 clone，tested-ref digest 为 `23e076e8ba07ca442f928cd185d8670da48bdff4`；clone HEAD 与 target contract 一致，未使用 hardlink 或 symlink。target contract 使用 `repo_root: "."`，runtime 为 `manual-blocked`，verify mode 为 `not-executed-manual-blocked`，entrypoints、trust boundaries 与 in-scope bug classes 均为空；生产 target validator 通过。

当前生产 bootstrap 在该 clone 内建立 workspace，并写入初始 event。随后使用 canonical writer、显式 expected revision 和 workspace-relative `fingerprint.md` 写入一个同阶段 `observe` event。最终 journal 为 R2、2 records、state revision 2；journal/state/target contract validator 均通过，event chain、tested-ref binding、handoff integrity、checkpoint 和 next-actions validator 均通过。pilot 没有 candidate、verdict、disposition、confirmed bundle 或其他 authority facts；baseline 记录 105 个 workspace 文件、0 个 symlink，且没有 Docker resource 被创建。

## Real-Copy CAS

从同一个 pilot 复制出独立的 `cas-copy`，不在原始 source 或 pilot 上竞争写入。两个独立 OS processes 同时以相同 expected state revision 运行当前 canonical writer：

| Invariant | Observed |
| --- | --- |
| writer process count | 2 |
| distinct process identities | true |
| successful commit | exactly 1 |
| failed commit | exactly 1, `STATE_REVISION_CONFLICT` |
| loser `journal_committed` | false |
| loser state-view update | false |
| authority fact delta | 0 |
| final journal/state | 3 events, revision 3, R2 validators passed |

冲突 writer 没有追加 event，也没有修改 authority；winner 只追加一个合法 observation event。最终 recovery check、handoff、checkpoint 和 next-actions 均重新验证通过。真实 CAS ledger 的 success/conflict 数由两个 writer 返回值和最终 journal 共同推导，而不是手写一个成功结论。

## Real-Copy Rebuild

从同一个 pilot 复制出独立的 `rebuild-copy`。先记录 journal bytes 与 digest，再只破坏副本的 derived state revision。production recovery `--check` 以只读方式检测 `STATE_REVISION_MISMATCH`，确认完整 journal 能推导 canonical state；之后仅在显式 journal digest 与 expected state digest 匹配时执行 `--apply`。

rebuild 结果为：apply 成功，journal before/after SHA-256 相同且 byte-identical，rebuilt state 与 pilot canonical JSON 等价，post-rebuild journal/state/recovery/handoff/checkpoint/next-actions validator 全部通过；authority fact delta 为 0。rebuild 没有借助 fixture、没有产生新的 authority fact，也没有把恢复结果提升为漏洞或验证结论。

## Fresh-Context Agent B

Agent B 使用平台 `multi_agent_v1` sub-agent，以 `fork_context=false` 启动；平台返回的 child identity 只以 SHA-256 receipt 保存，parent identity 未由工具暴露，因此公开 receipt 只保留 `parent_child_distinct=true` 和该事实的 provenance，不伪造 raw parent ID。`resume=false`，PID distinct 对该 platform mechanism 不适用；receipt 记录了 input hash、allowlist digest、observation hash、生命周期 timestamps、completed 状态，以及 `raw_chat_saved=false`、`hidden_reasoning_saved=false`。

Agent B 只得到一个最小 task，允许读取 pilot copy 的 audit journal、state、target contract、fingerprint、handoff、checkpoint 与 next-actions，并可调用对应 read-only validators。task 没有提供 expected answer、status、revision、count、blocker、next-action 或报告内容；Agent B 只返回结构化 observation，不返回路径、chat 或 reasoning，也没有修改 workspace。

Agent A 先独立运行 production target/audit/handoff/checkpoint/next-actions validators，再将预期观察与 Agent B 输出逐字段比较：9 个关键字段中 correct 为 9，unknown 为 0，incorrect 为 0，critical incorrect 为 0。观察包括 R2 protocol mode、target binding、tested-ref verification、event chain、handoff/checkpoint/next-actions validity、empty scope 和 absence of authority facts。该结果满足 fresh-context isolation gate。

## Deterministic R2 Fixture Regression

现有 R2 fixture regression 继续单独计量，永远不计入 real-workspace acceptance。fixture 验证了 exactly one CAS success 与 one `STATE_REVISION_CONFLICT`、一次 recovery check、一次 digest-CAS apply、journal zero mutation 和 canonical rebuilt state；fixture 的 next-actions 因缺少真实 target authority 而保持 fail closed。这些结果只证明 deterministic regression 没有倒退，不证明真实 copy 的 CAS/rebuild。

## Original Workspace Immutability

实施前后重新计算了 source worktree 与三份历史 R1 workspace 的 file list、file type、size、SHA-256 和 symlink manifest，共 4 个 baseline roots。before/after manifests 完全一致，file mutation violations 为 0，symlink mutation violations 为 0。所有 pilot、CAS、rebuild、Agent B workspace 与 private ledger 都位于独立临时目录；原始 source 只读，历史 R1 样本未被迁移、清洗或补写。

## Metrics 与资格计算

机器可读账本位于 `p9-protocol-chain-real-workspace-dogfood-metrics.json`。aggregate 由 historical R1、real R2 pilot、real-copy CAS、real-copy rebuild、fresh-context receipt、fixture regression 和 original-workspace manifests 的详细字段重算。关键 acceptance 字段为：real R2 workspace count 1、real-copy CAS true、real-copy rebuild true、fresh-context isolation true、original mutation 0、P9.1–P9.11 regression passed。

## 最终判定

所有 hard conditions 均满足：真实 R2 workspace 已由生产 bootstrap 建立；真实独立副本 CAS 恰有一个成功和一个 revision conflict；真实独立副本 recovery/rebuild 使用 digest-CAS 且 journal 不变；Agent B 是 fresh context 且与 Agent A 逐字段一致；原始工作区零写入；fixture 未被计入；full regression 通过。因此本次结果为 `passed`，closure eligibility 为 `eligible_for_next_phase`。这不授权执行本报告明确排除的 workload，也不改变历史 R1 样本的协议身份。
