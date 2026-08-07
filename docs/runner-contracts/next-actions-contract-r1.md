# 下一步建议协议

`next-actions.json` 是由当前已校验工作区事实派生的确定性、只建议索引。它不是
candidate、verdict、disposition、confirmed bundle、recording、finalization 或完成状态的
事实源；生成成功也不表示审计完成或漏洞成立。生成器不执行建议入口，validator 只读地
重新派生期望文档并逐字段比较。

## 固定入口与安全边界

建议入口是闭合枚举：handoff 重新生成、Recon 校验、candidate 独立核验、报告 bundle
校验、同类 seed/candidate helper、Docker 资源 review、finalization 和 `manual_review`。
入口由结构化名称和受限参数表示，绝不包含 shell、Docker 命令、重定向、管道、环境变量
赋值或自由文本命令。所有引用均为 workspace-relative POSIX 路径；绝对路径、URI、`~`、
`..`、反斜杠和 symlink escape 都会失败。

## 真值表与排序

| Code | 正向结构化条件 | 反向条件 | 优先级 |
| --- | --- | --- | --- |
| `HANDOFF_STALE` | authority 有效且 handoff 缺失/漂移 | current handoff | critical |
| `ENTRYPOINT_CHAIN_INCOMPLETE` | validated Recon 的 public entrypoints=`unknown` | 非 unknown | high |
| `TRUST_BOUNDARY_REVIEW_INCOMPLETE` | validated Recon 的 trust boundaries=`unknown` | 非 unknown | high |
| `VERDICT_MISSING` | validated candidate 没有配对 validated verdict | verdict 已存在 | high |
| `DOCKER_ORACLE_UNPROVEN` | 具体 verdict 是 code-level/blocked entrypoint evidence | Docker entrypoint evidence 已成立 | high |
| `REPLAY_MATERIAL_MISSING` | 具体 confirmed verdict 缺结构化 replay material | replay material 存在 | high |
| `SEVERITY_ESCALATION_PENDING` | 具体 confirmed verdict 且 journal 无 completed severity stage | completed severity stage 存在 | normal |
| `SEEDED_VARIANT_DISCOVERY_PENDING` | validated bundle count>0 且正式 variant 状态为 not executed/invalid | 零 bundle 或已完成 | normal |
| `DOCKER_CLEANUP_INCOMPLETE` | strict Docker 状态为 dirty/unclean/failed | clean/missing/unverifiable | high |
| `FINALIZATION_EVENT_MISSING` | finalization running、已配对 verdict、valid disposition、strict clean、无 finalization event | 任一门不满足 | normal |

未知、畸形、冲突、R1 冒充 R2、validator 异常或 authority digest 漂移一律 fail closed，
不会用 Markdown、agent notes、目录名、聊天或状态字符串补推。action 按固定 priority、
code、subject kind/id、action ID 排序；同 code+subject 最多一个。
