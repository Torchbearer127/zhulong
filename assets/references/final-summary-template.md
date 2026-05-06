# Final Summary Template

Use this structure for the final terminal / chat summary after an audit run finishes.

## Rules

- Match the selected output language exactly.
- Keep the prompt template in English, but keep the final human-facing audit summary in the selected output language.
- Clearly distinguish:
  - confirmed vulnerabilities
  - false positives / non-security defects
  - unverified leads, including high-confidence-but-not-Docker-confirmed leads
- Do not list false positives, non-security defects, unverified leads, or high-confidence-unverified leads as confirmed vulnerabilities.
- If Docker confirmation did not complete, say that no vulnerability was confirmed for that lead, state the missing evidence, and provide the safe Docker-only resume step.
- Do not describe exploratory scratch output such as `vulnerability-packages/` or `SECURITY-RESEARCH-SUMMARY.md` as the final deliverable.
- When confirmed vulnerabilities exist, point to the per-vulnerability bundle under `<audit-workspace>/confirmed/`.
- A finding may be called a confirmed deliverable only after Docker evidence and successful bundle validation.
- Docker-confirmed evidence with incomplete bundle artifacts must be reported as `Docker-confirmed but bundle incomplete`, not as a completed confirmed deliverable.
- If validation fails, list the validation failure and remediation step instead of claiming the bundle is ready.
- When no confirmed vulnerabilities exist, write `确认漏洞：无` / `Confirmed vulnerabilities: none` instead of creating a fake confirmed bundle.
- After the completion gate passes, keep a stable workspace-level `SUMMARY.md` (or `final-audit-summary.md`) under `<audit-workspace>/`. Do not leave the final human-facing summary only in chat output or timestamped terminal logs.
- Before writing the final summary, refresh or explicitly resolve stale blocker wording in lightweight files. `attack-surface.md`, `candidate-findings.md`, `unverified-leads.md`, and `handoff-summary.md` must not still claim `blocked_no_docker`, `NOT STARTED`, or `image pull required` after the summary claims Docker verification succeeded.

## Chinese Template

```text
审计已完成。

确认漏洞：
- <漏洞名称 1>：<影响简述>。交付目录：<audit-workspace>/confirmed/<bundle-1>/。验证状态：bundle validation passed。
- <漏洞名称 2>：<影响简述>。交付目录：<audit-workspace>/confirmed/<bundle-2>/

Docker-confirmed but bundle incomplete：
- <候选项>：Docker 证据存在，但最终交付包未通过验证。失败原因：<partial confirmed bundle / validation_failed / 缺失工件>。修复步骤：<用 renderer 重新生成到顶层 confirmed/ 或移回 candidate/unverified>。

误报 / 非安全缺陷：
- <候选项 1>：<为什么不是漏洞 / 为什么只是非安全缺陷>。记录位置：<audit-workspace>/false-positives.md

未确认线索：
- <线索 1>：<为什么暂未确认 / 还缺什么验证条件>。安全恢复步骤：<下一步 Docker-only 操作>。记录位置：<audit-workspace>/unverified-leads.md
- <高置信但未确认线索>：<sandbox 限制或阻塞原因>。注意：该项不是 confirmed，不生成 DOCX，不进入 <audit-workspace>/confirmed/。

补充说明：
- 所有 PoC 与攻击流量均只在 Docker / Docker Compose 内执行。
- 最终提交材料位于 <audit-workspace>/confirmed/，每个确认漏洞一个独立文件夹。
- 误报、非安全缺陷和未确认线索仅作为工作区记录保留，不属于最终确认漏洞交付。
- 如果本轮做了清理，可补一句 Docker 清理结果。
- 本总结已保存为 <audit-workspace>/SUMMARY.md，后续交叉审计不需要从聊天日志中恢复最终结论。
```

## English Template

```text
The audit is complete.

Confirmed vulnerabilities:
- <Finding 1>: <short impact statement>. Bundle: <audit-workspace>/confirmed/<bundle-1>/. Validation: bundle validation passed.
- <Finding 2>: <short impact statement>. Bundle: <audit-workspace>/confirmed/<bundle-2>/

Docker-confirmed but bundle incomplete:
- <Candidate>: Docker evidence exists, but the final deliverable bundle did not pass validation. Failure: <partial confirmed bundle / validation_failed / missing artifacts>. Remediation: <rerender through the renderer into top-level confirmed/ or move back to candidate/unverified records>.

False positives / non-security defects:
- <Candidate 1>: <why it is not a real vulnerability / why it is only a non-security defect>. Record: <audit-workspace>/false-positives.md

Unverified leads:
- <Lead 1>: <why it is still unverified / what verification condition is missing>. Safe resume step: <next Docker-only action>. Record: <audit-workspace>/unverified-leads.md
- <High-confidence but unconfirmed lead>: <sandbox limitation or blocker>. Note: this is not confirmed, does not generate DOCX, and must not enter <audit-workspace>/confirmed/.

Additional notes:
- All PoCs and attack traffic were executed only inside Docker / Docker Compose.
- Final deliverables are under <audit-workspace>/confirmed/, with one folder per confirmed vulnerability.
- False positives, non-security defects, and unverified leads are retained only as workspace records, not final confirmed deliverables.
- If cleanup was performed in this run, optionally add one short Docker cleanup note.
- This summary is saved as <audit-workspace>/SUMMARY.md so later cross-audits do not need to recover the final conclusion from chat logs.
```
