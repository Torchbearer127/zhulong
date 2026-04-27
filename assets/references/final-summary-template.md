# Final Summary Template

Use this structure for the final terminal / chat summary after an audit run finishes.

## Rules

- Match the selected output language exactly.
- Keep the prompt template in English, but keep the final human-facing audit summary in the selected output language.
- Clearly distinguish:
  - confirmed vulnerabilities
  - false positives
  - unverified leads
- Do not describe exploratory scratch output such as `vulnerability-packages/` or `SECURITY-RESEARCH-SUMMARY.md` as the final deliverable.
- When confirmed vulnerabilities exist, point to the per-vulnerability bundle under `<audit-workspace>/confirmed/`.

## Chinese Template

```text
审计已完成。

确认漏洞：
- <漏洞名称 1>：<影响简述>。交付目录：<audit-workspace>/confirmed/<bundle-1>/
- <漏洞名称 2>：<影响简述>。交付目录：<audit-workspace>/confirmed/<bundle-2>/

误报：
- <候选项 1>：<为什么不是漏洞>

未确认线索：
- <线索 1>：<为什么暂未确认 / 还缺什么验证条件>

补充说明：
- 所有 PoC 与攻击流量均只在 Docker / Docker Compose 内执行。
- 最终提交材料位于 <audit-workspace>/confirmed/，每个确认漏洞一个独立文件夹。
- 如果本轮做了清理，可补一句 Docker 清理结果。
```

## English Template

```text
The audit is complete.

Confirmed vulnerabilities:
- <Finding 1>: <short impact statement>. Bundle: <audit-workspace>/confirmed/<bundle-1>/
- <Finding 2>: <short impact statement>. Bundle: <audit-workspace>/confirmed/<bundle-2>/

False positives:
- <Candidate 1>: <why it is not a real vulnerability>

Unverified leads:
- <Lead 1>: <why it is still unverified / what verification condition is missing>

Additional notes:
- All PoCs and attack traffic were executed only inside Docker / Docker Compose.
- Final deliverables are under <audit-workspace>/confirmed/, with one folder per confirmed vulnerability.
- If cleanup was performed in this run, optionally add one short Docker cleanup note.
```
