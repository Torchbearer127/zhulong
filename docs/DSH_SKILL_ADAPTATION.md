# DeepSeek Harness Support

Zhulong can be installed for DeepSeek Harness (dsh) through the shared agent
skill directory. This is a limited integration, not a native dsh plugin or a
claim that the complete Docker-backed audit workflow has passed. The tested
scope below is one recorded configuration. The tested `0.1.0-rc.7` release was
a developer preview at the time; other versions, providers, models, or
deployments are not covered.

## Install

dsh uses `$DSH_AGENTS_HOME` as its agent configuration root, or `~/.agents` by
default, and discovers skills below `<agents-home>/skills/`. From the plugin
root, install to that shared directory:

```bash
agents_home="${DSH_AGENTS_HOME:-$HOME/.agents}"
bash scripts/sync_to_codex_skill.sh --codex-skills-dir "$agents_home/skills"
python3 "$agents_home/skills/zhulong/scripts/selftest_plugin.py"
```

The sync script's name is historical; it writes the shared skill layout and
does not invoke Codex. Pass the `skills/` directory, not `DSH_AGENTS_HOME`
itself. The script may back up an existing Zhulong installation before
replacing it. Restart dsh after syncing.

## Invoke And Check The Source

Start dsh through the entry point configured for your installation. Use its
skill discovery/invocation tool to select `zhulong`; do not use Codex's
`$zhulong` syntax as a dsh command. A plain-language request can be:

```text
Use the installed zhulong skill to audit this local repository:
/path/to/repo

Output language: en-US.
```

The shared directory on disk does not prove which same-name skill dsh loaded.
Check dsh's configured `agentsHome`, `dshHome`, custom skill directories, and
project-level sources. For a controlled source check, use an isolated dsh
configuration and an inert, uniquely marked skill copy; ask the runtime skill
tool to read the marker. Do not delete or overwrite other skill copies to hide
a collision. Running the installed helper with `--print-skill-root` reports
that helper's own package root only; it does not prove which source the dsh
provider selected.

## Permissions And Recovery

Skill instructions do not enforce tool permissions. The reviewed headless dsh
configuration had no per-command or per-path allowlist, and the recorded
session history included an out-of-scope global Docker inventory query. Keep
work within the explicitly authorized target and actions, review consequential
tool operations and their results, and stop an operation if a permission check
rejects it. Do not route around a rejection.

If Docker is unavailable or unsafe, preserve the workspace and pause
verification. Never run a PoC on the host. To resume after interruption, reopen
the same workspace, inspect its authoritative event log, current state, and
checkpoint, then continue only from the recorded stage. A chat summary or a
host-side command does not establish that dsh performed or completed a step.

## Tested Scope

| Item | Recorded value and limit |
| --- | --- |
| dsh | `0.1.0-rc.7`; this closeout did not re-verify its source commit or exact macOS release. |
| Host and configuration | macOS; Volcengine Agent Plan with `deepseek-v4.1-flash`; headless profile. The reviewed profile contained `dsh-base` and `dsh-headless`; recorded sessions exposed `skill`, `read`, and `bash` calls. A complete component manifest was not retained. |
| Docker preflight | Docker Engine `29.4.0`, `linux/aarch64`, observed before the recorded synthetic verification. This is not a general compatibility matrix. |
| Offline regression runtime | Python `3.12.14`, PyYAML `6.0.3`, python-docx `1.2.0`, Pillow `12.3.0`; Docker calls were intercepted by a deny-only shim. |

Historical evidence supports shared-skill discovery, reading a reference, and
resolving the installed helper root for the recorded setup. There is also
limited evidence for Docker blocking, rejected or failed operations, checkpoint
resume, and same-name source selection. These checks do not cover every
configuration.

An earlier real dsh session ran the verifier on an older harmless synthetic
HTTP fixture and produced a `confirmed_in_docker` result for that fixture's
marker. A different, newer synthetic fixture was verified on the host; its
later disposition and bundle-contract steps were also host-side, not a
continuation of the earlier dsh session. The bundle builder failed on an
attachment reference. No bundle was promoted and workspace finalization did
not complete. This does not establish a complete dsh-driven audit or an
upstream vulnerability finding. The supported statement is limited to shared
skill integration and the recorded partial validation; full end-to-end support
remains unverified.
