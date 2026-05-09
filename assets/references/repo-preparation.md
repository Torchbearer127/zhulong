# Repo Preparation

Prefer the one-shot launcher instead of calling `prepare_target_repo.sh` directly from an arbitrary current working directory.

For GitHub repositories, prefer `gh` for clone and later GitHub intelligence lookups whenever it is available. Treat browser-style GitHub fetches as a fallback, not the default path.

Recommended manual fallback:

```bash
bash "$HOME/.claude/skills/zhulong/scripts/asr_start.sh" --source <local-path-or-repo-url>
```

By default, OMC suspect teammate PIDs are written to
`runtime/runtime-hygiene-status.json`, `handoff-summary.md`, and the final
workspace summary without interrupting the operator. If you want the launcher to
print an explicit end-of-startup PID review block, add
`--prompt-runtime-pid-review`. This is a prompt-only affordance; Zhulong still
does not signal teammate PIDs.

Use `prepare_target_repo.sh` only as an internal helper or when you are already invoking it by absolute path from a known location.

## Supported Inputs

- local path such as `/work/project`
- GitHub URL such as `https://github.com/owner/repo`
- GitLab URL such as `https://gitlab.com/group/project.git`
- Gitee URL such as `https://gitee.com/owner/repo.git`
- short slug such as `owner/repo`

## What the Script Does

1. Resolve whether the input is local or GitHub.
2. For GitHub, prefer `gh repo clone`; for other public git hosts, clone with `git clone`.
3. Clone the repository into the current working directory or another user-selected workspace root when needed, then keep all audit artifacts under the cloned repository itself.
4. Optionally check out a branch, tag, or commit-like ref if `--ref` is provided.
5. Call `bootstrap_verification_workspace.sh` to create a per-audit workspace such as `security-research-YYYYMMDD-HHMMSS/`.

## Examples

Prepare a local repo in place:

```bash
bash "$HOME/.claude/skills/zhulong/scripts/asr_start.sh" --source /path/to/repo
```

Prepare a GitHub repo under the current working directory:

```bash
bash "$HOME/.claude/skills/zhulong/scripts/asr_start.sh" --source https://github.com/owner/repo
```

Prepare a GitLab repo under the current working directory:

```bash
bash "$HOME/.claude/skills/zhulong/scripts/asr_start.sh" --source https://gitlab.com/group/project.git
```

Prepare a Gitee repo under the current working directory:

```bash
bash "$HOME/.claude/skills/zhulong/scripts/asr_start.sh" --source https://gitee.com/owner/repo.git
```

Prepare a GitHub repo with a specific branch:

```bash
bash "$HOME/.claude/skills/zhulong/scripts/asr_start.sh" --source owner/repo --ref main
```

## Relative Path Warning

- Do not run `bash ./scripts/prepare_target_repo.sh ...` unless your current working directory really contains that `scripts/` directory.
- In Claude Code sessions, the current working directory is often the target repo root rather than the installed skill directory, so `./scripts/...` usually points to the wrong place.

## Rules

- Do not treat repository preparation as vulnerability verification.
- After preparation, if the target is on GitHub, prefer `gh` for advisories, issues, pull requests, commits, releases, and patch-history lookup.
- After preparation, the target service and the PoC sender must still be containerized before any payload is sent.
- Before any PoC or exploit verification, run `check-docker-gate.sh`. If Docker is unavailable, write or update `<audit-workspace>/audit-log.md`, preserve collected evidence, and stop verification instead of switching to host execution.
- If a repository already exists locally, prefer reusing it unless the user wants a fresh clone.
- Some platforms may return a login page, anti-bot challenge, or geo-specific access gate for anonymous HTTPS git operations. If direct URL preparation fails, clone the repository manually first and then pass the local path to the skill.

## Output Location Rule

- Local-path audit: write to `<repo>/<audit-workspace>/`.
- Remote-URL audit: clone to `<workspace-root>/<repo>/`, then write to `<workspace-root>/<repo>/<audit-workspace>/`.
- Do not place a shared sibling audit workspace next to multiple repositories in the same working directory unless the user explicitly asks for that custom layout.
