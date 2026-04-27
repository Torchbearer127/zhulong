# Changelog

## 0.1.1

- clarified that `.codex-plugin` is package metadata rather than Claude Code's native loading format
- added `scripts/sync_to_claude_skill.sh` to install the package into `~/.claude/skills`
- added `scripts/refresh_workspace_helpers.sh` to update existing bootstrapped repositories
- added `scripts/asr_start.sh` as a one-shot launcher so users do not need to run many helper commands manually
- added a Claude-native installed skill template at `templates/claude-skill/SKILL.md`
- extended self-test coverage to validate Claude skill sync

## 0.1.0

- Created the initial plugin scaffold.
- Packaged runtime checks, workspace bootstrap, dynamic toolchain planning, reporting, and bundle validation into a plugin-friendly structure.
- Added first-tier security tooling detection and optional installer support.
- Added deterministic DOCX report generation and validation helpers.
