#!/usr/bin/env bash

set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_SKILLS_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
SKILL_NAME="zhulong"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
DEST_DIR=""
BACKUP_PATH=""
BACKUP_ROOT=""
REPO_ROOT="$(cd "${PLUGIN_ROOT}/../.." && pwd)"
CANONICAL_PROMPT_PATH="${PLUGIN_ROOT}/assets/references/claude-code-invocation-template.md"
ROOT_PROMPT_PATH="${REPO_ROOT}/claude-code-zhulong-prompt-template.md"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/sync_to_claude_skill.sh [--skill-name NAME] [--claude-skills-dir DIR] [--keep-backups N]

Description:
  Sync this repository package into a Claude Code native skill directory so Claude
  can actually load and use it from ~/.claude/skills.

Options:
  --skill-name NAME         Claude skill directory name. Default: zhulong
  --claude-skills-dir DIR   Override Claude skills root. Default: ~/.claude/skills
  --keep-backups N          Keep only the most recent N timestamped backups. Default: 5
  -h, --help                Show this help message
EOF
}

sync_root_prompt() {
  if [[ -f "$CANONICAL_PROMPT_PATH" ]]; then
    cp "$CANONICAL_PROMPT_PATH" "$ROOT_PROMPT_PATH"
  fi
}

prune_old_backups() {
  if [[ "${KEEP_BACKUPS}" =~ ^[0-9]+$ ]]; then
    :
  else
    echo "Invalid --keep-backups value: ${KEEP_BACKUPS}" >&2
    exit 1
  fi
  mkdir -p "$BACKUP_ROOT"
  find "$BACKUP_ROOT" -maxdepth 1 -type d -name "${SKILL_NAME}.backup.*" -print \
    | LC_ALL=C sort -r \
    | awk -v keep="${KEEP_BACKUPS}" 'NR > keep { print }' \
    | while IFS= read -r backup; do
        [[ -n "$backup" ]] && rm -rf "$backup"
      done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skill-name)
      SKILL_NAME="$2"
      shift 2
      ;;
    --claude-skills-dir)
      CLAUDE_SKILLS_DIR="$2"
      shift 2
      ;;
    --keep-backups)
      KEEP_BACKUPS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

DEST_DIR="${CLAUDE_SKILLS_DIR%/}/${SKILL_NAME}"
BACKUP_ROOT="${CLAUDE_SKILLS_DIR%/}/.${SKILL_NAME}-backups"
mkdir -p "$CLAUDE_SKILLS_DIR"
mkdir -p "$BACKUP_ROOT"

if [[ -e "$DEST_DIR" ]]; then
  BACKUP_PATH="${BACKUP_ROOT}/${SKILL_NAME}.backup.$(date +%Y%m%d-%H%M%S)"
  mv "$DEST_DIR" "$BACKUP_PATH"
fi

mkdir -p "$DEST_DIR"
cp "$PLUGIN_ROOT/templates/claude-skill/SKILL.md" "$DEST_DIR/SKILL.md"
cp -R "$PLUGIN_ROOT/scripts" "$DEST_DIR/scripts"
cp -R "$PLUGIN_ROOT/assets" "$DEST_DIR/assets"
cp "$PLUGIN_ROOT/README.md" "$DEST_DIR/README.plugin-package.md"
cp "$PLUGIN_ROOT/INSTALL.md" "$DEST_DIR/INSTALL.plugin-package.md"
sync_root_prompt
prune_old_backups

cat <<EOF
Claude skill synced successfully.
Installed skill directory:
  $DEST_DIR
EOF

if [[ -n "$BACKUP_PATH" ]]; then
  cat <<EOF
Previous skill backup:
  $BACKUP_PATH
EOF
fi

cat <<EOF
Root prompt template synced from canonical source:
  $ROOT_PROMPT_PATH
Backup directory:
  $BACKUP_ROOT
Backup retention:
  keep most recent ${KEEP_BACKUPS}
EOF

cat <<'EOF'

Claude Code can now use this skill from ~/.claude/skills.
If Claude Code was already running, restart it or open a new session before testing.
EOF
