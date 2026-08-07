#!/usr/bin/env bash

set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEX_SKILLS_DIR="${CODEX_SKILLS_DIR:-$HOME/.agents/skills}"
SKILL_NAME="zhulong"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
DEST_DIR=""
BACKUP_PATH=""
BACKUP_ROOT=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/sync_to_codex_skill.sh [--skill-name NAME] [--codex-skills-dir DIR] [--keep-backups N]

Description:
  Sync this repository package into a Codex user-level skill directory so Codex
  can load it from ~/.agents/skills.

Options:
  --skill-name NAME              Codex skill directory name. Default: zhulong
  --codex-skills-dir DIR         Override Codex skills root. Default: ~/.agents/skills
  --keep-backups N               Keep only the most recent N timestamped backups. Default: 5
  -h, --help                     Show this help message
EOF
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

sanitize_installed_package() {
  find "$DEST_DIR" -type f \( \
    -name 'AGENTS.md' -o \
    -name '*.hidden' -o \
    -name '*.bak' -o \
    -name '*.tmp' -o \
    -name '*.orig' -o \
    -name '*.rej' -o \
    -name '*.pyc' -o \
    -name '.DS_Store' \
  \) -delete
  find "$DEST_DIR" -depth \( \
    -path '*/__pycache__' -o \
    -path '*/__pycache__/*' -o \
    -path '*/.omc' -o \
    -path '*/.omc/*' \
  \) -delete
}

next_backup_path() {
  local timestamp
  local candidate
  local counter
  timestamp="$(date +%Y%m%d-%H%M%S)"
  candidate="${BACKUP_ROOT}/${SKILL_NAME}.backup.${timestamp}"
  counter=1
  while [[ -e "$candidate" ]]; do
    candidate="${BACKUP_ROOT}/${SKILL_NAME}.backup.${timestamp}.${counter}"
    counter=$((counter + 1))
  done
  printf '%s\n' "$candidate"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skill-name)
      SKILL_NAME="$2"
      shift 2
      ;;
    --codex-skills-dir)
      CODEX_SKILLS_DIR="$2"
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

DEST_DIR="${CODEX_SKILLS_DIR%/}/${SKILL_NAME}"
BACKUP_ROOT="${CODEX_SKILLS_DIR%/}/.${SKILL_NAME}-backups"
mkdir -p "$CODEX_SKILLS_DIR"
mkdir -p "$BACKUP_ROOT"

if [[ -e "$DEST_DIR" ]]; then
  BACKUP_PATH="$(next_backup_path)"
  mv "$DEST_DIR" "$BACKUP_PATH"
fi

mkdir -p "$DEST_DIR"
cp "$PLUGIN_ROOT/skills/zhulong/SKILL.md" "$DEST_DIR/SKILL.md"
cp -R "$PLUGIN_ROOT/scripts" "$DEST_DIR/scripts"
cp -R "$PLUGIN_ROOT/assets" "$DEST_DIR/assets"
cp -R "$PLUGIN_ROOT/docs" "$DEST_DIR/docs"
cp "$PLUGIN_ROOT/README.md" "$DEST_DIR/README.plugin-package.md"
cp "$PLUGIN_ROOT/docs/INSTALL.md" "$DEST_DIR/INSTALL.plugin-package.md"
sanitize_installed_package
prune_old_backups

cat <<EOF
Codex skill synced successfully.
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
Backup directory:
  $BACKUP_ROOT
Backup retention:
  keep most recent ${KEEP_BACKUPS}
EOF

cat <<'EOF'

Codex can now use this skill from ~/.agents/skills.
If Codex was already running, restart it or open a new session before testing.
EOF
