#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "resolve_skill_root.sh: $*" >&2
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$SKILL_ROOT/SKILL.md" ]]; then
  :
elif [[ -f "$SKILL_ROOT/skills/zhulong/SKILL.md" ]]; then
  :
else
  fail "missing SKILL.md or skills/zhulong/SKILL.md in skill root"
fi

[[ -f "$SKILL_ROOT/scripts/asr_start.sh" ]] || fail "missing scripts/asr_start.sh in skill root"
[[ -d "$SKILL_ROOT/assets" ]] || fail "missing assets/ in skill root"

printf '%s\n' "$SKILL_ROOT"
