#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  prepare_target_repo.sh --source <local-path|repo-url|owner/repo> [--workspace-root <dir>] [--workspace-name security-research-YYYYMMDD-HHMMSS] [--output-language zh-CN|en-US] [--summary-language zh-CN|en-US] [--ref <branch-or-tag>] [--force]

Purpose:
  Prepare a target repository for Docker-first vulnerability research.
  The verification workspace is always created under the target repository, not as a sibling top-level directory.

Behavior:
  - Local path: reuse the repository in place and bootstrap the verification workspace.
  - GitHub URL or owner/repo: clone into the workspace root as `<workspace-root>/<repo>`, then bootstrap a new per-audit workspace under `<workspace-root>/<repo>/`.
  - GitLab, Gitee, or other public git URL: clone with git into the workspace root as `<workspace-root>/<repo>`, then bootstrap a new per-audit workspace under `<workspace-root>/<repo>/`.

Notes:
  - The script prepares the repo and workspace only. PoCs must still run in Docker, never on the host.
  - Existing repos and workspace files are preserved unless --force is supplied.
EOF
}

SOURCE=""
WORKSPACE_ROOT="${ASR_WORKSPACE_ROOT:-${PWD}}"
WORKSPACE_NAME=""
OUTPUT_LANGUAGE=""
SUMMARY_LANGUAGE=""
REF=""
FORCE="0"
CLONE_METHOD="reuse"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE="${2:-}"
      shift 2
      ;;
    --workspace-root)
      WORKSPACE_ROOT="${2:-}"
      shift 2
      ;;
    --workspace-name)
      WORKSPACE_NAME="${2:-}"
      shift 2
      ;;
    --output-language)
      OUTPUT_LANGUAGE="${2:-}"
      shift 2
      ;;
    --summary-language)
      SUMMARY_LANGUAGE="${2:-}"
      shift 2
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    --force)
      FORCE="1"
      shift
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

if [[ -z "$SOURCE" ]]; then
  echo "--source is required." >&2
  usage >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_SCRIPT="$SCRIPT_DIR/bootstrap_verification_workspace.sh"
WORKSPACE_ROOT="${WORKSPACE_ROOT/#\~/$HOME}"
mkdir -p "$WORKSPACE_ROOT"
WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd)"

is_github_source() {
  [[ "$1" =~ ^https://github\.com/[^/]+/[^/]+(/)?$ ]] || [[ "$1" =~ ^[^/[:space:]]+/[^/[:space:]]+$ ]]
}

is_repo_url() {
  [[ "$1" =~ ^https?://[^[:space:]]+$ ]] || [[ "$1" =~ ^git@[^[:space:]]+$ ]]
}

normalize_github_slug() {
  local src="$1"
  if [[ "$src" =~ ^https://github\.com/([^/]+/[^/]+)/?$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  else
    printf '%s\n' "$src"
  fi
}

repo_dir_name_from_url() {
  local src="$1"
  local base
  base="$(basename "$src")"
  base="${base%.git}"
  printf '%s\n' "$base"
}

clone_github_with_best_tool() {
  local slug="$1"
  local dest="$2"

  if command -v gh >/dev/null 2>&1; then
    CLONE_METHOD="gh"
    gh repo clone "$slug" "$dest"
  else
    CLONE_METHOD="git"
    git clone "https://github.com/$slug" "$dest"
  fi
}

clone_generic_repo_url() {
  local repo_url="$1"
  local dest="$2"
  CLONE_METHOD="git"
  git clone "$repo_url" "$dest"
}

prepare_git_ref() {
  local repo_dir="$1"
  local ref="$2"
  if [[ -z "$ref" ]]; then
    return
  fi
  git -C "$repo_dir" fetch --all --tags
  git -C "$repo_dir" checkout "$ref"
}

if [[ -d "$SOURCE" ]]; then
  REPO_DIR="$(cd "$SOURCE" && pwd)"
  SOURCE_KIND="local"
else
  if is_github_source "$SOURCE"; then
    REPO_SLUG="$(normalize_github_slug "$SOURCE")"
    REPO_BASENAME="$(basename "$REPO_SLUG")"
    REPO_DIR="$WORKSPACE_ROOT/$REPO_BASENAME"
    SOURCE_KIND="github"
  elif is_repo_url "$SOURCE"; then
    REPO_URL="$SOURCE"
    REPO_BASENAME="$(repo_dir_name_from_url "$REPO_URL")"
    REPO_DIR="$WORKSPACE_ROOT/$REPO_BASENAME"
    SOURCE_KIND="repo_url"
  else
    echo "Unsupported --source value: $SOURCE" >&2
    echo "Use a local path, a public repository URL, or a GitHub owner/repo shorthand." >&2
    exit 1
  fi

  if [[ -d "$REPO_DIR/.git" ]]; then
    CLONE_METHOD="reuse"
    echo "preserve repo $REPO_DIR"
  else
    if [[ -e "$REPO_DIR" && "$FORCE" != "1" ]]; then
      echo "Destination already exists and is not a git repo: $REPO_DIR" >&2
      echo "Use --force after cleaning it up manually, or choose another --workspace-root." >&2
      exit 1
    fi
    if [[ -e "$REPO_DIR" && "$FORCE" == "1" ]]; then
      rm -rf "$REPO_DIR"
    fi
    if [[ "$SOURCE_KIND" == "github" ]]; then
      clone_github_with_best_tool "$REPO_SLUG" "$REPO_DIR"
    else
      clone_generic_repo_url "$REPO_URL" "$REPO_DIR"
    fi
  fi
fi

if [[ -n "$REF" ]]; then
  prepare_git_ref "$REPO_DIR" "$REF"
fi

BOOTSTRAP_ARGS=(--target-dir "$REPO_DIR")
if [[ -n "$WORKSPACE_NAME" ]]; then
  BOOTSTRAP_ARGS+=(--workspace-name "$WORKSPACE_NAME")
fi
if [[ -n "$OUTPUT_LANGUAGE" ]]; then
  BOOTSTRAP_ARGS+=(--output-language "$OUTPUT_LANGUAGE")
fi
if [[ -n "$SUMMARY_LANGUAGE" ]]; then
  BOOTSTRAP_ARGS+=(--summary-language "$SUMMARY_LANGUAGE")
fi
if [[ "$FORCE" == "1" ]]; then
  BOOTSTRAP_ARGS+=(--force)
fi

"$BOOTSTRAP_SCRIPT" "${BOOTSTRAP_ARGS[@]}"

if [[ -z "$WORKSPACE_NAME" && -f "$REPO_DIR/.asr-latest-workspace" ]]; then
  WORKSPACE_NAME="$(tr -d '\n' < "$REPO_DIR/.asr-latest-workspace")"
fi
WORKSPACE_DIR="$REPO_DIR/$WORKSPACE_NAME"

cat <<EOF

Prepared repository:
  source_kind: $SOURCE_KIND
  repo_dir: $REPO_DIR
  workspace_dir: $WORKSPACE_DIR
  clone_method: $CLONE_METHOD

Next:
  - if this target is on GitHub, prefer gh for clone, advisories, issues, pull requests, commits, releases, and patch-history lookup
  - inspect $WORKSPACE_DIR/fingerprint.md
  - inspect $WORKSPACE_DIR/asr-config.json
  - run $WORKSPACE_DIR/bin/check_omc_runtime.sh
  - or, after changing directory to $WORKSPACE_DIR, run: bash scripts/check_omc_runtime.sh
  - before any PoC or exploit verification, run: bash $WORKSPACE_DIR/bin/check-docker-gate.sh --repo-root $REPO_DIR
  - if Docker gate fails, stop verification, inspect $WORKSPACE_DIR/audit-log.md, fix Docker, and resume from the same repo workspace
  - launch the target in Docker
  - send PoCs only from Docker or Docker Compose
EOF
