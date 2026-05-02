#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any


STACK_MARKERS = {
    "node": ["package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"],
    "python": ["pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "go": ["go.mod", "go.sum"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "docker": ["Dockerfile", "docker-compose.yml", "compose.yml", "compose.yaml"],
}

SKIP_SCAN_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".omc",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "venv",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan a repository-specific security toolchain based on stack markers and installed tools."
    )
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--workspace-dir")
    parser.add_argument("--format", choices=["json", "text"], default="text")
    return parser.parse_args()


def has_any(root: Path, names: list[str]) -> bool:
    return any((root / name).exists() for name in names)


def detect_stack(root: Path) -> list[str]:
    stacks: list[str] = []
    for stack, markers in STACK_MARKERS.items():
        if has_any(root, markers):
            stacks.append(stack)
    return stacks or ["generic"]


def skip_scan_dir(name: str) -> bool:
    return name in SKIP_SCAN_DIR_NAMES or name.startswith("security-research-")


def iter_repo_dirs(root: Path, max_depth: int | None = None):
    for dirpath, dirnames, _filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if not skip_scan_dir(name)]
        current = Path(dirpath)
        if current == root:
            continue
        rel = current.relative_to(root)
        if max_depth is not None and len(rel.parts) > max_depth:
            dirnames[:] = []
            continue
        yield current


def iter_repo_files(root: Path, suffixes: set[str] | None = None, max_size: int = 2_000_000):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if not skip_scan_dir(name)]
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                if not path.is_file() or path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            if suffixes is not None and path.suffix.lower() not in suffixes:
                continue
            yield path


def package_json_indicates_library(root: Path) -> bool:
    package_json = root / "package.json"
    if not package_json.exists():
        return False
    try:
        package = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(package, dict):
        return False
    library_fields = ("main", "module", "types", "typings", "exports", "bin")
    if any(field in package for field in library_fields):
        return True
    return (root / "lib").is_dir() or (root / "src").is_dir()


def detect_attack_surface(root: Path) -> list[str]:
    indicators: list[str] = []
    interesting_dirs = ["routes", "route", "router", "controllers", "controller", "api", "graphql", "auth", "cmd"]
    names = {path.name.lower() for path in iter_repo_dirs(root, max_depth=3)}
    for name in interesting_dirs:
        if name in names:
            indicators.append(name)
    if any(name in names for name in ("api", "routes", "graphql", "controller", "controllers")):
        indicators.append("http-api")
    if any(name in names for name in ("auth",)):
        indicators.append("auth")
    java_markers = [
        "@RestController",
        "@Controller",
        "@RequestMapping",
        "@GetMapping",
        "@PostMapping",
        "SecurityFilterChain",
        "OncePerRequestFilter",
        "extends HttpServlet",
    ]
    go_markers = [
        "http.HandleFunc",
        "http.Handle(",
        ".ServeHTTP",
        "gin.Default(",
        "gin.New(",
        "router.GET(",
        "router.POST(",
        "chi.NewRouter(",
        "echo.New(",
        "fiber.New(",
    ]
    node_markers = [
        "require('express')",
        'require("express")',
        "from 'express'",
        'from "express"',
        "express()",
        "new koa(",
        "require('koa')",
        'require("koa")',
        "fastify(",
        "require('fastify')",
        'require("fastify")',
        "app.get(",
        "app.post(",
        "router.get(",
        "router.post(",
        "export default function handler",
        "export async function get",
        "export async function post",
        "nextrequest",
        "nextresponse",
    ]
    python_markers = [
        "from flask import",
        "flask(",
        "@app.route(",
        "blueprint(",
        "django.urls",
        "urlpatterns",
        "path(",
        "re_path(",
        "fastapi(",
        "apirouter(",
        "@app.get(",
        "@app.post(",
        "starlette(",
        "route(",
    ]
    for path in iter_repo_files(root):
        if path.suffix in {".java", ".kt"}:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if any(marker in text for marker in java_markers):
                indicators.append("java-web")
                indicators.append("http-api")
                break
    for path in iter_repo_files(root, {".go"}):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(marker in text for marker in go_markers):
            indicators.append("go-web")
            indicators.append("http-api")
            break
    for path in iter_repo_files(root, {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if any(marker in text for marker in node_markers):
            indicators.append("node-web")
            indicators.append("http-api")
            break
    for path in iter_repo_files(root, {".py"}):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if any(marker in text for marker in python_markers):
            indicators.append("python-web")
            indicators.append("http-api")
            break
    if package_json_indicates_library(root) and "node-web" not in indicators:
        # Pure packages often have docs/api or public API folders. Directory names
        # alone are not enough to force a web route/middleware model.
        indicators = [
            item for item in indicators
            if item not in {"api", "routes", "route", "router", "controllers", "controller", "graphql", "auth", "http-api"}
        ]
        indicators.append("node-library")
    return sorted(set(indicators))


def tool_available(*names: str) -> bool:
    return any(shutil.which(name) for name in names)


def repository_contains(root: Path, markers: list[str], suffixes: set[str] | None = None) -> bool:
    lowered_markers = [marker.lower() for marker in markers]
    for path in iter_repo_files(root, suffixes):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if any(marker in text for marker in lowered_markers):
            return True
    return False


def choose_tools(root: Path, stacks: list[str], attack_surface: list[str]) -> dict[str, list[str]]:
    plan: dict[str, list[str]] = {
        "broad_probe": [],
        "sast": [],
        "dependency": [],
        "secrets": [],
        "dast": [],
        "verification": [],
        "hardening": [],
        "document_qa": [],
    }

    if tool_available("ship-safe"):
        plan["broad_probe"].append("ship-safe")
    if tool_available("semgrep"):
        plan["sast"].append("semgrep")
    if tool_available("codeql"):
        plan["sast"].append("codeql")

    if "node" in stacks and tool_available("npm") and ((root / "package-lock.json").exists() or (root / "npm-shrinkwrap.json").exists()):
        plan["dependency"].append("npm audit")
    if "python" in stacks and tool_available("pip-audit"):
        plan["dependency"].append("pip-audit")
    if "rust" in stacks and tool_available("cargo-audit"):
        plan["dependency"].append("cargo audit")
    if "java" in stacks:
        if (root / "pom.xml").exists() and tool_available("mvn"):
            plan["dependency"].append("maven dependency:tree")
        if ((root / "build.gradle").exists() or (root / "build.gradle.kts").exists()) and (tool_available("gradle") or (root / "gradlew").exists()):
            plan["dependency"].append("gradle dependencies")
        if tool_available("dependency-check", "dependency-check.sh"):
            plan["dependency"].append("OWASP Dependency-Check")
        if tool_available("spotbugs"):
            plan["sast"].append("spotbugs")
        if tool_available("findsecbugs"):
            plan["sast"].append("findsecbugs")
    if "go" in stacks:
        if tool_available("go"):
            plan["dependency"].append("go list -m all")
        if tool_available("govulncheck"):
            plan["dependency"].append("govulncheck")
        if tool_available("gosec"):
            plan["sast"].append("gosec")
        if tool_available("golangci-lint"):
            plan["sast"].append("golangci-lint")

    if tool_available("osv-scanner"):
        plan["dependency"].append("osv-scanner")
    if tool_available("trivy"):
        plan["dependency"].append("trivy")
    if tool_available("syft"):
        plan["dependency"].append("syft")
    if tool_available("grype"):
        plan["dependency"].append("grype")

    if tool_available("gitleaks"):
        plan["secrets"].append("gitleaks")
    if tool_available("trufflehog"):
        plan["secrets"].append("trufflehog")

    if "http-api" in attack_surface:
        if tool_available("nuclei"):
            plan["dast"].append("nuclei")
        if tool_available("ffuf"):
            plan["dast"].append("ffuf")
        if tool_available("zap.sh", "zaproxy", "zap-baseline.py"):
            plan["dast"].append("owasp zap")
    if tool_available("sqlmap"):
        plan["dast"].append("sqlmap (only after a live injectable endpoint exists in Docker)")

    if "docker" in stacks:
        if tool_available("trivy"):
            plan["verification"].append("trivy image")
        if tool_available("syft"):
            plan["verification"].append("syft sbom")
        if tool_available("grype"):
            plan["verification"].append("grype image")

    if tool_available("mcpserver-audit"):
        plan["hardening"].append("mcpserver-audit")
    if tool_available("mcp-scanner"):
        plan["hardening"].append("mcp-scanner")

    if tool_available("markitdown"):
        plan["document_qa"].append("markitdown")
    if tool_available("soffice"):
        plan["document_qa"].append("libreoffice")

    return {key: value for key, value in plan.items() if value}


def discover_workspace_dir(root: Path, cli_workspace_dir: str | None) -> Path:
    def is_valid_workspace(path: Path) -> bool:
        config_path = path / "asr-config.json"
        if not config_path.exists():
            return False
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(data, dict):
            return False
        workspace_root = str(data.get("workspace_root", "")).strip()
        workspace_created_at = str(data.get("workspace_created_at", "")).strip()
        confirmed_output_dir = str(data.get("confirmed_output_dir", "")).strip()
        if workspace_root != path.name:
            return False
        if not workspace_created_at:
            return False
        if confirmed_output_dir != f"{path.name}/confirmed":
            return False
        if path.name == "security-research":
            return False
        return True

    if cli_workspace_dir:
        candidate = Path(cli_workspace_dir).expanduser().resolve()
        if not is_valid_workspace(candidate):
            raise SystemExit(
                f"workspace directory is not a valid per-audit workspace: {candidate}. "
                "Run asr_start.sh first and resume from the generated security-research-YYYYMMDD-HHMMSS workspace."
            )
        return candidate

    script_path = Path(__file__).resolve()
    script_workspace = script_path.parent.parent
    if is_valid_workspace(script_workspace):
        return script_workspace

    latest = root / ".asr-latest-workspace"
    if latest.exists():
        name = latest.read_text(encoding="utf-8").strip()
        if name:
            candidate = (root / name).resolve()
            if is_valid_workspace(candidate):
                return candidate

    candidates = sorted(
        (
            path for path in root.iterdir()
            if path.is_dir() and re.fullmatch(r"security-research-\d{8}-\d{6}(?:-\d+)?", path.name) and is_valid_workspace(path)
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        return candidates[0].resolve()

    raise SystemExit(
        f"No valid per-audit workspace was found under {root}. "
        "Run asr_start.sh first instead of writing to a bare repo/security-research directory."
    )


def command_hints(root: Path, workspace_dir: Path, plan: dict[str, list[str]]) -> list[str]:
    hints: list[str] = [f"bash {workspace_dir}/bin/run-initial-probes.sh --repo-root {root} --workspace-dir {workspace_dir}"]
    if "ship-safe" in plan.get("broad_probe", []):
        hints.append(f"ship-safe {root}")
    if "semgrep" in plan.get("sast", []):
        hints.append(f"semgrep scan --config auto {root}")
    if "osv-scanner" in plan.get("dependency", []):
        hints.append(
            f"bash {workspace_dir}/bin/run-initial-probes.sh --repo-root {root} --workspace-dir {workspace_dir} "
            "# preferred: classifies osv-scanner 'No package sources found' as skipped"
        )
    if "trivy" in plan.get("dependency", []):
        hints.append(f"trivy fs {root}")
    if "syft" in plan.get("dependency", []):
        hints.append(f"syft dir:{root}")
    if "grype" in plan.get("dependency", []):
        hints.append(f"grype dir:{root}")
    if "gitleaks" in plan.get("secrets", []):
        hints.append(f"gitleaks detect -s {root}")
    if "trufflehog" in plan.get("secrets", []):
        hints.append(f"trufflehog filesystem {root}")
    if "nuclei" in plan.get("dast", []):
        hints.append("nuclei -u http://<docker-service-host>:<port>")
    if any("ffuf" == item for item in plan.get("dast", [])):
        hints.append("ffuf -u http://<docker-service-host>:<port>/FUZZ -w <wordlist>")
    return hints


def specialized_playbooks(stacks: list[str], attack_surface: list[str]) -> list[str]:
    playbooks: list[str] = []
    if "java" in stacks or "java-web" in attack_surface:
        playbooks.append("assets/references/java-web-audit-playbook.md")
    if "go" in stacks or "go-web" in attack_surface:
        playbooks.append("assets/references/go-web-audit-playbook.md")
    if "node-library" in attack_surface:
        playbooks.append("assets/references/nodejs-library-audit-playbook.md")
    if "node-web" in attack_surface or ("node" in stacks and "http-api" in attack_surface):
        playbooks.append("assets/references/nodejs-web-audit-playbook.md")
    if "python-web" in attack_surface or ("python" in stacks and "http-api" in attack_surface):
        playbooks.append("assets/references/python-web-audit-playbook.md")
    return playbooks


def audit_focus(stacks: list[str], attack_surface: list[str]) -> list[str]:
    focus: list[str] = []
    if "java" in stacks or "java-web" in attack_surface:
        focus.extend([
            "Build a Java entry map: Spring/JAX-RS/Servlet routes, filters, interceptors, and security configuration.",
            "Prioritize authz gaps, MyBatis ${...}, JDBC/JPA string-built queries, SpEL/OGNL/template injection, SSRF, XXE, deserialization, upload/path traversal, and Actuator exposure.",
            "For each candidate, trace source -> service layer -> sink and record why framework validation or security filters do not block it.",
        ])
    if "go" in stacks or "go-web" in attack_surface:
        focus.extend([
            "Build a Go entry map: main.go, router registration, middleware, handlers, and debug/pprof endpoints.",
            "Prioritize missing auth middleware, SSRF and redirect behavior, exec.Command shell use, path traversal, SQL string construction, template trusted types, CORS/CSRF, and missing timeouts/body limits.",
            "For each candidate, trace request input -> handler -> sink and record middleware, validation, timeout, and whitelist assumptions.",
        ])
    if "node-web" in attack_surface or ("node" in stacks and "http-api" in attack_surface):
        focus.extend([
            "Build a Node.js entry map: Express/Koa/Fastify/Next.js routes, middleware, body parsers, upload handlers, and auth/session/CORS/CSRF coverage.",
            "Prioritize authz gaps, SSRF, command execution, path traversal/upload issues, prototype pollution, template/XSS, config injection, and missing body/upload/timeouts limits.",
            "For each candidate, trace request input -> middleware -> handler -> sink and record validation, parser limits, redirects, and dependency-version assumptions.",
        ])
    if "node-library" in attack_surface:
        focus.extend([
            "Build a Node.js library API map: exported functions/classes, parser callbacks, option objects, CLI/bin entry points, and files that transform caller-controlled input.",
            "Prioritize unsafe parsing/normalization, prototype property injection, path or archive handling, template/HTML generation, deserialization/config injection, ReDoS/parser exhaustion, and callback/plugin trust boundaries.",
            "For each candidate, trace caller-controlled input -> public API/parser/processor -> sink and record required caller options, downstream impact assumptions, and a minimal Docker Node PoC plan.",
        ])
    if "python-web" in attack_surface or ("python" in stacks and "http-api" in attack_surface):
        focus.extend([
            "Build a Python Web entry map: Flask/Django/FastAPI/Starlette routes, middleware, dependencies/decorators, upload handlers, and auth/session/CORS/CSRF coverage.",
            "Prioritize authz gaps, raw SQL/ORM injection, SSRF, command execution, path traversal/upload issues, template injection/XSS, deserialization, and missing body/upload/timeouts limits.",
            "For each candidate, trace request input -> middleware/dependency/decorator -> handler/view -> sink and record validation, permissions, settings, and parameterization assumptions.",
        ])
    if focus:
        focus.append("Write or update <audit-workspace>/attack-surface.md before final confirmation so the review path is recoverable.")
    return focus


def attack_surface_guidance(stacks: list[str], attack_surface: list[str]) -> list[str]:
    guidance: list[str] = [
        "Maintain <audit-workspace>/attack-surface.md as a concise handoff packet, not as raw scanner output or a final vulnerability report.",
        "Route unverified hypotheses to candidate-findings.md or unverified-leads.md until Docker reproduction succeeds.",
    ]

    def append_once(value: str) -> None:
        if value not in guidance:
            guidance.append(value)

    minimum_fields = (
        "Minimum entry inventory fields: route or endpoint, method, handler/controller, "
        "authentication requirement, input source, downstream sink or service, current verification status."
    )
    if "java" in stacks or "java-web" in attack_surface:
        guidance.append(
            "Java Web: inventory Spring/JAX-RS/Servlet routes, filters, interceptors, and security annotations in attack-surface.md."
        )
        append_once(minimum_fields)
        guidance.append(
            "For each Java entry, note controller method, DTO/body binding, security filter or @PreAuthorize coverage, service-layer hop, and sink class/function when known."
        )
    if "go" in stacks or "go-web" in attack_surface:
        guidance.append(
            "Go Web: inventory router registrations, middleware chain, handlers, and debug/pprof endpoints in attack-surface.md."
        )
        append_once(minimum_fields)
        guidance.append(
            "For each Go entry, note handler function, request readers such as query/path/body/header/cookie, middleware/auth coverage, downstream service, and sink function when known."
        )
    if "node-web" in attack_surface or ("node" in stacks and "http-api" in attack_surface):
        guidance.append(
            "Node.js Web: inventory Express/Koa/Fastify/Next.js routes, middleware chain, body parsers, upload handlers, and auth/session/CORS/CSRF coverage in attack-surface.md."
        )
        append_once(minimum_fields)
        guidance.append(
            "For each Node.js entry, note handler/API route, request readers such as query/path/body/header/cookie/files, middleware/auth coverage, downstream service, and sink function when known."
        )
    if "node-library" in attack_surface:
        guidance.append(
            "Node.js Library: inventory exported APIs, parser/processor callbacks, option objects, CLI/bin entry points, and caller-controlled input shapes in attack-surface.md."
        )
        guidance.append(
            "Minimum library inventory fields: public API or CLI, input shape, caller-controlled options, transformation path, high-risk sink, consumer impact assumption, current verification status."
        )
        guidance.append(
            "For each Node.js library lead, distinguish library-local behavior from application-level impact; keep consumer-impact assumptions unverified until a minimal Docker Node PoC proves the oracle."
        )
    if "python-web" in attack_surface or ("python" in stacks and "http-api" in attack_surface):
        guidance.append(
            "Python Web: inventory Flask/Django/FastAPI/Starlette routes, middleware, dependencies/decorators, upload handlers, and auth/session/CORS/CSRF coverage in attack-surface.md."
        )
        append_once(minimum_fields)
        guidance.append(
            "For each Python entry, note handler/view/path operation, request readers such as query/path/body/header/cookie/files, middleware/dependency/auth coverage, downstream service, and sink function when known."
        )
    if "http-api" in attack_surface:
        guidance.append("HTTP/API: summarize route or API inventory in attack-surface.md before deep verification.")
        append_once(minimum_fields)
    if any(item in attack_surface for item in ("routes", "route", "router", "controllers", "controller", "api", "graphql", "auth", "cmd")):
        guidance.append(
            "Detected route/controller/API/auth/cmd directories: inspect them for entry points, trust boundaries, and source-to-sink hypotheses."
        )
    return guidance


def local_knowledge_checklists(root: Path, stacks: list[str], attack_surface: list[str]) -> list[str]:
    checklists: list[str] = []

    def add(path: str) -> None:
        if path not in checklists:
            checklists.append(path)

    ssrf_markers = [
        "http.get",
        "http.post",
        "http.client.do",
        "resttemplate",
        "webclient",
        "httpurlconnection",
        "okhttp",
        "fetch(",
        "axios",
        "request(",
        "got(",
        "requests.get",
        "requests.post",
        "urlopen",
        "callbackurl",
        "callback_url",
        "webhook",
        "proxy",
    ]
    path_traversal_markers = [
        "path.join",
        "filepath.join",
        "paths.get",
        "files.read",
        "files.write",
        "fs.readfile",
        "fs.createreadstream",
        "sendfile",
        "os.open",
        "os.readfile",
        "archive",
        "zip",
        "tar",
        "multipart",
        "filename",
        "download",
        "../",
    ]
    prototype_pollution_markers = [
        "__proto__",
        "constructor.prototype",
        "lodash.merge",
        "deepmerge",
        "object.assign",
        "set-value",
        "object-path",
        "prototype pollution",
    ]

    code_suffixes = {
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".py",
        ".rb",
        ".php",
        ".kt",
        ".scala",
        ".json",
        ".yaml",
        ".yml",
    }

    if "http-api" in attack_surface and repository_contains(root, ssrf_markers, code_suffixes):
        add("assets/references/ssrf-checklist.md")
    elif repository_contains(root, ["webhook", "callback_url", "callbackurl", "metadata"], code_suffixes):
        add("assets/references/ssrf-checklist.md")

    if repository_contains(root, path_traversal_markers, code_suffixes):
        add("assets/references/path-traversal-checklist.md")

    if "node" in stacks and repository_contains(root, prototype_pollution_markers, code_suffixes):
        add("assets/references/prototype-pollution-checklist.md")

    return checklists


def build_result(root: Path, workspace_dir: Path) -> dict[str, Any]:
    stacks = detect_stack(root)
    attack_surface = detect_attack_surface(root)
    plan = choose_tools(root, stacks, attack_surface)
    return {
        "target_dir": str(root),
        "workspace_dir": str(workspace_dir),
        "detected_stack": stacks,
        "attack_surface_hints": attack_surface,
        "specialized_playbooks": specialized_playbooks(stacks, attack_surface),
        "local_knowledge_checklists": local_knowledge_checklists(root, stacks, attack_surface),
        "audit_focus": audit_focus(stacks, attack_surface),
        "attack_surface_guidance": attack_surface_guidance(stacks, attack_surface),
        "recommended_tools": plan,
        "command_hints": command_hints(root, workspace_dir, plan),
        "execution_notes": [
            "Treat first-pass scanner non-zero exits as findings or environmental notes unless they clearly indicate a broken command.",
            "Read <audit-workspace>/evidence/initial-probes/initial-probes-summary.json before interpreting raw scanner logs.",
            "Initial probe statuses are ran_ok, skipped_tool_missing, skipped_no_package_sources, failed_nonfatal, and failed_fatal.",
            "Skip npm audit when the repository has no package-lock.json or npm-shrinkwrap.json.",
            "Prefer run-initial-probes.sh for osv-scanner so 'No package sources found' is recorded as skipped, not as a blocker.",
            "If osv-scanner is run manually and exits 128 with 'No package sources found', record it as no supported package source / skipped and continue.",
            "Run trivy against the absolute repository path, not against '.' unless the cwd is already anchored correctly.",
            "The first trivy run may spend time downloading its vulnerability database; that is normal and not by itself a hang.",
        ],
    }


def render_text(result: dict[str, Any]) -> str:
    lines = [
        f"target_dir={result['target_dir']}",
        f"workspace_dir={result['workspace_dir']}",
        f"detected_stack={','.join(result['detected_stack'])}",
        f"attack_surface_hints={','.join(result['attack_surface_hints']) or 'none'}",
        "",
        "recommended_tools:",
    ]
    tools = result["recommended_tools"]
    for category in ("broad_probe", "sast", "dependency", "secrets", "dast", "verification", "hardening", "document_qa"):
        if category in tools:
            lines.append(f"- {category}: {', '.join(tools[category])}")
    if result["command_hints"]:
        lines.extend(["", "command_hints:"])
        for hint in result["command_hints"]:
            lines.append(f"- {hint}")
    playbooks = result.get("specialized_playbooks") or []
    if playbooks:
        lines.extend(["", "specialized_playbooks:"])
        for playbook in playbooks:
            lines.append(f"- {playbook}")
    checklists = result.get("local_knowledge_checklists") or []
    if checklists:
        lines.extend(["", "local_knowledge_checklists:"])
        for checklist in checklists:
            lines.append(f"- {checklist}")
    focus = result.get("audit_focus") or []
    if focus:
        lines.extend(["", "audit_focus:"])
        for item in focus:
            lines.append(f"- {item}")
    handoff = result.get("attack_surface_guidance") or []
    if handoff:
        lines.extend(["", "attack_surface_guidance:"])
        for item in handoff:
            lines.append(f"- {item}")
    notes = result.get("execution_notes") or []
    if notes:
        lines.extend(["", "execution_notes:"])
        for note in notes:
            lines.append(f"- {note}")
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    root = Path(args.target_dir).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"target directory does not exist: {root}")
    workspace_dir = discover_workspace_dir(root, args.workspace_dir)
    result = build_result(root, workspace_dir)
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render_text(result))


if __name__ == "__main__":
    main()
