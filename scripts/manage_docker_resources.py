#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_NETWORKS = {"bridge", "host", "none"}
BASELINE_RELATIVE_PATH = Path("docker") / "docker-resource-baseline.json"
PLAN_RELATIVE_PATH = Path("docker") / "docker-cleanup-plan.json"
CLEAN_STATUS_RELATIVE_PATH = Path("docker") / "docker-cleanliness-status.json"
LABEL_MANAGED = "org.zhulong.managed"
LABEL_WORKSPACE = "org.zhulong.workspace"
LEGACY_LABEL_WORKSPACE = "com.zhulong.workspace"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_docker(args: list[str], *, allow_fail: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True)
    if proc.returncode != 0 and not allow_fail:
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        raise RuntimeError(f"docker {' '.join(args)} failed: {output}")
    return proc


def docker_json_lines(args: list[str]) -> list[dict[str, Any]]:
    proc = run_docker(args, allow_fail=True)
    if proc.returncode != 0:
        return []
    items: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            items.append(value)
    return items


def capture_build_cache() -> list[dict[str, Any]]:
    proc = run_docker(["builder", "du", "--verbose"], allow_fail=True)
    if proc.returncode != 0:
        return []
    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            if current.get("id"):
                records.append(current)
            current = {}
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if key == "id":
            current["id"] = value
        elif key == "reclaimable":
            current["reclaimable"] = value.lower() == "true"
        elif key == "size":
            current["size"] = value
        elif key == "description":
            current["description"] = value
        elif key == "created_at":
            current["created_at"] = value
        elif key == "last_used":
            current["last_used"] = value
    if current.get("id"):
        records.append(current)
    return records


def inspect_labels(kind: str, identifier: str) -> dict[str, str]:
    if not identifier:
        return {}
    inspect_args = {
        "image": ["image", "inspect", identifier],
        "volume": ["volume", "inspect", identifier],
        "network": ["network", "inspect", identifier],
        "container": ["container", "inspect", identifier],
    }[kind]
    proc = run_docker(inspect_args, allow_fail=True)
    if proc.returncode != 0:
        return {}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return {}
    raw_labels = data[0].get("Labels")
    if raw_labels is None and isinstance(data[0].get("Config"), dict):
        raw_labels = data[0]["Config"].get("Labels")
    if not isinstance(raw_labels, dict):
        return {}
    return {str(key): str(value) for key, value in raw_labels.items() if value is not None}


def capture_snapshot() -> dict[str, Any]:
    info_proc = run_docker(["info", "--format", "{{json .}}"], allow_fail=True)
    if info_proc.returncode != 0:
        return {
            "schema_version": 1,
            "captured_at": utc_now(),
            "docker_available": False,
            "error": ((info_proc.stdout or "") + (info_proc.stderr or "")).strip(),
            "images": [],
            "volumes": [],
            "networks": [],
            "containers": [],
        }

    context_proc = run_docker(["context", "show"], allow_fail=True)
    images = docker_json_lines(["image", "ls", "-a", "--no-trunc", "--format", "{{json .}}"])
    volumes = docker_json_lines(["volume", "ls", "--format", "{{json .}}"])
    networks = docker_json_lines(["network", "ls", "--no-trunc", "--format", "{{json .}}"])
    containers = docker_json_lines(["ps", "-a", "--no-trunc", "--format", "{{json .}}"])
    build_cache = capture_build_cache()

    return {
        "schema_version": 1,
        "captured_at": utc_now(),
        "docker_available": True,
        "docker_context": context_proc.stdout.strip() if context_proc.returncode == 0 else "",
        "images": [
            {
                "id": str(item.get("ID") or item.get("ID".lower()) or "").strip(),
                "repository": str(item.get("Repository") or "").strip(),
                "tag": str(item.get("Tag") or "").strip(),
                "labels": inspect_labels("image", str(item.get("ID") or item.get("ID".lower()) or "").strip()),
            }
            for item in images
        ],
        "volumes": [
            {
                "name": str(item.get("Name") or "").strip(),
                "driver": str(item.get("Driver") or "").strip(),
                "labels": inspect_labels("volume", str(item.get("Name") or "").strip()),
            }
            for item in volumes
        ],
        "networks": [
            {
                "id": str(item.get("ID") or "").strip(),
                "name": str(item.get("Name") or "").strip(),
                "driver": str(item.get("Driver") or "").strip(),
                "labels": inspect_labels("network", str(item.get("Name") or "").strip()),
            }
            for item in networks
        ],
        "containers": [
            {
                "id": str(item.get("ID") or "").strip(),
                "name": str(item.get("Names") or "").strip(),
                "image": str(item.get("Image") or "").strip(),
                "state": str(item.get("State") or "").strip(),
                "status": str(item.get("Status") or "").strip(),
                "labels": inspect_labels("container", str(item.get("ID") or "").strip()),
            }
            for item in containers
        ],
        "build_cache": build_cache,
    }


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"Missing JSON file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON file: {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"Expected object JSON file: {path}")
    return data


def image_ids(snapshot: dict[str, Any]) -> set[str]:
    return {
        str(item.get("id") or "").strip()
        for item in snapshot.get("images", [])
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    }


def ids(snapshot: dict[str, Any], key: str) -> set[str]:
    return {
        str(item.get("id") or "").strip()
        for item in snapshot.get(key, [])
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    }


def names(snapshot: dict[str, Any], key: str, field: str = "name") -> set[str]:
    return {
        str(item.get(field) or "").strip()
        for item in snapshot.get(key, [])
        if isinstance(item, dict) and str(item.get(field) or "").strip()
    }


def by_name(snapshot: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in snapshot.get(key, []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            result[name] = item
    return result


def by_id(snapshot: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in snapshot.get(key, []):
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or "").strip()
        if item_id:
            result[item_id] = item
    return result


def labels(item: dict[str, Any]) -> dict[str, str]:
    raw = item.get("labels")
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def image_ref(item: dict[str, Any]) -> str:
    repository = str(item.get("repository") or "").strip()
    tag = str(item.get("tag") or "").strip()
    if not repository or not tag or repository == "<none>" or tag == "<none>":
        return ""
    return f"{repository}:{tag}"


def is_owned(item: dict[str, Any], workspace_name: str, adopted_compose_projects: set[str] | None = None) -> bool:
    item_labels = labels(item)
    if item_labels.get(LABEL_MANAGED) == "true" and item_labels.get(LABEL_WORKSPACE) == workspace_name:
        return True
    if item_labels.get(LEGACY_LABEL_WORKSPACE) == workspace_name:
        return True
    compose_project = item_labels.get("com.docker.compose.project", "")
    return bool(compose_project and adopted_compose_projects and compose_project in adopted_compose_projects)


def is_owned_image(
    item: dict[str, Any],
    workspace_name: str,
    adopted_compose_projects: set[str] | None = None,
    adopted_image_refs: set[str] | None = None,
) -> bool:
    if is_owned(item, workspace_name, adopted_compose_projects):
        return True
    ref = image_ref(item)
    return bool(ref and adopted_image_refs and ref in adopted_image_refs)


def split_owned(
    items: list[dict[str, Any]],
    workspace_name: str,
    adopted_compose_projects: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    owned: list[dict[str, Any]] = []
    unowned: list[dict[str, Any]] = []
    for item in items:
        if is_owned(item, workspace_name, adopted_compose_projects):
            owned.append(item)
        else:
            unowned.append(item)
    return owned, unowned


def split_owned_named(
    items: list[dict[str, Any]],
    workspace_name: str,
    adopted_compose_projects: set[str] | None = None,
    adopted_names: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    owned: list[dict[str, Any]] = []
    unowned: list[dict[str, Any]] = []
    adopted_names = adopted_names or set()
    for item in items:
        name = str(item.get("name") or "").strip()
        if is_owned(item, workspace_name, adopted_compose_projects) or (name and name in adopted_names):
            owned.append(item)
        else:
            unowned.append(item)
    return owned, unowned


def split_owned_images(
    items: list[dict[str, Any]],
    workspace_name: str,
    adopted_compose_projects: set[str] | None = None,
    adopted_image_refs: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    owned: list[dict[str, Any]] = []
    unowned: list[dict[str, Any]] = []
    for item in items:
        if is_owned_image(item, workspace_name, adopted_compose_projects, adopted_image_refs):
            owned.append(item)
        else:
            unowned.append(item)
    return owned, unowned


def build_cleanup_plan(
    baseline: dict[str, Any],
    current: dict[str, Any],
    workspace_name: str,
    *,
    adopted_compose_projects: set[str] | None = None,
    adopted_image_refs: set[str] | None = None,
    adopted_network_names: set[str] | None = None,
    adopted_volume_names: set[str] | None = None,
    adopt_build_cache: bool = False,
    adopted_build_cache_ids: set[str] | None = None,
) -> dict[str, Any]:
    baseline_images = image_ids(baseline)
    current_images = by_id(current, "images")
    new_image_ids = sorted(set(current_images) - baseline_images)

    baseline_volumes = names(baseline, "volumes")
    current_volumes = by_name(current, "volumes")
    new_volume_names = sorted(set(current_volumes) - baseline_volumes)

    baseline_networks = names(baseline, "networks")
    current_networks = by_name(current, "networks")
    new_network_names = sorted(
        name
        for name in set(current_networks) - baseline_networks
        if name not in DEFAULT_NETWORKS
    )

    baseline_containers = image_ids({"images": baseline.get("containers", [])})
    current_containers = by_id(current, "containers")
    new_container_ids = sorted(set(current_containers) - baseline_containers)

    baseline_build_cache = ids(baseline, "build_cache")
    current_build_cache = by_id(current, "build_cache")
    new_build_cache_ids = sorted(set(current_build_cache) - baseline_build_cache)

    new_containers = []
    for container_id in new_container_ids:
        new_containers.append(current_containers[container_id])
    owned_containers, unowned_containers = split_owned(new_containers, workspace_name, adopted_compose_projects)
    running_containers = [item for item in owned_containers if str(item.get("state") or "").lower() == "running"]
    stopped_containers = [item for item in owned_containers if str(item.get("state") or "").lower() != "running"]

    owned_images, unowned_images = split_owned_images(
        [current_images[item_id] for item_id in new_image_ids],
        workspace_name,
        adopted_compose_projects,
        adopted_image_refs,
    )
    owned_volumes, unowned_volumes = split_owned_named(
        [current_volumes[name] for name in new_volume_names],
        workspace_name,
        adopted_compose_projects,
        adopted_volume_names,
    )
    owned_networks, unowned_networks = split_owned_named(
        [current_networks[name] for name in new_network_names],
        workspace_name,
        adopted_compose_projects,
        adopted_network_names,
    )
    new_build_cache = [current_build_cache[item_id] for item_id in new_build_cache_ids]
    reclaimable_build_cache = [item for item in new_build_cache if item.get("reclaimable") is True]
    non_reclaimable_build_cache = [item for item in new_build_cache if item.get("reclaimable") is not True]
    adopted_build_cache_ids = adopted_build_cache_ids or set()
    owned_build_cache = [
        item for item in reclaimable_build_cache
        if str(item.get("id") or "").strip() in adopted_build_cache_ids
    ]
    unowned_build_cache = [
        item for item in reclaimable_build_cache
        if str(item.get("id") or "").strip() not in adopted_build_cache_ids
    ]

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "baseline_captured_at": baseline.get("captured_at"),
        "current_captured_at": current.get("captured_at"),
        "safety_policy": {
            "delete_baseline_resources": False,
            "delete_running_containers_by_default": False,
            "delete_unowned_resources": False,
            "uses_docker_prune": False,
            "ownership_labels_required": {
                LABEL_MANAGED: "true",
                LABEL_WORKSPACE: workspace_name,
            },
            "adopted_compose_projects": sorted(adopted_compose_projects or []),
            "adopted_image_refs": sorted(adopted_image_refs or []),
            "adopted_network_names": sorted(adopted_network_names or []),
            "adopted_volume_names": sorted(adopted_volume_names or []),
            "adopt_build_cache": adopt_build_cache,
            "adopted_build_cache_ids": sorted(adopted_build_cache_ids),
            "note": (
                "Only resources absent from the baseline and carrying this workspace's Zhulong ownership labels are eligible by default. "
                "Explicitly adopted Compose projects, image refs, or exact BuildKit cache IDs are also eligible when absent from baseline. "
                "Cleanup uses explicit docker rm/rmi/volume rm/network rm commands and exact cache-id filtered BuildKit cleanup."
            ),
        },
        "containers": {
            "stopped_owned": stopped_containers,
            "running_owned_skipped": running_containers,
            "unattributed_new_skipped": unowned_containers,
        },
        "volumes": owned_volumes,
        "networks": owned_networks,
        "images": owned_images,
        "build_cache": {
            "adopted_reclaimable": owned_build_cache,
            "unattributed_new_skipped": unowned_build_cache,
            "non_reclaimable_new_skipped": non_reclaimable_build_cache,
        },
        "unattributed_new_skipped": {
            "images": unowned_images,
            "volumes": unowned_volumes,
            "networks": unowned_networks,
        },
    }


def plan_counts(plan: dict[str, Any]) -> dict[str, int]:
    return {
        "stopped_owned_containers": len(plan.get("containers", {}).get("stopped_owned", [])),
        "running_owned_containers_skipped": len(plan.get("containers", {}).get("running_owned_skipped", [])),
        "owned_volumes": len(plan.get("volumes", [])),
        "owned_networks": len(plan.get("networks", [])),
        "owned_images": len(plan.get("images", [])),
        "owned_build_cache": len(plan.get("build_cache", {}).get("adopted_reclaimable", [])),
        "unattributed_new_skipped": sum(
            len(plan.get("unattributed_new_skipped", {}).get(key, []))
            for key in ("images", "volumes", "networks")
        )
        + len(plan.get("containers", {}).get("unattributed_new_skipped", []))
        + len(plan.get("build_cache", {}).get("unattributed_new_skipped", []))
        + len(plan.get("build_cache", {}).get("non_reclaimable_new_skipped", [])),
    }


def owned_residue_count(plan: dict[str, Any]) -> int:
    counts = plan_counts(plan)
    return (
        counts["stopped_owned_containers"]
        + counts["running_owned_containers_skipped"]
        + counts["owned_volumes"]
        + counts["owned_networks"]
        + counts["owned_images"]
        + counts["owned_build_cache"]
    )


def print_plan(plan: dict[str, Any]) -> None:
    counts = plan_counts(plan)
    print("Docker cleanup plan:")
    for key, value in counts.items():
        print(f"- {key}: {value}")
    if counts["running_owned_containers_skipped"]:
        print("- note: running containers are skipped by default; stop them deliberately before cleanup if they belong to this audit.")
    if counts["unattributed_new_skipped"]:
        print("- note: new resources without this workspace's Zhulong ownership labels are listed for review but will not be removed.")


def print_strict_unattributed_blocker(plan: dict[str, Any]) -> None:
    print(
        "unattributed Docker resources remain; inspect the cleanup plan and remove only resources proven to belong to this audit.",
        file=sys.stderr,
    )
    build_cache = plan.get("build_cache", {})
    review_only_cache = [
        item for key in ("unattributed_new_skipped", "non_reclaimable_new_skipped")
        for item in build_cache.get(key, [])
        if isinstance(item, dict)
    ]
    if review_only_cache:
        exact_ids = [str(item.get("id") or "").strip() for item in review_only_cache if str(item.get("id") or "").strip()]
        print(
            "BuildKit cache blocker: unattributed BuildKit cache is review-only and cannot be auto-deleted safely.",
            file=sys.stderr,
        )
        print(
            "The workspace must remain blocked unless the operator explicitly resolves the cache or accepts a new baseline before verification resumes.",
            file=sys.stderr,
        )
        print("The agent must not manually mark the audit completed while strict Docker cleanliness is blocked.", file=sys.stderr)
        if exact_ids:
            print("Review-only BuildKit cache IDs:", file=sys.stderr)
            for cache_id in exact_ids[:8]:
                print(f"- {cache_id}", file=sys.stderr)
            if len(exact_ids) > 8:
                print(f"- ... {len(exact_ids) - 8} more omitted; inspect docker-cleanup-plan.json", file=sys.stderr)
            print(
                "If one exact cache ID is proven to belong to this isolated audit, use this command shape:",
                file=sys.stderr,
            )
            print(
                "python3 <audit-workspace>/bin/manage-docker-resources.py "
                "--workspace-dir <audit-workspace> --cleanup-created "
                "--adopt-build-cache --adopt-build-cache-id <cache-id> --apply",
                file=sys.stderr,
            )
        non_reclaimable_ids = [
            str(item.get("id") or "").strip()
            for item in build_cache.get("non_reclaimable_new_skipped", [])
            if isinstance(item, dict) and str(item.get("id") or "").strip()
        ]
        if non_reclaimable_ids:
            print(
                "Some BuildKit cache records are not reclaimable by Docker; leave the audit blocked until the operator resolves or baselines them deliberately.",
                file=sys.stderr,
            )


def refuse_baseline_overwrite_if_residue_exists(
    *,
    workspace: Path,
    baseline_path: Path,
    plan_path: Path,
    adopted_compose_projects: set[str],
    adopted_image_refs: set[str],
    adopted_network_names: set[str],
    adopted_volume_names: set[str],
    adopt_build_cache: bool,
    adopted_build_cache_ids: set[str],
    current_file: str | None,
) -> None:
    baseline = load_json(baseline_path)
    if not baseline.get("docker_available", True):
        return
    current = load_json(Path(current_file).expanduser().resolve()) if current_file else capture_snapshot()
    if not current.get("docker_available", True):
        raise SystemExit("Docker is unavailable; refusing to overwrite baseline safely.")
    plan = build_cleanup_plan(
        baseline,
        current,
        workspace.name,
        adopted_compose_projects=adopted_compose_projects,
        adopted_image_refs=adopted_image_refs,
        adopted_network_names=adopted_network_names,
        adopted_volume_names=adopted_volume_names,
        adopt_build_cache=adopt_build_cache,
        adopted_build_cache_ids=adopted_build_cache_ids if adopt_build_cache else set(),
    )
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts = plan_counts(plan)
    if owned_residue_count(plan) or counts["unattributed_new_skipped"]:
        raise SystemExit(
            "Refusing to overwrite Docker baseline while post-baseline resources remain.\n"
            f"cleanup_plan={plan_path}\n"
            "Overwriting now would hide Docker residue from strict cleanliness checks. "
            "Clean owned resources with --cleanup-created --apply, adopt only exact proven resources "
            "with --adopt-image-ref/--adopt-network-name/--adopt-volume-name/--adopt-build-cache-id, "
            "or leave the workspace blocked with the review-only residue recorded."
        )


def write_cleanliness_status(workspace: Path, plan: dict[str, Any], *, strict: bool) -> dict[str, Any]:
    counts = plan_counts(plan)
    owned_remaining = owned_residue_count(plan)
    unattributed_remaining = counts["unattributed_new_skipped"]
    status = {
        "schema_version": 1,
        "checked_at": utc_now(),
        "workspace": workspace.name,
        "clean": owned_remaining == 0 and (not strict or unattributed_remaining == 0),
        "strict": strict,
        "counts": counts,
        "note": (
            "clean=true means no current-workspace owned Docker resources remain. "
            "When strict=true, clean also requires zero post-baseline unattributed resources. "
            "Unattributed resources are review-only and may belong to parallel work; they are not auto-deleted."
        ),
    }
    path = workspace / CLEAN_STATUS_RELATIVE_PATH
    path.write_text(json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return status


def remove_resource(kind: str, identifier: str) -> tuple[bool, str]:
    commands = {
        "container": ["rm", "-f", identifier],
        "volume": ["volume", "rm", identifier],
        "network": ["network", "rm", identifier],
        "image": ["image", "rm", identifier],
    }
    proc = run_docker(commands[kind], allow_fail=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, output


def remove_build_cache(identifier: str) -> tuple[bool, str]:
    proc = run_docker(["buildx", "prune", "--force", "--filter", f"id={identifier}"], allow_fail=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, output


def apply_cleanup(plan: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in plan.get("containers", {}).get("stopped_owned", []):
        identifier = str(item.get("id") or "").strip()
        if identifier:
            ok, output = remove_resource("container", identifier)
            results.append({"kind": "container", "id": identifier, "ok": ok, "output": output})
    for item in plan.get("networks", []):
        name = str(item.get("name") or "").strip()
        if name:
            ok, output = remove_resource("network", name)
            results.append({"kind": "network", "name": name, "ok": ok, "output": output})
    for item in plan.get("volumes", []):
        name = str(item.get("name") or "").strip()
        if name:
            ok, output = remove_resource("volume", name)
            results.append({"kind": "volume", "name": name, "ok": ok, "output": output})
    for item in plan.get("images", []):
        identifier = str(item.get("id") or "").strip()
        if identifier:
            ok, output = remove_resource("image", identifier)
            results.append({"kind": "image", "id": identifier, "ok": ok, "output": output})
    for item in plan.get("build_cache", {}).get("adopted_reclaimable", []):
        identifier = str(item.get("id") or "").strip()
        if identifier:
            ok, output = remove_build_cache(identifier)
            results.append({"kind": "build_cache", "id": identifier, "ok": ok, "output": output})
    return results


def workspace_path(raw: str) -> Path:
    workspace = Path(raw).expanduser().resolve()
    if not (workspace / "asr-config.json").exists():
        raise SystemExit(f"Not a Zhulong audit workspace: {workspace}")
    return workspace


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture and clean Docker resources created after a Zhulong audit workspace baseline.",
    )
    parser.add_argument("--workspace-dir", required=True, help="Zhulong audit workspace directory.")
    parser.add_argument("--capture-baseline", action="store_true", help="Capture the current Docker resource baseline.")
    parser.add_argument("--show-created", action="store_true", help="Show resources created after the baseline.")
    parser.add_argument("--cleanup-created", action="store_true", help="Clean resources created after the baseline.")
    parser.add_argument("--verify-clean", action="store_true", help="Fail if current-workspace owned Docker resources still exist.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="With --verify-clean, also fail when post-baseline unattributed resources remain; never auto-deletes them.",
    )
    parser.add_argument(
        "--adopt-compose-project",
        action="append",
        default=[],
        metavar="PROJECT",
        help="Treat new resources labeled com.docker.compose.project=PROJECT as audit-owned for this cleanup run.",
    )
    parser.add_argument(
        "--adopt-image-ref",
        action="append",
        default=[],
        metavar="IMAGE:TAG",
        help="Treat a new image ref such as mysql:5.7 as audit-owned for this cleanup run when it was absent from the baseline.",
    )
    parser.add_argument(
        "--adopt-network-name",
        action="append",
        default=[],
        metavar="NETWORK",
        help="Treat one exact new Docker network name as audit-owned for this cleanup run when it was absent from the baseline.",
    )
    parser.add_argument(
        "--adopt-volume-name",
        action="append",
        default=[],
        metavar="VOLUME",
        help="Treat one exact new Docker volume name as audit-owned for this cleanup run when it was absent from the baseline.",
    )
    parser.add_argument(
        "--adopt-build-cache",
        action="store_true",
        help="Allow exact BuildKit cache-id adoption for this cleanup run. Pair with --adopt-build-cache-id.",
    )
    parser.add_argument(
        "--adopt-build-cache-id",
        action="append",
        default=[],
        metavar="CACHE_ID",
        help="Treat one new reclaimable BuildKit cache record as audit-owned for this cleanup run by exact cache id.",
    )
    parser.add_argument("--apply", action="store_true", help="Actually remove resources. Without this, cleanup is dry-run only.")
    parser.add_argument(
        "--force-overwrite-baseline",
        action="store_true",
        help=(
            "Replace an existing Docker baseline. Use only before verification starts or after a deliberate manual reset; "
            "normal audits should keep the first available baseline."
        ),
    )
    parser.add_argument("--baseline-file", help="Use a custom baseline snapshot JSON file.")
    parser.add_argument("--current-file", help="Use a custom current snapshot JSON file, mainly for tests.")
    args = parser.parse_args()

    if not (args.capture_baseline or args.show_created or args.cleanup_created or args.verify_clean):
        parser.error("choose one of --capture-baseline, --show-created, --cleanup-created, or --verify-clean")

    workspace = workspace_path(args.workspace_dir)
    docker_dir = workspace / "docker"
    docker_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = Path(args.baseline_file).expanduser().resolve() if args.baseline_file else workspace / BASELINE_RELATIVE_PATH
    plan_path = workspace / PLAN_RELATIVE_PATH
    adopted_compose_projects = {str(value).strip() for value in args.adopt_compose_project if str(value).strip()}
    adopted_image_refs = {str(value).strip() for value in args.adopt_image_ref if str(value).strip()}
    adopted_network_names = {str(value).strip() for value in args.adopt_network_name if str(value).strip()}
    adopted_volume_names = {str(value).strip() for value in args.adopt_volume_name if str(value).strip()}
    adopted_build_cache_ids = {str(value).strip() for value in args.adopt_build_cache_id if str(value).strip()}
    if adopted_build_cache_ids and not args.adopt_build_cache:
        raise SystemExit("--adopt-build-cache-id requires --adopt-build-cache so cache cleanup is explicitly acknowledged.")

    if args.capture_baseline:
        if baseline_path.exists() and not args.force_overwrite_baseline:
            try:
                existing = load_json(baseline_path)
            except SystemExit:
                existing = {}
            if existing.get("docker_available") is True:
                raise SystemExit(
                    f"Refusing to overwrite existing Docker resource baseline: {baseline_path}\n"
                    "Existing available baselines protect against late-capture mistakes that would hide resources "
                    "created by this audit. If Docker was deliberately reset before verification, rerun with "
                    "--force-overwrite-baseline."
                )
        if baseline_path.exists() and args.force_overwrite_baseline:
            refuse_baseline_overwrite_if_residue_exists(
                workspace=workspace,
                baseline_path=baseline_path,
                plan_path=plan_path,
                adopted_compose_projects=adopted_compose_projects,
                adopted_image_refs=adopted_image_refs,
                adopted_network_names=adopted_network_names,
                adopted_volume_names=adopted_volume_names,
                adopt_build_cache=args.adopt_build_cache,
                adopted_build_cache_ids=adopted_build_cache_ids,
                current_file=args.current_file,
            )
        snapshot = load_json(Path(args.current_file).expanduser().resolve()) if args.current_file else capture_snapshot()
        baseline_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if snapshot.get("docker_available"):
            print(f"docker_resource_baseline={baseline_path}")
            return 0
        print(f"docker_resource_baseline_unavailable={baseline_path}", file=sys.stderr)
        return 0

    baseline = load_json(baseline_path)
    current = load_json(Path(args.current_file).expanduser().resolve()) if args.current_file else capture_snapshot()
    if not baseline.get("docker_available", True):
        raise SystemExit("Baseline was captured while Docker was unavailable; recapture before cleanup.")
    if not current.get("docker_available", True):
        raise SystemExit("Docker is unavailable; cannot compute cleanup plan safely.")

    plan = build_cleanup_plan(
        baseline,
        current,
        workspace.name,
        adopted_compose_projects=adopted_compose_projects,
        adopted_image_refs=adopted_image_refs,
        adopted_network_names=adopted_network_names,
        adopted_volume_names=adopted_volume_names,
        adopt_build_cache=args.adopt_build_cache,
        adopted_build_cache_ids=adopted_build_cache_ids if args.adopt_build_cache else set(),
    )
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print_plan(plan)
    print(f"cleanup_plan={plan_path}")

    if args.verify_clean:
        status = write_cleanliness_status(workspace, plan, strict=args.strict)
        print(f"clean={str(status['clean']).lower()}")
        print(f"cleanliness_status={workspace / CLEAN_STATUS_RELATIVE_PATH}")
        if not status["clean"]:
            if owned_residue_count(plan) != 0:
                print("owned Docker resources remain; run --cleanup-created --apply, then verify again.", file=sys.stderr)
            elif args.strict:
                print_strict_unattributed_blocker(plan)
            return 1
        return 0

    if args.cleanup_created:
        if not args.apply:
            print("dry_run=true")
            print("rerun with --cleanup-created --apply to remove the listed resources.")
            return 0
        results = apply_cleanup(plan)
        (docker_dir / "docker-cleanup-results.json").write_text(
            json.dumps({"finished_at": utc_now(), "results": results}, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        failed = [item for item in results if not item.get("ok")]
        print(f"cleanup_attempted={len(results)}")
        print(f"cleanup_failed={len(failed)}")
        return 1 if failed else 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
