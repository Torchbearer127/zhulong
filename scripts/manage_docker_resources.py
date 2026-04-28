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
    images = docker_json_lines(["image", "ls", "--no-trunc", "--format", "{{json .}}"])
    volumes = docker_json_lines(["volume", "ls", "--format", "{{json .}}"])
    networks = docker_json_lines(["network", "ls", "--no-trunc", "--format", "{{json .}}"])
    containers = docker_json_lines(["ps", "-a", "--no-trunc", "--format", "{{json .}}"])

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


def is_owned(item: dict[str, Any], workspace_name: str) -> bool:
    item_labels = labels(item)
    return item_labels.get(LABEL_MANAGED) == "true" and item_labels.get(LABEL_WORKSPACE) == workspace_name


def split_owned(items: list[dict[str, Any]], workspace_name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    owned: list[dict[str, Any]] = []
    unowned: list[dict[str, Any]] = []
    for item in items:
        if is_owned(item, workspace_name):
            owned.append(item)
        else:
            unowned.append(item)
    return owned, unowned


def build_cleanup_plan(baseline: dict[str, Any], current: dict[str, Any], workspace_name: str) -> dict[str, Any]:
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

    new_containers = []
    for container_id in new_container_ids:
        new_containers.append(current_containers[container_id])
    owned_containers, unowned_containers = split_owned(new_containers, workspace_name)
    running_containers = [item for item in owned_containers if str(item.get("state") or "").lower() == "running"]
    stopped_containers = [item for item in owned_containers if str(item.get("state") or "").lower() != "running"]

    owned_images, unowned_images = split_owned([current_images[item_id] for item_id in new_image_ids], workspace_name)
    owned_volumes, unowned_volumes = split_owned([current_volumes[name] for name in new_volume_names], workspace_name)
    owned_networks, unowned_networks = split_owned([current_networks[name] for name in new_network_names], workspace_name)

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
            "note": "Only resources absent from the baseline and carrying this workspace's Zhulong ownership labels are eligible; cleanup uses explicit docker rm/rmi/volume rm/network rm commands.",
        },
        "containers": {
            "stopped_owned": stopped_containers,
            "running_owned_skipped": running_containers,
            "unattributed_new_skipped": unowned_containers,
        },
        "volumes": owned_volumes,
        "networks": owned_networks,
        "images": owned_images,
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
        "unattributed_new_skipped": sum(
            len(plan.get("unattributed_new_skipped", {}).get(key, []))
            for key in ("images", "volumes", "networks")
        ) + len(plan.get("containers", {}).get("unattributed_new_skipped", [])),
    }


def owned_residue_count(plan: dict[str, Any]) -> int:
    counts = plan_counts(plan)
    return (
        counts["stopped_owned_containers"]
        + counts["running_owned_containers_skipped"]
        + counts["owned_volumes"]
        + counts["owned_networks"]
        + counts["owned_images"]
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
    parser.add_argument("--apply", action="store_true", help="Actually remove resources. Without this, cleanup is dry-run only.")
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

    if args.capture_baseline:
        snapshot = capture_snapshot()
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

    plan = build_cleanup_plan(baseline, current, workspace.name)
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
                print(
                    "unattributed Docker resources remain; inspect the cleanup plan and remove only resources proven to belong to this audit.",
                    file=sys.stderr,
                )
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
