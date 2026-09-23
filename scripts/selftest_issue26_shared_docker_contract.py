#!/usr/bin/env python3
"""Focused offline checks for the issue #26 shared-Docker contract."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCRIPT_ROOT = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_ROOT.parent
sys.path.insert(0, str(SCRIPT_ROOT))

import manage_docker_resources as docker_resources  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")


def run_cli(command: list[str]) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(command, cwd=PLUGIN_ROOT, env=env, capture_output=True, text=True, check=False)


def image(item_id: str, repository: str, tag: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"id": item_id, "repository": repository, "tag": tag}
    if labels:
        value["labels"] = labels
    return value


def volume(name: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"name": name, "driver": "local"}
    if labels:
        value["labels"] = labels
    return value


def network(name: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"id": f"id-{name}", "name": name, "driver": "bridge"}
    if labels:
        value["labels"] = labels
    return value


def container(container_id: str, name: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"id": container_id, "name": name, "state": "exited"}
    if labels:
        value["labels"] = labels
    return value


def build_cache(cache_id: str, *, reclaimable: bool) -> dict[str, Any]:
    return {"id": cache_id, "reclaimable": reclaimable, "size": "1MB"}


def snapshot(
    captured_at: str,
    *,
    docker_available: bool = True,
    images: list[dict[str, Any]],
    volumes: list[dict[str, Any]],
    networks: list[dict[str, Any]],
    containers: list[dict[str, Any]],
    build_cache: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "captured_at": captured_at,
        "docker_available": docker_available,
        "images": images,
        "volumes": volumes,
        "networks": networks,
        "containers": containers,
        "build_cache": build_cache,
    }


def write_snapshot(path: Path, value: dict[str, Any]) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_json_value(path: Path, value: Any) -> Path:
    if isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def assert_rejected(
    command: list[str],
    *,
    expected: str,
    label: str,
    unchanged_path: Path | None = None,
    before: bytes | None = None,
    forbidden_output: tuple[str, ...] = (),
) -> None:
    proc = run_cli(command)
    output = (proc.stdout or "") + (proc.stderr or "")
    require(proc.returncode != 0, f"{label} unexpectedly succeeded")
    require(expected in output, f"{label} did not emit stable error marker: {output!r}")
    require("Traceback" not in output, f"{label} leaked a traceback")
    for forbidden in forbidden_output:
        require(forbidden not in output, f"{label} leaked forbidden diagnostic text: {forbidden!r}")
    if unchanged_path is not None:
        require(unchanged_path.read_bytes() == before, f"{label} changed the protected baseline")


def resource_ids(plan: dict[str, Any], key: str, field: str = "id") -> set[str]:
    return {
        str(item.get(field) or "")
        for item in plan.get(key, [])
        if isinstance(item, dict) and str(item.get(field) or "")
    }


def container_ids(plan: dict[str, Any]) -> set[str]:
    return {
        str(item.get("id") or "")
        for item in plan.get("containers", {}).get("stopped_owned", [])
        if isinstance(item, dict) and str(item.get("id") or "")
    }


def assert_no_foreign_resources_in_delete_plan(plan: dict[str, Any]) -> None:
    forbidden = {
        "sha256:baseline-foreign",
        "sha256:concurrent-foreign",
        "sha256:concurrent-unknown",
    }
    require(not resource_ids(plan, "images") & forbidden, "foreign or unknown images entered the delete plan")
    require(not resource_ids(plan, "volumes", "name") & {"baseline-foreign-volume", "concurrent-foreign-volume", "concurrent-unknown-volume"}, "foreign or unknown volumes entered the delete plan")
    require(not resource_ids(plan, "networks", "name") & {"baseline-foreign-network", "concurrent-foreign-network", "concurrent-unknown-network"}, "foreign or unknown networks entered the delete plan")
    require(not container_ids(plan) & {"container-baseline-foreign", "container-concurrent-foreign", "container-concurrent-unknown"}, "foreign or unknown containers entered the delete plan")


def test_shared_daemon_plan_and_cleanliness_cli() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue26-shared-docker-") as raw:
        workspace = Path(raw) / "security-research-issue26"
        (workspace / "docker").mkdir(parents=True)
        (workspace / "asr-config.json").write_text("{}\n", encoding="utf-8")

        owned = {"org.zhulong.managed": "true", "org.zhulong.workspace": workspace.name}
        foreign = {"org.zhulong.managed": "true", "org.zhulong.workspace": "security-research-other"}
        external_compose = {"com.docker.compose.project": "other-compose-project"}

        baseline = snapshot(
            "2026-09-22T00:00:00Z",
            images=[
                image("sha256:base", "base", "latest"),
                image("sha256:baseline-foreign", "baseline-foreign", "latest", foreign),
            ],
            volumes=[volume("baseline-volume"), volume("baseline-foreign-volume", foreign)],
            networks=[network("bridge"), network("baseline-foreign-network", foreign)],
            containers=[
                container("container-base", "base"),
                container("container-baseline-foreign", "baseline-foreign", foreign),
            ],
            build_cache=[build_cache("cache-base", reclaimable=True), build_cache("cache-baseline-foreign", reclaimable=True)],
        )
        additions = [
            image("sha256:owned", "owned", "latest", owned),
            image("sha256:concurrent-foreign", "concurrent-foreign", "latest", foreign),
            image("sha256:concurrent-unknown", "concurrent-unknown", "latest"),
        ]
        current_with_owned = snapshot(
            "2026-09-22T00:10:00Z",
            images=baseline["images"] + additions,
            volumes=baseline["volumes"]
            + [
                volume("owned-volume", owned),
                volume("concurrent-foreign-volume", external_compose),
                volume("concurrent-unknown-volume"),
            ],
            networks=baseline["networks"]
            + [
                network("owned-network", owned),
                network("concurrent-foreign-network", external_compose),
                network("concurrent-unknown-network"),
            ],
            containers=baseline["containers"]
            + [
                container("container-owned", "owned", owned),
                container("container-concurrent-foreign", "concurrent-foreign", external_compose),
                container("container-concurrent-unknown", "concurrent-unknown"),
            ],
            build_cache=baseline["build_cache"]
            + [build_cache("cache-concurrent", reclaimable=True), build_cache("cache-locked", reclaimable=False)],
        )
        current_without_owned = snapshot(
            "2026-09-22T00:20:00Z",
            images=baseline["images"] + additions[1:],
            volumes=baseline["volumes"] + [volume("concurrent-foreign-volume", external_compose), volume("concurrent-unknown-volume")],
            networks=baseline["networks"] + [network("concurrent-foreign-network", external_compose), network("concurrent-unknown-network")],
            containers=baseline["containers"] + [
                container("container-concurrent-foreign", "concurrent-foreign", external_compose),
                container("container-concurrent-unknown", "concurrent-unknown"),
            ],
            build_cache=baseline["build_cache"] + [build_cache("cache-concurrent", reclaimable=True), build_cache("cache-locked", reclaimable=False)],
        )
        current_matches_baseline = snapshot(
            "2026-09-22T00:30:00Z",
            images=baseline["images"],
            volumes=baseline["volumes"],
            networks=baseline["networks"],
            containers=baseline["containers"],
            build_cache=baseline["build_cache"],
        )
        current_subset = snapshot(
            "2026-09-22T00:35:00Z",
            images=list(baseline["images"])[:1],
            volumes=list(baseline["volumes"])[:1],
            networks=list(baseline["networks"])[:1],
            containers=list(baseline["containers"])[:1],
            build_cache=list(baseline["build_cache"])[:1],
        )
        current_unknown_only = snapshot(
            "2026-09-22T00:40:00Z",
            images=baseline["images"] + [image("sha256:unknown-only", "unknown-only", "latest")],
            volumes=baseline["volumes"] + [volume("unknown-only-volume")],
            networks=baseline["networks"] + [network("unknown-only-network")],
            containers=baseline["containers"] + [container("container-unknown-only", "unknown-only")],
            build_cache=baseline["build_cache"] + [build_cache("cache-unknown-only", reclaimable=True)],
        )

        plan = docker_resources.build_cleanup_plan(baseline, current_with_owned, workspace.name)
        require(docker_resources.owned_residue_count(plan) == 4, "owned resources were not counted for ordinary cleanup")
        require(docker_resources.plan_counts(plan)["unattributed_new_skipped"] == 10, "concurrent external/unknown resources were not recorded")
        require(resource_ids(plan, "images") == {"sha256:owned"}, "only the owned image should be deletable")
        require(resource_ids(plan, "volumes", "name") == {"owned-volume"}, "only the owned volume should be deletable")
        require(resource_ids(plan, "networks", "name") == {"owned-network"}, "only the owned network should be deletable")
        require(container_ids(plan) == {"container-owned"}, "only the owned container should be deletable")
        assert_no_foreign_resources_in_delete_plan(plan)

        baseline_file = write_snapshot(workspace / "docker" / "baseline.json", baseline)
        owned_file = write_snapshot(workspace / "docker" / "current-owned.json", current_with_owned)
        external_file = write_snapshot(workspace / "docker" / "current-external.json", current_without_owned)
        clean_file = write_snapshot(workspace / "docker" / "current-baseline.json", current_matches_baseline)
        subset_file = write_snapshot(workspace / "docker" / "current-subset.json", current_subset)
        unknown_file = write_snapshot(workspace / "docker" / "current-unknown-only.json", current_unknown_only)
        cli = [sys.executable, str(SCRIPT_ROOT / "manage_docker_resources.py"), "--workspace-dir", str(workspace), "--baseline-file", str(baseline_file)]

        ordinary = run_cli([*cli, "--current-file", str(external_file), "--verify-clean"])
        require(ordinary.returncode == 0, "ordinary clean must ignore post-baseline unattributed resources")
        ordinary_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        require(ordinary_status["clean"] is True and ordinary_status["strict"] is False, "ordinary clean status contract changed")

        strict = run_cli([*cli, "--current-file", str(external_file), "--verify-clean", "--strict"])
        strict_output = (strict.stdout or "") + (strict.stderr or "")
        require(strict.returncode != 0, "strict clean must remain blocked while concurrent residue is present")
        require("resource owner or Docker administrator" in strict_output, "strict blocker must route unknown resources to their owner or administrator")
        require("remain blocked" in strict_output, "strict blocker must keep the workspace blocked")
        require("accepts a new baseline" not in strict_output, "strict blocker must not suggest accepting a new baseline")
        require("baselines them deliberately" not in strict_output, "strict blocker must not suggest baselining residue")
        strict_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        require(strict_status["clean"] is False and strict_status["strict"] is True, "strict blocker status must remain dirty and strict")

        strict_clean = run_cli([*cli, "--current-file", str(clean_file), "--verify-clean", "--strict"])
        require(strict_clean.returncode == 0, "strict clean must pass when current state matches the baseline")
        strict_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        require(strict_status["clean"] is True and strict_status["strict"] is True, "strict clean status contract changed")

        subset_ordinary = run_cli([*cli, "--current-file", str(subset_file), "--verify-clean"])
        require(subset_ordinary.returncode == 0, "ordinary clean must pass when baseline resources were removed")
        subset_strict = run_cli([*cli, "--current-file", str(subset_file), "--verify-clean", "--strict"])
        require(subset_strict.returncode == 0, "strict clean must pass when baseline resources were removed")
        subset_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        require(subset_status["clean"] is True and subset_status["strict"] is True, "subset strict status contract changed")

        for overwrite_source in (owned_file, unknown_file):
            baseline_before = baseline_file.read_bytes()
            overwrite = run_cli([*cli, "--current-file", str(overwrite_source), "--capture-baseline", "--force-overwrite-baseline"])
            require(overwrite.returncode != 0, "baseline overwrite must remain blocked while post-baseline residue exists")
            require(baseline_file.read_bytes() == baseline_before, "refused baseline overwrite changed the existing baseline")
            overwrite_plan = json.loads((workspace / "docker" / "docker-cleanup-plan.json").read_text(encoding="utf-8"))
            assert_no_foreign_resources_in_delete_plan(overwrite_plan)

        residue_current = external_file
        malformed_baselines: list[tuple[str, Any, str]] = [
            ("unavailable", snapshot("2026-09-22T01:00:00Z", docker_available=False, images=[], volumes=[], networks=[], containers=[], build_cache=[]), "DOCKER_BASELINE_UNAVAILABLE"),
            ("missing-docker-available", {"schema_version": 1, "images": [], "volumes": [], "networks": [], "containers": [], "build_cache": []}, "DOCKER_BASELINE_INVALID"),
            ("empty-object", {}, "DOCKER_BASELINE_INVALID"),
            ("non-object", [], "DOCKER_BASELINE_INVALID"),
            ("truncated", '{"schema_version": 1,', "DOCKER_BASELINE_INVALID"),
            ("non-bool", {**baseline, "docker_available": "true"}, "DOCKER_BASELINE_INVALID"),
            ("malformed-resource", {**baseline, "images": {}}, "DOCKER_BASELINE_INVALID"),
            ("malformed-resource-item", {**baseline, "images": ["not-an-object"]}, "DOCKER_BASELINE_INVALID"),
            ("malformed-build-cache", {**baseline, "build_cache": {}}, "DOCKER_BASELINE_INVALID"),
            ("malformed-build-cache-item", {**baseline, "build_cache": ["not-an-object"]}, "DOCKER_BASELINE_INVALID"),
        ]
        for label, value, expected in malformed_baselines:
            for force in (False, True):
                malformed_path = workspace / "docker" / f"malformed-{label}-{force}.json"
                write_json_value(malformed_path, value)
                before = malformed_path.read_bytes()
                command = [*cli[:-2], "--baseline-file", str(malformed_path), "--current-file", str(residue_current), "--capture-baseline"]
                if force:
                    command.append("--force-overwrite-baseline")
                assert_rejected(command, expected=expected, label=f"{label} force={force}", unchanged_path=malformed_path, before=before)

        invalid_utf8_baseline = workspace / "docker" / "malformed-invalid-utf8.json"
        invalid_utf8_baseline.write_bytes(b"{\xff")
        invalid_utf8_before = invalid_utf8_baseline.read_bytes()
        invalid_utf8_cli = [*cli[:-2], "--baseline-file", str(invalid_utf8_baseline), "--current-file", str(residue_current), "--capture-baseline"]
        assert_rejected(
            invalid_utf8_cli,
            expected="DOCKER_BASELINE_INVALID",
            label="invalid UTF-8 baseline",
            unchanged_path=invalid_utf8_baseline,
            before=invalid_utf8_before,
            forbidden_output=(str(invalid_utf8_baseline), "UnicodeDecodeError"),
        )

        invalid_baseline = workspace / "docker" / "invalid-baseline-for-operations.json"
        write_json_value(invalid_baseline, {})
        operation_cli = [sys.executable, str(SCRIPT_ROOT / "manage_docker_resources.py"), "--workspace-dir", str(workspace), "--baseline-file", str(invalid_baseline), "--current-file", str(external_file)]
        for operation in (
            ["--verify-clean"],
            ["--verify-clean", "--strict"],
            ["--show-created"],
            ["--cleanup-created"],
        ):
            assert_rejected([*operation_cli, *operation], expected="DOCKER_BASELINE_INVALID", label=f"invalid baseline operation {operation}")

        malformed_current = workspace / "docker" / "malformed-current.json"
        write_json_value(malformed_current, {**current_matches_baseline, "images": {}})
        valid_operation_cli = [sys.executable, str(SCRIPT_ROOT / "manage_docker_resources.py"), "--workspace-dir", str(workspace), "--baseline-file", str(baseline_file), "--current-file", str(malformed_current)]
        for operation in (
            ["--verify-clean"],
            ["--verify-clean", "--strict"],
            ["--show-created"],
            ["--cleanup-created"],
        ):
            assert_rejected([*valid_operation_cli, *operation], expected="DOCKER_CURRENT_INVALID", label=f"invalid current operation {operation}")

        unavailable_current = workspace / "docker" / "unavailable-current.json"
        write_snapshot(unavailable_current, snapshot("2026-09-22T01:05:00Z", docker_available=False, images=[], volumes=[], networks=[], containers=[], build_cache=[]))
        unavailable_operation_cli = [sys.executable, str(SCRIPT_ROOT / "manage_docker_resources.py"), "--workspace-dir", str(workspace), "--baseline-file", str(baseline_file), "--current-file", str(unavailable_current)]
        for operation in (
            ["--verify-clean"],
            ["--verify-clean", "--strict"],
            ["--show-created"],
            ["--cleanup-created"],
        ):
            assert_rejected([*unavailable_operation_cli, *operation], expected="DOCKER_CURRENT_UNAVAILABLE", label=f"unavailable current operation {operation}")

        first_available = workspace / "docker" / "first-available-baseline.json"
        first_capture = run_cli([
            sys.executable,
            str(SCRIPT_ROOT / "manage_docker_resources.py"),
            "--workspace-dir", str(workspace),
            "--baseline-file", str(first_available),
            "--current-file", str(clean_file),
            "--capture-baseline",
        ])
        require(first_capture.returncode == 0, "first capture without a baseline must remain available")
        require(json.loads(first_available.read_text(encoding="utf-8"))["docker_available"] is True, "first available capture did not persist a usable snapshot")

        unavailable_current = workspace / "docker" / "first-unavailable-current.json"
        write_snapshot(unavailable_current, snapshot("2026-09-22T01:10:00Z", docker_available=False, images=[], volumes=[], networks=[], containers=[], build_cache=[]))
        first_unavailable = workspace / "docker" / "first-unavailable-baseline.json"
        unavailable_capture = run_cli([
            sys.executable,
            str(SCRIPT_ROOT / "manage_docker_resources.py"),
            "--workspace-dir", str(workspace),
            "--baseline-file", str(first_unavailable),
            "--current-file", str(unavailable_current),
            "--capture-baseline",
        ])
        require(unavailable_capture.returncode == 0, "first unavailable capture must record a non-authoritative snapshot")
        require(json.loads(first_unavailable.read_text(encoding="utf-8"))["docker_available"] is False, "unavailable first capture must stay non-authoritative")

        invalid_first_current = workspace / "docker" / "invalid-first-current.json"
        write_json_value(invalid_first_current, {**current_matches_baseline, "images": {}})
        invalid_first_baseline = workspace / "docker" / "invalid-first-baseline.json"
        assert_rejected([
            sys.executable,
            str(SCRIPT_ROOT / "manage_docker_resources.py"),
            "--workspace-dir", str(workspace),
            "--baseline-file", str(invalid_first_baseline),
            "--current-file", str(invalid_first_current),
            "--capture-baseline",
        ], expected="DOCKER_CURRENT_INVALID", label="invalid current cannot create a baseline")
        require(not invalid_first_baseline.exists(), "invalid current created a baseline file")


def main() -> int:
    test_shared_daemon_plan_and_cleanliness_cli()
    print("issue26 shared Docker contract selftest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
