#!/usr/bin/env python3
"""Independent focused checks for the RH.5 Docker case lifecycle boundary."""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


STUB = r'''#!/usr/bin/env python3
import json
import os
import re
import sys
import tarfile
import tempfile
import time
from pathlib import Path

state_path = Path(os.environ["ZHULONG_RH5_STUB_STATE"])
log_path = Path(os.environ["ZHULONG_RH5_STUB_LOG"])
args = sys.argv[1:]

def load():
    if not state_path.exists():
        return {"container": None, "network": None, "volume": None,
                "unrelated": {"container": "unrelated-c", "network": "unrelated-n", "volume": "unrelated-v"}}
    return json.loads(state_path.read_text())

def save(value):
    fd, name = tempfile.mkstemp(dir=state_path.parent)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, sort_keys=True)
    os.replace(name, state_path)

with log_path.open("a") as handle:
    handle.write(json.dumps(args) + "\n")

state = load()
if not args:
    raise SystemExit(2)
if args[0] == "info":
    raise SystemExit(0)
if args[:2] == ["image", "inspect"]:
    raise SystemExit(0)

if args[:3] in (["container", "ls", "--all"], ["network", "ls", "--no-trunc"]):
    kind = args[0]
    if kind == "container" and os.environ.get("ZHULONG_RH5_STUB_DELAY_CREATE") == "1":
        phase = state.get("delayed_phase")
        if phase == "pending_zero":
            state["delayed_phase"] = "residue"
            save(state)
        elif phase == "residue" and state.get("container") is None:
            state["container"] = state.get("delayed_container")
            state["delayed_phase"] = "restored"
            save(state)
    if state[kind] is not None:
        print("case-" + kind)
    print(state["unrelated"][kind])
    raise SystemExit(0)
if args[:2] == ["volume", "ls"]:
    if state["volume"] is not None:
        print("case-volume")
    print(state["unrelated"]["volume"])
    raise SystemExit(0)

if len(args) >= 3 and args[1] == "inspect":
    kind, identity = args[0], args[2]
    if identity.startswith("unrelated-"):
        value = {"Labels": {"owner": "unrelated"}}
        if kind == "container":
            value = {"Name": "/unrelated", "Config": {"Labels": {"owner": "unrelated"}}}
        print(json.dumps([value]))
        raise SystemExit(0)
    item = state.get(kind)
    if item is None:
        raise SystemExit(1)
    if kind == "container":
        value = {"Name": "/" + item["name"], "Config": {"Labels": item["labels"]}}
    else:
        value = {"Labels": item["labels"]}
    print(json.dumps([value]))
    raise SystemExit(0)

if len(args) >= 3 and args[1] == "rm":
    kind = args[0]
    if os.environ.get("ZHULONG_RH5_STUB_CLEANUP_FAIL") == kind:
        raise SystemExit(1)
    if kind == "container" and os.environ.get("ZHULONG_RH5_STUB_DELAY_CREATE") == "1" and state.get("delayed_phase") == "zero":
        state["delayed_container"] = state.get("container")
        state["delayed_phase"] = "pending_zero"
    state[kind] = None
    save(state)
    raise SystemExit(0)

if args[0] == "pull":
    raise SystemExit(1)

if args[0] == "cp":
    destination = Path(args[-1])
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "stub-output.txt").write_text("RH5_OUTPUT\n", encoding="utf-8")
    raise SystemExit(0)

if args[0] == "exec":
    with tempfile.TemporaryDirectory() as temp_value:
        with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
            archive.add(temp_value, arcname=".", recursive=True)
    raise SystemExit(0)

if args[0] == "run":
    name = args[args.index("--name") + 1]
    labels = {}
    for index, value in enumerate(args):
        if value == "--label":
            key, item = args[index + 1].split("=", 1)
            labels[key] = item
    state["container"] = {"name": name, "labels": labels}
    if os.environ.get("ZHULONG_RH5_STUB_DELAY_CREATE") == "1":
        state["delayed_phase"] = "zero"
    save(state)
    if os.environ.get("ZHULONG_RH5_STUB_SLEEP") == "1":
        time.sleep(30)
    print("RH5_ORACLE")
    marker_match = re.search(r"ZHULONG_OUTPUT_READY_[0-9a-f]{32}", " ".join(args))
    marker = marker_match.group(0) + ":0" if marker_match else ""
    if marker:
        print(marker)
    raise SystemExit(0)

if args[0] == "compose":
    project = args[args.index("-p") + 1]
    operation = next((item for item in ("config", "pull", "run") if item in args), "")
    if operation == "config":
        files = [args[index + 1] for index, item in enumerate(args) if item == "-f"]
        override = json.loads(Path(files[-1]).read_text())
        service, policy = next(iter(override["services"].items()))
        merged = {"image": "local/rh5-test", "privileged": False, **policy}
        print(json.dumps({"services": {service: merged}}, sort_keys=True))
        raise SystemExit(0)
    if operation == "pull":
        raise SystemExit(1)
    if operation == "run":
        name = args[args.index("--name") + 1]
        labels = {"com.docker.compose.project": project}
        for index, value in enumerate(args):
            if value == "--label":
                key, item = args[index + 1].split("=", 1)
                labels[key] = item
        state["container"] = {"name": name, "labels": labels}
        state["network"] = {"labels": {"com.docker.compose.project": project}}
        save(state)
        if os.environ.get("ZHULONG_RH5_STUB_SLEEP") == "1":
            time.sleep(30)
        print("RH5_ORACLE")
        marker_match = re.search(r"ZHULONG_OUTPUT_READY_[0-9a-f]{32}", " ".join(args))
        marker = marker_match.group(0) + ":0" if marker_match else ""
        if marker:
            print(marker)
        raise SystemExit(0)

raise SystemExit(2)
'''


def make_workspace(root: Path) -> Path:
    target = root / "target"
    workspace = target / "security-research-rh5"
    workspace.mkdir(parents=True)
    (workspace / "poc").mkdir()
    (workspace / "evidence").mkdir()
    (workspace / "asr-config.json").write_text(json.dumps({
        "workspace_root": workspace.name,
        "project_root_name": target.name,
        "workspace_created_at": "2026-08-13T00:00:00Z",
        "confirmed_output_dir": f"{workspace.name}/confirmed",
    }), encoding="utf-8")
    legacy_state = {
        "schema_version": 1,
        "plugin": "zhulong",
        "plugin_version": "selftest",
        "stage": "candidate_verifying",
        "status": "running",
        "last_event_at": "2026-08-13T00:00:00Z",
        "blocker": None,
        "resume_step": None,
        "workspace": workspace.name,
        "target_repo": ".",
        "last_event": "legacy_seed",
        "last_message": "RH.5 focused selftest legacy seed.",
    }
    legacy_event = {
        "ts": "2026-08-13T00:00:00Z",
        "event": "legacy_seed",
        "stage": "candidate_verifying",
        "status": "running",
        "message": "RH.5 focused selftest legacy seed.",
        "details": {},
    }
    (workspace / "stage-status.json").write_text(json.dumps(legacy_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (workspace / "audit-events.jsonl").write_text(json.dumps(legacy_event, sort_keys=True) + "\n", encoding="utf-8")
    return workspace


def wrapper_command(plugin_root: Path, workspace: Path, case_id: str, mode: str, compose: Path | None = None, extra: list[str] | None = None) -> list[str]:
    command = [
        "bash", str(plugin_root / "scripts/run_verification_case.sh"),
        "--workspace-dir", str(workspace), "--case-id", case_id,
        "--mode", mode, "--timeout-seconds", "2", "--expected-oracle", "RH5_ORACLE",
    ]
    if mode == "docker-run":
        command.extend(["--image", "local/rh5-test", "--no-default-mounts"])
    else:
        assert compose is not None
        command.extend(["--compose-file", str(compose.relative_to(workspace)), "--compose-service", "runner"])
    command.extend(extra or [])
    command.extend(["--", "true"])
    return command


def read_log(path: Path) -> list[list[str]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def main() -> int:
    plugin_root = Path(__file__).resolve().parents[1]
    lifecycle = plugin_root / "scripts/docker_case_lifecycle.py"
    wrapper = plugin_root / "scripts/run_verification_case.sh"
    preflight = plugin_root / "scripts/check_sandbox_preflight.py"
    for path in (lifecycle, wrapper, preflight):
        require(path.is_file(), f"missing focused production input: {path.name}")

    with tempfile.TemporaryDirectory(prefix="zhulong-rh5-selftest-") as temp_value:
        temp = Path(temp_value)
        workspace = make_workspace(temp)
        stub_dir = temp / "stub-bin"
        stub_dir.mkdir()
        docker_stub = stub_dir / "docker"
        docker_stub.write_text(STUB, encoding="utf-8")
        docker_stub.chmod(0o755)
        state = temp / "docker-state.json"
        log = temp / "docker-log.jsonl"
        env = os.environ.copy()
        env.update({
            "PATH": str(stub_dir) + os.pathsep + env.get("PATH", ""),
            "ZHULONG_RH5_STUB_STATE": str(state),
            "ZHULONG_RH5_STUB_LOG": str(log),
        })

        policy_cases = [
            ("0", "1", "256"), ("15m", "1", "256"), ("3g", "1", "256"),
            ("512m", "0", "256"), ("512m", "5", "256"),
            ("512m", "1", "0"), ("512m", "1", "1025"),
        ]
        for index, (memory, cpus, pids) in enumerate(policy_cases):
            result = run(wrapper_command(plugin_root, workspace, f"policy-{index}", "docker-run", extra=[
                "--memory", memory, "--cpus", cpus, "--pids-limit", pids,
            ]), cwd=plugin_root, env=env)
            require(result.returncode != 0 and "DOCKER_RESOURCE_LIMIT_INVALID" in result.stdout, f"invalid dedicated resource limit was accepted: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")
        for value in ("--memory", "--memory=1g", "-m", "--cpus=2", "--pids-limit", "--read-only"):
            result = run(wrapper_command(plugin_root, workspace, "override-" + str(abs(hash(value))), "docker-run", extra=["--docker-arg", value]), cwd=plugin_root, env=env)
            require(result.returncode != 0 and "DOCKER_RESOURCE_OVERRIDE_FORBIDDEN" in result.stdout, f"resource override was accepted: {value}; rc={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}")

        for network in ("none", "bridge", "audit-network"):
            case_id = "network-" + network
            result = run(wrapper_command(plugin_root, workspace, case_id, "docker-run", extra=["--network", network]), cwd=plugin_root, env=env)
            require(result.returncode == 0 and "verification_status=confirmed_in_docker" in result.stdout, f"legal docker-run network case failed: {network}; stdout={result.stdout!r}; stderr={result.stderr!r}")
            result_json = json.loads((workspace / "evidence" / case_id / "verification-result.json").read_text())
            require(result_json["network"] == network, f"docker-run result lost requested network: {network}")
            require(result_json["docker_case_lifecycle"]["resource_policy"]["network_mode"] == network, f"docker-run receipt policy did not bind network_mode={network}")
            require(result_json["resource_limits"]["policy_version"] == "docker-case-policy-v2", "docker-run result published a non-current policy")

        for network in ("host", "bad/name", "bad network", "audit\nnetwork", "service:other", "${NETWORK}"):
            case_id = "network-invalid-" + str(abs(hash(network)))
            before = len(read_log(log)) if log.exists() else 0
            result = run(wrapper_command(plugin_root, workspace, case_id, "docker-run", extra=["--network", network]), cwd=plugin_root, env=env)
            after = len(read_log(log)) if log.exists() else 0
            require(result.returncode != 0 and before == after and "DOCKER_NETWORK_UNSAFE" in result.stdout, f"unsafe docker-run network was accepted: {network!r}; stdout={result.stdout!r}; stderr={result.stderr!r}")

        compose_cases = {
            "depends": "depends_on: []",
            "restart": "restart: always",
            "reserved-zhulong": "labels: {org.zhulong.case: forged}",
            "reserved-compose": "labels: {com.docker.compose.project: forged}",
            "network-bridge": "network_mode: bridge",
            "network-host": "network_mode: host",
            "network-custom": "network_mode: custom-network",
            "network-default": "network_mode: default",
            "network-service": "network_mode: service:other",
            "network-container": "network_mode: container:other",
            "network-name": "network_mode: audit-network",
            "network-non-string": "network_mode: false",
            "network-dynamic": "network_mode: ${NETWORK_MODE}",
        }
        for name, extra in compose_cases.items():
            source = workspace / f"compose-{name}.yaml"
            source.write_text(f"services:\n  runner:\n    image: local/rh5-test\n    privileged: false\n    {extra}\n", encoding="utf-8")
            before = len(read_log(log)) if log.exists() else 0
            result = run(wrapper_command(plugin_root, workspace, f"compose-{name}", "docker-compose", source), cwd=plugin_root, env=env)
            after = len(read_log(log)) if log.exists() else 0
            require(result.returncode != 0 and before == after, f"unsafe Compose case reached Docker: {name}")
            if name.startswith("network-"):
                require("COMPOSE_NAMESPACE_UNSUPPORTED" in result.stderr, f"unsafe Compose network case did not use the stable namespace issue code: {name}; stderr={result.stderr!r}")
        missing = workspace / "compose-missing.yaml"
        missing.write_text("services:\n  other:\n    image: local/rh5-test\n    privileged: false\n    restart: \"no\"\n", encoding="utf-8")
        result = run(wrapper_command(plugin_root, workspace, "compose-missing", "docker-compose", missing), cwd=plugin_root, env=env)
        require(result.returncode != 0 and "COMPOSE_SERVICE_MISSING" in result.stderr, "missing selected service did not fail closed")

        explicit_none = workspace / "compose-none.yaml"
        explicit_none.write_text("services:\n  runner:\n    image: local/rh5-test\n    privileged: false\n    network_mode: none\n", encoding="utf-8")
        result = run(wrapper_command(plugin_root, workspace, "compose-none", "docker-compose", explicit_none), cwd=plugin_root, env=env)
        require(result.returncode == 0 and "verification_status=confirmed_in_docker" in result.stdout, f"literal network_mode:none Compose case did not confirm: rc={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}")
        explicit_config = json.loads((workspace / "evidence/compose-none/compose-config.json").read_text())
        require(explicit_config["services"]["runner"].get("network_mode") == "none", "literal network_mode:none was not preserved in merged Compose config")

        safe_compose = workspace / "compose-safe.yaml"
        safe_compose.write_text("services:\n  runner:\n    image: local/rh5-test\n    privileged: false\n    restart: \"no\"\n", encoding="utf-8")
        result = run(wrapper_command(plugin_root, workspace, "compose-ok", "docker-compose", safe_compose, extra=["--network", "bridge"]), cwd=plugin_root, env=env)
        require(result.returncode == 0 and "verification_status=confirmed_in_docker" in result.stdout, f"legal Compose case did not confirm after cleanup: rc={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}")
        safe_config = json.loads((workspace / "evidence/compose-ok/compose-config.json").read_text())
        require(safe_config["services"]["runner"].get("network_mode") == "none", "Compose override did not force network_mode none when source omitted it")
        calls = read_log(log)
        compose_run = next(call for call in reversed(calls) if "compose" in call and "run" in call)
        require("-p" in compose_run and "--name" in compose_run and "--no-deps" in compose_run, "Compose run lacks exact lifecycle flags")
        result_json = json.loads((workspace / "evidence/compose-ok/verification-result.json").read_text())
        require(result_json["network"] == "none", "Compose result borrowed docker-run network input")
        require(result_json["docker_case_lifecycle"]["resource_policy"]["network_mode"] == "none", "Compose lifecycle policy borrowed docker-run network input")
        require(result_json["docker_case_lifecycle"]["cleanup_verified"] is True, "legal Compose cleanup was not verified")
        require(result_json["docker_case_lifecycle"]["residue_counts_after"] == {"containers": 0, "networks": 0, "volumes": 0}, "legal Compose left lifecycle residue")

        first = run([sys.executable, str(lifecycle), "prepare", "--evidence-root", str(workspace / "evidence"), "--case-id", "same", "--mode", "docker-compose", "--compose-service", "runner"], cwd=plugin_root)
        second = run([sys.executable, str(lifecycle), "prepare", "--evidence-root", str(workspace / "evidence"), "--case-id", "same", "--mode", "docker-compose", "--compose-service", "runner"], cwd=plugin_root)
        first_value, second_value = json.loads(first.stdout), json.loads(second.stdout)
        require(first_value["project_name"] != second_value["project_name"] and first_value["container_name"] != second_value["container_name"], "same service cases did not get unique lifecycle identities")

        receipt_value = json.loads(Path(first_value["receipt_path"]).read_text())
        policy = receipt_value["policy"]
        labels = receipt_value["labels"]
        override_value = json.loads(Path(first_value["override_path"]).read_text())
        require(receipt_value.get("schema_version") == 2 and policy.get("version") == "docker-case-policy-v2", "new lifecycle receipt did not use schema/policy v2")
        require(policy.get("network_mode") == "none", "Compose lifecycle policy did not bind network_mode none")
        require(override_value["services"]["runner"].get("network_mode") == "none", "Compose lifecycle override did not inject network_mode none")
        valid_service = {
            "image": "local/rh5-test", "restart": "no", "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "network_mode": "none",
            "mem_limit": policy["memory_bytes"], "memswap_limit": policy["memory_bytes"],
            "cpus": float(policy["cpus"]), "pids_limit": policy["pids_limit"], "labels": labels,
        }
        config_path = workspace / "evidence/config-mutation.json"
        override_path = Path(first_value["override_path"])
        receipt_path = Path(first_value["receipt_path"])
        original_receipt = receipt_path.read_bytes()
        for field in ("mem_limit", "memswap_limit", "cpus", "pids_limit", "labels", "read_only", "cap_drop", "security_opt", "restart", "privileged", "network_mode"):
            mutated = dict(valid_service)
            if field == "restart":
                mutated[field] = "always"
            elif field == "privileged":
                mutated[field] = True
            else:
                mutated.pop(field)
            config_path.write_text(json.dumps({"services": {"runner": mutated}}), encoding="utf-8")
            rejected = run([
                sys.executable, str(lifecycle), "validate-config", "--evidence-root", str(workspace / "evidence"),
                "--receipt", first_value["receipt_path"], "--receipt-sha256", first_value["receipt_sha256"],
                "--override", str(override_path), "--config-json", str(config_path),
            ], cwd=plugin_root)
            require(rejected.returncode != 0 and "COMPOSE_CONFIG_POLICY_MISMATCH" in rejected.stdout, f"merged Compose policy mutation was accepted: {field}")

        config_path.write_text(json.dumps({"services": {"runner": {**valid_service, "network_mode": "bridge"}}}), encoding="utf-8")
        rejected = run([
            sys.executable, str(lifecycle), "validate-config", "--evidence-root", str(workspace / "evidence"),
            "--receipt", first_value["receipt_path"], "--receipt-sha256", first_value["receipt_sha256"],
            "--override", str(override_path), "--config-json", str(config_path),
        ], cwd=plugin_root)
        require(rejected.returncode != 0 and "COMPOSE_CONFIG_POLICY_MISMATCH" in rejected.stdout, "merged Compose network_mode drift was accepted")

        config_path.write_text(json.dumps({"services": {"runner": valid_service}}), encoding="utf-8")
        original_override = override_path.read_bytes()
        forged_override = json.loads(original_override)
        forged_override["services"]["runner"].pop("network_mode")
        override_path.write_text(json.dumps(forged_override, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        forged_receipt = json.loads(original_receipt)
        forged_receipt["override_sha256"] = sha256(override_path)
        receipt_path.write_text(json.dumps(forged_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        forged_receipt_digest = sha256(receipt_path)
        rejected = run([
            sys.executable, str(lifecycle), "validate-config", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(receipt_path), "--receipt-sha256", forged_receipt_digest,
            "--override", str(override_path), "--config-json", str(config_path),
        ], cwd=plugin_root)
        require(rejected.returncode != 0 and "COMPOSE_CONFIG_POLICY_MISMATCH" in rejected.stdout, "Compose override network_mode omission was accepted")
        override_path.write_bytes(original_override)
        receipt_path.write_bytes(original_receipt)

        legacy = json.loads(original_receipt)
        legacy["schema_version"] = 1
        legacy_policy = {key: value for key, value in legacy["policy"].items() if key != "network_mode"}
        legacy_policy["version"] = "docker-case-policy-v1"
        legacy["policy"] = legacy_policy
        legacy["labels"] = dict(legacy["labels"])
        legacy["labels"]["org.zhulong.policy"] = "docker-case-policy-v1"
        legacy_path = workspace / "evidence/legacy-v1-receipt.json"
        legacy_path.write_text(json.dumps(legacy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        legacy_digest = sha256(legacy_path)
        legacy_cleanup = run([
            sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(legacy_path), "--receipt-sha256", legacy_digest, "--docker", str(docker_stub),
        ], cwd=plugin_root, env=env)
        require(legacy_cleanup.returncode == 0 and json.loads(legacy_cleanup.stdout).get("policy_version") == "docker-case-policy-v1", "exact legacy v1 receipt was not accepted for cleanup-only")
        legacy_config = run([
            sys.executable, str(lifecycle), "validate-config", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(legacy_path), "--receipt-sha256", legacy_digest,
            "--override", str(override_path), "--config-json", str(config_path),
        ], cwd=plugin_root, env=env)
        require(legacy_config.returncode != 0 and "DOCKER_CASE_RECEIPT_DRIFT" in legacy_config.stdout, "legacy v1 receipt entered config validation")
        legacy_drift = dict(legacy)
        legacy_drift["policy"] = dict(legacy["policy"])
        legacy_drift["policy"]["memory"] = "1g"
        legacy_path.write_text(json.dumps(legacy_drift, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run([
            sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(legacy_path), "--receipt-sha256", sha256(legacy_path), "--docker", str(docker_stub),
        ], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "DOCKER_CASE_RECEIPT_DRIFT" in rejected.stdout, "legacy policy-drift receipt was accepted")
        legacy_extra = dict(legacy)
        legacy_extra["unexpected"] = True
        legacy_path.write_text(json.dumps(legacy_extra, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run([
            sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(legacy_path), "--receipt-sha256", sha256(legacy_path), "--docker", str(docker_stub),
        ], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "DOCKER_CASE_RECEIPT_DRIFT" in rejected.stdout, "legacy extra-key receipt was accepted")
        legacy_path.write_text('{"schema_version":1,"policy":', encoding="utf-8")
        rejected = run([
            sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(legacy_path), "--receipt-sha256", sha256(legacy_path), "--docker", str(docker_stub),
        ], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "DOCKER_CASE_RECEIPT_DRIFT" in rejected.stdout, "malformed legacy receipt was accepted")
        legacy_path.write_text(json.dumps(legacy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        legacy_path.unlink()
        legacy_path.symlink_to("/dev/null")
        rejected = run([
            sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(legacy_path), "--receipt-sha256", legacy_digest, "--docker", str(docker_stub),
        ], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "EVIDENCE_TARGET_UNSAFE" in rejected.stdout, "legacy symlink receipt was accepted")
        legacy_path.unlink()
        legacy_path.write_text(json.dumps(legacy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        legacy_hardlink = workspace / "evidence/legacy-v1-hardlink.json"
        os.link(legacy_path, legacy_hardlink)
        rejected = run([
            sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"),
            "--receipt", str(legacy_hardlink), "--receipt-sha256", legacy_digest, "--docker", str(docker_stub),
        ], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "EVIDENCE_TARGET_UNSAFE" in rejected.stdout, "legacy hardlink receipt was accepted")
        legacy_hardlink.unlink()
        legacy_path.unlink()

        result = run(wrapper_command(plugin_root, workspace, "run-ok", "docker-run"), cwd=plugin_root, env=env)
        require(result.returncode == 0, "legal docker-run case failed")
        state_value = json.loads(state.read_text())
        require(state_value["container"] is None and state_value["unrelated"] == {"container": "unrelated-c", "network": "unrelated-n", "volume": "unrelated-v"}, "exact cleanup touched unrelated resources")

        delayed_env = dict(env)
        delayed_env["ZHULONG_RH5_STUB_DELAY_CREATE"] = "1"
        result = run(wrapper_command(plugin_root, workspace, "delayed-create", "docker-run"), cwd=plugin_root, env=delayed_env)
        require(result.returncode == 0, f"delayed-create settlement path failed: {result.stdout!r} {result.stderr!r}")
        delayed_result = json.loads((workspace / "evidence/delayed-create/verification-result.json").read_text())
        require(delayed_result["docker_case_lifecycle"]["cleanup_verified"] is True and delayed_result["docker_case_lifecycle"]["settlement_checks"] >= 5, "delayed-create did not require a stable zero-residue window")
        require(json.loads(state.read_text())["container"] is None, "delayed-create settlement left case residue")

        fail_env = dict(env)
        fail_env["ZHULONG_RH5_STUB_CLEANUP_FAIL"] = "container"
        result = run(wrapper_command(plugin_root, workspace, "cleanup-fail", "docker-run"), cwd=plugin_root, env=fail_env)
        require(result.returncode != 0 and "DOCKER_CASE_CLEANUP_FAILED" in result.stdout and "confirmed_in_docker" not in result.stdout, "cleanup failure was confirmation-ready")
        failed_result = json.loads((workspace / "evidence/cleanup-fail/verification-result.json").read_text())
        require(failed_result["status"] == "rejected_unsafe_sandbox" and failed_result["oracle_matched"] is False, "cleanup failure result was not fail closed")

        state.write_text(json.dumps({"container": None, "network": None, "volume": None, "unrelated": {"container": "unrelated-c", "network": "unrelated-n", "volume": "unrelated-v"}}), encoding="utf-8")
        signal_env = dict(env)
        signal_env["ZHULONG_RH5_STUB_SLEEP"] = "1"
        for signal_name, signal_value in (("term", signal.SIGTERM), ("int", signal.SIGINT)):
            state.write_text(json.dumps({"container": None, "network": None, "volume": None, "unrelated": {"container": "unrelated-c", "network": "unrelated-n", "volume": "unrelated-v"}}), encoding="utf-8")
            process = subprocess.Popen(wrapper_command(plugin_root, workspace, f"signal-{signal_name}", "docker-run"), cwd=plugin_root, env=signal_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.time() + 10
            while time.time() < deadline:
                if state.exists() and json.loads(state.read_text()).get("container") is not None:
                    break
                time.sleep(0.05)
            process.send_signal(signal_value)
            stdout, _stderr = process.communicate(timeout=15)
            require(process.returncode != 0 and "DOCKER_CASE_CLEANUP_FAILED" not in stdout, f"SIG{signal_name.upper()} path did not exit through exact cleanup")
            require(json.loads(state.read_text())["container"] is None, f"SIG{signal_name.upper()} path left a case container")

        timeout_env = dict(env)
        timeout_env["ZHULONG_RH5_STUB_SLEEP"] = "1"
        timeout_command = wrapper_command(plugin_root, workspace, "timeout", "docker-run")
        timeout_command[timeout_command.index("--timeout-seconds") + 1] = "1"
        result = run(timeout_command, cwd=plugin_root, env=timeout_env, timeout=20)
        require(result.returncode != 0 and "verification_status=failed_timeout" in result.stdout, "timeout path classification changed")
        timeout_result = json.loads((workspace / "evidence/timeout/verification-result.json").read_text())
        require(timeout_result["docker_case_lifecycle"]["cleanup_verified"] is True and timeout_result["docker_case_lifecycle"]["residue_counts_after"]["containers"] == 0, "timeout path left case residue")

        receipt_path = Path(first_value["receipt_path"])
        receipt_digest = first_value["receipt_sha256"]
        original = receipt_path.read_bytes()
        receipt_path.unlink()
        receipt_path.symlink_to("/dev/null")
        rejected = run([sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"), "--receipt", str(receipt_path), "--receipt-sha256", receipt_digest, "--docker", str(docker_stub)], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "EVIDENCE_TARGET_UNSAFE" in rejected.stdout, "symlink lifecycle receipt was accepted")
        receipt_path.unlink()
        receipt_path.write_bytes(original)
        hardlink_path = workspace / "evidence/hardlink-receipt.json"
        os.link(receipt_path, hardlink_path)
        rejected = run([sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"), "--receipt", str(hardlink_path), "--receipt-sha256", receipt_digest, "--docker", str(docker_stub)], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "EVIDENCE_TARGET_UNSAFE" in rejected.stdout, "hardlink lifecycle receipt was accepted")
        hardlink_path.unlink()
        fifo_path = workspace / "evidence/fifo-receipt.json"
        os.mkfifo(fifo_path)
        rejected = run([sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"), "--receipt", str(fifo_path), "--receipt-sha256", receipt_digest, "--docker", str(docker_stub)], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "EVIDENCE_TARGET_UNSAFE" in rejected.stdout, "FIFO lifecycle receipt was accepted")
        fifo_path.unlink()
        forged = json.loads(original)
        forged["policy"]["network_mode"] = "bridge"
        receipt_path.write_text(json.dumps(forged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run([sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"), "--receipt", str(receipt_path), "--receipt-sha256", sha256(receipt_path), "--docker", str(docker_stub)], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "DOCKER_CASE_RECEIPT_DRIFT" in rejected.stdout, "forged Compose network policy receipt was accepted")
        receipt_path.write_bytes(original)
        forged = json.loads(original)
        forged["token"] = "0" * 32
        receipt_path.write_text(json.dumps(forged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run([sys.executable, str(lifecycle), "cleanup", "--evidence-root", str(workspace / "evidence"), "--receipt", str(receipt_path), "--receipt-sha256", sha256(receipt_path), "--docker", str(docker_stub)], cwd=plugin_root, env=env)
        require(rejected.returncode != 0 and "DOCKER_CASE_RECEIPT_DRIFT" in rejected.stdout, "forged lifecycle receipt was accepted")

    print("DOCKER CASE LIFECYCLE SELFTEST PASSED: closed Compose, bounded policy, exact cleanup, signals, and receipt safety")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
