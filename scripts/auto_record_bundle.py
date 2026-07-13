#!/usr/bin/env python3
"""Record, validate, and atomically promote a Zhulong bundle recording.

The bundle copy, final screenshots, recording manifest, and ZIP are all built in
recorder-owned staging.  The original confirmed bundle and its archive are not
modified until the independent recording validator and the ZIP integrity gate
have passed.  OBS output is kept outside the bundle until promotion.

Normal report validation does not imply recording readiness.  This command is
the explicit recording opt-in and requires the generated root helper's
checkpoint protocol; handwritten helpers fail closed in recording mode.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    from recording_identity import compare_identity, parse_canonical_identity, sha256_file
except ImportError:  # pragma: no cover
    from .recording_identity import compare_identity, parse_canonical_identity, sha256_file  # type: ignore

try:
    import validate_recording_evidence as recording_validator
except ImportError:  # pragma: no cover
    from . import validate_recording_evidence as recording_validator  # type: ignore


VIDEO_SUFFIXES = {".mp4", ".mov", ".mkv", ".m4v", ".webm", ".gif", ".webp"}
STAGES = ("identity", "code_or_trigger_context", "final_impact")
SCREENSHOT_PATHS = {
    "identity": "attachments/evidence/screenshots/01-target-identity.png",
    "code_or_trigger_context": "attachments/evidence/screenshots/02-code-or-trigger-context.png",
    "final_impact": "attachments/evidence/screenshots/03-final-impact.png",
}
OBS_WEBSOCKET_CONFIG = Path.home() / "Library/Application Support/obs-studio/plugin_config/obs-websocket/config.json"
DEFAULT_OBS_SOURCE = "macOS 屏幕采集"


def command_output(command: list[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=dict(env) if env else None, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def run(command: list[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = command_output(command, cwd=cwd, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def discover_run_script(bundle: Path, explicit: str | None = None) -> Path:
    if explicit:
        path = (bundle / explicit).resolve()
        if not path.is_file() or path.parent != bundle.resolve() or path.suffix != ".sh":
            raise RuntimeError(f"recording helper must be a bundle-root .sh file: {explicit}")
        return path
    scripts = sorted(path for path in bundle.glob("run-*.sh") if path.is_file() and not path.is_symlink())
    if len(scripts) != 1:
        raise RuntimeError("recording mode requires exactly one bundle-root run-*.sh helper; pass --script when needed")
    return scripts[0]


def require_checkpoint_protocol(script: Path) -> None:
    text = script.read_text(encoding="utf-8", errors="strict")
    required = ("recording_checkpoint", "ZHULONG_RECORDING_STAGE_DIR", "ZHULONG_RECORDING_STAGE_ACK_DIR", "ZHULONG_RECORDING_OWNER_MARKER")
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise RuntimeError(
            "recording helper has no fail-closed checkpoint protocol; regenerate it before recording: "
            + ", ".join(missing)
        )


def build_replay_command_lines(
    repo_root: Path,
    bundle: Path,
    run_script: Path,
    exit_file: Path,
    mode: str,
    engine: str,
    pause_short: str,
    pause_long: str,
    pause_code: str = "0",
    pause_final: str = "0",
    recording_environment: Mapping[str, str] | None = None,
) -> list[str]:
    exports = {
        "REVIEWER_PAUSE_SHORT": pause_short,
        "REVIEWER_PAUSE_LONG": pause_long,
        "REVIEWER_CODE_PAUSE": pause_code,
        "REVIEWER_PAUSE_FINAL": pause_final,
    }
    if recording_environment:
        exports.update({str(key): str(value) for key, value in recording_environment.items()})
    export_line = "export " + " ".join(f"{key}={shlex.quote(value)}" for key, value in sorted(exports.items()))
    script_name = "./" + run_script.name
    return [
        f"cd {shlex.quote(str(repo_root))}",
        f"cd {shlex.quote(str(bundle))}",
        export_line,
        (
            f"{shlex.quote(script_name)} {shlex.quote(mode)} {shlex.quote(engine)}; "
            "__zhulong_rc=$?; "
            "printf '\\n__ZHULONG_REPLAY_BUNDLE__=%s\\n__ZHULONG_REPLAY_SCRIPT__=%s\\n__ZHULONG_RECORDING_EXIT_CODE__=%s\\n' "
            f"{shlex.quote(bundle.name)} {shlex.quote(run_script.name)} \"$__zhulong_rc\"; "
            f"printf '%s\\n' \"$__zhulong_rc\" > {shlex.quote(str(exit_file))}"
        ),
    ]


class RecordingSession:
    """Recorder-owned temporary root for events, acknowledgements, and images."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="zhulong-recording-session-"))
        self.stage_dir = self.root / "events"
        self.ack_dir = self.root / "acks"
        self.checkpoint_dir = self.root / "checkpoints"
        self.stage_dir.mkdir()
        self.ack_dir.mkdir()
        self.checkpoint_dir.mkdir()
        self.owner_marker = self.root / "owner.json"
        write_json_atomic(
            self.owner_marker,
            {
                "owner": "zhulong-recording",
                "pid": os.getpid(),
                "created_epoch": int(time.time()),
                "token": uuid.uuid4().hex,
                "root": str(self.root),
            },
        )

    def environment(self) -> dict[str, str]:
        return {
            "ZHULONG_RECORDING_PROTOCOL_VERSION": "1",
            "ZHULONG_RECORDING_ROOT": str(self.root),
            "ZHULONG_RECORDING_STAGE_DIR": str(self.stage_dir),
            "ZHULONG_RECORDING_STAGE_ACK_DIR": str(self.ack_dir),
            "ZHULONG_RECORDING_OWNER_MARKER": str(self.owner_marker),
            "ZHULONG_RECORDING_ACK_TIMEOUT_SECONDS": "30",
        }

    def keep_failed(self, reason: str, raw_video: Path | None = None) -> None:
        write_json_atomic(
            self.root / "failed-recording.json",
            {"status": "failed_unpromoted", "reason": reason, "raw_video": str(raw_video) if raw_video else ""},
        )
        print(f"[recording-failed-unpromoted] recorder session retained at {self.root}", file=sys.stderr)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def applescript_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class MacOSTerminalWindow:
    """Create the reviewer-facing Terminal window captured by OBS."""

    def __init__(self, title: str = "zhulong-recording-terminal") -> None:
        self.title = title
        self.window_id: int | None = None

    def open(self, command: str) -> int:
        if sys.platform != "darwin":
            raise RuntimeError("RECORDING_WRONG_WINDOW: final OBS recording requires a macOS Terminal window")
        script = f"""
tell application \"Terminal\"
  activate
  do script {applescript_quote(command)}
  delay 0.4
  try
    set custom title of selected tab of front window to {applescript_quote(self.title)}
  end try
  return id of front window as text
end tell
"""
        try:
            result = command_output(["osascript", "-e", script])
        except OSError as exc:
            raise RuntimeError(f"RECORDING_WRONG_WINDOW: cannot create Terminal recording window: {exc}") from exc
        if result.returncode != 0 or not result.stdout.strip().isdigit():
            raise RuntimeError(f"RECORDING_WRONG_WINDOW: Terminal window creation failed: {result.stdout.strip()}")
        self.window_id = int(result.stdout.strip())
        return self.window_id

    def contents(self) -> str:
        if self.window_id is None:
            return ""
        script = f"""
tell application \"Terminal\"
  repeat with w in windows
    try
      if id of w is {self.window_id} then
        return contents of selected tab of w
      end if
    end try
  end repeat
end tell
return \"\"
"""
        result = command_output(["osascript", "-e", script])
        if result.returncode != 0:
            raise RuntimeError(f"RECORDING_WRONG_WINDOW: cannot read recording Terminal window: {result.stdout.strip()}")
        return result.stdout

    def close(self) -> None:
        if self.window_id is None or sys.platform != "darwin":
            return
        script = f"""
tell application \"Terminal\"
  repeat with w in windows
    try
      if id of w is {self.window_id} then
        close w
        return
      end if
    end try
  end repeat
end tell
"""
        command_output(["osascript", "-e", script])


class MacOSOBSAdapter:
    """Small OBS websocket adapter with source/window stability checks."""

    def __init__(self, source_name: str, session: RecordingSession) -> None:
        self.source_name = source_name
        self.session = session
        self.client: Any = None
        self.recording_started: float | None = None
        self.window_identity: str | None = None
        self.window_title: str | None = None
        self.source_kind = "window_capture"
        self.terminal_window: MacOSTerminalWindow | None = None

    def bind_terminal_window(self, terminal_window: MacOSTerminalWindow) -> None:
        self.terminal_window = terminal_window

    def connect(self) -> None:
        try:
            import obsws_python as obs  # type: ignore
        except ImportError as exc:
            raise RuntimeError("OBS websocket control is required for recording checkpoints; install obsws-python locally") from exc
        if not OBS_WEBSOCKET_CONFIG.is_file():
            raise RuntimeError(f"OBS websocket config is missing: {OBS_WEBSOCKET_CONFIG}")
        config = json.loads(OBS_WEBSOCKET_CONFIG.read_text(encoding="utf-8"))
        if not config.get("server_enabled"):
            raise RuntimeError("OBS websocket server is disabled; enable it before recording")
        self.client = obs.ReqClient(
            host="localhost",
            port=int(config.get("server_port", 4455)),
            password=config.get("server_password", ""),
            timeout=5,
        )
        settings = self.client.get_input_settings(self.source_name).input_settings
        self._update_source_identity(settings)

    def _update_source_identity(self, settings: Mapping[str, Any]) -> None:
        capture_type = settings.get("type")
        self.source_kind = "window_capture" if capture_type in (1, "1") or settings.get("window") else "display_capture"
        window = str(settings.get("window") or settings.get("display_uuid") or self.source_name).strip()
        title = str(settings.get("window_title") or window).strip()
        if self.window_identity is None:
            self.window_identity = window
            self.window_title = title
        elif window != self.window_identity or title != self.window_title:
            raise RuntimeError("RECORDING_WRONG_WINDOW: OBS source/window identity changed during recording")

    def start(self) -> None:
        self.connect()
        status = self.client.get_record_status()
        if getattr(status, "output_active", False):
            raise RuntimeError("OBS is already recording; stop it before starting a final recording")
        self.client.start_record()
        self.recording_started = time.time()
        time.sleep(1.0)

    def stop(self) -> Path | None:
        if self.client is None:
            return None
        status = self.client.get_record_status()
        if not getattr(status, "output_active", False):
            return None
        result = self.client.stop_record()
        time.sleep(2.0)
        output = getattr(result, "output_path", None)
        return Path(output).expanduser() if output else None

    def capture_checkpoint(self, stage: str) -> dict[str, Any]:
        if self.client is None or self.recording_started is None:
            raise RuntimeError("OBS adapter is not recording")
        settings = self.client.get_input_settings(self.source_name).input_settings
        self._update_source_identity(settings)
        image_data = self.client.get_source_screenshot(self.source_name, "png", 1600, 900, 100).image_data
        raw = base64.b64decode(image_data.split(",", 1)[1] if image_data.startswith("data:image") else image_data)
        checkpoint = self.session.checkpoint_dir / f"{stage}.png"
        checkpoint.write_bytes(raw)
        width, height, nonblack = recording_validator._image_info(checkpoint)
        if not nonblack:
            raise RuntimeError(f"RECORDING_VIDEO_CONTENT_UNVERIFIED: OBS checkpoint for {stage} is black or empty")
        now = time.time() - self.recording_started
        return {
            "name": checkpoint.name,
            "sha256": sha256_file(checkpoint),
            "width": width,
            "height": height,
            "video_timestamp": now,
            "hold_start": max(0.0, now - 0.15),
            "hold_end": now + 2.5,
        }

    def terminal_contents(self) -> str:
        """Read the current recording Terminal window locally, never remotely."""

        terminal_id = str(self.terminal_window.window_id if self.terminal_window else os.environ.get("ZHULONG_RECORDING_TERMINAL_WINDOW_ID", "")).strip()
        if terminal_id:
            if not terminal_id.isdigit():
                raise RuntimeError("RECORDING_WRONG_WINDOW: terminal window id is not numeric")
            script = f"""
tell application \"Terminal\"
  repeat with w in windows
    try
      if id of w is {int(terminal_id)} then
        return contents of selected tab of w
      end if
    end try
  end repeat
end tell
return \"\"
"""
        else:
            script = "tell application \"Terminal\" to return contents of selected tab of front window"
        try:
            result = command_output(["osascript", "-e", script])
        except OSError as exc:
            raise RuntimeError(f"RECORDING_WRONG_WINDOW: cannot inspect Terminal locally: {exc}") from exc
        if result.returncode != 0:
            raise RuntimeError(f"RECORDING_WRONG_WINDOW: Terminal inspection failed: {result.stdout.strip()}")
        return result.stdout

    def verify_terminal_stage(self, event: Mapping[str, Any], identity: Mapping[str, str]) -> None:
        stage = str(event.get("stage") or "")
        if self.terminal_window is not None:
            if self.source_kind != "window_capture":
                raise RuntimeError("RECORDING_WRONG_WINDOW: OBS source is not a Terminal window capture")
            expected_window = os.environ.get("ZHULONG_OBS_WINDOW_IDENTITY", "").strip() or self.terminal_window.title
            if expected_window not in (self.window_identity or "") and expected_window not in (self.window_title or ""):
                raise RuntimeError("RECORDING_WRONG_WINDOW: OBS source is not bound to the recorder-created Terminal window")
        content = self.terminal_contents()
        canonical = event.get("canonical_identity")
        if not isinstance(canonical, Mapping):
            raise RuntimeError("RECORDING_IDENTITY_MISSING: checkpoint omitted canonical identity")
        expected = str(event.get("expected_marker") or "")
        required: list[str] = []
        if stage == "identity":
            required = [identity["software_name"], identity["tested_ref"], expected]
        elif stage == "code_or_trigger_context":
            for part in identity["code_context_identity"].split(";"):
                if "=" in part:
                    required.append(part.split("=", 1)[1])
            required.append(identity["trigger_context_identity"])
        elif stage == "final_impact":
            required = [identity["direct_impact_marker"], identity["oracle_marker"], expected]
        missing = [item for item in required if item and item not in content]
        if missing:
            code = {
                "identity": "RECORDING_IDENTITY_FRAME_MISSING",
                "code_or_trigger_context": "RECORDING_STAGE_FRAME_MISMATCH",
                "final_impact": "RECORDING_IMPACT_FRAME_MISSING",
            }.get(stage, "RECORDING_VIDEO_CONTENT_UNVERIFIED")
            raise RuntimeError(f"{code}: Terminal stage text is missing {missing}")

    def obs_metadata(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_kind": self.source_kind,
            "window_identity": self.window_identity or self.source_name,
            "window_title": self.window_title or self.source_name,
            "window_stable": True,
        }


def _handle_checkpoint_event(
    event_path: Path,
    session: RecordingSession,
    adapter: MacOSOBSAdapter,
    identity: Mapping[str, str],
    handled: set[str],
) -> None:
    if event_path.name in handled:
        return
    if event_path.is_symlink() or event_path.parent.resolve() != session.stage_dir.resolve():
        raise RuntimeError("RECORDING_PATH_UNSAFE: checkpoint event is not a recorder-owned regular file")
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise RuntimeError("recording checkpoint event must be a JSON object")
    stage = str(event.get("stage") or "")
    if stage not in STAGES:
        raise RuntimeError(f"recording checkpoint has unknown stage: {stage}")
    event_identity = event.get("canonical_identity")
    if not isinstance(event_identity, dict):
        raise RuntimeError("RECORDING_IDENTITY_MISSING: checkpoint omitted canonical identity")
    compare_identity(
        {
            **identity,
        },
        {
            **identity,
            "software_name": event_identity.get("software_name"),
            "tested_ref": event_identity.get("tested_ref"),
            "finding_slug": event_identity.get("finding_slug"),
            "direct_impact_marker": event_identity.get("direct_impact_marker"),
            "oracle_marker": event_identity.get("oracle_marker"),
            "code_context_identity": event_identity.get("code_context_identity"),
            "trigger_context_identity": event_identity.get("trigger_context_identity"),
            "tested_ref_kind": identity.get("tested_ref_kind"),
        },
        source=f"checkpoint {stage}",
    )
    sequence = int(event.get("sequence") or 0)
    expected_marker = str(event.get("expected_marker") or "")
    if sequence < 1 or not expected_marker:
        raise RuntimeError("RECORDING_IDENTITY_MISSING: checkpoint sequence or expected marker is missing")
    adapter.verify_terminal_stage(event, identity)
    checkpoint = adapter.capture_checkpoint(stage)
    ack = {
        "protocol_version": 1,
        "status": "ack",
        "stage": stage,
        "sequence": sequence,
        "event_timestamp": event.get("event_timestamp"),
        "expected_marker": expected_marker,
        "source_checkpoint": checkpoint,
    }
    ack_path = session.ack_dir / f"{sequence}-{stage}.ack.json"
    write_json_atomic(ack_path, ack)
    handled.add(event_path.name)
    print(f"[recording] checkpoint acknowledged: {stage} seq={sequence} source={checkpoint['name']}")


def wait_for_replay(
    script: Path,
    staging_bundle: Path,
    mode: str,
    engine: str,
    session: RecordingSession,
    adapter: MacOSOBSAdapter,
    identity: Mapping[str, str],
    timeout: int,
    pause_short: str,
    pause_long: str,
    terminal: MacOSTerminalWindow | None = None,
) -> tuple[int, str]:
    env = {**os.environ, **session.environment(), "REVIEWER_PAUSE_SHORT": pause_short, "REVIEWER_PAUSE_LONG": pause_long}
    env["REVIEWER_CODE_PAUSE"] = "0"
    env["REVIEWER_PAUSE_FINAL"] = "0"
    exit_file = session.root / "replay-exit.txt"
    if exit_file.exists():
        exit_file.unlink()
    proc: subprocess.Popen[str] | None = None
    if terminal is not None:
        terminal_command = "; ".join(
            build_replay_command_lines(
                repo_root=staging_bundle.parent,
                bundle=staging_bundle,
                run_script=script,
                exit_file=exit_file,
                mode=mode,
                engine=engine,
                pause_short=pause_short,
                pause_long=pause_long,
                recording_environment=session.environment(),
            )
        )
        terminal.open(terminal_command)
    else:
        proc = subprocess.Popen(
            ["sh", str(script), mode, engine],
            cwd=staging_bundle,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    handled: set[str] = set()
    lines: list[str] = []
    deadline = time.time() + timeout
    while True:
        for event_path in sorted(session.stage_dir.glob("*.event.json")):
            _handle_checkpoint_event(event_path, session, adapter, identity, handled)
        if proc is not None:
            assert proc.stdout is not None
            line = proc.stdout.readline() if proc.poll() is None else ""
            if line:
                print(line, end="")
                lines.append(line)
            if proc.poll() is not None:
                for tail in proc.stdout.readlines():
                    print(tail, end="")
                    lines.append(tail)
                break
        elif exit_file.is_file():
            break
        if time.time() > deadline:
            if proc is not None:
                proc.kill()
                proc.wait(timeout=5)
            raise TimeoutError(f"replay exceeded {timeout}s")
        time.sleep(0.05)
    for event_path in sorted(session.stage_dir.glob("*.event.json")):
        _handle_checkpoint_event(event_path, session, adapter, identity, handled)
    if len(handled) != len(STAGES):
        raise RuntimeError(f"recording checkpoint protocol incomplete; acknowledged {sorted(handled)}")
    if terminal is not None:
        try:
            replay_rc = int(exit_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"RECORDING_REPLAY_FAILED: Terminal exit marker is unreadable: {exc}") from exc
        return replay_rc, terminal.contents()
    assert proc is not None
    return int(proc.returncode or 0), "".join(lines)


def _media_video_details(video: Path) -> tuple[float, int, int, int]:
    return recording_validator._media_metadata(video)


def validate_video_capture(video: Path) -> list[Path]:
    """Validate several encoded frames before a video can enter staging."""

    duration, _width, _height, frames = _media_video_details(video)
    if frames <= 1:
        raise RuntimeError("RECORDING_VIDEO_CONTENT_UNVERIFIED: video has only one frame")
    thumb_dir = Path(tempfile.mkdtemp(prefix="zhulong-video-check-"))
    outputs: list[Path] = []
    try:
        for index, timestamp in enumerate((0.0, duration * 0.5, max(0.0, duration - 0.05))):
            output = thumb_dir / f"frame-{index}.png"
            recording_validator._extract_frame(video, timestamp, output)
            _width, _height, nonblack = recording_validator._image_info(output)
            if not nonblack:
                raise RuntimeError(f"RECORDING_VIDEO_CONTENT_UNVERIFIED: encoded frame at {timestamp:.3f}s is black")
            outputs.append(output)
        return outputs
    except BaseException:
        shutil.rmtree(thumb_dir, ignore_errors=True)
        raise


def latest_video_after(directory: Path, started_at: float) -> Path | None:
    candidates = [
        path for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() in VIDEO_SUFFIXES and path.stat().st_mtime >= started_at - 2
    ]
    return max(candidates, key=lambda path: path.stat().st_mtime) if candidates else None


def replace_bundle_video(bundle: Path, new_video: Path, output_name: str, keep_old: bool = False) -> Path:
    """Compatibility helper restricted to an owned staging directory.

    Direct replacement of a confirmed bundle is deliberately forbidden.  The
    normal path copies the OBS output into recorder-owned staging and promotes
    the complete transaction with :func:`transactional_promote`.
    """

    marker = bundle / ".zhulong-recording-transaction.json"
    if not marker.is_file() or marker.is_symlink():
        raise RuntimeError("replace_bundle_video is staging-only; missing recorder owner marker")
    target = bundle / output_name
    if target.name != output_name or target.suffix.lower() not in VIDEO_SUFFIXES:
        raise RuntimeError("staging video filename is unsafe")
    if not keep_old:
        for path in bundle.iterdir():
            if path.is_file() and path.suffix.lower() in VIDEO_SUFFIXES and path != target:
                path.unlink()
    shutil.copy2(new_video, target)
    return target


def _stage_events(session: RecordingSession) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    result: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for stage in STAGES:
        events = sorted(session.stage_dir.glob(f"*-{stage}.event.json"))
        acks = sorted(session.ack_dir.glob(f"*-{stage}.ack.json"))
        if len(events) != 1 or len(acks) != 1:
            raise RuntimeError(f"recording checkpoint requires one event and one acknowledgement for {stage}")
        result[stage] = (
            json.loads(events[0].read_text(encoding="utf-8")),
            json.loads(acks[0].read_text(encoding="utf-8")),
        )
    return result


def _update_recording_registrations(staging_bundle: Path, video_rel: str, screenshot_rels: list[str]) -> str:
    verification_path = staging_bundle / "verification-evidence.json"
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    evidence_files = [str(item) for item in verification.get("evidence_files", []) if str(item).strip()]
    for rel in [video_rel, *screenshot_rels, "recording-evidence.json", "attachments/recording-screenshot-inventory.md"]:
        if rel not in evidence_files:
            evidence_files.append(rel)
    verification["evidence_files"] = evidence_files
    write_json_atomic(verification_path, verification)

    reviewer_path = staging_bundle / "attachments/reviewer-evidence-index.json"
    reviewer = json.loads(reviewer_path.read_text(encoding="utf-8")) if reviewer_path.is_file() else {
        "schema_version": 1,
        "replay_command": "REVIEWER_PAUSE_SHORT=0 REVIEWER_PAUSE_LONG=0 ./run-recording.sh quick docker",
        "evidence_artifacts": [],
        "oracle_tokens": [],
    }
    artifacts = reviewer.setdefault("evidence_artifacts", [])
    if not isinstance(artifacts, list):
        artifacts = []
        reviewer["evidence_artifacts"] = artifacts
    existing = {str(item.get("path")) if isinstance(item, dict) else str(item) for item in artifacts}
    for rel in [video_rel, *screenshot_rels, "recording-evidence.json", "attachments/recording-screenshot-inventory.md"]:
        if rel not in existing:
            artifacts.append({"path": rel, "label": "final recording evidence"})
    write_json_atomic(reviewer_path, reviewer)

    inventory_rel = "attachments/recording-screenshot-inventory.md"
    inventory_path = staging_bundle / inventory_rel
    lines = ["# Final recording screenshot inventory", "", "Generated from accepted final encoded video frames.", ""]
    for rel in screenshot_rels:
        lines.append(f"- `{rel}` — registered in `verification-evidence.json`, `attachments/reviewer-evidence-index.json`, and this inventory.")
    inventory_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return inventory_rel


def build_recording_manifest(
    staging_bundle: Path,
    recorded_video: Path,
    script: Path,
    session: RecordingSession,
    identity: Mapping[str, str],
    obs_metadata: Mapping[str, Any],
    replay_rc: int,
    video_name: str,
) -> dict[str, Any]:
    if recorded_video.suffix.lower() not in VIDEO_SUFFIXES:
        raise RuntimeError(f"OBS output is not a supported video file: {recorded_video}")
    video_rel = video_name
    video_target = staging_bundle / video_rel
    if video_target.is_absolute() and video_target.parent != staging_bundle:
        raise RuntimeError("video name must stay at the bundle root")
    if not video_name or Path(video_name).name != video_name or Path(video_name).suffix.lower() not in VIDEO_SUFFIXES:
        raise RuntimeError("--video-name must be a root-level video filename")
    stale_root_videos = [
        path for path in staging_bundle.iterdir()
        if path.is_file() and path.suffix.lower() in VIDEO_SUFFIXES and path.name != video_name
    ]
    for stale_video in stale_root_videos:
        stale_video.unlink()
    if stale_root_videos:
        verification_path = staging_bundle / "verification-evidence.json"
        if verification_path.is_file():
            verification = json.loads(verification_path.read_text(encoding="utf-8"))
            verification["evidence_files"] = [
                item for item in verification.get("evidence_files", [])
                if str(item) not in {item.name for item in stale_root_videos}
            ]
            write_json_atomic(verification_path, verification)
        reviewer_path = staging_bundle / "attachments/reviewer-evidence-index.json"
        if reviewer_path.is_file():
            reviewer = json.loads(reviewer_path.read_text(encoding="utf-8"))
            artifacts = reviewer.get("evidence_artifacts")
            if isinstance(artifacts, list):
                reviewer["evidence_artifacts"] = [
                    item for item in artifacts
                    if (str(item.get("path")) if isinstance(item, dict) else str(item)) not in {item.name for item in stale_root_videos}
                ]
            write_json_atomic(reviewer_path, reviewer)
    shutil.copy2(recorded_video, video_target)
    duration, width, height, frames = _media_video_details(video_target)
    if frames <= 1:
        raise RuntimeError("final encoded video has no verifiable multi-frame content")
    stage_data = _stage_events(session)
    screenshot_items: list[dict[str, Any]] = []
    stage_items: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="zhulong-final-frames-") as tempdir:
        frame_root = Path(tempdir)
        for stage in STAGES:
            event, ack = stage_data[stage]
            source = ack.get("source_checkpoint")
            if not isinstance(source, dict):
                raise RuntimeError(f"checkpoint acknowledgement omitted source image for {stage}")
            source_name = str(source.get("name") or "")
            source_path = session.checkpoint_dir / source_name
            if not source_name or source_path.parent != session.checkpoint_dir or not source_path.is_file():
                raise RuntimeError(f"checkpoint source path is not recorder-owned for {stage}")
            timestamp = float(source.get("video_timestamp"))
            frame_path = frame_root / f"{stage}.png"
            recording_validator._extract_frame(video_target, timestamp, frame_path)
            frame_width, frame_height, nonblack = recording_validator._image_info(frame_path)
            if not nonblack:
                raise RuntimeError(f"RECORDING_VIDEO_CONTENT_UNVERIFIED: final frame is black for {stage}")
            similarity = recording_validator._image_similarity(source_path, frame_path)
            if similarity < recording_validator.MIN_SIMILARITY:
                raise RuntimeError(f"RECORDING_STAGE_FRAME_MISMATCH: final frame differs from live source for {stage} ({similarity:.3f})")
            screenshot_rel = SCREENSHOT_PATHS[stage]
            screenshot_path = staging_bundle / screenshot_rel
            screenshot_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(frame_path, screenshot_path)
            observations = {
                "identity": [identity["software_name"], identity["tested_ref"], str(event["expected_marker"])],
                "code_or_trigger_context": [identity["code_context_identity"], identity["trigger_context_identity"], str(event["expected_marker"])],
                "final_impact": [identity["direct_impact_marker"], identity["oracle_marker"], str(event["expected_marker"])],
            }[stage]
            stage_items.append(
                {
                    "stage": stage,
                    "sequence": int(event["sequence"]),
                    "event_timestamp": float(event["event_timestamp"]),
                    "video_timestamp": timestamp,
                    "hold_start": float(source["hold_start"]),
                    "hold_end": float(source["hold_end"]),
                    "expected_marker": str(event["expected_marker"]),
                    "source_name": str(obs_metadata["source_name"]),
                    "source_window_identity": str(obs_metadata["window_identity"]),
                    "canonical_identity": {
                        "software_name": identity["software_name"],
                        "tested_ref": identity["tested_ref"],
                        "finding_slug": identity["finding_slug"],
                        "code_context_identity": identity["code_context_identity"],
                        "trigger_context_identity": identity["trigger_context_identity"],
                    },
                    "source_checkpoint": {
                        "name": source_name,
                        "sha256": sha256_file(source_path),
                        "width": int(source["width"]),
                        "height": int(source["height"]),
                    },
                    "frame": {
                        "sha256": sha256_file(frame_path),
                        "width": frame_width,
                        "height": frame_height,
                        "perceptual_similarity": round(similarity, 6),
                        "recording_time_observations": observations,
                    },
                }
            )
            screenshot_items.append(
                {
                    "stage": stage,
                    "path": screenshot_rel,
                    "sha256": sha256_file(screenshot_path),
                    "size": screenshot_path.stat().st_size,
                    "width": frame_width,
                    "height": frame_height,
                    "video_timestamp": timestamp,
                    "source_frame_sha256": sha256_file(frame_path),
                }
            )
    inventory_rel = _update_recording_registrations(staging_bundle, video_rel, [item["path"] for item in screenshot_items])
    required_entries = [
        video_rel,
        *[item["path"] for item in screenshot_items],
        script.name,
        "recording-evidence.json",
        "verification-evidence.json",
        "attachments/reviewer-evidence-index.json",
        inventory_rel,
    ]
    required_docx = sorted(path.name for path in staging_bundle.glob("*.docx") if path.is_file() and not path.is_symlink())
    for docx_name in required_docx:
        if docx_name not in required_entries:
            required_entries.append(docx_name)
    manifest = {
        "schema_version": 1,
        "recording_status": "staging",
        "canonical_identity": dict(identity),
        "video": {
            "path": video_rel,
            "sha256": sha256_file(video_target),
            "size": video_target.stat().st_size,
            "duration_seconds": duration,
            "width": width,
            "height": height,
        },
        "replay": {"script_path": script.name, "script_sha256": sha256_file(script), "exit_code": replay_rc},
        "obs": dict(obs_metadata),
        "stages": stage_items,
        "screenshots": screenshot_items,
        "registrations": {
            "verification_evidence_path": "verification-evidence.json",
            "reviewer_index_path": "attachments/reviewer-evidence-index.json",
            "attachment_inventory_path": inventory_rel,
            "screenshot_paths": [item["path"] for item in screenshot_items],
        },
        "archive": {
            "status": "not_ready",
            "archive_name": f"{identity['finding_slug']}.zip",
            "testzip": None,
            "required_entries": required_entries,
            "recording_ready": False,
            "submission_ready": False,
        },
        "transaction": {
            "owner": "zhulong-recording",
            "owner_marker": ".zhulong-recording-transaction.json",
            "promotion_status": "staging",
            "rollback_safe": True,
            "full_recording_time_validated": False,
        },
    }
    write_json_atomic(staging_bundle / "recording-evidence.json", manifest)
    write_json_atomic(staging_bundle / ".zhulong-recording-transaction.json", {"owner": "zhulong-recording", "status": "staging", "created_epoch": int(time.time())})
    return manifest


def make_zip(bundle: Path, output_zip: Path, *, archive_root_name: str | None = None) -> Path:
    """Create a ZIP at a temporary/diagnostic path without deleting existing output."""

    if output_zip.exists():
        raise RuntimeError(f"refusing to overwrite an existing ZIP before promotion: {output_zip}")
    root_name = archive_root_name or bundle.name
    if not root_name or "/" in root_name or root_name in {".", ".."}:
        raise RuntimeError("archive root name is unsafe")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(bundle.rglob("*")):
            if path.is_symlink():
                raise RuntimeError(f"refusing to archive symlink: {path}")
            if path.name == ".DS_Store" or path.name.startswith("._"):
                continue
            rel = path.relative_to(bundle).as_posix()
            arcname = f"{root_name}/{rel}"
            if path.is_dir():
                archive.writestr(arcname.rstrip("/") + "/", b"")
            elif path.is_file():
                archive.write(path, arcname)
    with zipfile.ZipFile(output_zip) as archive:
        bad = archive.testzip()
        if bad is not None:
            raise RuntimeError(f"created ZIP failed testzip at {bad}")
    return output_zip


def require_full_recording_time_validation(staging_bundle: Path) -> None:
    """Require the full recorder-owned gate before archive/promotion authority."""

    manifest_path = staging_bundle / "recording-evidence.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("recording manifest is unreadable before promotion") from exc
    transaction = manifest.get("transaction") if isinstance(manifest, dict) else None
    if (
        manifest.get("recording_status") != "passed"
        or not isinstance(transaction, dict)
        or transaction.get("full_recording_time_validated") is not True
    ):
        raise RuntimeError(
            "recording promotion requires a staging bundle that passed full recording-time validation with live checkpoints"
        )


def retain_unpromoted_archive(staging_zip: Path, destination_dir: Path, final_bundle: Path) -> Path:
    """Persist a verified, unpromoted archive only in an explicit external directory."""

    if not staging_zip.is_file() or staging_zip.is_symlink():
        raise RuntimeError("verified unpromoted archive is unavailable")
    requested_dir = destination_dir.expanduser()
    if requested_dir.exists() and (not requested_dir.is_dir() or requested_dir.is_symlink()):
        raise RuntimeError("--keep-unpromoted-archive must name a non-symlink directory")
    requested_dir.mkdir(parents=True, exist_ok=True)
    resolved_dir = requested_dir.resolve(strict=True)
    resolved_bundle = final_bundle.resolve()
    if resolved_dir == resolved_bundle or resolved_bundle in resolved_dir.parents:
        raise RuntimeError("--keep-unpromoted-archive directory must remain outside the final bundle")
    output = resolved_dir / f"{final_bundle.name}.unpromoted-diagnostic.zip"
    if output.exists() or output.is_symlink():
        raise RuntimeError(f"refusing to overwrite retained diagnostic archive: {output}")
    with zipfile.ZipFile(staging_zip) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("verified unpromoted archive no longer passes testzip")
    shutil.copy2(staging_zip, output)
    if sha256_file(output) != sha256_file(staging_zip):
        output.unlink(missing_ok=True)
        raise RuntimeError("retained diagnostic archive bytes differ from the verified staging archive")
    return output


def transactional_promote(
    staging_bundle: Path,
    final_bundle: Path,
    staging_zip: Path,
    final_zip: Path,
    *,
    verify: Callable[[Path, Path], None] | None = None,
) -> None:
    """Promote bundle and archive together, restoring both on any interruption."""

    require_full_recording_time_validation(staging_bundle)
    marker = staging_bundle / ".zhulong-recording-transaction.json"
    if not marker.is_file() or marker.is_symlink():
        raise RuntimeError("recording staging owner marker is missing")
    if final_bundle.resolve() == staging_bundle.resolve() or final_zip.resolve() == staging_zip.resolve():
        raise RuntimeError("staging and final paths must be distinct")
    token = uuid.uuid4().hex
    bundle_backup = final_bundle.parent / f".{final_bundle.name}.recording-backup-{token}"
    zip_backup = final_zip.parent / f".{final_zip.name}.recording-backup-{token}"
    bundle_moved = False
    zip_moved = False
    try:
        if final_bundle.exists():
            os.replace(final_bundle, bundle_backup)
            bundle_moved = True
        if final_zip.exists():
            os.replace(final_zip, zip_backup)
            zip_moved = True
        os.replace(staging_bundle, final_bundle)
        os.replace(staging_zip, final_zip)
        if verify is not None:
            verify(final_bundle, final_zip)
    except BaseException:
        if final_zip.exists() and not staging_zip.exists():
            os.replace(final_zip, staging_zip)
        if final_bundle.exists() and not staging_bundle.exists():
            os.replace(final_bundle, staging_bundle)
        if zip_moved and zip_backup.exists() and not final_zip.exists():
            os.replace(zip_backup, final_zip)
        if bundle_moved and bundle_backup.exists() and not final_bundle.exists():
            os.replace(bundle_backup, final_bundle)
        raise
    else:
        if bundle_backup.exists():
            shutil.rmtree(bundle_backup)
        if zip_backup.exists():
            zip_backup.unlink()


def incomplete_recording_transactions(staging_parent: Path) -> list[Path]:
    """Find owned staging markers left by an interrupted recorder process."""

    if not staging_parent.is_dir():
        return []
    return sorted(
        marker for marker in staging_parent.glob("*/.zhulong-recording-transaction.json")
        if marker.is_file() and not marker.is_symlink()
    )


def update_archive_readiness(staging_bundle: Path, archive_name: str) -> None:
    require_full_recording_time_validation(staging_bundle)
    path = staging_bundle / "recording-evidence.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    archive = manifest["archive"]
    archive["status"] = "ready"
    archive["archive_name"] = archive_name
    archive["submission_ready"] = True
    archive["recording_ready"] = True
    manifest["transaction"]["promotion_status"] = "promoted"
    write_json_atomic(path, manifest)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="confirmed submission bundle directory")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--script")
    parser.add_argument("--mode", default="record")
    parser.add_argument("--engine", default="docker")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--pause-short", default=os.environ.get("REVIEWER_PAUSE_SHORT", "2"))
    parser.add_argument("--pause-long", default=os.environ.get("REVIEWER_PAUSE_LONG", "4"))
    parser.add_argument("--pause-code", default="0")
    parser.add_argument("--pause-final", default="0")
    parser.add_argument("--video-name", default="漏洞复现录屏.mp4")
    parser.add_argument("--zip-name")
    parser.add_argument("--obs-source-name", default=os.environ.get("ZHULONG_OBS_SOURCE_NAME", DEFAULT_OBS_SOURCE))
    parser.add_argument("--keep-old-videos", action="store_true", help="deprecated compatibility flag; staging always preserves original bytes")
    parser.add_argument(
        "--keep-unpromoted-archive",
        type=Path,
        metavar="DIR",
        help="on a later promotion failure, retain an already verified unpromoted ZIP in explicit external DIR",
    )
    parser.add_argument(
        "--zip-on-fail",
        action="store_true",
        help="deprecated compatibility flag; emits a warning and never creates a failure ZIP",
    )
    parser.add_argument("--keep-session", action="store_true", help="retain recorder-owned temporary state after success")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.zip_on_fail:
        print(
            "[deprecated] --zip-on-fail no longer retains any ZIP; use --keep-unpromoted-archive DIR for a verified, unpromoted diagnostic copy.",
            file=sys.stderr,
        )
    original_bundle = args.bundle.expanduser().resolve()
    if not original_bundle.is_dir():
        raise NotADirectoryError(original_bundle)
    script = discover_run_script(original_bundle, args.script)
    require_checkpoint_protocol(script)
    identity = parse_canonical_identity(original_bundle)
    print("[recording] canonical identity: " + json.dumps(identity, ensure_ascii=False, sort_keys=True))

    staging_parent = original_bundle.parent / ".staging"
    incomplete = incomplete_recording_transactions(staging_parent)
    if incomplete:
        raise RuntimeError(
            "RECORDING_TRANSACTION_INCOMPLETE: recorder-owned staging marker(s) require explicit recovery before a new run: "
            + ", ".join(str(path) for path in incomplete)
        )
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging_bundle = staging_parent / f"{original_bundle.name}-recording-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    shutil.copytree(original_bundle, staging_bundle, symlinks=False)
    staging_script = staging_bundle / script.name
    session = RecordingSession()
    raw_video: Path | None = None
    staging_zip: Path | None = None
    archive_verified = False
    adapter = MacOSOBSAdapter(args.obs_source_name, session)
    terminal = MacOSTerminalWindow() if sys.platform == "darwin" else None
    if terminal is not None:
        adapter.bind_terminal_window(terminal)
    try:
        staging_script.chmod(staging_script.stat().st_mode | 0o111)
        adapter.start()
        replay_rc, replay_output = wait_for_replay(
            staging_script,
            staging_bundle,
            args.mode,
            args.engine,
            session,
            adapter,
            identity,
            args.timeout,
            args.pause_short,
            args.pause_long,
            terminal=terminal,
        )
        raw_video = adapter.stop()
        if replay_rc != 0:
            raise RuntimeError(f"RECORDING_REPLAY_FAILED: replay exited with code {replay_rc}")
        if raw_video is None or not raw_video.is_file():
            raise RuntimeError("no OBS output video was returned; final promotion is forbidden")
        print(f"[recording] raw OBS output retained outside bundle: {raw_video}")
        validate_video_capture(raw_video)
        manifest = build_recording_manifest(staging_bundle, raw_video, staging_script, session, identity, adapter.obs_metadata(), replay_rc, args.video_name)
        (staging_bundle / "attachments/evidence/replay-output.log").write_text(replay_output, encoding="utf-8")

        report_validator = Path(__file__).with_name("validate_report_bundle.py")
        report_result = command_output([sys.executable, str(report_validator), "--bundle-dir", str(staging_bundle)])
        if report_result.returncode != 0:
            raise RuntimeError("staging report validation failed before recording promotion:\n" + report_result.stdout)

        evidence_validator = Path(__file__).with_name("validate_recording_evidence.py")
        result = command_output([sys.executable, str(evidence_validator), "--bundle-dir", str(staging_bundle), "--checkpoint-dir", str(session.checkpoint_dir), "--finalize"])
        if result.returncode != 0:
            raise RuntimeError("recording evidence validation failed:\n" + result.stdout)
        print(result.stdout.strip())

        output_zip = original_bundle.parent / (args.zip_name or f"{original_bundle.name}.zip")
        update_archive_readiness(staging_bundle, output_zip.name)
        staging_zip = session.root / "staged-final.zip"
        make_zip(staging_bundle, staging_zip, archive_root_name=original_bundle.name)
        archive_result = command_output([
            sys.executable,
            str(evidence_validator),
            "--bundle-dir",
            str(staging_bundle),
            "--archive",
            str(staging_zip),
            "--archive-root",
            original_bundle.name,
        ])
        if archive_result.returncode != 0:
            raise RuntimeError("staged archive validation failed:\n" + archive_result.stdout)
        archive_verified = True
        def verify_promoted(final_bundle: Path, final_archive: Path) -> None:
            final_result = command_output([
                sys.executable,
                str(evidence_validator),
                "--bundle-dir",
                str(final_bundle),
                "--archive",
                str(final_archive),
                "--archive-root",
                original_bundle.name,
            ])
            if final_result.returncode != 0:
                raise RuntimeError("post-promotion recording validation failed:\n" + final_result.stdout)
            print(final_result.stdout.strip())

        transactional_promote(staging_bundle, original_bundle, staging_zip, output_zip, verify=verify_promoted)
        print(f"[zip] atomically promoted: {output_zip}")
        if terminal is not None:
            terminal.close()
        if not args.keep_session:
            session.cleanup()
        return 0
    except BaseException as exc:
        try:
            adapter.stop()
        except BaseException:
            pass
        if terminal is not None:
            try:
                terminal.close()
            except BaseException:
                pass
        if raw_video is None:
            raw_video = None
        session.keep_failed(str(exc), raw_video)
        if args.keep_unpromoted_archive is not None and archive_verified and staging_zip is not None and staging_zip.is_file():
            try:
                retained = retain_unpromoted_archive(staging_zip, args.keep_unpromoted_archive, original_bundle)
                print(f"[recording-failed-unpromoted] retained verified diagnostic ZIP: {retained}", file=sys.stderr)
            except BaseException as retain_exc:
                print(f"[recording-failed-unpromoted] could not retain diagnostic ZIP: {retain_exc}", file=sys.stderr)
        shutil.rmtree(staging_bundle, ignore_errors=True)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
