#!/usr/bin/env python3
"""Validate final recording identity, media frames, screenshots, and archive state.

This is an opt-in gate separate from ``validate_report_bundle.py``.  It performs
only local filesystem/media checks and never starts Docker, OBS, a browser, OCR
service, or a network client.  The recorder calls this validator with its owned
live checkpoint directory before promotion.  A reviewer may re-run it later
without that directory, but that is artifact-only revalidation rather than a
new recording-time proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping

try:
    from PIL import Image, ImageChops, ImageStat
except ImportError:  # pragma: no cover - the report renderer already requires Pillow.
    Image = None  # type: ignore[assignment]
    ImageChops = None  # type: ignore[assignment]
    ImageStat = None  # type: ignore[assignment]

try:
    from recording_identity import (
        IDENTITY_FIELDS,
        RECORDING_IDENTITY_MISMATCH,
        RECORDING_IDENTITY_MISSING,
        RECORDING_TESTED_REF_MISMATCH,
        RecordingIdentityError,
        assert_relative_bundle_path,
        compare_identity,
        parse_canonical_identity,
        path_within,
        sha256_file,
    )
except ImportError:  # pragma: no cover - supports direct package imports in tests.
    from .recording_identity import (  # type: ignore
        IDENTITY_FIELDS,
        RECORDING_IDENTITY_MISMATCH,
        RECORDING_IDENTITY_MISSING,
        RECORDING_TESTED_REF_MISMATCH,
        RecordingIdentityError,
        assert_relative_bundle_path,
        compare_identity,
        parse_canonical_identity,
        path_within,
        sha256_file,
    )


RECORDING_WRONG_WINDOW = "RECORDING_WRONG_WINDOW"
RECORDING_IDENTITY_FRAME_MISSING = "RECORDING_IDENTITY_FRAME_MISSING"
RECORDING_STAGE_FRAME_MISMATCH = "RECORDING_STAGE_FRAME_MISMATCH"
RECORDING_IMPACT_FRAME_MISSING = "RECORDING_IMPACT_FRAME_MISSING"
RECORDING_VIDEO_CONTENT_UNVERIFIED = "RECORDING_VIDEO_CONTENT_UNVERIFIED"
RECORDING_SCREENSHOT_MISSING = "RECORDING_SCREENSHOT_MISSING"
RECORDING_SCREENSHOT_DUPLICATE = "RECORDING_SCREENSHOT_DUPLICATE"
RECORDING_SCREENSHOT_UNREGISTERED = "RECORDING_SCREENSHOT_UNREGISTERED"
RECORDING_SCREENSHOT_SOURCE_MISMATCH = "RECORDING_SCREENSHOT_SOURCE_MISMATCH"
RECORDING_HASH_MISMATCH = "RECORDING_HASH_MISMATCH"
RECORDING_REPLAY_FAILED = "RECORDING_REPLAY_FAILED"
RECORDING_ARCHIVE_MISSING = "RECORDING_ARCHIVE_MISSING"
RECORDING_ARCHIVE_INCOMPLETE = "RECORDING_ARCHIVE_INCOMPLETE"
RECORDING_ARCHIVE_CORRUPT = "RECORDING_ARCHIVE_CORRUPT"
RECORDING_MANIFEST_INVALID = "RECORDING_MANIFEST_INVALID"
RECORDING_PATH_UNSAFE = "RECORDING_PATH_UNSAFE"

EXPECTED_STAGES = ("identity", "code_or_trigger_context", "final_impact")
EXPECTED_SCREENSHOTS = {
    "identity": "attachments/evidence/screenshots/01-target-identity.png",
    "code_or_trigger_context": "attachments/evidence/screenshots/02-code-or-trigger-context.png",
    "final_impact": "attachments/evidence/screenshots/03-final-impact.png",
}
VIDEO_SUFFIXES = {".mp4", ".mov", ".mkv", ".m4v", ".webm", ".gif", ".webp"}
MIN_SIMILARITY = 0.86
MIN_CONTENT_WIDTH = 32
MIN_CONTENT_HEIGHT = 20


class RecordingEvidenceError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _error(code: str, message: str) -> RecordingEvidenceError:
    return RecordingEvidenceError(code, message)


def _text(value: Any) -> str:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value).strip()
    return ""


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise _error(code, message)


def _require_keys(value: Mapping[str, Any], required: set[str], allowed: set[str], label: str) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - allowed)
    if missing or extra:
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if extra:
            detail.append("additional=" + ",".join(extra))
        raise _error(RECORDING_MANIFEST_INVALID, f"{label} has invalid keys ({'; '.join(detail)})")


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _error(RECORDING_MANIFEST_INVALID, f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise _error(RECORDING_MANIFEST_INVALID, f"{label} must be a JSON object")
    return value


def _load_manifest(bundle_dir: Path) -> dict[str, Any]:
    path = bundle_dir / "recording-evidence.json"
    _require(path.is_file() and not path.is_symlink(), RECORDING_MANIFEST_INVALID, "recording-evidence.json is missing or symlinked")
    manifest = _read_json(path, label="recording-evidence.json")
    _require_keys(
        manifest,
        {"schema_version", "recording_status", "canonical_identity", "video", "replay", "obs", "stages", "screenshots", "registrations", "archive", "transaction"},
        {"schema_version", "recording_status", "canonical_identity", "video", "replay", "obs", "stages", "screenshots", "registrations", "archive", "transaction"},
        "recording-evidence.json",
    )
    _require(manifest.get("schema_version") == 1, RECORDING_MANIFEST_INVALID, "schema_version must be 1")
    _require(manifest.get("recording_status") in {"staging", "passed", "failed"}, RECORDING_MANIFEST_INVALID, "recording_status is invalid")
    return manifest


def _validate_manifest_structure(manifest: Mapping[str, Any]) -> None:
    identity = manifest.get("canonical_identity")
    _require(isinstance(identity, dict), RECORDING_MANIFEST_INVALID, "canonical_identity must be an object")
    _require_keys(identity, set(IDENTITY_FIELDS), set(IDENTITY_FIELDS), "canonical_identity")
    for field in IDENTITY_FIELDS:
        _require(bool(_text(identity.get(field))), RECORDING_MANIFEST_INVALID, f"canonical_identity.{field} is empty")

    video = manifest.get("video")
    replay = manifest.get("replay")
    obs = manifest.get("obs")
    registrations = manifest.get("registrations")
    archive = manifest.get("archive")
    transaction = manifest.get("transaction")
    _require(isinstance(video, dict), RECORDING_MANIFEST_INVALID, "video must be an object")
    _require_keys(video, {"path", "sha256", "size", "duration_seconds", "width", "height"}, {"path", "sha256", "size", "duration_seconds", "width", "height"}, "video")
    _require(isinstance(replay, dict), RECORDING_MANIFEST_INVALID, "replay must be an object")
    _require_keys(replay, {"script_path", "script_sha256", "exit_code"}, {"script_path", "script_sha256", "exit_code"}, "replay")
    _require(isinstance(obs, dict), RECORDING_MANIFEST_INVALID, "obs must be an object")
    _require_keys(obs, {"source_name", "source_kind", "window_identity", "window_title", "window_stable"}, {"source_name", "source_kind", "window_identity", "window_title", "window_stable"}, "obs")
    _require(isinstance(registrations, dict), RECORDING_MANIFEST_INVALID, "registrations must be an object")
    _require_keys(registrations, {"verification_evidence_path", "reviewer_index_path", "attachment_inventory_path", "screenshot_paths"}, {"verification_evidence_path", "reviewer_index_path", "attachment_inventory_path", "screenshot_paths"}, "registrations")
    _require(isinstance(archive, dict), RECORDING_MANIFEST_INVALID, "archive must be an object")
    _require_keys(archive, {"status", "archive_name", "testzip", "required_entries", "recording_ready", "submission_ready"}, {"status", "archive_name", "archive_sha256", "archive_size", "testzip", "required_entries", "recording_ready", "submission_ready"}, "archive")
    _require(isinstance(transaction, dict), RECORDING_MANIFEST_INVALID, "transaction must be an object")
    _require_keys(transaction, {"owner", "owner_marker", "promotion_status", "rollback_safe", "full_recording_time_validated"}, {"owner", "owner_marker", "promotion_status", "rollback_safe", "full_recording_time_validated"}, "transaction")
    _require(type(video.get("size")) is int and video.get("size", 0) > 0, RECORDING_MANIFEST_INVALID, "video.size must be a positive integer")
    _require(type(video.get("duration_seconds")) in {int, float} and video.get("duration_seconds", 0) > 0, RECORDING_MANIFEST_INVALID, "video.duration_seconds must be positive")
    _require(type(video.get("width")) is int and video.get("width", 0) > 0, RECORDING_MANIFEST_INVALID, "video.width must be a positive integer")
    _require(type(video.get("height")) is int and video.get("height", 0) > 0, RECORDING_MANIFEST_INVALID, "video.height must be a positive integer")
    _require(isinstance(replay.get("exit_code"), int), RECORDING_MANIFEST_INVALID, "replay.exit_code must be an integer")
    _require(obs.get("source_kind") in {"window_capture", "display_capture", "fixture_media"}, RECORDING_MANIFEST_INVALID, "obs.source_kind is invalid")
    _require(all(_text(obs.get(field)) for field in ("source_name", "window_identity", "window_title")), RECORDING_WRONG_WINDOW, "OBS source/window identity is incomplete")
    _require(obs.get("window_stable") is True, RECORDING_WRONG_WINDOW, "OBS/window identity was not stable")
    _require(transaction.get("owner") == "zhulong-recording" and transaction.get("rollback_safe") is True, RECORDING_MANIFEST_INVALID, "transaction ownership/rollback contract is invalid")
    _require(type(transaction.get("full_recording_time_validated")) is bool, RECORDING_MANIFEST_INVALID, "transaction.full_recording_time_validated must be boolean")
    if manifest.get("recording_status") == "passed":
        _require(transaction.get("full_recording_time_validated") is True, RECORDING_MANIFEST_INVALID, "passed recording status requires full recording-time validation")
    _require(archive.get("status") in {"not_ready", "ready", "failed"}, RECORDING_MANIFEST_INVALID, "archive.status is invalid")
    _require(type(archive.get("archive_name")) is str and bool(archive.get("archive_name").strip()), RECORDING_MANIFEST_INVALID, "archive.archive_name is missing")
    _require(archive.get("testzip") is None, RECORDING_MANIFEST_INVALID, "archive.testzip must be null until the ZIP gate records success")
    _require(isinstance(archive.get("required_entries"), list) and bool(archive.get("required_entries")) and all(type(item) is str and item.strip() for item in archive["required_entries"]), RECORDING_MANIFEST_INVALID, "archive.required_entries is invalid")
    _require(type(archive.get("recording_ready")) is bool and type(archive.get("submission_ready")) is bool, RECORDING_MANIFEST_INVALID, "archive readiness fields must be booleans")
    _require(type(manifest.get("stages")) is list and len(manifest["stages"]) == 3, RECORDING_MANIFEST_INVALID, "stages must contain exactly three checkpoints")
    _require(type(manifest.get("screenshots")) is list and len(manifest["screenshots"]) == 3, RECORDING_MANIFEST_INVALID, "screenshots must contain exactly three files")


def _safe_path(bundle_dir: Path, value: Any, *, field: str, allow_missing: bool = False) -> Path:
    try:
        return assert_relative_bundle_path(bundle_dir, value, field=field, allow_missing=allow_missing)
    except RecordingIdentityError as exc:
        raise _error(RECORDING_PATH_UNSAFE, str(exc)) from exc


def _image_info(path: Path) -> tuple[int, int, bool]:
    if Image is None:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, "Pillow is unavailable for deterministic image checks")
    try:
        with Image.open(path) as image:
            rgb = image.convert("RGB")
            width, height = rgb.size
            if width < MIN_CONTENT_WIDTH or height < MIN_CONTENT_HEIGHT:
                return width, height, False
            extrema = rgb.getextrema()
            nonblack = any(high - low > 4 and high > 8 for low, high in extrema)
            if nonblack:
                stat = ImageStat.Stat(rgb)
                nonblack = max(stat.mean) > 8.0
            return width, height, bool(nonblack)
    except (OSError, ValueError) as exc:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, f"cannot decode image {path.name}: {exc}") from exc


def _image_similarity(left: Path, right: Path) -> float:
    if Image is None:
        return 0.0
    with Image.open(left) as left_image, Image.open(right) as right_image:
        left_rgb = left_image.convert("RGB").resize((96, 54))
        right_rgb = right_image.convert("RGB").resize((96, 54))
        diff = ImageChops.difference(left_rgb, right_rgb)
        stat = ImageStat.Stat(diff)
        mean = sum(stat.mean) / (len(stat.mean) * 255.0)
        return max(0.0, min(1.0, 1.0 - mean))


def _gif_metadata(path: Path) -> tuple[float, int, int, int]:
    if Image is None:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, "Pillow is unavailable for fixture media")
    try:
        with Image.open(path) as image:
            width, height = image.size
            frames = getattr(image, "n_frames", 1)
            duration_ms = 0
            for index in range(frames):
                image.seek(index)
                duration_ms += int(image.info.get("duration", 100))
            return max(duration_ms / 1000.0, 0.1), width, height, frames
    except (OSError, ValueError) as exc:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, f"cannot decode animated media: {exc}") from exc


def _ffprobe_metadata(path: Path) -> tuple[float, int, int, int]:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, "ffprobe is unavailable for encoded video verification")
    proc = subprocess.run(
        [ffprobe, "-v", "error", "-show_entries", "format=duration:stream=width,height,nb_frames", "-of", "json", str(path)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, f"ffprobe failed: {proc.stderr.strip()}")
    try:
        payload = json.loads(proc.stdout)
        streams = [item for item in payload.get("streams", []) if item.get("width") and item.get("height")]
        stream = streams[0]
        duration = float(payload.get("format", {}).get("duration") or 0)
        frames = int(float(stream.get("nb_frames") or 0))
        return duration, int(stream["width"]), int(stream["height"]), frames
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, f"ffprobe returned incomplete metadata: {exc}") from exc


def _media_metadata(path: Path) -> tuple[float, int, int, int]:
    if path.suffix.lower() in {".gif", ".webp"}:
        return _gif_metadata(path)
    return _ffprobe_metadata(path)


def _extract_frame(path: Path, timestamp: float, output: Path) -> None:
    if Image is not None and path.suffix.lower() in {".gif", ".webp"}:
        try:
            with Image.open(path) as image:
                elapsed = 0.0
                frame_index = 0
                for index in range(getattr(image, "n_frames", 1)):
                    image.seek(index)
                    if elapsed <= timestamp:
                        frame_index = index
                    elapsed += int(image.info.get("duration", 100)) / 1000.0
                image.seek(frame_index)
                image.convert("RGB").save(output, format="PNG")
                return
        except (OSError, ValueError) as exc:
            raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, f"cannot extract fixture frame: {exc}") from exc
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, "ffmpeg is unavailable for encoded frame extraction")
    proc = subprocess.run(
        [ffmpeg, "-v", "error", "-ss", f"{max(0.0, timestamp):.6f}", "-i", str(path), "-frames:v", "1", "-y", str(output)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not output.is_file():
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, f"ffmpeg frame extraction failed: {proc.stderr.strip()}")


def _validate_video(bundle_dir: Path, manifest: Mapping[str, Any], temp_dir: Path) -> tuple[Path, float, int, int]:
    video = manifest["video"]
    video_value = _text(video.get("path"))
    _require(Path(video_value).suffix.lower() in VIDEO_SUFFIXES, RECORDING_VIDEO_CONTENT_UNVERIFIED, "video.path does not name a supported video format")
    video_path = _safe_path(bundle_dir, video["path"], field="video.path", allow_missing=True)
    _require(video_path.is_file() and not video_path.is_symlink(), RECORDING_VIDEO_CONTENT_UNVERIFIED, "final encoded video is missing or symlinked")
    extra_media = [
        path for path in bundle_dir.rglob("*")
        if path.is_file() and not path.is_symlink() and path.suffix.lower() in {".mp4", ".mov", ".mkv", ".m4v", ".webm"} and path.resolve() != video_path.resolve()
    ]
    if extra_media:
        raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, "bundle contains an additional unregistered video: " + str(extra_media[0].relative_to(bundle_dir)))
    actual_hash = sha256_file(video_path)
    _require(actual_hash == video.get("sha256"), RECORDING_HASH_MISMATCH, "video sha256 does not match recording manifest")
    _require(video_path.stat().st_size == video.get("size"), RECORDING_HASH_MISMATCH, "video size does not match recording manifest")
    duration, width, height, frames = _media_metadata(video_path)
    _require(frames != 1 or video_path.suffix.lower() not in {".gif", ".webp"}, RECORDING_VIDEO_CONTENT_UNVERIFIED, "video contains no verifiable multi-frame content")
    _require(abs(duration - float(video["duration_seconds"])) <= 0.20, RECORDING_VIDEO_CONTENT_UNVERIFIED, "video duration differs from manifest")
    _require((width, height) == (video["width"], video["height"]), RECORDING_VIDEO_CONTENT_UNVERIFIED, "video dimensions differ from manifest")
    return video_path, duration, width, height


def _stage_map(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    stages = manifest["stages"]
    seen: set[str] = set()
    result: dict[str, dict[str, Any]] = {}
    sequences: list[int] = []
    for stage in stages:
        _require(isinstance(stage, dict), RECORDING_MANIFEST_INVALID, "each stage must be an object")
        _require_keys(stage, {"stage", "sequence", "event_timestamp", "video_timestamp", "hold_start", "hold_end", "expected_marker", "canonical_identity", "source_name", "source_window_identity", "source_checkpoint", "frame"}, {"stage", "sequence", "event_timestamp", "video_timestamp", "hold_start", "hold_end", "expected_marker", "canonical_identity", "source_name", "source_window_identity", "source_checkpoint", "frame"}, "stage")
        name = _text(stage.get("stage"))
        _require(name in EXPECTED_STAGES and name not in seen, RECORDING_MANIFEST_INVALID, "stage names must be unique identity/context/final-impact checkpoints")
        _require(type(stage.get("sequence")) is int and 1 <= stage["sequence"] <= 3, RECORDING_MANIFEST_INVALID, f"{name}.sequence is invalid")
        stage_identity = stage.get("canonical_identity")
        source_checkpoint = stage.get("source_checkpoint")
        frame = stage.get("frame")
        _require(isinstance(stage_identity, dict), RECORDING_MANIFEST_INVALID, f"{name}.canonical_identity must be an object")
        _require_keys(stage_identity, {"software_name", "tested_ref", "finding_slug", "code_context_identity", "trigger_context_identity"}, {"software_name", "tested_ref", "finding_slug", "code_context_identity", "trigger_context_identity"}, f"{name}.canonical_identity")
        _require(isinstance(source_checkpoint, dict), RECORDING_MANIFEST_INVALID, f"{name}.source_checkpoint must be an object")
        _require_keys(source_checkpoint, {"name", "sha256", "width", "height"}, {"name", "sha256", "width", "height"}, f"{name}.source_checkpoint")
        _require(type(source_checkpoint.get("width")) is int and source_checkpoint["width"] > 0, RECORDING_MANIFEST_INVALID, f"{name}.source_checkpoint.width is invalid")
        _require(type(source_checkpoint.get("height")) is int and source_checkpoint["height"] > 0, RECORDING_MANIFEST_INVALID, f"{name}.source_checkpoint.height is invalid")
        _require(isinstance(frame, dict), RECORDING_MANIFEST_INVALID, f"{name}.frame must be an object")
        _require_keys(frame, {"sha256", "width", "height", "perceptual_similarity", "recording_time_observations"}, {"sha256", "width", "height", "perceptual_similarity", "recording_time_observations"}, f"{name}.frame")
        _require(type(frame.get("width")) is int and frame["width"] > 0, RECORDING_MANIFEST_INVALID, f"{name}.frame.width is invalid")
        _require(type(frame.get("height")) is int and frame["height"] > 0, RECORDING_MANIFEST_INVALID, f"{name}.frame.height is invalid")
        _require(type(frame.get("perceptual_similarity")) in {int, float} and 0 <= frame["perceptual_similarity"] <= 1, RECORDING_MANIFEST_INVALID, f"{name}.frame.perceptual_similarity is invalid")
        _require(isinstance(frame.get("recording_time_observations"), list) and all(_text(item) for item in frame["recording_time_observations"]), RECORDING_MANIFEST_INVALID, f"{name}.frame.recording_time_observations is invalid")
        seen.add(name)
        sequences.append(stage.get("sequence"))
        result[name] = stage
    _require(tuple(sorted(seen, key=EXPECTED_STAGES.index)) == EXPECTED_STAGES, RECORDING_MANIFEST_INVALID, "all three recording stages are required")
    _require(sequences == [1, 2, 3], RECORDING_MANIFEST_INVALID, "stage sequence must be 1, 2, 3")
    return result


def _validate_stage_content(
    bundle_dir: Path,
    manifest: Mapping[str, Any],
    identity: Mapping[str, str],
    video_path: Path,
    duration: float,
    temp_dir: Path,
    checkpoint_dir: Path | None,
) -> dict[str, Path]:
    stages = _stage_map(manifest)
    extracted: dict[str, Path] = {}
    previous_timestamp = -1.0
    for name in EXPECTED_STAGES:
        stage = stages[name]
        event_time = stage["event_timestamp"]
        timestamp = stage["video_timestamp"]
        hold_start = stage["hold_start"]
        hold_end = stage["hold_end"]
        _require(all(isinstance(item, (int, float)) and not isinstance(item, bool) for item in (event_time, timestamp, hold_start, hold_end)), RECORDING_MANIFEST_INVALID, f"{name} timestamps must be numeric")
        _require(0 <= hold_start <= timestamp <= hold_end <= duration + 0.05, RECORDING_VIDEO_CONTENT_UNVERIFIED, f"{name} timestamp is outside its visual hold")
        _require(timestamp > previous_timestamp, RECORDING_VIDEO_CONTENT_UNVERIFIED, "recording stages are out of video order")
        _require(hold_end > hold_start, RECORDING_VIDEO_CONTENT_UNVERIFIED, f"{name} has no positive visual hold")
        previous_timestamp = timestamp
        stage_identity = stage["canonical_identity"]
        _require(_text(stage.get("source_name")) == _text(manifest["obs"].get("source_name")), RECORDING_WRONG_WINDOW, f"{name} OBS source identity changed")
        _require(_text(stage.get("source_window_identity")) == _text(manifest["obs"].get("window_identity")), RECORDING_WRONG_WINDOW, f"{name} OBS window identity changed")
        _require(isinstance(stage_identity, dict), RECORDING_MANIFEST_INVALID, f"{name}.canonical_identity must be an object")
        for field in ("software_name", "tested_ref", "finding_slug", "code_context_identity", "trigger_context_identity"):
            _require(_text(stage_identity.get(field)) == _text(identity.get(field)), RECORDING_IDENTITY_MISMATCH, f"{name} canonical identity differs from source")
        expected_marker = _text(stage.get("expected_marker"))
        observations = stage["frame"].get("recording_time_observations") if isinstance(stage.get("frame"), dict) else None
        _require(isinstance(observations, list) and all(_text(item) for item in observations), RECORDING_VIDEO_CONTENT_UNVERIFIED, f"{name} has no recording-time observations")
        observation_text = "\n".join(_text(item) for item in observations)
        if name == "identity":
            if identity["software_name"] not in observation_text or identity["tested_ref"] not in observation_text:
                raise _error(RECORDING_IDENTITY_FRAME_MISSING, "identity frame does not contain exact software name and tested ref")
        # Recorder-supplied observations route precise consistency failures but
        # never independently prove encoded video content. Full promotion also
        # requires OBS/window binding and live-checkpoint similarity below.
        _require(expected_marker in observation_text, RECORDING_VIDEO_CONTENT_UNVERIFIED, f"{name} recording-time observations do not contain the expected marker")
        if name == "code_or_trigger_context":
            if identity["code_context_identity"] not in observation_text and identity["trigger_context_identity"] not in observation_text:
                raise _error(RECORDING_STAGE_FRAME_MISMATCH, "code/context frame lacks canonical code or trigger context")
        elif name == "final_impact" and identity["direct_impact_marker"] not in observation_text:
            raise _error(RECORDING_IMPACT_FRAME_MISSING, "final-impact frame lacks the direct-impact marker")

        frame_path = temp_dir / f"{name}-frame.png"
        _extract_frame(video_path, float(timestamp), frame_path)
        width, height, nonblack = _image_info(frame_path)
        _require(nonblack, RECORDING_VIDEO_CONTENT_UNVERIFIED, f"{name} encoded frame is black or empty")
        frame = stage["frame"]
        _require(sha256_file(frame_path) == frame.get("sha256"), RECORDING_HASH_MISMATCH, f"{name} encoded frame hash differs from manifest")
        _require((width, height) == (frame.get("width"), frame.get("height")), RECORDING_VIDEO_CONTENT_UNVERIFIED, f"{name} encoded frame dimensions differ from manifest")
        similarity = frame.get("perceptual_similarity")
        _require(isinstance(similarity, (int, float)) and similarity >= MIN_SIMILARITY, RECORDING_STAGE_FRAME_MISMATCH, f"{name} perceptual similarity is below the conservative threshold")
        if checkpoint_dir is not None:
            checkpoint_name = _text(stage["source_checkpoint"].get("name"))
            checkpoint_path = checkpoint_dir / checkpoint_name
            _require(path_within(checkpoint_dir, checkpoint_path) and checkpoint_path.is_file() and not checkpoint_path.is_symlink(), RECORDING_STAGE_FRAME_MISMATCH, f"{name} live checkpoint image is missing or escapes its owned temp directory")
            _require(sha256_file(checkpoint_path) == stage["source_checkpoint"].get("sha256"), RECORDING_HASH_MISMATCH, f"{name} live checkpoint hash differs from manifest")
            checkpoint_width, checkpoint_height, checkpoint_nonblack = _image_info(checkpoint_path)
            _require(checkpoint_nonblack and (checkpoint_width, checkpoint_height) == (stage["source_checkpoint"].get("width"), stage["source_checkpoint"].get("height")), RECORDING_STAGE_FRAME_MISMATCH, f"{name} live checkpoint is empty or has wrong dimensions")
            actual_similarity = _image_similarity(checkpoint_path, frame_path)
            _require(actual_similarity >= MIN_SIMILARITY, RECORDING_STAGE_FRAME_MISMATCH, f"{name} final frame differs from the live source image ({actual_similarity:.3f})")
            _require(abs(actual_similarity - float(similarity)) <= 0.08, RECORDING_STAGE_FRAME_MISMATCH, f"{name} manifest similarity is not consistent with recomputed similarity")
        extracted[name] = frame_path
    return extracted


def _artifact_paths(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            path = _text(item.get("path"))
            if path:
                result.append(path)
    return result


def _validate_screenshots(bundle_dir: Path, manifest: Mapping[str, Any], stage_frames: Mapping[str, Path]) -> None:
    registrations = manifest["registrations"]
    expected_paths = [EXPECTED_SCREENSHOTS[name] for name in EXPECTED_STAGES]
    screenshot_items = manifest["screenshots"]
    for index, item in enumerate(screenshot_items):
        _require(isinstance(item, dict), RECORDING_MANIFEST_INVALID, f"screenshots[{index}] must be an object")
        _require_keys(item, {"stage", "path", "sha256", "size", "width", "height", "video_timestamp", "source_frame_sha256"}, {"stage", "path", "sha256", "size", "width", "height", "video_timestamp", "source_frame_sha256"}, f"screenshots[{index}]")
        _require(type(item.get("size")) is int and item["size"] > 0, RECORDING_MANIFEST_INVALID, f"screenshots[{index}].size is invalid")
        _require(type(item.get("width")) is int and item["width"] > 0, RECORDING_MANIFEST_INVALID, f"screenshots[{index}].width is invalid")
        _require(type(item.get("height")) is int and item["height"] > 0, RECORDING_MANIFEST_INVALID, f"screenshots[{index}].height is invalid")
        _require(type(item.get("video_timestamp")) in {int, float} and item["video_timestamp"] >= 0, RECORDING_MANIFEST_INVALID, f"screenshots[{index}].video_timestamp is invalid")
    paths = [_text(item.get("path")) for item in screenshot_items]
    _require(paths == expected_paths, RECORDING_SCREENSHOT_MISSING, "screenshot paths must be the three canonical stage paths in order")
    _require(len(set(paths)) == 3, RECORDING_SCREENSHOT_DUPLICATE, "screenshot paths are duplicated")
    screenshot_stages = [_text(item.get("stage")) for item in screenshot_items]
    _require(screenshot_stages == list(EXPECTED_STAGES), RECORDING_SCREENSHOT_SOURCE_MISMATCH, "screenshot stages must align with the canonical screenshot paths")
    _require(registrations.get("screenshot_paths") == expected_paths, RECORDING_SCREENSHOT_UNREGISTERED, "manifest registration targets do not enumerate all screenshots")
    hashes: set[str] = set()
    frame_hashes: set[str] = set()
    stage_by_name = {str(item["stage"]): item for item in manifest["stages"]}
    for item in screenshot_items:
        stage = _text(item.get("stage"))
        path = _safe_path(bundle_dir, item.get("path"), field=f"screenshots[{stage}].path", allow_missing=True)
        _require(path.is_file() and not path.is_symlink(), RECORDING_SCREENSHOT_MISSING, f"screenshot for {stage} is missing")
        actual_hash = sha256_file(path)
        _require(actual_hash == item.get("sha256"), RECORDING_HASH_MISMATCH, f"screenshot hash mismatch for {stage}")
        _require(actual_hash not in hashes, RECORDING_SCREENSHOT_DUPLICATE, f"screenshot bytes are duplicated for {stage}")
        hashes.add(actual_hash)
        width, height, nonblack = _image_info(path)
        _require(nonblack, RECORDING_SCREENSHOT_SOURCE_MISMATCH, f"screenshot for {stage} is black or unreadable")
        _require((width, height) == (item.get("width"), item.get("height")), RECORDING_SCREENSHOT_SOURCE_MISMATCH, f"screenshot dimensions mismatch for {stage}")
        source_hash = _text(item.get("source_frame_sha256"))
        _require(source_hash and source_hash not in frame_hashes, RECORDING_SCREENSHOT_DUPLICATE, f"screenshot source frame is duplicated for {stage}")
        frame_hashes.add(source_hash)
        stage_item = stage_by_name.get(stage)
        _require(stage_item is not None, RECORDING_SCREENSHOT_SOURCE_MISMATCH, f"screenshot stage is not backed by a checkpoint: {stage}")
        _require(abs(float(item.get("video_timestamp")) - float(stage_item["video_timestamp"])) <= 0.05, RECORDING_SCREENSHOT_SOURCE_MISMATCH, f"screenshot timestamp differs from accepted frame for {stage}")
        _require(source_hash == str(stage_item["frame"]["sha256"]), RECORDING_SCREENSHOT_SOURCE_MISMATCH, f"screenshot source frame hash differs from stage frame for {stage}")
        if stage in stage_frames:
            _require(_image_similarity(stage_frames[stage], path) >= MIN_SIMILARITY, RECORDING_SCREENSHOT_SOURCE_MISMATCH, f"screenshot for {stage} is not derived from the accepted final video frame")

    verification_path = _safe_path(bundle_dir, registrations.get("verification_evidence_path"), field="registrations.verification_evidence_path")
    reviewer_path = _safe_path(bundle_dir, registrations.get("reviewer_index_path"), field="registrations.reviewer_index_path")
    inventory_path = _safe_path(bundle_dir, registrations.get("attachment_inventory_path"), field="registrations.attachment_inventory_path")
    for path, label in ((verification_path, "verification-evidence.json"), (reviewer_path, "reviewer evidence index"), (inventory_path, "attachment inventory")):
        _require(path.is_file() and not path.is_symlink(), RECORDING_SCREENSHOT_UNREGISTERED, f"{label} is missing")
    verification = _read_json(verification_path, label="verification-evidence.json")
    evidence_files = _artifact_paths(verification.get("evidence_files"))
    _require(all(path in evidence_files for path in expected_paths), RECORDING_SCREENSHOT_UNREGISTERED, "verification-evidence.json does not register every screenshot")
    reviewer = _read_json(reviewer_path, label="reviewer-evidence-index.json")
    reviewer_paths = _artifact_paths(reviewer.get("evidence_artifacts")) + _artifact_paths(reviewer.get("artifacts"))
    _require(all(path in reviewer_paths for path in expected_paths), RECORDING_SCREENSHOT_UNREGISTERED, "reviewer evidence index does not register every screenshot")
    inventory = inventory_path.read_text(encoding="utf-8", errors="strict")
    _require(all(path in inventory for path in expected_paths), RECORDING_SCREENSHOT_UNREGISTERED, "attachment inventory does not register every screenshot")


def _validate_replay(bundle_dir: Path, manifest: Mapping[str, Any]) -> None:
    replay = manifest["replay"]
    script_path = _safe_path(bundle_dir, replay.get("script_path"), field="replay.script_path")
    _require(script_path.is_file() and not script_path.is_symlink(), RECORDING_REPLAY_FAILED, "recording helper script is missing")
    _require(sha256_file(script_path) == replay.get("script_sha256"), RECORDING_HASH_MISMATCH, "recording helper hash differs from manifest")
    _require(replay.get("exit_code") == 0, RECORDING_REPLAY_FAILED, "replay exited non-zero; final promotion is forbidden")
    content = script_path.read_text(encoding="utf-8", errors="strict")
    _require("recording_checkpoint" in content and "ZHULONG_RECORDING_STAGE_DIR" in content, RECORDING_REPLAY_FAILED, "recording helper lacks the public checkpoint protocol")


def _archive_member_name(root_name: str, relative: str) -> str:
    return f"{root_name.rstrip('/')}/{relative.lstrip('/')}"


def _validate_archive(bundle_dir: Path, manifest: Mapping[str, Any], archive_path: Path | None, archive_root: str | None) -> None:
    archive = manifest["archive"]
    status = _text(archive.get("status"))
    if archive_path is None:
        _require(status not in {"ready"} and archive.get("submission_ready") is not True, RECORDING_ARCHIVE_MISSING, "manifest claims an archive is ready but no archive was supplied")
        return
    _require(archive_path.is_file() and not archive_path.is_symlink(), RECORDING_ARCHIVE_MISSING, "archive is missing or symlinked")
    if status == "ready":
        _require(archive.get("submission_ready") is True and archive.get("recording_ready") is True, RECORDING_ARCHIVE_INCOMPLETE, "ready archive is missing readiness state")
        _require(archive_path.name == _text(archive.get("archive_name")), RECORDING_ARCHIVE_INCOMPLETE, "archive filename differs from recording manifest")
    try:
        with zipfile.ZipFile(archive_path) as zf:
            _require(zf.testzip() is None, RECORDING_ARCHIVE_CORRUPT, "zip testzip did not pass")
            names = [item.filename for item in zf.infolist()]
            _require(len(names) == len(set(names)), RECORDING_ARCHIVE_INCOMPLETE, "archive contains duplicate entries")
            _require(all(name and not name.startswith("/") and ".." not in Path(name).parts for name in names), RECORDING_ARCHIVE_INCOMPLETE, "archive contains unsafe entry paths")
            root = archive_root or bundle_dir.name
            required = [_text(item) for item in archive.get("required_entries", [])]
            for relative in required:
                member = relative if relative in names else _archive_member_name(root, relative)
                _require(member in names, RECORDING_ARCHIVE_INCOMPLETE, f"archive is missing required entry: {member}")
                bundle_member_path = _safe_path(bundle_dir, relative, field=f"archive.required_entries[{relative}]")
                _require(bundle_member_path.is_file() and not bundle_member_path.is_symlink(), RECORDING_ARCHIVE_INCOMPLETE, f"required archive entry is not a bundle file: {relative}")
                archived_hash = hashlib.sha256(zf.read(member)).hexdigest()
                _require(archived_hash == sha256_file(bundle_member_path), RECORDING_HASH_MISMATCH, f"archive member bytes differ from bundle: {relative}")

            # A final archive is a submission snapshot, so every regular file in
            # the validated bundle must be present byte-for-byte, including
            # findings/source-bound metadata, replay logs, and DOCX reports.
            bundle_files = sorted(
                path for path in bundle_dir.rglob("*") if path.is_file() and not path.is_symlink()
            )
            for bundle_file in bundle_files:
                relative = bundle_file.relative_to(bundle_dir).as_posix()
                member = relative if relative in names else _archive_member_name(root, relative)
                _require(member in names, RECORDING_ARCHIVE_INCOMPLETE, f"archive is missing bundle file: {relative}")
                archived_hash = hashlib.sha256(zf.read(member)).hexdigest()
                _require(archived_hash == sha256_file(bundle_file), RECORDING_HASH_MISMATCH, f"archive member bytes differ from bundle: {relative}")
            manifest_member = _archive_member_name(root, "recording-evidence.json")
            _require(manifest_member in names, RECORDING_ARCHIVE_INCOMPLETE, "archive is missing recording-evidence.json")
            current_manifest_hash = sha256_file(bundle_dir / "recording-evidence.json")
            archived_manifest_hash = hashlib.sha256(zf.read(manifest_member)).hexdigest()
            _require(current_manifest_hash == archived_manifest_hash, RECORDING_ARCHIVE_INCOMPLETE, "archive manifest differs from validated bundle manifest")
    except zipfile.BadZipFile as exc:
        raise _error(RECORDING_ARCHIVE_CORRUPT, f"archive is not a valid ZIP: {exc}") from exc
    if archive.get("archive_sha256"):
        _require(sha256_file(archive_path) == archive.get("archive_sha256"), RECORDING_HASH_MISMATCH, "archive sha256 does not match manifest")
    if archive.get("archive_size"):
        _require(archive_path.stat().st_size == archive.get("archive_size"), RECORDING_HASH_MISMATCH, "archive size does not match manifest")


def validate_recording_bundle(
    bundle_dir: Path,
    *,
    archive_path: Path | None = None,
    archive_root: str | None = None,
    checkpoint_dir: Path | None = None,
) -> dict[str, Any]:
    bundle_dir = bundle_dir.resolve()
    manifest = _load_manifest(bundle_dir)
    _validate_manifest_structure(manifest)
    if manifest.get("recording_status") == "failed":
        raise _error(RECORDING_MANIFEST_INVALID, "failed recording manifests are never promotable")
    try:
        canonical = parse_canonical_identity(bundle_dir)
        compare_identity(canonical, manifest["canonical_identity"])
    except RecordingIdentityError as exc:
        raise _error(exc.code, str(exc)) from exc
    _require(manifest["canonical_identity"]["direct_impact_marker"] == canonical["direct_impact_marker"], RECORDING_IDENTITY_MISMATCH, "direct-impact marker differs from source-bound identity")
    _require(manifest["replay"]["exit_code"] == 0, RECORDING_REPLAY_FAILED, "replay exit code is non-zero")
    temp_root = Path(tempfile.mkdtemp(prefix="zhulong-recording-validate-"))
    try:
        video_path, duration, width, height = _validate_video(bundle_dir, manifest, temp_root)
        stage_frames = _validate_stage_content(bundle_dir, manifest, canonical, video_path, duration, temp_root, checkpoint_dir)
        _validate_screenshots(bundle_dir, manifest, stage_frames)
        _validate_replay(bundle_dir, manifest)
        _validate_archive(bundle_dir, manifest, archive_path, archive_root)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
    validation_mode = "full_recording_time" if checkpoint_dir is not None else "artifact_only"
    return {
        "status": "passed",
        "validation_mode": validation_mode,
        "live_checkpoint_proof_recomputed": checkpoint_dir is not None,
        "recording_time_observations_authority": "non_authoritative_consistency_claims",
        "canonical_identity": canonical,
        "video": {"path": manifest["video"]["path"], "sha256": manifest["video"]["sha256"], "duration_seconds": duration, "width": width, "height": height},
        "stages": list(EXPECTED_STAGES),
        "screenshots": [item["path"] for item in manifest["screenshots"]],
        "archive_supplied": archive_path is not None,
    }


def _write_manifest_status(bundle_dir: Path, status: str, *, archive_ready: bool = False, full_recording_time_validated: bool = False) -> None:
    path = bundle_dir / "recording-evidence.json"
    manifest = _read_json(path, label="recording-evidence.json")
    manifest["recording_status"] = status
    archive = manifest.get("archive")
    if isinstance(archive, dict):
        archive["recording_ready"] = True
        if archive_ready:
            archive["submission_ready"] = True
            archive["status"] = "ready"
    transaction = manifest.get("transaction")
    if isinstance(transaction, dict) and full_recording_time_validated:
        transaction["full_recording_time_validated"] = True
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--archive-root")
    parser.add_argument("--checkpoint-dir", type=Path)
    parser.add_argument("--finalize", action="store_true", help="write recording_status=passed only after full recording-time validation with --checkpoint-dir")
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.finalize and args.checkpoint_dir is None:
            raise _error(RECORDING_VIDEO_CONTENT_UNVERIFIED, "--finalize requires --checkpoint-dir for full recording-time validation")
        result = validate_recording_bundle(
            args.bundle_dir,
            archive_path=args.archive,
            archive_root=args.archive_root,
            checkpoint_dir=args.checkpoint_dir,
        )
        if args.finalize:
            _write_manifest_status(
                args.bundle_dir.resolve(),
                "passed",
                archive_ready=args.archive is not None,
                full_recording_time_validated=True,
            )
            result["recording_status"] = "passed"
            result["full_recording_time_validated"] = True
        if args.as_json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print("VALIDATION PASSED: recording evidence")
            print("Canonical identity: " + json.dumps(result["canonical_identity"], ensure_ascii=False, sort_keys=True))
            print("Screenshots: " + ", ".join(result["screenshots"]))
        return 0
    except (RecordingEvidenceError, RecordingIdentityError) as exc:
        if args.as_json:
            print(json.dumps({"status": "failed", "error_code": getattr(exc, "code", RECORDING_MANIFEST_INVALID), "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        else:
            print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        message = f"{RECORDING_MANIFEST_INVALID}: local filesystem error: {exc}"
        print(message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
