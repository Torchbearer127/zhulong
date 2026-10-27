#!/usr/bin/env python3
"""Check one build-only npm overlay form, never attest successful execution."""
from __future__ import annotations

import hashlib
import base64
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
from urllib.parse import urlsplit


FIELDS = {"kind", "purpose", "tested_ref", "source_archive", "original_manifest",
          "original_lock", "compatibility_manifest", "compatibility_lock", "dockerfile", "compose_file",
          "service", "build_image", "runtime_image", "registry", "output_dir"}
FILES = ("source_archive", "compatibility_manifest", "compatibility_lock", "dockerfile", "compose_file")


def invalid(message: str) -> ValueError:
    return ValueError("DEPENDENCY_RESOLUTION_INVALID: " + message)


def relative_path(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", value):
        raise invalid("expected a portable literal relative path")
    if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise invalid("path must stay inside its declared root")
    return value


def descriptor(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise invalid("file descriptors require path and sha256")
    relative_path(value["path"])
    if not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise invalid("invalid SHA-256")
    return value


def checked_file(root: Path, spec: dict) -> Path:
    descriptor(spec)
    current = root
    try:
        for part in PurePosixPath(spec["path"]).parts:
            current = current / part
            if current.is_symlink():
                raise invalid("symlink in resolution input")
        info = current.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise invalid("resolution input must be a regular unlinked file")
        if hashlib.sha256(current.read_bytes()).hexdigest() != spec["sha256"]:
            raise invalid("resolution input hash mismatch")
    except OSError as exc:
        raise invalid("resolution input is missing or unreadable") from exc
    return current


def check_declaration(spec: object, tested_ref: str) -> None:
    if not isinstance(spec, dict) or set(spec) != FIELDS:
        raise invalid("unsupported declaration fields")
    if spec["kind"] != "npm-static-build-v1" or spec["purpose"] != "build_only":
        raise invalid("only the build-only npm static-output form is supported")
    if spec["tested_ref"] != tested_ref or not re.fullmatch(r"[0-9a-f]{40}", str(tested_ref)):
        raise invalid("tested source revision mismatch")
    for key in FILES + ("original_manifest", "original_lock"):
        descriptor(spec[key])
    if spec["original_manifest"]["path"] != "package.json" or spec["original_lock"]["path"] != "package-lock.json":
        raise invalid("source archive must contain the original root npm manifest and lock")
    paths = [spec[key]["path"] for key in FILES]
    if len(set(paths)) != len(paths):
        raise invalid("resolution input paths must be distinct")
    for key in ("build_image", "runtime_image"):
        if not isinstance(spec[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}", spec[key]):
            raise invalid("build and runtime images require immutable digests")
    registry = spec["registry"]
    if not isinstance(registry, str) or not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9._/-]*)?", registry):
        raise invalid("registry must be an explicit credential-free HTTPS URL without query or fragment")
    if not urlsplit(registry).hostname or any(part in {".", ".."} for part in urlsplit(registry).path.split("/") if part):
        raise invalid("invalid registry URL")
    if spec["output_dir"] not in {"dist", "build"} or not isinstance(spec["service"], str) or not re.fullmatch(r"[A-Za-z0-9_-]+", spec["service"]):
        raise invalid("unsupported static output directory or service")


def expected_dockerfile(spec: dict) -> str:
    # A complete template, not a Dockerfile interpreter. The runtime stage never
    # copies node_modules or the compatibility manifest from the build stage.
    return (
        f'FROM {spec["build_image"]} AS build\n'
        'WORKDIR /build\n'
        f'COPY ["{spec["source_archive"]["path"]}", "/tmp/source.tar"]\n'
        'RUN tar -xf /tmp/source.tar -C /build\n'
        f'COPY ["{spec["compatibility_manifest"]["path"]}", "/build/package.json"]\n'
        f'COPY ["{spec["compatibility_lock"]["path"]}", "/build/package-lock.json"]\n'
        'RUN printf \'\' > /tmp/zhulong-npm-globalrc && '
        f'npm ci --include=dev --ignore-scripts --userconfig=/dev/null --globalconfig=/tmp/zhulong-npm-globalrc --registry={spec["registry"]}\n'
        'RUN npm run build\n'
        f'FROM {spec["runtime_image"]}\n'
        f'COPY --from=build /build/{spec["output_dir"]}/ /usr/share/nginx/html/\n'
    )


def check_compose(spec: dict, data: object) -> None:
    services = data.get("services", {}) if isinstance(data, dict) else {}
    service = services.get(spec["service"], {}) if isinstance(services, dict) else {}
    if not isinstance(service, dict) or service.get("build") != {"context": ".", "dockerfile": spec["dockerfile"]["path"]}:
        raise invalid("Compose must build the declared Dockerfile from the bundle root without args or target")
    if "image" in service or "pull_policy" in service or "profiles" in service:
        raise invalid("declared service must use its build, without an alternative image, pull policy or profile")


def validate_resolution_inputs(root: Path, spec: dict, tested_ref: str) -> None:
    check_declaration(spec, tested_ref)
    files = {key: checked_file(root, spec[key]) for key in FILES}
    if spec["compose_file"]["path"] != PurePosixPath(spec["compose_file"]["path"]).name:
        raise invalid("Compose file must be at the bundle root")
    if any((root / name).exists() or (root / name).is_symlink()
           for name in (".dockerignore", spec["dockerfile"]["path"] + ".dockerignore")):
        raise invalid("ignore files are outside the supported build form")
    if files["dockerfile"].read_bytes() != expected_dockerfile(spec).encode("utf-8"):
        raise invalid("Dockerfile does not consume the compatibility manifest in the supported build-only form")
    try:
        import yaml
        check_compose(spec, yaml.safe_load(files["compose_file"].read_text(encoding="utf-8")))
        originals = {}
        with tarfile.open(files["source_archive"], mode="r:") as archive:
            seen = set()
            for member in archive:
                name = relative_path(member.name.rstrip("/") if member.isdir() else member.name)
                if name in seen or not (member.isfile() or member.isdir()):
                    raise invalid("source archive has duplicate or nonregular members")
                seen.add(name)
                if PurePosixPath(name).name in {".npmrc", "npm-shrinkwrap.json", "node_modules"}:
                    raise invalid("source archive contains unsupported npm configuration or installed dependencies")
                if name in {"package.json", "package-lock.json"}:
                    if not member.isfile():
                        raise invalid("original npm inputs must be regular archive members")
                    originals[name] = archive.extractfile(member).read()
        for key in ("original_manifest", "original_lock"):
            item = spec[key]
            if hashlib.sha256(originals.get(item["path"], b"")).hexdigest() != item["sha256"]:
                raise invalid("original source manifest or lock mismatch")
        original = json.loads(originals["package.json"])
        compatibility = json.loads(files["compatibility_manifest"].read_bytes())
        lock = json.loads(files["compatibility_lock"].read_bytes())
    except (OSError, UnicodeError, KeyError, ImportError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise invalid("cannot read source archive, npm manifests or Compose (PyYAML required)") from exc
    except yaml.YAMLError as exc:
        raise invalid("invalid Compose YAML") from exc
    if not isinstance(original, dict) or not isinstance(compatibility, dict):
        raise invalid("npm manifests must be objects")
    overrides = compatibility.get("overrides")
    if not isinstance(overrides, dict) or not overrides or any(
        not isinstance(name, str) or not re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", name)
        or not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version)
        for name, version in overrides.items()
    ):
        raise invalid("compatibility overrides must be explicit package names and exact versions")
    if {key: value for key, value in original.items() if key != "overrides"} != {
        key: value for key, value in compatibility.items() if key != "overrides"
    }:
        raise invalid("compatibility manifest may change only overrides, not application dependencies or scripts")
    if not isinstance(lock, dict) or lock.get("lockfileVersion") != 3 or not isinstance(lock.get("packages"), dict):
        raise invalid("compatibility lock must contain a v3 packages graph")
    packages = lock["packages"]
    root_package = packages.get("")
    if not isinstance(root_package, dict):
        raise invalid("compatibility lock is missing its root package")
    for key in ("name", "version", "dependencies", "devDependencies", "optionalDependencies"):
        if root_package.get(key) != compatibility.get(key):
            raise invalid("compatibility lock root differs from the preserved application manifest")
    matched = set()
    for path, package in packages.items():
        if path == "":
            continue
        if not isinstance(path, str) or not re.fullmatch(r"(?:node_modules/(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+/)*node_modules/(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", path):
            raise invalid("compatibility lock contains unsupported local or workspace packages")
        if not isinstance(package, dict) or package.get("link") or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", str(package.get("version", ""))):
            raise invalid("compatibility lock requires exact package versions")
        resolved = package.get("resolved")
        if not isinstance(resolved, str) or not resolved.startswith(spec["registry"].rstrip("/") + "/"):
            raise invalid("locked packages must resolve through the declared registry")
        url = urlsplit(resolved)
        if url.username or url.password or url.query or url.fragment or re.search(r"[\s\\]", resolved):
            raise invalid("locked package URL contains unsupported or sensitive inputs")
        integrity = package.get("integrity", "")
        try:
            algorithm, encoded = integrity.split("-", 1)
            size = {"sha512": 64, "sha256": 32}.get(algorithm)
            if size is None or len(base64.b64decode(encoded, validate=True)) != size:
                raise ValueError
        except (AttributeError, TypeError, ValueError) as exc:
            raise invalid("locked packages require valid SHA-512 or SHA-256 integrity") from exc
        name = path.rsplit("node_modules/", 1)[-1]
        if name in overrides:
            if package["version"] != overrides[name]:
                raise invalid("compatibility lock does not apply the declared exact override")
            matched.add(name)
    if matched != set(overrides):
        raise invalid("compatibility overrides are unused by the locked graph")


def check_source_archive(repo: Path, spec: dict) -> None:
    # git archive is read-only; byte equality binds all delivered source, not
    # only the two package-manager files. Never extract or rewrite that source.
    proc = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", spec["tested_ref"]], capture_output=True)
    if proc.returncode or hashlib.sha256(proc.stdout).hexdigest() != spec["source_archive"]["sha256"]:
        raise invalid("source archive must be the unmodified git archive of tested_ref")
