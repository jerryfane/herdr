#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ASSET_TARGETS = (
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-aarch64",
    "windows-x86_64",
)
EXPECTED_ASSET_NAMES = {
    **{target: f"herdr-{target}" for target in ASSET_TARGETS},
    "windows-x86_64": "herdr-windows-x86_64.zip",
}

MANIFEST_SCHEMA_VERSION = 2
SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
FULL_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
BUILD_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]+")

# minisign signature line: 2-byte algorithm, 8-byte key id, 64-byte Ed25519 signature.
# "ED" is the prehashed (BLAKE2b-512) algorithm; legacy "Ed" signs raw bytes and is refused.
MINISIGN_PREHASHED_ALGORITHM = b"ED"
MINISIGN_SIGNATURE_LENGTH = 74
MINISIGN_GLOBAL_SIGNATURE_LENGTH = 64

ENDPOINT_PROTOCOL_SOURCE_PATH = Path("src/protocol/endpoint.rs")


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def normalize_version(version: str) -> str:
    return version.strip().removeprefix("v")


def read_endpoint_protocol_generation(
    source_path: Path = ENDPOINT_PROTOCOL_SOURCE_PATH,
) -> int:
    content = source_path.read_text(encoding="utf-8")
    match = re.search(r"pub const ENDPOINT_PROTOCOL_GENERATION: u32 = (\d+);", content)
    if not match:
        raise ValueError(
            f"could not read ENDPOINT_PROTOCOL_GENERATION from {source_path}"
        )
    return int(match.group(1))


def latest_stable_tag(ref: str | None = None) -> str:
    args = ["describe", "--tags", "--match", "v[0-9]*", "--abbrev=0"]
    if ref:
        args.append(ref)
    return run_git(args)


def git_is_ancestor(ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def previous_preview_commit(path: Path) -> str | None:
    data = read_json(path)
    if not data:
        return None
    commit = data.get("commit")
    return commit if isinstance(commit, str) and commit.strip() else None


def preview_range_base(previous: str, commit: str) -> str:
    try:
        stable = latest_stable_tag(commit)
    except subprocess.CalledProcessError:
        return previous
    if not git_is_ancestor(previous, commit):
        return stable
    if git_is_ancestor(previous, stable) and git_is_ancestor(stable, commit):
        return stable
    return previous


def build_notes(previous: str, commit: str, build_id: str, repo: str) -> str:
    compare = f"https://github.com/{repo}/compare/{previous}...{commit}"
    return f"Preview build {build_id}\n\n[View changes]({compare})\n"


def default_asset_urls(repo: str, tag: str) -> dict[str, str]:
    return {
        target: f"https://github.com/{repo}/releases/download/{tag}/{EXPECTED_ASSET_NAMES[target]}"
        for target in ASSET_TARGETS
    }


def commit_time_of(commit: str) -> int:
    return int(run_git(["show", "-s", "--format=%ct", commit]))


def read_target_map(path: Path, label: str) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{label} file must be a JSON object")
    return {str(key): value for key, value in data.items()}


def asset_objects(
    urls: dict[str, str],
    shas: dict[str, Any],
    sizes: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    assets: dict[str, dict[str, Any]] = {}
    for target in ASSET_TARGETS:
        sha = shas.get(target)
        if not isinstance(sha, str) or not SHA256_PATTERN.fullmatch(sha):
            raise ValueError(f"{target} requires a SHA-256 digest")
        size = sizes.get(target)
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError(f"{target} requires a positive byte size")
        entry: dict[str, Any] = {"url": urls[target], "sha256": sha.lower(), "size": size}
        if target.startswith("windows-"):
            entry["format"] = "zip"
        assets[target] = entry
    return assets


def build_manifest(
    output: Path,
    repo: str,
    tag: str,
    build_id: str,
    commit: str,
    commit_time: int,
    built_at: str,
    base_version: str,
    protocol: int,
    notes: str,
    shas: dict[str, Any],
    sizes: dict[str, Any],
    retain: int,
    endpoint_generation: int | None = None,
) -> str:
    if isinstance(commit_time, bool) or not isinstance(commit_time, int) or commit_time <= 0:
        raise ValueError("commit_time must be positive unix seconds")
    urls = default_asset_urls(repo, tag)
    assets = asset_objects(urls, shas, sizes)
    current = read_json(output) or {}
    # Builds archived by schema v1 lack commit_time and size; they are kept verbatim
    # because update verification only reads the top-level build.
    builds = current.get("builds") if isinstance(current.get("builds"), dict) else {}
    builds = dict(builds)
    if endpoint_generation is None:
        endpoint_generation = read_endpoint_protocol_generation()
    builds[build_id] = {
        "base_version": normalize_version(base_version),
        "commit": commit,
        "commit_time": commit_time,
        "built_at": built_at,
        "protocol": protocol,
        "endpoint_generation": endpoint_generation,
        "tag": tag,
        "assets": assets,
    }
    ordered_builds = {
        key: builds[key]
        for key in sorted(
            builds,
            key=lambda key: str(builds[key].get("built_at", "")),
            reverse=True,
        )[:retain]
    }
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "channel": "preview",
        "base_version": normalize_version(base_version),
        "build_id": build_id,
        "commit": commit,
        "commit_time": commit_time,
        "built_at": built_at,
        "protocol": protocol,
        "endpoint_generation": endpoint_generation,
        "notes": notes.strip(),
        "assets": assets,
        "builds": ordered_builds,
    }
    return json.dumps(manifest, indent=2) + "\n"


class SigningError(Exception):
    pass


def signature_path_for(manifest: Path) -> Path:
    return manifest.with_name(manifest.name + ".minisig")


def trusted_comment_for(manifest_bytes: bytes) -> str:
    try:
        data = json.loads(manifest_bytes)
    except ValueError as error:
        raise SigningError(f"manifest is not valid JSON: {error}") from error
    if not isinstance(data, dict) or data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise SigningError(f"manifest must be schema_version {MANIFEST_SCHEMA_VERSION}")
    build_id = data.get("build_id")
    commit = data.get("commit")
    if not isinstance(build_id, str) or not BUILD_ID_PATTERN.fullmatch(build_id):
        raise SigningError("manifest has no valid build_id")
    if not isinstance(commit, str) or not FULL_COMMIT_PATTERN.fullmatch(commit):
        raise SigningError("manifest commit must be a full 40-hex commit")
    return f"herdr-preview {build_id} {commit}"


def request_signature(url: str, digest_hex: str, trusted_comment: str, timeout: float) -> str:
    body = json.dumps({"blake2b512_hex": digest_hex, "trusted_comment": trusted_comment}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise SigningError(f"keyring relay answered HTTP {error.code} {error.reason}") from error
    except (urllib.error.URLError, OSError) as error:
        raise SigningError(f"keyring relay request failed: {error}") from error
    except ValueError as error:
        raise SigningError("keyring relay returned invalid JSON") from error
    minisig = payload.get("minisig") if isinstance(payload, dict) else None
    if not isinstance(minisig, str):
        raise SigningError("keyring relay response has no minisig text")
    return minisig


def decode_signature_line(line: str, name: str, length: int) -> bytes:
    try:
        decoded = base64.b64decode(line, validate=True)
    except ValueError as error:
        raise SigningError(f"minisig {name} line is not base64") from error
    if len(decoded) != length:
        raise SigningError(f"minisig {name} is {len(decoded)} bytes, expected {length}")
    return decoded


def validate_minisig(text: str, trusted_comment: str) -> None:
    if not text.isascii():
        raise SigningError("minisig is not ASCII")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) != 4:
        raise SigningError(f"minisig has {len(lines)} lines, expected 4")
    untrusted_line, signature_line, trusted_line, global_line = lines
    if not untrusted_line.startswith("untrusted comment: "):
        raise SigningError("minisig does not start with an untrusted comment")
    signature = decode_signature_line(signature_line, "signature", MINISIGN_SIGNATURE_LENGTH)
    if signature[:2] != MINISIGN_PREHASHED_ALGORITHM:
        raise SigningError(
            f"minisig algorithm is {signature[:2]!r}, expected prehashed {MINISIGN_PREHASHED_ALGORITHM!r}"
        )
    if trusted_line != f"trusted comment: {trusted_comment}":
        raise SigningError(f"minisig trusted comment must be exactly {trusted_comment!r}")
    decode_signature_line(global_line, "global signature", MINISIGN_GLOBAL_SIGNATURE_LENGTH)


def write_atomically(path: Path, data: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
        raise


def sign_manifest(manifest: Path, keyring_url: str, timeout: float) -> Path:
    manifest_bytes = manifest.read_bytes()
    trusted_comment = trusted_comment_for(manifest_bytes)
    digest_hex = hashlib.blake2b(manifest_bytes, digest_size=64).hexdigest()
    minisig = request_signature(keyring_url, digest_hex, trusted_comment, timeout)
    validate_minisig(minisig, trusted_comment)
    if manifest.read_bytes() != manifest_bytes:
        raise SigningError("manifest changed while it was being signed")
    signature_path = signature_path_for(manifest)
    write_atomically(signature_path, minisig.encode("ascii"))
    return signature_path


def cmd_notes(args: argparse.Namespace) -> int:
    previous = args.previous or previous_preview_commit(Path(args.manifest)) or latest_stable_tag()
    notes = build_notes(previous, args.commit, args.build_id, args.repo)
    Path(args.output).write_text(notes, encoding="utf-8")
    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    notes = Path(args.notes).read_text(encoding="utf-8")
    commit_time = args.commit_time if args.commit_time is not None else commit_time_of(args.commit)
    content = build_manifest(
        output=Path(args.output),
        repo=args.repo,
        tag=args.tag,
        build_id=args.build_id,
        commit=args.commit,
        commit_time=commit_time,
        built_at=args.built_at,
        base_version=args.base_version,
        protocol=args.protocol,
        notes=notes,
        shas=read_target_map(Path(args.sha_file), "sha"),
        sizes=read_target_map(Path(args.size_file), "size"),
        retain=args.retain,
        endpoint_generation=args.endpoint_generation,
    )
    Path(args.output).write_text(content, encoding="utf-8")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    try:
        signature_path = sign_manifest(Path(args.manifest), args.keyring_url, args.timeout)
    except (SigningError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(signature_path)
    return 0


def cmd_current_commit(args: argparse.Namespace) -> int:
    commit = previous_preview_commit(Path(args.manifest))
    if commit:
        print(commit)
    return 0


def cmd_range_base(args: argparse.Namespace) -> int:
    print(preview_range_base(args.previous, args.commit))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview channel release helpers")
    sub = parser.add_subparsers(required=True)

    notes = sub.add_parser("notes")
    notes.add_argument("--manifest", default="distribution/preview.json")
    notes.add_argument("--previous")
    notes.add_argument("--commit", required=True)
    notes.add_argument("--build-id", required=True)
    notes.add_argument("--repo", default="herdrdev/herdr")
    notes.add_argument("--output", required=True)
    notes.set_defaults(func=cmd_notes)

    manifest = sub.add_parser("manifest")
    manifest.add_argument("--output", default="distribution/preview.json")
    manifest.add_argument("--repo", default="herdrdev/herdr")
    manifest.add_argument("--tag", required=True)
    manifest.add_argument("--build-id", required=True)
    manifest.add_argument("--commit", required=True)
    manifest.add_argument(
        "--commit-time",
        type=int,
        help="committer time of --commit in unix seconds (default: git show -s --format=%%ct)",
    )
    manifest.add_argument("--built-at", required=True)
    manifest.add_argument("--base-version", required=True)
    manifest.add_argument("--protocol", required=True, type=int)
    manifest.add_argument("--endpoint-generation", required=True, type=int)
    manifest.add_argument("--notes", required=True)
    manifest.add_argument("--sha-file", required=True, help="JSON object: target -> sha256 hex")
    manifest.add_argument("--size-file", required=True, help="JSON object: target -> asset byte size")
    manifest.add_argument("--retain", type=int, default=30)
    manifest.set_defaults(func=cmd_manifest)

    current = sub.add_parser("current-commit")
    current.add_argument("--manifest", default="distribution/preview.json")
    current.set_defaults(func=cmd_current_commit)

    range_base = sub.add_parser("range-base")
    range_base.add_argument("--previous", required=True)
    range_base.add_argument("--commit", required=True)
    range_base.set_defaults(func=cmd_range_base)

    sign = sub.add_parser(
        "sign",
        help="sign a preview manifest through the keyring relay and write <manifest>.minisig",
    )
    sign.add_argument("--manifest", default="distribution/preview.json")
    sign.add_argument(
        "--keyring-url",
        required=True,
        help="full relay route, e.g. http://127.0.0.1:7700/<role>/_keyring/minisign/herdr-release",
    )
    sign.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for the relay")
    sign.set_defaults(func=cmd_sign)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
