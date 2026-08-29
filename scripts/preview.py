#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
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
HIDDEN_SUBJECTS = (
    "docs: publish preview",
    "docs: update website manifest",
    "docs: update preview manifest",
    "chore: approve contributor",
    "chore: approve merged contributor",
)
TYPE_HEADINGS = {
    "feat": "Added",
    "fix": "Fixed",
    "perf": "Performance",
    "docs": "Maintenance",
    "ci": "Maintenance",
    "test": "Maintenance",
    "refactor": "Maintenance",
    "chore": "Maintenance",
}
TYPE_ORDER = ("Added", "Fixed", "Performance", "Maintenance", "Other")
COMMIT_RE = re.compile(r"^(?P<kind>[a-z]+)(?:\([^)]+\))?!?:\s+(?P<body>.+)$")
PUBLICATION_BRANCH_PREFIX = "automation/preview-"


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def normalize_version(version: str) -> str:
    return version.strip().removeprefix("v")


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


def hidden_subject(subject: str) -> bool:
    lowered = subject.strip().lower()
    return any(lowered.startswith(prefix) for prefix in HIDDEN_SUBJECTS)


def latest_publishable_commit(ref: str) -> str:
    output = run_git(["log", "--pretty=format:%H%x00%s", ref])
    for line in output.splitlines():
        commit, _, subject = line.partition("\x00")
        if commit and not hidden_subject(subject):
            return commit
    raise SystemExit(f"no publishable commit found in {ref}")


def commit_subjects(previous: str, commit: str) -> list[str]:
    output = run_git(["log", "--pretty=format:%s", f"{previous}..{commit}"])
    if not output:
        return []
    subjects = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if hidden_subject(stripped):
            continue
        subjects.append(stripped)
    return subjects


def preview_range_base(previous: str, commit: str) -> str:
    try:
        stable = latest_stable_tag(commit)
    except subprocess.CalledProcessError:
        return previous
    if git_is_ancestor(previous, stable) and git_is_ancestor(stable, commit):
        return stable
    return previous


def publication_branch(commit: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("preview publication commit must be a lowercase 40-character SHA")
    return f"{PUBLICATION_BRANCH_PREFIX}{commit[:12]}"


def validate_publication_paths(paths: list[str]) -> None:
    normalized = {path.strip() for path in paths if path.strip()}
    if "website/preview.json" not in normalized:
        raise ValueError("preview publication must update website/preview.json")
    invalid = sorted(
        path
        for path in normalized
        if path != "website/preview.json" and not path.startswith("docs/preview/")
    )
    if invalid:
        raise ValueError(
            "preview publication contains unexpected path(s): " + ", ".join(invalid)
        )


def validate_publication_files(pages: object) -> None:
    if not isinstance(pages, list):
        raise ValueError("preview publication file response must be a list of pages")
    paths = []
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("preview publication file page must be a list")
        for file in page:
            if not isinstance(file, dict):
                raise ValueError("preview publication file entry must be an object")
            filename = file.get("filename")
            if not isinstance(filename, str) or not filename:
                raise ValueError("preview publication file entry must have a filename")
            paths.append(filename)
            previous_filename = file.get("previous_filename")
            if previous_filename is not None:
                if not isinstance(previous_filename, str) or not previous_filename:
                    raise ValueError(
                        "preview publication previous filename must be a non-empty string"
                    )
                paths.append(previous_filename)
    validate_publication_paths(paths)


def humanize_subject(subject: str) -> tuple[str, str]:
    match = COMMIT_RE.match(subject)
    if not match:
        return "Other", subject[0].upper() + subject[1:]
    kind = match.group("kind")
    body = match.group("body").strip()
    heading = TYPE_HEADINGS.get(kind, "Other")
    if body:
        body = body[0].upper() + body[1:]
    else:
        body = subject
    return heading, body


def build_notes(previous: str, commit: str, build_id: str, base_version: str, repo: str) -> str:
    short = commit[:12]
    compare = f"https://github.com/{repo}/compare/{previous}...{commit}"
    lines = [
        f"Preview build {build_id}",
        "",
        f"Built from `{short}` on `master`.",
        f"Base stable: v{normalize_version(base_version)}",
        f"Compare: {compare}",
        "",
    ]
    grouped: dict[str, list[str]] = {heading: [] for heading in TYPE_ORDER}
    for subject in commit_subjects(previous, commit):
        heading, body = humanize_subject(subject)
        grouped.setdefault(heading, []).append(body)

    wrote = False
    for heading in TYPE_ORDER:
        items = grouped.get(heading, [])
        if not items:
            continue
        wrote = True
        lines.append(f"### {heading}")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")

    if not wrote:
        lines.extend(["### Changed", "- Rebuilt preview from the current master branch.", ""])

    return "\n".join(lines).rstrip() + "\n"


def default_asset_urls(repo: str, tag: str) -> dict[str, str]:
    return {
        target: f"https://github.com/{repo}/releases/download/{tag}/{EXPECTED_ASSET_NAMES[target]}"
        for target in ASSET_TARGETS
    }


def read_sha_file(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("sha file must be a JSON object")
    return {str(key): str(value) for key, value in data.items()}


def asset_objects(urls: dict[str, str], shas: dict[str, str]) -> dict[str, dict[str, str]]:
    assets: dict[str, dict[str, str]] = {}
    for target in ASSET_TARGETS:
        url = urls[target]
        entry = {"url": url}
        sha = shas.get(target)
        if sha:
            entry["sha256"] = sha
        if target.startswith("windows-"):
            if not sha or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
                raise ValueError(f"{target} requires a SHA-256 digest")
            entry["format"] = "zip"
        assets[target] = entry
    return assets


def rebind_asset_urls(assets: object, repo: str, tag: str) -> dict[str, dict[str, str]]:
    if not isinstance(assets, dict):
        raise ValueError("preview build assets must be an object")
    expected_urls = default_asset_urls(repo, tag)
    rebound: dict[str, dict[str, str]] = {}
    for target, entry in assets.items():
        if target not in expected_urls:
            raise ValueError(f"preview build contains unexpected asset target: {target}")
        if not isinstance(entry, dict):
            raise ValueError(f"preview asset {target} must be an object")
        rebound[target] = {**entry, "url": expected_urls[target]}
    return rebound


def rebind_retained_builds(builds: dict[str, Any], repo: str) -> dict[str, Any]:
    rebound = {}
    for build_id, build in builds.items():
        if not isinstance(build, dict):
            raise ValueError(f"preview build {build_id} must be an object")
        tag = build.get("tag")
        if not isinstance(tag, str) or not tag:
            raise ValueError(f"preview build {build_id} tag is missing")
        rebound[build_id] = {
            **build,
            "assets": rebind_asset_urls(build.get("assets"), repo, tag),
        }
    return rebound


def validate_manifest_repository(manifest: object, repo: str) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("preview manifest must be an object")
    build_id = manifest.get("build_id")
    builds = manifest.get("builds")
    if not isinstance(build_id, str) or not isinstance(builds, dict):
        raise ValueError("preview manifest must contain build_id and builds")
    current_build = builds.get(build_id)
    if not isinstance(current_build, dict):
        raise ValueError("preview manifest current build is missing")
    current_tag = current_build.get("tag")
    if not isinstance(current_tag, str) or not current_tag:
        raise ValueError("preview manifest current build tag is missing")

    def validate_assets(assets: object, tag: str, context: str) -> None:
        if not isinstance(assets, dict):
            raise ValueError(f"{context} assets must be an object")
        expected_urls = default_asset_urls(repo, tag)
        for target, entry in assets.items():
            if target not in expected_urls:
                raise ValueError(f"{context} contains unexpected asset target: {target}")
            if not isinstance(entry, dict) or entry.get("url") != expected_urls[target]:
                raise ValueError(
                    f"{context} asset {target} does not resolve to repository {repo}"
                )

    validate_assets(manifest.get("assets"), current_tag, "preview manifest")
    for archived_id, archived_build in builds.items():
        if not isinstance(archived_build, dict):
            raise ValueError(f"preview build {archived_id} must be an object")
        archived_tag = archived_build.get("tag")
        if not isinstance(archived_tag, str) or not archived_tag:
            raise ValueError(f"preview build {archived_id} tag is missing")
        validate_assets(
            archived_build.get("assets"),
            archived_tag,
            f"preview build {archived_id}",
        )


def build_manifest(
    output: Path,
    repo: str,
    tag: str,
    build_id: str,
    commit: str,
    built_at: str,
    base_version: str,
    protocol: int,
    notes: str,
    shas: dict[str, str],
    retain: int,
) -> str:
    urls = default_asset_urls(repo, tag)
    assets = asset_objects(urls, shas)
    current = read_json(output)
    if current is None:
        builds = {}
    elif not isinstance(current, dict):
        raise ValueError("existing preview manifest must be an object")
    else:
        builds = current.get("builds")
        if not isinstance(builds, dict):
            raise ValueError("existing preview manifest builds must be an object")
    builds = rebind_retained_builds(dict(builds), repo)
    builds[build_id] = {
        "base_version": normalize_version(base_version),
        "commit": commit,
        "built_at": built_at,
        "protocol": protocol,
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
        "schema_version": 1,
        "channel": "preview",
        "base_version": normalize_version(base_version),
        "build_id": build_id,
        "commit": commit,
        "built_at": built_at,
        "protocol": protocol,
        "notes": notes.strip(),
        "assets": assets,
        "builds": ordered_builds,
    }
    return json.dumps(manifest, indent=2) + "\n"


def cmd_notes(args: argparse.Namespace) -> int:
    previous = args.previous or previous_preview_commit(Path(args.manifest)) or latest_stable_tag()
    notes = build_notes(previous, args.commit, args.build_id, args.base_version, args.repo)
    Path(args.output).write_text(notes, encoding="utf-8")
    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    notes = Path(args.notes).read_text(encoding="utf-8")
    shas = read_sha_file(Path(args.sha_file) if args.sha_file else None)
    content = build_manifest(
        output=Path(args.output),
        repo=args.repo,
        tag=args.tag,
        build_id=args.build_id,
        commit=args.commit,
        built_at=args.built_at,
        base_version=args.base_version,
        protocol=args.protocol,
        notes=notes,
        shas=shas,
        retain=args.retain,
    )
    Path(args.output).write_text(content, encoding="utf-8")
    return 0


def cmd_current_commit(args: argparse.Namespace) -> int:
    commit = previous_preview_commit(Path(args.manifest))
    if commit:
        print(commit)
    return 0


def cmd_select_commit(args: argparse.Namespace) -> int:
    print(latest_publishable_commit(args.ref))
    return 0


def cmd_range_base(args: argparse.Namespace) -> int:
    print(preview_range_base(args.previous, args.commit))
    return 0


def cmd_publication_branch(args: argparse.Namespace) -> int:
    print(publication_branch(args.commit))
    return 0


def cmd_validate_publication_paths(_args: argparse.Namespace) -> int:
    try:
        validate_publication_paths(sys.stdin.readlines())
    except ValueError as error:
        raise SystemExit(str(error)) from error
    return 0


def cmd_validate_publication_files(_args: argparse.Namespace) -> int:
    try:
        validate_publication_files(json.load(sys.stdin))
    except ValueError as error:
        raise SystemExit(str(error)) from error
    return 0


def cmd_validate_manifest_repository(args: argparse.Namespace) -> int:
    try:
        validate_manifest_repository(read_json(Path(args.manifest)), args.repo)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Preview channel release helpers")
    sub = parser.add_subparsers(required=True)

    notes = sub.add_parser("notes")
    notes.add_argument("--manifest", default="website/preview.json")
    notes.add_argument("--previous")
    notes.add_argument("--commit", required=True)
    notes.add_argument("--build-id", required=True)
    notes.add_argument("--base-version", required=True)
    notes.add_argument("--repo", required=True)
    notes.add_argument("--output", required=True)
    notes.set_defaults(func=cmd_notes)

    manifest = sub.add_parser("manifest")
    manifest.add_argument("--output", default="website/preview.json")
    manifest.add_argument("--repo", required=True)
    manifest.add_argument("--tag", required=True)
    manifest.add_argument("--build-id", required=True)
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--built-at", required=True)
    manifest.add_argument("--base-version", required=True)
    manifest.add_argument("--protocol", required=True, type=int)
    manifest.add_argument("--notes", required=True)
    manifest.add_argument("--sha-file")
    manifest.add_argument("--retain", type=int, default=30)
    manifest.set_defaults(func=cmd_manifest)

    current = sub.add_parser("current-commit")
    current.add_argument("--manifest", default="website/preview.json")
    current.set_defaults(func=cmd_current_commit)

    select = sub.add_parser("select-commit")
    select.add_argument("--ref", default="origin/master")
    select.set_defaults(func=cmd_select_commit)

    range_base = sub.add_parser("range-base")
    range_base.add_argument("--previous", required=True)
    range_base.add_argument("--commit", required=True)
    range_base.set_defaults(func=cmd_range_base)

    publication = sub.add_parser("publication-branch")
    publication.add_argument("--commit", required=True)
    publication.set_defaults(func=cmd_publication_branch)

    publication_paths = sub.add_parser("validate-publication-paths")
    publication_paths.set_defaults(func=cmd_validate_publication_paths)

    publication_files = sub.add_parser("validate-publication-files")
    publication_files.set_defaults(func=cmd_validate_publication_files)

    manifest_repository = sub.add_parser("validate-manifest-repository")
    manifest_repository.add_argument("--manifest", default="website/preview.json")
    manifest_repository.add_argument("--repo", required=True)
    manifest_repository.set_defaults(func=cmd_validate_manifest_repository)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
