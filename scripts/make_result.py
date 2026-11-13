#!/usr/bin/env python3
"""Write result.json for a signed request, from each build's files.

The checksums are computed again here from the DMG files themselves, and must match what
each build recorded, so a file swapped between the signing job and this one is caught.

Usage:  python3 scripts/make_result.py <dir with leg-*.json and the DMGs> <source_sha> <request_id> <run_url> <dmg name>...
One DMG name per build the policy lists. Keys follow section 17.11 of the contract:
request_id, source_sha, team_id, sha256{<dmg name>: ...}, notarization, hallmark_run_url.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy import DISABLE_SENTENCE  # noqa: E402

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUEST_RE = re.compile(r"^[0-9]{1,20}-[0-9]{1,20}$")
LEG_RE = re.compile(r"^[a-z0-9]{1,16}$")
TEAM_RE = re.compile(r"^[A-Z0-9]{10}$")
ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ResultError(Exception):
    pass


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build(directory: Path, source_sha: str, request_id: str, run_url: str, dmg_names) -> dict:
    if not SHA_RE.match(source_sha):
        raise ResultError("source_sha is not a 40-character commit id")
    if not REQUEST_RE.match(request_id):
        raise ResultError("request_id is not <run id>-<attempt>")
    if not run_url.startswith("https://github.com/"):
        raise ResultError("run url is not a github.com address")
    dmg_names = list(dmg_names)
    if not dmg_names or len(set(dmg_names)) != len(dmg_names):
        raise ResultError("the list of DMG names is empty or repeats a name")
    records = {}
    for path in sorted(directory.glob("leg-*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ResultError(f"{path.name} is not a readable result file: {exc}") from exc
        records[str(record.get("dmg"))] = record
    for name in dmg_names:
        if name not in records:
            raise ResultError(f"{name} has no readable result file")
    if set(records) != set(dmg_names):
        raise ResultError("the result files name a DMG the policy does not list")
    team = None
    sha256 = {}
    notarization = {}
    for name in dmg_names:
        record = records[name]
        leg = str(record.get("leg"))
        if not LEG_RE.match(leg):
            raise ResultError(f"{name} result names an unusable build")
        if record.get("request_id") != request_id:
            raise ResultError(f"{name} was signed for a different request")
        if not TEAM_RE.match(str(record.get("team_id"))):
            raise ResultError(f"{name} has no usable team id")
        if team is None:
            team = record["team_id"]
        elif record["team_id"] != team:
            raise ResultError("the builds were signed by different teams")
        actual = sha256_of(directory / name)
        if not HEX64_RE.match(str(record.get("sha256"))) or record["sha256"] != actual:
            raise ResultError(f"{name} does not match the checksum its build recorded")
        for key in ("app_submission_id", "dmg_submission_id"):
            if not ID_RE.match(str(record.get(key))):
                raise ResultError(f"{name} has no usable {key}")
        sha256[name] = actual
        notarization[leg] = {
            "app": record["app_submission_id"],
            "dmg": record["dmg_submission_id"],
        }
    return {
        "request_id": request_id,
        "source_sha": source_sha,
        "team_id": team,
        "sha256": sha256,
        "notarization": notarization,
        "hallmark_run_url": run_url,
    }


def main(argv) -> int:
    if len(argv) < 6:
        print(__doc__, file=sys.stderr)
        return 2
    directory = Path(argv[1])
    try:
        result = build(directory, argv[2], argv[3], argv[4], argv[5:])
    except ResultError as exc:
        print(f"::error::result.json not written: {exc}. {DISABLE_SENTENCE}", file=sys.stderr)
        return 1
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
