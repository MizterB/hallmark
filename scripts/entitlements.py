#!/usr/bin/env python3
"""Entitlements, written from the policy at signing time.

The policy says which entitlement keys a path in the app gets. Only keys named below are
accepted, so a policy can ask for a Hardened Runtime exception and nothing that needs a
provisioning profile. The source repository never supplies any of this.

Usage:  python3 scripts/entitlements.py write <outdir>   reads HALLMARK_POLICY and
                                                         HALLMARK_SOURCE_REPO; writes the
                                                         plists and <outdir>/index.json
"""

from __future__ import annotations

import fnmatch
import json
import os
import plistlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Hardened Runtime exceptions and device access: every one is a plain true/false key.
ALLOWED_KEYS = (
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.device.audio-input",
    "com.apple.security.device.camera",
)

RULE_KEYS = {"match", "keys"}
SPEC_KEYS = {"default", "rules"}


def validate(spec, where: str) -> list:
    """Problems with an `entitlements` entry of the policy; empty means acceptable."""
    problems: list = []
    if not isinstance(spec, dict):
        return [f"{where}: must be a mapping with default and rules"]
    extra = set(spec) - SPEC_KEYS
    if extra:
        problems.append(f"{where}: unknown keys {sorted(extra)}")
    for needed in sorted(SPEC_KEYS - set(spec)):
        problems.append(f"{where}: missing {needed}")
    problems += _check_keys(spec.get("default"), f"{where}.default")
    rules = spec.get("rules")
    if not isinstance(rules, list):
        problems.append(f"{where}.rules: must be a list (empty if no path needs its own set)")
        return problems
    for number, rule in enumerate(rules):
        rwhere = f"{where}.rules[{number}]"
        if not isinstance(rule, dict) or set(rule) != RULE_KEYS:
            problems.append(f"{rwhere}: must have exactly match and keys")
            continue
        pattern = rule["match"]
        if not isinstance(pattern, str) or not pattern or pattern.startswith("/") or ".." in pattern.split("/"):
            problems.append(f"{rwhere}.match: must be a non-empty pattern relative to the app, with no ..")
        problems += _check_keys(rule["keys"], f"{rwhere}.keys")
    return problems


def _check_keys(keys, where: str) -> list:
    if not isinstance(keys, list):
        return [f"{where}: must be a list of entitlement keys (empty for none)"]
    problems = []
    for key in keys:
        if key not in ALLOWED_KEYS:
            problems.append(f"{where}: {key!r} is not one of the allowed entitlement keys")
    if len(set(k for k in keys if isinstance(k, str))) != len(keys):
        problems.append(f"{where}: a key is listed twice")
    return problems


def write_plists(spec: dict, outdir: Path) -> dict:
    """Write one plist per distinct set of keys. Returns the index sign_plan.py reads:
    {"default": <plist path or "">, "rules": [{"match": pattern, "plist": path or ""}]}."""
    outdir.mkdir(parents=True, exist_ok=True)
    written: dict = {}

    def plist_for(keys: list) -> str:
        if not keys:
            return ""
        ident = tuple(sorted(keys))
        if ident not in written:
            path = outdir / f"set-{len(written)}.entitlements"
            path.write_bytes(plistlib.dumps({key: True for key in ident}))
            written[ident] = str(path)
        return written[ident]

    index = {"default": plist_for(spec["default"]), "rules": []}
    for rule in spec["rules"]:
        index["rules"].append({"match": rule["match"], "plist": plist_for(rule["keys"])})
    return index


def choose(index: dict, relpath: str) -> str:
    """The plist for a path inside the app, relative to the bundle; the first rule that
    matches the path or one of its parent folders wins. Empty means no entitlements."""
    parts = relpath.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for rule in index["rules"]:
        if any(fnmatch.fnmatchcase(prefix, rule["match"]) for prefix in prefixes):
            return rule["plist"]
    return index["default"]


def main(argv) -> int:
    import policy as policy_mod

    if len(argv) != 3 or argv[1] != "write":
        print("usage: entitlements.py write <outdir>", file=sys.stderr)
        return 2
    try:
        apps = policy_mod.load()["apps"]
        repo = os.environ.get("HALLMARK_SOURCE_REPO", "")
        if repo not in apps:
            raise policy_mod.PolicyError("the repository has no entry in the policy")
        index = write_plists(apps[repo]["entitlements"], Path(argv[2]))
    except policy_mod.PolicyError as exc:
        print(f"::error::policy: {exc}. {policy_mod.DISABLE_SENTENCE}")
        return 1
    (Path(argv[2]) / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
