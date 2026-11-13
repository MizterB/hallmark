#!/usr/bin/env python3
"""Load and validate the signing policy.

The policy is one line of JSON held in the secret HALLMARK_POLICY, so the repository carries
no list of what it signs for.

Usage:
  python3 scripts/policy.py FILE                 validate a policy file before it is set as the secret
  python3 scripts/policy.py facts REPO OUT [LEG] write what the signing scripts need to know about
                                                 REPO to OUT as JSON, reading HALLMARK_POLICY
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import entitlements as entitlements_mod  # noqa: E402

DISABLE_SENTENCE = (
    "To skip Mac signing set the repository variable MAC_SIGNING to 0; "
    'to remove it permanently follow the "Remove Mac signing" runbook.'
)

KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
ENV_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
TEAM_RE = re.compile(r"^[A-Z0-9]{10}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$")
ACTOR_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")

MODE_EVENTS = {"release": {"push"}, "dev": {"workflow_dispatch"}}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BUILD_RE = re.compile(r"^[a-z0-9]{1,16}$")
DMG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.dmg$")
APP_KEYS = {
    "workflow",
    "environment",
    "team_id",
    "modes",
    "builds",
    "artifact_prefix",
    "app_zip",
    "icon",
    "background",
    "dmg_name",
    "entitlements",
}
MODE_KEYS = {
    "release": {"events", "ref_pattern", "branches", "allowed_actors", "notarize", "retention_days"},
    "dev": {"events", "ref_pattern", "allowed_actors", "notarize", "retention_days"},
}


class PolicyError(Exception):
    """The policy file is unreadable or does not pass validation."""

    def __init__(self, problems):
        if isinstance(problems, str):
            problems = [problems]
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


# ------------------------------------------------------------------------- validation


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_list(problems, where, value, pattern, allowed=None, nonempty=True):
    if not isinstance(value, list) or (nonempty and not value):
        problems.append(f"{where}: must be a non-empty list")
        return
    for item in value:
        if not isinstance(item, str) or not pattern.match(item):
            problems.append(f"{where}: {item!r} is not an allowed value")
        elif allowed is not None and item not in allowed:
            problems.append(f"{where}: {item!r} is not one of {sorted(allowed)}")


def _check_product(where: str, app: dict) -> list:
    """What the app hands over and what comes back: builds, file names, entitlements."""
    problems: list = []
    builds = app.get("builds")
    if not isinstance(builds, list) or not 1 <= len(builds) <= 8:
        problems.append(f"{where}.builds: must list from 1 to 8 build names")
    else:
        for build in builds:
            if not isinstance(build, str) or not BUILD_RE.match(build):
                problems.append(f"{where}.builds: {build!r} must be lowercase letters and digits")
        if len(set(b for b in builds if isinstance(b, str))) != len(builds):
            problems.append(f"{where}.builds: a build is listed twice")
    prefix = app.get("artifact_prefix")
    if not isinstance(prefix, str) or not PREFIX_RE.match(prefix):
        problems.append(f"{where}.artifact_prefix: must be a name made of letters, digits, . _ -")
    for key in ("app_zip", "icon", "background"):
        value = app.get(key)
        if not isinstance(value, str) or not NAME_RE.match(value):
            problems.append(f"{where}.{key}: must be a plain file name")
    dmg_name = app.get("dmg_name")
    if not isinstance(dmg_name, str) or dmg_name.count("{build}") != 1 or not DMG_NAME_RE.match(
        dmg_name.replace("{build}", "x")
    ):
        problems.append(f"{where}.dmg_name: must be a .dmg file name with {{build}} in it once")
    problems += entitlements_mod.validate(app.get("entitlements"), f"{where}.entitlements")
    return problems


def validate(policy: dict) -> list:
    """Return a list of problems; empty means the policy is acceptable."""
    problems: list = []
    if not isinstance(policy, dict):
        return ["the policy must be a mapping"]
    extra = set(policy) - {"version", "apps"}
    if extra:
        problems.append(f"unknown top-level keys: {sorted(extra)}")
    if policy.get("version") != 1:
        problems.append("version: must be 1")
    apps = policy.get("apps")
    if not isinstance(apps, dict) or not apps:
        problems.append("apps: must list at least one source repository")
        return problems
    seen_envs: dict = {}
    for repo, app in apps.items():
        where = f"apps.{repo}"
        if not REPO_RE.match(repo):
            problems.append(f"{where}: key must look like owner/name")
        if not isinstance(app, dict):
            problems.append(f"{where}: must be a mapping")
            continue
        extra = set(app) - APP_KEYS
        if extra:
            problems.append(f"{where}: unknown keys {sorted(extra)}")
        missing = APP_KEYS - set(app)
        if missing:
            problems.append(f"{where}: missing keys {sorted(missing)}")
        workflow = app.get("workflow")
        if not isinstance(workflow, str) or not WORKFLOW_RE.match(workflow):
            problems.append(f"{where}.workflow: must be a path under .github/workflows/")
        env = app.get("environment")
        if not isinstance(env, str) or not ENV_RE.match(env):
            problems.append(f"{where}.environment: must be a name made of letters, digits, . _ -")
        elif env in seen_envs:
            problems.append(
                f"{where}.environment: {env!r} is already used by {seen_envs[env]}; "
                "every app needs an environment of its own so their secrets never mix"
            )
        else:
            seen_envs[env] = repo
        team = app.get("team_id")
        if not isinstance(team, str) or not TEAM_RE.match(team):
            problems.append(f"{where}.team_id: must be a ten-character Apple Team ID in quotes")
        problems += _check_product(where, app)
        modes = app.get("modes")
        if not isinstance(modes, dict) or not modes:
            problems.append(f"{where}.modes: must define release, dev or both")
            continue
        for mode, cfg in modes.items():
            mwhere = f"{where}.modes.{mode}"
            if mode not in MODE_EVENTS:
                problems.append(f"{mwhere}: mode must be release or dev")
                continue
            if not isinstance(cfg, dict):
                problems.append(f"{mwhere}: must be a mapping")
                continue
            extra = set(cfg) - MODE_KEYS[mode]
            if extra:
                problems.append(f"{mwhere}: unknown keys {sorted(extra)}")
            for needed in MODE_KEYS[mode]:
                if needed not in cfg:
                    problems.append(f"{mwhere}: missing {needed}")
            _check_list(problems, f"{mwhere}.events", cfg.get("events"), re.compile(r"^[a-z_]+$"), MODE_EVENTS[mode])
            _check_list(problems, f"{mwhere}.allowed_actors", cfg.get("allowed_actors"), ACTOR_RE)
            pattern = cfg.get("ref_pattern")
            if not isinstance(pattern, str) or not pattern:
                problems.append(f"{mwhere}.ref_pattern: must be a non-empty string")
            elif mode == "release" and not pattern.startswith("refs/tags/"):
                problems.append(f"{mwhere}.ref_pattern: a release is a tag, the pattern must start with refs/tags/")
            if mode == "release":
                _check_list(problems, f"{mwhere}.branches", cfg.get("branches"), BRANCH_RE)
            if cfg.get("notarize") is not True:
                problems.append(f"{mwhere}.notarize: must be true, signing without notarizing is not implemented")
            days = cfg.get("retention_days")
            if not _is_int(days) or not 1 <= days <= 90:
                problems.append(f"{mwhere}.retention_days: must be a whole number from 1 to 90")
    return problems


def parse(text: str) -> dict:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise PolicyError("the policy is not valid JSON") from exc


def load_text(text: str) -> dict:
    """Parse and validate; raises PolicyError listing every problem."""
    policy = parse(text)
    problems = validate(policy)
    if problems:
        raise PolicyError(problems)
    return policy


def load(env=None) -> dict:
    """The policy held in HALLMARK_POLICY."""
    env = os.environ if env is None else env
    text = env.get("HALLMARK_POLICY", "")
    if not text.strip():
        raise PolicyError("no policy is set")
    return load_text(text)


def load_file(path) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc
    return load_text(text)


def dmg_name(app: dict, build: str) -> str:
    return app["dmg_name"].replace("{build}", build)


def facts(app: dict, leg=None) -> dict:
    """What the signing scripts read about an app. `leg` adds that build's DMG name."""
    out = {
        "team_id": app["team_id"],
        "app_zip": app["app_zip"],
        "icon": app["icon"],
        "background": app["background"],
        "builds": list(app["builds"]),
        "dmg_names": [dmg_name(app, b) for b in app["builds"]],
    }
    if leg is not None:
        if leg not in app["builds"]:
            raise PolicyError("the signing job names no build the policy lists")
        out["dmg_name"] = dmg_name(app, leg)
    return out


def main(argv) -> int:
    try:
        if len(argv) in (4, 5) and argv[1] == "facts":
            apps = load()["apps"]
            if argv[2] not in apps:
                raise PolicyError("the repository has no entry in the policy")
            data = facts(apps[argv[2]], argv[4] if len(argv) == 5 else None)
            Path(argv[3]).write_text(json.dumps(data), encoding="utf-8")
            return 0
        if len(argv) != 2:
            print("usage: policy.py FILE | policy.py facts REPO OUT [LEG]", file=sys.stderr)
            return 2
        policy = load_file(argv[1])
    except PolicyError as exc:
        for problem in exc.problems:
            print(f"::error::policy: {problem}. {DISABLE_SENTENCE}")
        return 1
    print(f"policy ok: {len(policy['apps'])} app(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
