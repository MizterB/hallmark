#!/usr/bin/env python3
"""Decide whether a signing request is allowed, and fetch its inputs.

Standard library plus the `gh` CLI only. Everything about the request is untrusted: the
dispatch inputs, the run record, the artifact, the layout file inside it. Every check is
a small function that raises Rejection with a plain message, and the whole thing fails
closed: any error, expected or not, is a rejection.

  verify.py gate                run every check in the unprivileged `verify` job and write the
                                outputs the later jobs need (environment, team id, mode)
  verify.py fetch --dest DIR    run every check again in the privileged job, with that job's
                                own token, and leave the verified files under DIR/<leg>/

The privileged job never trusts what the `verify` job saw: it checks again, then signs.

Inputs come from the environment (set from workflow inputs, never interpolated into a
shell): HALLMARK_SOURCE_REPO, _SOURCE_RUN_ID, _SOURCE_RUN_ATTEMPT, _SOURCE_SHA,
_SOURCE_REF, _TAG, _MODE, _REQUEST_ID, _ARTIFACTS. GITHUB_REF is hallmark's own ref.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))

import layout as layout_mod  # noqa: E402
import policy as policy_mod  # noqa: E402

DISABLE_SENTENCE = policy_mod.DISABLE_SENTENCE

LAYOUT_MEMBER = "dmg/layout.json"

MAX_ARTIFACT_BYTES = 3 * 1024**3
MAX_APP_ZIP_BYTES = 3 * 1024**3
MAX_APP_UNCOMPRESSED = 6 * 1024**3
MAX_APP_ENTRIES = 300_000
MAX_SMALL_FILE_BYTES = 20 * 1024**2

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DIGITS_RE = re.compile(r"^[0-9]{1,20}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
REF_RE = re.compile(r"^[A-Za-z0-9/._-]{1,200}$")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
ICNS_MAGIC = b"icns"


class Rejection(Exception):
    """The request is refused. The message says why in plain words."""


def safe(value, limit: int = 120) -> str:
    """An untrusted value made safe to print: ASCII only, no newlines, clipped."""
    return ascii(str(value))[:limit]


# ----------------------------------------------------------------------- gh wrapper


class Gh:
    """The only place that runs `gh`. Tests replace it with a fake."""

    def api(self, path: str):
        result = subprocess.run(
            ["gh", "api", "-H", "Accept: application/vnd.github+json", path],
            capture_output=True, text=True, encoding="utf-8", check=False, timeout=120,
        )
        if result.returncode != 0:
            raise Rejection(f"GitHub refused the lookup of {safe(path)}: {safe(result.stderr.strip(), 200)}")
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise Rejection(f"GitHub returned something unreadable for {safe(path)}") from exc

    def download(self, path: str, dest: Path) -> None:
        with open(dest, "wb") as handle:
            result = subprocess.run(
                ["gh", "api", path], stdout=handle, stderr=subprocess.PIPE, check=False, timeout=1800,
            )
        if result.returncode != 0:
            raise Rejection(f"the download of {safe(path)} failed: {safe(result.stderr.decode('utf-8', 'replace'), 200)}")

    def attest(self, file: Path, repo: str, signer_workflow: str, source_ref, source_digest: str) -> None:
        cmd = [
            "gh", "attestation", "verify", str(file),
            "--repo", repo,
            "--signer-workflow", signer_workflow,
            "--source-digest", source_digest,
            "--deny-self-hosted-runners",
        ]
        if source_ref:
            cmd += ["--source-ref", source_ref]
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", check=False, timeout=300,
        )
        if result.returncode != 0:
            raise Rejection(
                f"the build attestation for {file.name} did not verify: {safe(result.stderr.strip(), 300)}"
            )


# -------------------------------------------------------------------------- inputs


class Inputs:
    """The dispatch inputs, checked for shape. Not yet checked against the run."""

    def __init__(self, env):
        def need(name):
            value = env.get(name, "")
            if not value:
                raise Rejection(f"the request has no {name.removeprefix('HALLMARK_').lower()}")
            return value

        self.source_repo = need("HALLMARK_SOURCE_REPO")
        if not REPO_RE.match(self.source_repo):
            raise Rejection(f"source_repo {safe(self.source_repo)} is not owner/name")
        self.run_id = need("HALLMARK_SOURCE_RUN_ID")
        self.attempt = need("HALLMARK_SOURCE_RUN_ATTEMPT")
        for name, value in (("source_run_id", self.run_id), ("source_run_attempt", self.attempt)):
            if not DIGITS_RE.match(value):
                raise Rejection(f"{name} {safe(value)} is not a number")
        self.sha = need("HALLMARK_SOURCE_SHA")
        if not SHA_RE.match(self.sha):
            raise Rejection(f"source_sha {safe(self.sha)} is not a 40-character commit id")
        self.ref = env.get("HALLMARK_SOURCE_REF", "")
        if self.ref and not REF_RE.match(self.ref):
            raise Rejection("source_ref has characters that are not allowed")
        self.tag = need("HALLMARK_TAG")
        self.mode = need("HALLMARK_MODE")
        if self.mode not in ("release", "dev"):
            raise Rejection(f"mode {safe(self.mode)} is not release or dev")
        self.request_id = need("HALLMARK_REQUEST_ID")
        if self.request_id != f"{self.run_id}-{self.attempt}":
            raise Rejection("request_id is not <run id>-<run attempt>")
        self.artifacts = need("HALLMARK_ARTIFACTS")


# ---------------------------------------------------------------------------- checks


def check_hallmark_ref(env) -> None:
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise Rejection("hallmark only signs from its own main branch; this run is on " + safe(env.get("GITHUB_REF")))


def check_policy_entry(policy: dict, record: dict):
    """The repository the run belongs to must be a policy key. Returns (repo, app)."""
    repo = (record.get("repository") or {}).get("full_name")
    if not isinstance(repo, str) or repo not in policy["apps"]:
        raise Rejection(f"{safe(repo)} is not a repository hallmark signs for")
    return repo, policy["apps"][repo]


def artifact_names(app: dict) -> list:
    return [app["artifact_prefix"] + build for build in app["builds"]]


def check_artifact_names(inputs: Inputs, app: dict) -> None:
    """The request names exactly the artifacts the policy says this app hands over."""
    wanted = ",".join(artifact_names(app))
    if inputs.artifacts != wanted:
        raise Rejection(f"artifacts must be exactly {safe(wanted, 300)}")


def members_of(app: dict) -> set:
    return {app["app_zip"], f"dmg/{app['icon']}", f"dmg/{app['background']}", LAYOUT_MEMBER}


def check_input_matches_record(inputs: Inputs, repo: str) -> None:
    if inputs.source_repo.lower() != repo.lower():
        raise Rejection(f"the request names {safe(inputs.source_repo)} but the run belongs to {safe(repo)}")


def check_workflow(record: dict, app: dict) -> None:
    path = str(record.get("path", ""))
    if path.split("@", 1)[0] != app["workflow"]:
        raise Rejection(f"the run is from workflow {safe(path)}, not {app['workflow']}")


def check_sha(record: dict, inputs: Inputs) -> None:
    if record.get("head_sha") != inputs.sha:
        raise Rejection("the run's commit is not the commit the request names")


def check_in_progress(record: dict, inputs: Inputs) -> None:
    """A request is made from inside a running build; a finished run cannot be replayed."""
    if record.get("status") != "in_progress":
        raise Rejection(f"the source run is {safe(record.get('status'))}, not in progress")
    if record.get("run_attempt") != int(inputs.attempt):
        raise Rejection("the run attempt is not the attempt the request names")


def check_event(record: dict, mode_cfg: dict) -> None:
    event = record.get("event")
    if event not in mode_cfg["events"]:
        raise Rejection(f"a {safe(event)} run is not allowed for this mode (allowed: {', '.join(mode_cfg['events'])})")


def check_not_a_fork_run(record: dict) -> None:
    """Refuse a run that came from another repository. The source repo may itself be a fork
    of something else; what matters is that the run's code lives in the repo it belongs to."""
    repo = (record.get("repository") or {}).get("full_name")
    head = (record.get("head_repository") or {}).get("full_name")
    if not head or str(head).lower() != str(repo).lower():
        raise Rejection(f"the run's code is from {safe(head)}, not from {safe(repo)}")
    if record.get("pull_requests"):
        raise Rejection("the run is attached to a pull request")


def check_actors(record: dict, mode_cfg: dict) -> None:
    """The person who started the run and the person who last re-ran it must both be allowed."""
    allowed = {a.lower() for a in mode_cfg["allowed_actors"]}
    for field in ("actor", "triggering_actor"):
        login = (record.get(field) or {}).get("login")
        if not isinstance(login, str) or login.lower() not in allowed:
            raise Rejection(f"{field} {safe(login)} is not allowed to request signing")


def check_tag_input(inputs: Inputs) -> None:
    if inputs.mode == "release":
        if not TAG_RE.match(inputs.tag):
            raise Rejection(f"tag {safe(inputs.tag)} is not a usable tag name")
    elif inputs.tag != "-":
        raise Rejection("a dev request must pass - as the tag")


def check_release_ref(record: dict, inputs: Inputs, mode_cfg: dict) -> None:
    if record.get("head_branch") != inputs.tag:
        raise Rejection("the run was not started by the tag the request names")
    ref = f"refs/tags/{inputs.tag}"
    if not fnmatch.fnmatchcase(ref, mode_cfg["ref_pattern"]):
        raise Rejection(f"{ref} does not match the allowed pattern {mode_cfg['ref_pattern']}")


def check_tag_points_at_commit(gh, repo: str, tag: str, sha: str) -> None:
    """The name must be a real tag (not a branch that happens to look like one) and must point
    at the commit that was built. An annotated tag is followed to the commit it names."""
    ref = gh.api(f"repos/{repo}/git/ref/tags/{quote(tag, safe='')}")
    obj = ref.get("object") or {}
    for _ in range(4):
        if obj.get("type") == "commit":
            if obj.get("sha") != sha:
                raise Rejection("the tag does not point at the commit the request names")
            return
        if obj.get("type") != "tag" or not isinstance(obj.get("sha"), str):
            break
        obj = (gh.api(f"repos/{repo}/git/tags/{obj['sha']}").get("object")) or {}
    raise Rejection("the tag does not resolve to a commit")


def check_dev_ref(record: dict, mode_cfg: dict) -> None:
    head = str(record.get("head_branch", ""))
    pattern = mode_cfg["ref_pattern"]
    if not (fnmatch.fnmatchcase(f"refs/heads/{head}", pattern) or fnmatch.fnmatchcase(f"refs/tags/{head}", pattern)):
        raise Rejection(f"the run's ref {safe(head)} does not match the allowed pattern")


def check_commit_on_branch(gh, repo: str, sha: str, branches: list) -> None:
    """The tagged commit must be the tip of an allowed branch or one of its ancestors."""
    for branch in branches:
        comparison = gh.api(f"repos/{repo}/compare/{quote(branch, safe='')}...{sha}")
        if comparison.get("status") in ("identical", "behind"):
            return
    raise Rejection(f"the tagged commit is not on {', '.join(branches)}")


def check_artifacts(gh, repo: str, inputs: Inputs) -> dict:
    """Each named artifact exists exactly once, belongs to this run and commit, and has not expired."""
    listing = gh.api(f"repos/{repo}/actions/runs/{inputs.run_id}/artifacts?per_page=100")
    found = {}
    for name in inputs.artifacts.split(","):
        matches = [a for a in listing.get("artifacts", []) if a.get("name") == name]
        if len(matches) != 1:
            raise Rejection(f"the run has {len(matches)} artifacts named {name}, expected exactly one")
        art = matches[0]
        if art.get("expired"):
            raise Rejection(f"artifact {name} has expired")
        run = art.get("workflow_run") or {}
        if str(run.get("id")) != inputs.run_id or run.get("head_sha") != inputs.sha:
            raise Rejection(f"artifact {name} does not belong to this run and commit")
        size = art.get("size_in_bytes")
        if not isinstance(size, int) or size <= 0 or size > MAX_ARTIFACT_BYTES:
            raise Rejection(f"artifact {name} has an unusable size")
        found[name] = art
    return found


def safe_extract(zip_path: Path, dest: Path, app: dict) -> None:
    """Pull out only the files we expect, by explicit name, never by the archive's own paths."""
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise Rejection("an artifact is not a readable zip file") from exc
    with archive:
        infos = [i for i in archive.infolist() if not i.is_dir()]
        names = [i.filename for i in infos]
        expected = members_of(app)
        if sorted(names) != sorted(expected):
            raise Rejection(f"the artifact holds {safe(sorted(names), 300)}, expected {sorted(expected)}")
        for info in infos:
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise Rejection(f"{safe(info.filename)} in the artifact is a symbolic link")
            limit = MAX_APP_ZIP_BYTES if info.filename == app["app_zip"] else MAX_SMALL_FILE_BYTES
            if info.file_size > limit:
                raise Rejection(f"{safe(info.filename)} in the artifact is too large")
            target = dest / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(1024 * 1024):
                    written += len(chunk)
                    if written > limit:
                        raise Rejection(f"{safe(info.filename)} in the artifact is too large")
                    out.write(chunk)


def check_app_zip(path: Path, app_name: str) -> None:
    """The app zip holds one bundle with the layout's name, nothing outside it."""
    label = path.name
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise Rejection(f"{label} is not a readable zip file") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_APP_ENTRIES:
            raise Rejection(f"{label} has an unusable number of entries")
        total = 0
        for info in infos:
            name = info.filename
            parts = name.split("/")
            if name.startswith("/") or ".." in parts or "\\" in name or any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
                raise Rejection(f"{label} has an unsafe path: {safe(name)}")
            if parts[0] != app_name:
                raise Rejection(f"{label} has an entry outside {app_name}: {safe(name)}")
            total += info.file_size
        if total > MAX_APP_UNCOMPRESSED:
            raise Rejection(f"{label} unpacks to more than {MAX_APP_UNCOMPRESSED // 1024**3} GiB")


def check_dmg_assets(directory: Path, app: dict) -> dict:
    """Icon and background are what they say; the layout passes its own validator."""
    for name, magic in ((f"dmg/{app['icon']}", ICNS_MAGIC), (f"dmg/{app['background']}", PNG_MAGIC)):
        with open(directory / name, "rb") as handle:
            if handle.read(len(magic)) != magic:
                raise Rejection(f"{name} is not the file type it claims to be")
    try:
        return layout_mod.load(directory / "dmg" / "layout.json")
    except layout_mod.LayoutError as exc:
        raise Rejection(str(exc)) from exc


def check_attestation(gh, file: Path, repo: str, app: dict, inputs: Inputs) -> None:
    signer = f"{repo}/{app['workflow']}"
    source_ref = f"refs/tags/{inputs.tag}" if inputs.mode == "release" else None
    gh.attest(file, repo, signer, source_ref, inputs.sha)


# ------------------------------------------------------------------------ the whole


class Verified:
    def __init__(self, repo, app, mode_cfg, inputs, record):
        self.repo = repo
        self.app = app
        self.mode_cfg = mode_cfg
        self.inputs = inputs
        self.record = record


def verify_request(gh, env, policy: dict, workdir: Path, legs=None) -> Verified:
    """Run every check in order. `workdir/<leg>/` receives each verified leg's files.
    `legs` narrows the fetch to some of the app's builds; the default is all of them."""
    check_hallmark_ref(env)
    inputs = Inputs(env)
    record = gh.api(f"repos/{inputs.source_repo}/actions/runs/{inputs.run_id}")
    repo, app = check_policy_entry(policy, record)
    check_input_matches_record(inputs, repo)
    check_artifact_names(inputs, app)
    legs = tuple(app["builds"]) if legs is None else tuple(legs)
    for leg in legs:
        if leg not in app["builds"]:
            raise Rejection("the signing job names a build the policy does not list")
    mode_cfg = app["modes"].get(inputs.mode)
    if mode_cfg is None:
        raise Rejection(f"{repo} has no {inputs.mode} mode in the policy")
    check_workflow(record, app)
    check_sha(record, inputs)
    check_in_progress(record, inputs)
    check_event(record, mode_cfg)
    check_not_a_fork_run(record)
    check_actors(record, mode_cfg)
    check_tag_input(inputs)
    if inputs.mode == "release":
        check_release_ref(record, inputs, mode_cfg)
        check_tag_points_at_commit(gh, repo, inputs.tag, inputs.sha)
        check_commit_on_branch(gh, repo, inputs.sha, mode_cfg["branches"])
    else:
        check_dev_ref(record, mode_cfg)
    artifacts = check_artifacts(gh, repo, inputs)
    for leg in legs:
        art = artifacts[app["artifact_prefix"] + leg]
        leg_dir = workdir / leg
        leg_dir.mkdir(parents=True, exist_ok=True)
        archive = leg_dir / "artifact.zip"
        gh.download(f"repos/{repo}/actions/artifacts/{int(art['id'])}/zip", archive)
        safe_extract(archive, leg_dir, app)
        archive.unlink()
        layout = check_dmg_assets(leg_dir, app)
        check_app_zip(leg_dir / app["app_zip"], layout["app_name"])
        check_attestation(gh, leg_dir / app["app_zip"], repo, app, inputs)
    return Verified(repo, app, mode_cfg, inputs, record)


# ---------------------------------------------------------------------------- output


def annotate(level: str, message: str) -> None:
    text = f"{message} {DISABLE_SENTENCE}"
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} title=Mac signing::{text}")


def write_outputs(env, verified: Verified) -> None:
    path = env.get("GITHUB_OUTPUT")
    values = {
        "environment": verified.app["environment"],
        "mode": verified.inputs.mode,
        "source_repo": verified.repo,
        "source_sha": verified.inputs.sha,
        "request_id": verified.inputs.request_id,
        "retention_days": str(verified.mode_cfg["retention_days"]),
        "notarize": "true",
    }
    legs = list(verified.app["builds"])
    for build in legs:
        if not re.fullmatch(r"[a-z0-9]{1,16}", build):
            raise Rejection("a build name has characters that are not allowed")
    for key, value in values.items():
        # Each value already passed its own stricter pattern; this is the last line before it
        # reaches $GITHUB_OUTPUT, where a newline would start a new output.
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", value):
            raise Rejection(f"output {key} has characters that are not allowed")
    values["legs"] = json.dumps(legs, separators=(",", ":"))
    if not path:
        print(json.dumps(values, indent=2))
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def run(argv, env=None, gh=None, policy=None) -> int:
    env = os.environ if env is None else env
    gh = gh or Gh()
    command = argv[1] if len(argv) > 1 else ""
    if command not in ("gate", "fetch"):
        print("usage: verify.py gate | fetch --dest DIR", file=sys.stderr)
        return 2
    dest = None
    if command == "fetch":
        if len(argv) != 4 or argv[2] != "--dest":
            print("usage: verify.py fetch --dest DIR", file=sys.stderr)
            return 2
        dest = Path(argv[3])
    try:
        loaded = policy if policy is not None else policy_mod.load(env)
        if command == "gate":
            with tempfile.TemporaryDirectory() as tmp:
                verified = verify_request(gh, env, loaded, Path(tmp))
            write_outputs(env, verified)
        else:
            if dest.exists():
                shutil.rmtree(dest)
            dest.mkdir(parents=True)
            leg = env.get("HALLMARK_LEG", "")
            if not leg:
                raise Rejection("the signing job names no build")
            verified = verify_request(gh, env, loaded, dest, legs=(leg,))
    except policy_mod.PolicyError as exc:
        annotate("error", f"Request rejected: the policy is not valid ({safe(exc, 300)}).")
        return 1
    except Rejection as exc:
        annotate("error", f"Request rejected: {exc}.")
        return 1
    except Exception as exc:  # noqa: BLE001 - failing closed is the point
        annotate("error", f"Request rejected: unexpected {type(exc).__name__}, {safe(exc, 200)}.")
        return 1
    print(f"verified request {verified.inputs.request_id} from {verified.repo} ({verified.inputs.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv))
