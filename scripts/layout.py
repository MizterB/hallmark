#!/usr/bin/env python3
"""Validate dmg/layout.json and turn it into create-dmg arguments.

layout.json comes from the source repository, so every value is untrusted. Each key must be
present, no other key is allowed, and every value is checked against a tight pattern before
it becomes a command-line argument. Nothing is ever passed through a shell: the arguments
are printed NUL-separated for `read -d ''` in sign.sh.

Usage:  python3 scripts/layout.py args <layout.json> <icon file> <background file>   (arguments to stdout)
        python3 scripts/layout.py field <layout.json> <volname|app_name>
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy import DISABLE_SENTENCE  # noqa: E402

KEYS = {
    "volname",
    "app_name",
    "hide_extension",
    "window_pos",
    "window_size",
    "icon_size",
    "app_icon_pos",
    "app_drop_link_pos",
}

# Letters, digits, space, dot, underscore, hyphen; must start with a letter or digit so the
# value can never be read as a command-line option. 27 is the HFS+ volume name limit.
VOLNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,26}$")
APP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}\.app$")


class LayoutError(Exception):
    pass


def _int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise LayoutError(f"layout.json: {name} must be a whole number from {low} to {high}")
    return value


def _pair(value, name, low, high):
    if not isinstance(value, list) or len(value) != 2:
        raise LayoutError(f"layout.json: {name} must be a list of two whole numbers")
    return [_int(v, name, low, high) for v in value]


def validate(layout) -> dict:
    """Return a cleaned copy of the layout or raise LayoutError."""
    if not isinstance(layout, dict):
        raise LayoutError("layout.json: must be a JSON object")
    extra = set(layout) - KEYS
    missing = KEYS - set(layout)
    if extra:
        raise LayoutError(f"layout.json: unknown keys {sorted(extra)}")
    if missing:
        raise LayoutError(f"layout.json: missing keys {sorted(missing)}")
    volname = layout["volname"]
    if not isinstance(volname, str) or not VOLNAME_RE.match(volname):
        raise LayoutError("layout.json: volname must be 1 to 27 letters, digits, spaces, . _ -")
    app_name = layout["app_name"]
    if not isinstance(app_name, str) or not APP_NAME_RE.match(app_name):
        raise LayoutError("layout.json: app_name must be a name ending in .app, with no path")
    if not isinstance(layout["hide_extension"], bool):
        raise LayoutError("layout.json: hide_extension must be true or false")
    return {
        "volname": volname,
        "app_name": app_name,
        "hide_extension": layout["hide_extension"],
        "window_pos": _pair(layout["window_pos"], "window_pos", 0, 10000),
        "window_size": _pair(layout["window_size"], "window_size", 100, 4000),
        "icon_size": _int(layout["icon_size"], "icon_size", 16, 128),
        "app_icon_pos": _pair(layout["app_icon_pos"], "app_icon_pos", 0, 4000),
        "app_drop_link_pos": _pair(layout["app_drop_link_pos"], "app_drop_link_pos", 0, 4000),
    }


def load(path: Path) -> dict:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LayoutError(f"layout.json: cannot read it: {exc}") from exc
    return validate(raw)


def create_dmg_args(layout: dict, volicon: Path, background: Path) -> list:
    """The create-dmg options for a validated layout, as an argument list."""
    args = [
        "--volname", layout["volname"],
        "--volicon", str(volicon),
        "--background", str(background),
        "--window-pos", *map(str, layout["window_pos"]),
        "--window-size", *map(str, layout["window_size"]),
        "--icon-size", str(layout["icon_size"]),
        "--icon", layout["app_name"], *map(str, layout["app_icon_pos"]),
        "--app-drop-link", *map(str, layout["app_drop_link_pos"]),
    ]
    if layout["hide_extension"]:
        args += ["--hide-extension", layout["app_name"]]
    return args


def main(argv) -> int:
    usage = "usage: layout.py args <layout.json> <icon> <background> | layout.py field <layout.json> <key>"
    if argv[1:2] not in (["args"], ["field"]) or len(argv) != (5 if argv[1] == "args" else 4):
        print(usage, file=sys.stderr)
        return 2
    try:
        layout = load(Path(argv[2]))
    except LayoutError as exc:
        print(f"::error::{exc}. {DISABLE_SENTENCE}", file=sys.stderr)
        return 1
    if argv[1] == "field":
        value = layout.get(argv[3])
        if not isinstance(value, str):
            print(f"::error::layout.py: field must name a text value. {DISABLE_SENTENCE}", file=sys.stderr)
            return 2
        print(value)
        return 0
    out = create_dmg_args(layout, Path(argv[3]), Path(argv[4]))
    sys.stdout.buffer.write(b"".join(a.encode("utf-8") + b"\0" for a in out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
