#!/usr/bin/env python3
"""List what to sign in an app, each with the entitlements file it gets.

Prints NUL-separated pairs: a path, then the plist for it (empty when it gets none). Nested
code comes first, deepest first, and the app itself is last. The plist for each path is
chosen by entitlements.choose from the index that entitlements.py wrote.

Usage:  python3 scripts/sign_plan.py <App.app> <entitlements index.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import entitlements  # noqa: E402
import list_signables  # noqa: E402


def plan(app: Path, index: dict) -> list:
    app = Path(app)
    pairs = []
    for item in list_signables.signables(app):
        relative = Path(item).relative_to(app).as_posix()
        pairs.append((str(item), entitlements.choose(index, relative)))
    pairs.append((str(app), index["default"]))
    return pairs


def main(argv) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    index = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    out = b""
    for path, plist in plan(Path(argv[1]), index):
        out += path.encode("utf-8") + b"\0" + plist.encode("utf-8") + b"\0"
    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
