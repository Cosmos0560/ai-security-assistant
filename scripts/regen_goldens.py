#!/usr/bin/env python3
"""Regenerate ``tests/golden/*`` from ``tests/golden_cases.py``. The ONLY way goldens change.

Run it on purpose after an intended change to a prompt, a mock or a fixture, then review the diff
of ``tests/golden/`` before committing. Files are written with LF line endings (D29).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    from tests import golden_cases

    golden_cases.GOLDEN_DIR.mkdir(exist_ok=True)
    for name, text in golden_cases.render_goldens().items():
        path = golden_cases.GOLDEN_DIR / name
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        print(f"wrote {path.relative_to(ROOT).as_posix()} ({len(text)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
