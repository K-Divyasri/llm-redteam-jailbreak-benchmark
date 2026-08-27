"""Puts the two vendored packages on sys.path, once, before anything imports them.

`safeguard` (the guardrails layer) and `tool_agent` (the tool-calling agent) are
copied byte-for-byte from two earlier, separately-repo'd projects - see
vendor/README.md for exactly which ones and why they're copied rather than
imported across project folders. This module is the single place that wires them
onto the import path so every other module can just `import safeguard` /
`import tool_agent` without repeating the sys.path dance.
"""

from __future__ import annotations

import sys
from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parent.parent / "vendor"

if str(VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(VENDOR_DIR))
