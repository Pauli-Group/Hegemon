#!/usr/bin/env python3
"""Export dashboard CLI actions as JSON for the UI."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"

import sys

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from dashboard import _actions  # type: ignore  # noqa: E402


def _normalize_action(action: Any) -> dict[str, Any]:
    data = asdict(action)
    commands = []
    for cmd in data.get("commands", []):
        normalized = {
            "argv": cmd["argv"],
        }
        if cmd.get("cwd"):
            normalized["cwd"] = str(cmd["cwd"])
        if cmd.get("env"):
            normalized["env"] = cmd["env"]
        commands.append(normalized)
    data["commands"] = commands
    return data


def export_actions(pretty: bool) -> str:
    actions = _actions()
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "action_count": len(actions),
        "actions": [
            _normalize_action(actions[key]) for key in sorted(actions)
        ],
    }
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=False) + "\n"
    return json.dumps(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        help="Optional file path to write the JSON export. Prints to stdout when omitted.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON with indentation for easier diffs.",
    )
    args = parser.parse_args()
    output = export_actions(pretty=args.pretty or bool(args.out))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
