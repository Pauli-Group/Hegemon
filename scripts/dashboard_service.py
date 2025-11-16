#!/usr/bin/env python3
"""ASGI service that streams dashboard actions for the React UI.

Example NDJSON stream for `POST /run/fmt`:
    {"type":"action_start","slug":"fmt","title":"Format Rust workspace"}
    {"type":"command_start","slug":"fmt","command_index":0,"command":"cargo fmt --all"}
    {"type":"command_output","slug":"fmt","command_index":0,"line":"Formatting crates/state"}
    {"type":"command_end","slug":"fmt","command_index":0,"status":"success","duration":0.42}
    {"type":"action_complete","slug":"fmt","duration":0.43}
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Dict, Iterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

try:
    import uvicorn
except ImportError as exc:  # pragma: no cover - runtime dependency hint
    raise SystemExit(
        "uvicorn must be installed. Run `pip install -r scripts/dashboard_requirements.txt`."
    ) from exc

from scripts.dashboard import (  # type: ignore[import]
    CommandSpec,
    DashboardAction,
    _actions,
    _command_to_string,
    prepare_command,
)

ACTIONS = _actions()
STARTED_AT = datetime.now(tz=timezone.utc).isoformat()

app = FastAPI(title="Synthetic Hegemonic Currency Ops Dashboard Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CommandFailure(RuntimeError):
    def __init__(self, slug: str, command_index: int, exit_code: int, duration: float) -> None:
        super().__init__(f"Command {command_index} in action '{slug}' failed with {exit_code}")
        self.slug = slug
        self.command_index = command_index
        self.exit_code = exit_code
        self.duration = duration


def _serialize_event(event: Dict) -> str:
    event.setdefault("timestamp", time.time())
    return json.dumps(event, separators=(",", ":"), default=str) + "\n"


def _stream_command_output(
    action: DashboardAction, command: CommandSpec, command_index: int
) -> Iterator[str]:
    argv, cwd, env = prepare_command(command)
    started = time.perf_counter()
    yield _serialize_event(
        {
            "type": "command_start",
            "slug": action.slug,
            "command_index": command_index,
            "command": _command_to_string(command),
            "argv": argv,
            "cwd": str(cwd),
        }
    )
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in iter(process.stdout.readline, ""):
        yield _serialize_event(
            {
                "type": "command_output",
                "slug": action.slug,
                "command_index": command_index,
                "line": line.rstrip("\n"),
            }
        )
    exit_code = process.wait()
    duration = time.perf_counter() - started
    status = "success" if exit_code == 0 else "error"
    yield _serialize_event(
        {
            "type": "command_end",
            "slug": action.slug,
            "command_index": command_index,
            "status": status,
            "exit_code": exit_code,
            "duration": round(duration, 3),
        }
    )
    if exit_code != 0:
        raise CommandFailure(action.slug, command_index, exit_code, duration)


def _action_stream(action: DashboardAction) -> Iterator[str]:
    overall_start = time.perf_counter()
    yield _serialize_event(
        {
            "type": "action_start",
            "slug": action.slug,
            "title": action.title,
            "description": action.description,
            "command_count": len(action.commands),
        }
    )
    for index, command in enumerate(action.commands):
        yield from _stream_command_output(action, command, index)
    total = time.perf_counter() - overall_start
    yield _serialize_event(
        {
            "type": "action_complete",
            "slug": action.slug,
            "duration": round(total, 3),
        }
    )


def _generate_stream(action: DashboardAction) -> Iterator[str]:
    try:
        yield from _action_stream(action)
    except CommandFailure as exc:
        yield _serialize_event(
            {
                "type": "action_error",
                "slug": exc.slug,
                "command_index": exc.command_index,
                "exit_code": exc.exit_code,
                "duration": round(exc.duration, 3),
            }
        )


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "started_at": STARTED_AT}


@app.get("/actions")
def list_actions() -> Dict:
    actions = [asdict(action) for action in ACTIONS.values()]
    return {
        "generated_at": STARTED_AT,
        "action_count": len(actions),
        "actions": actions,
    }


@app.post("/run/{slug}")
def run_action(slug: str) -> StreamingResponse:
    action = ACTIONS.get(slug)
    if not action:
        raise HTTPException(status_code=404, detail=f"Unknown action slug: {slug}")
    generator = _generate_stream(action)
    return StreamingResponse(generator, media_type="application/x-ndjson")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (for development).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    uvicorn.run(
        "scripts.dashboard_service:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":  # pragma: no cover - manual entrypoint
    main()
