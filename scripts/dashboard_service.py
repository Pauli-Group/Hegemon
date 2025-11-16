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
import asyncio
import json
import os
import subprocess
import sys
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Deque, Dict, Iterator, List, Optional, Literal

import httpx
import websockets
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

try:
    import uvicorn
except ImportError as exc:  # pragma: no cover - runtime dependency hint
    raise SystemExit(
        "uvicorn must be installed. Run `pip install -r scripts/dashboard_requirements.txt`."
    ) from exc

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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

NODE_RPC_URL = os.environ.get("NODE_RPC_URL")
if NODE_RPC_URL:
    NODE_RPC_URL = NODE_RPC_URL.rstrip("/")
NODE_RPC_TOKEN = os.environ.get("NODE_RPC_TOKEN", "")
STREAM_RECONNECT_SECONDS = 3.0


def _build_ws_url(base_url: str) -> str:
    parsed = httpx.URL(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return str(parsed.copy_with(scheme=scheme, path="/ws", query=None))


NODE_WS_URL = _build_ws_url(NODE_RPC_URL) if NODE_RPC_URL else None


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


SAMPLE_TELEMETRY = {
    "hash_rate": 1_250_000.0,
    "total_hashes": 12_480_000,
    "best_height": 128,
    "mempool_depth": 32,
    "difficulty_bits": 50331670,
    "stale_share_rate": 0.012,
}

SAMPLE_NOTE_STATUS = {
    "leaf_count": 2048,
    "depth": 32,
    "root": 8731462512,
    "next_index": 2050,
}

SAMPLE_EVENTS: List[Dict[str, Any]] = [
    {
        "type": "telemetry",
        "hash_rate": 1_200_000.0,
        "best_height": 127,
        "mempool_depth": 28,
        "difficulty_bits": 50331670,
        "stale_share_rate": 0.01,
        "timestamp": _now_iso(),
    },
    {
        "type": "block",
        "height": 128,
        "hash": "mock-block-0128",
        "timestamp": _now_iso(),
    },
    {
        "type": "transaction",
        "tx_id": "mock-tx-9c7a",
        "timestamp": _now_iso(),
    },
]


@dataclass
class MinerControlState:
    is_running: bool = True
    target_hash_rate: float = 1_300_000.0
    thread_count: int = 2
    last_updated: float = time.time()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "target_hash_rate": self.target_hash_rate,
            "thread_count": self.thread_count,
            "last_updated": self.last_updated,
        }


@dataclass
class TransferRecord:
    id: str
    direction: Literal["incoming", "outgoing"]
    address: str
    memo: Optional[str]
    amount: float
    fee: float
    status: Literal["pending", "confirmed"]
    confirmations: int
    created_at: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "direction": self.direction,
            "address": self.address,
            "memo": self.memo,
            "amount": self.amount,
            "fee": self.fee,
            "status": self.status,
            "confirmations": self.confirmations,
            "created_at": self.created_at,
        }


class TransferPayload(BaseModel):
    address: str = Field(..., min_length=4)
    amount: float = Field(..., ge=0.0)
    fee: float = Field(0.0, ge=0.0)
    memo: Optional[str] = None


class MinerControlPayload(BaseModel):
    action: Literal["start", "stop"]
    target_hash_rate: Optional[float] = Field(default=None, ge=0.0)
    thread_count: Optional[int] = Field(default=None, ge=1)


MINER_STATE = MinerControlState()
TRANSFER_LOG: Deque[TransferRecord] = deque(
    [
        TransferRecord(
            id="bootstrap-transfer",
            direction="incoming",
            address="shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            memo="Genesis airdrop",
            amount=42.0,
            fee=0.0,
            status="confirmed",
            confirmations=64,
            created_at=_now_iso(),
        )
    ],
    maxlen=256,
)


def _node_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if NODE_RPC_TOKEN:
        headers["x-auth-token"] = NODE_RPC_TOKEN
    return headers


async def _fetch_node_json(path: str) -> Dict[str, Any]:
    if not NODE_RPC_URL:
        raise RuntimeError("NODE_RPC_URL is not configured")
    url = f"{NODE_RPC_URL}{path}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
        response = await client.get(url, headers=_node_headers())
    response.raise_for_status()
    return response.json()


async def _proxy_metrics() -> Dict[str, Any]:
    if not NODE_RPC_URL:
        return dict(SAMPLE_TELEMETRY)
    try:
        return await _fetch_node_json("/metrics")
    except httpx.HTTPError:
        return dict(SAMPLE_TELEMETRY)


async def _proxy_note_status() -> Dict[str, Any]:
    if not NODE_RPC_URL:
        return dict(SAMPLE_NOTE_STATUS)
    try:
        return await _fetch_node_json("/wallet/notes")
    except httpx.HTTPError:
        return dict(SAMPLE_NOTE_STATUS)


async def _node_event_messages() -> AsyncIterator[str]:
    if NODE_WS_URL:
        while True:
            try:
                async with websockets.connect(
                    NODE_WS_URL,
                    extra_headers=_node_headers(),
                    ping_interval=20,
                    ping_timeout=20,
                ) as ws:
                    async for message in ws:
                        yield message
            except Exception as exc:  # pragma: no cover - runtime resilience
                warning = json.dumps({"type": "warning", "message": str(exc)})
                yield warning
                await asyncio.sleep(STREAM_RECONNECT_SECONDS)
    else:
        index = 0
        while True:
            payload = dict(SAMPLE_EVENTS[index % len(SAMPLE_EVENTS)])
            payload["timestamp"] = _now_iso()
            yield json.dumps(payload)
            index += 1
            await asyncio.sleep(5)


def _append_transfer(payload: TransferPayload) -> TransferRecord:
    record = TransferRecord(
        id=uuid.uuid4().hex,
        direction="outgoing",
        address=payload.address,
        memo=payload.memo,
        amount=float(payload.amount),
        fee=float(payload.fee),
        status="pending",
        confirmations=0,
        created_at=_now_iso(),
    )
    TRANSFER_LOG.appendleft(record)
    return record

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


@app.get("/node/metrics")
async def node_metrics() -> Dict[str, Any]:
    return await _proxy_metrics()


@app.get("/node/wallet/notes")
async def node_wallet_notes() -> Dict[str, Any]:
    return await _proxy_note_status()


@app.get("/node/miner/status")
async def node_miner_status() -> Dict[str, Any]:
    metrics = await _proxy_metrics()
    payload = MINER_STATE.as_dict()
    payload["metrics"] = metrics
    return payload


@app.post("/node/miner/control")
async def node_miner_control(payload: MinerControlPayload) -> Dict[str, Any]:
    MINER_STATE.last_updated = time.time()
    MINER_STATE.is_running = payload.action == "start"
    if payload.target_hash_rate is not None:
        MINER_STATE.target_hash_rate = float(payload.target_hash_rate)
    if payload.thread_count is not None:
        MINER_STATE.thread_count = int(payload.thread_count)
    return {"status": "ok", "state": MINER_STATE.as_dict()}


@app.get("/node/wallet/transfers")
def node_transfer_history() -> Dict[str, Any]:
    return {"transfers": [record.as_dict() for record in TRANSFER_LOG]}


@app.post("/node/wallet/transfers")
async def node_submit_transfer(payload: TransferPayload) -> Dict[str, Any]:
    record = _append_transfer(payload)
    return {"transfer": record.as_dict()}


@app.get("/node/events/stream")
async def node_events_stream() -> StreamingResponse:
    async def event_generator() -> AsyncIterator[str]:
        async for message in _node_event_messages():
            yield f"data: {message}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


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
