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
import shutil
import secrets
import json
import os
import ssl
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Literal

import httpx
import websockets
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ValidationError

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

app = FastAPI(title="HEGEMON Ops Dashboard Service")
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
WALLET_API_URL = os.environ.get("WALLET_API_URL")
if WALLET_API_URL:
    WALLET_API_URL = WALLET_API_URL.rstrip("/")
WALLET_API_TOKEN = os.environ.get("WALLET_API_TOKEN", "")
STREAM_RECONNECT_SECONDS = 3.0
# Default to autostarting a local devnet node so the dashboard shows live mining
# immediately after `make quickstart`. Users can disable by setting
# DASHBOARD_AUTOSTART_NODE=0.
AUTOSTART_NODE = os.environ.get("DASHBOARD_AUTOSTART_NODE", "1").lower() in ("1", "true", "yes", "on")
AUTOSTART_NODE_HOST = os.environ.get("DASHBOARD_NODE_HOST", "127.0.0.1")
AUTOSTART_NODE_API_ADDR = os.environ.get("DASHBOARD_NODE_API_ADDR")
AUTOSTART_NODE_DB_PATH = os.environ.get(
    "DASHBOARD_NODE_DB_PATH", str(REPO_ROOT / "state" / "dashboard-node.db")
)
AUTOSTART_NODE_TOKEN = os.environ.get("DASHBOARD_NODE_TOKEN", "devnet-token")


def _parse_optional_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_port(value: Optional[str], default: int) -> int:
    parsed = _parse_optional_int(value)
    return parsed if parsed and parsed > 0 else default


AUTOSTART_NODE_PORT = _parse_port(os.environ.get("DASHBOARD_NODE_PORT", "8080"), 8080)
AUTOSTART_NODE_WORKERS = _parse_optional_int(os.environ.get("DASHBOARD_NODE_MINER_WORKERS"))
AUTOSTART_NODE_TREE_DEPTH = _parse_optional_int(os.environ.get("DASHBOARD_NODE_NOTE_TREE_DEPTH"))
AUTOSTART_NODE_SEED = os.environ.get("DASHBOARD_NODE_MINER_SEED")
AUTOSTART_WALLET = os.environ.get("DASHBOARD_AUTOSTART_WALLET", "1").lower() in ("1", "true", "yes", "on")
AUTOSTART_WALLET_HOST = os.environ.get("DASHBOARD_WALLET_HOST", "127.0.0.1")
AUTOSTART_WALLET_PORT = _parse_port(os.environ.get("DASHBOARD_WALLET_PORT", "61005"), 61005)
AUTOSTART_WALLET_STORE = os.environ.get(
    "DASHBOARD_WALLET_STORE", str(REPO_ROOT / "state" / "dashboard-wallet.store")
)
AUTOSTART_WALLET_META = os.environ.get(
    "DASHBOARD_WALLET_META", str(REPO_ROOT / "state" / "dashboard-wallet.meta.json")
)
AUTOSTART_WALLET_PASSPHRASE = os.environ.get("DASHBOARD_WALLET_PASSPHRASE", "test passphrase")
AUTOSTART_WALLET_SEED = os.environ.get("DASHBOARD_WALLET_SEED")


def _build_ws_url(base_url: str) -> str:
    parsed = httpx.URL(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return str(parsed.copy_with(scheme=scheme, path="/ws", query=None))


NODE_WS_URL = _build_ws_url(NODE_RPC_URL) if NODE_RPC_URL else None


def _set_node_rpc(url: Optional[str], token: str) -> None:
    global NODE_RPC_URL, NODE_RPC_TOKEN, NODE_WS_URL
    NODE_RPC_URL = url.rstrip("/") if url else None
    NODE_RPC_TOKEN = token
    NODE_WS_URL = _build_ws_url(NODE_RPC_URL) if NODE_RPC_URL else None


def _set_wallet_api(url: Optional[str], token: Optional[str] = None) -> None:
    global WALLET_API_URL, WALLET_API_TOKEN
    WALLET_API_URL = url.rstrip("/") if url else None
    if token is not None:
        WALLET_API_TOKEN = token


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


GENESIS_TRANSFER_TIMESTAMP = "2025-01-01T00:00:00Z"

SAMPLE_TELEMETRY = {
    "hash_rate": 1_250_000.0,
    "total_hashes": 12_480_000,
    "best_height": 128,
    "mempool_depth": 32,
    "difficulty_bits": 50331670,
    "stale_share_rate": 0.012,
    "tls_enabled": True,
    "mtls_enabled": True,
    "tor_enabled": False,
    "vpn_overlay": False,
    "exposure_scope": "local",
}

SAMPLE_NOTE_STATUS = {
    "leaf_count": 2048,
    "depth": 32,
    "root": 8731462512,
    "next_index": 2050,
}

MOCK_TRANSFERS: List[Dict[str, Any]] = [
    {
        "id": "bootstrap-transfer",
        "tx_id": "bootstrap-transfer",
        "direction": "incoming",
        "address": "shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        "memo": "Genesis airdrop",
        "amount": 4_200_000_000,
        "fee": 0,
        "status": "confirmed",
        "confirmations": 64,
        "created_at": GENESIS_TRANSFER_TIMESTAMP,
    }
]
MOCK_WALLET_STATUS: Dict[str, Any] = {
    "mode": "Full",
    "primary_address": "shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
    "balances": {"1": 4_200_000_000},
    "last_synced_height": 0,
    "pending": [],
}

WALLET_META_PATH = Path(AUTOSTART_WALLET_META)
WALLET_STORE_PATH = Path(AUTOSTART_WALLET_STORE)
WALLET_LOG_PATH = REPO_ROOT / "state" / "wallet-process.log"
WALLET_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


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


class TransferPayload(BaseModel):
    address: str = Field(..., min_length=4)
    amount: float = Field(..., ge=0.0)
    fee: float = Field(0.0, ge=0.0)
    memo: Optional[str] = None


class MinerControlPayload(BaseModel):
    action: Literal["start", "stop"]
    target_hash_rate: Optional[float] = Field(default=None, ge=0.0)
    thread_count: Optional[int] = Field(default=None, ge=1)


class NodeRoutingPayload(BaseModel):
    tls: bool = False
    mtls: bool = False
    doh: bool = False
    vpn: bool = False
    tor: bool = False
    local_only: bool = True


class NodeLifecyclePayload(BaseModel):
    mode: Literal["genesis", "join"]
    host: str = Field(..., min_length=1)
    port: int = Field(..., ge=1, le=65535)
    peer_url: Optional[str] = Field(default=None, min_length=6)
    routing: NodeRoutingPayload


class NodeLaunchPayload(NodeLifecyclePayload):
    db_path: Optional[str] = None
    api_addr: Optional[str] = None
    api_token: Optional[str] = None
    miner_workers: Optional[int] = Field(default=None, ge=1)
    note_tree_depth: Optional[int] = Field(default=None, ge=1)
    miner_seed: Optional[str] = Field(default=None, min_length=64, max_length=64)
    wallet_store: Optional[str] = None
    wallet_passphrase: Optional[str] = None


MINER_STATE = MinerControlState()
NODE_LIFECYCLE_STATE: Dict[str, Any] = {
    "mode": "genesis",
    "host": "127.0.0.1",
    "port": 8080,
    "peer_url": None,
    "routing": NodeRoutingPayload().model_dump(),
    "applied_at": _now_iso(),
}
NODE_LOG_PATH = REPO_ROOT / "state" / "node-process.log"
NODE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class WalletMaterial:
    seed_hex: str
    passphrase: str
    store_path: str
    meta_path: str
    api_host: str
    api_port: int
    created_at: str


@dataclass
class NodeProcessState:
    status: Literal["idle", "starting", "running", "exited", "error"] = "idle"
    pid: Optional[int] = None
    started_at: Optional[str] = None
    exited_at: Optional[str] = None
    return_code: Optional[int] = None
    stderr_tail: List[str] = field(default_factory=list)
    node_url: Optional[str] = None
    api_addr: Optional[str] = None
    api_token: Optional[str] = None
    db_path: Optional[str] = None
    last_error: Optional[str] = None
    command: Optional[List[str]] = None
    log_path: str = str(NODE_LOG_PATH)


class NodeProcessSupervisor:
    def __init__(self) -> None:
        self.process: Optional[asyncio.subprocess.Process] = None
        self.state = NodeProcessState()
        self._lock = asyncio.Lock()

    def snapshot(self) -> Dict[str, Any]:
        return asdict(self.state)

    def _append_log(self, line: str) -> None:
        timestamped = f"[{_now_iso()}] {line.rstrip()}"
        tail = self.state.stderr_tail + [timestamped]
        self.state.stderr_tail = tail[-100:]
        try:
            with NODE_LOG_PATH.open("a", encoding="utf-8") as log_file:
                log_file.write(timestamped + "\n")
        except OSError:
            pass

    async def _capture_output(self, process: asyncio.subprocess.Process) -> None:
        async def drain(stream: Optional[asyncio.StreamReader]) -> None:
            if not stream:
                return
            while True:
                line = await stream.readline()
                if not line:
                    break
                self._append_log(line.decode(errors="replace"))

        await asyncio.gather(drain(process.stderr), drain(process.stdout))

    async def _wait_for_exit(self, process: asyncio.subprocess.Process) -> None:
        return_code = await process.wait()
        async with self._lock:
            if process is not self.process:
                return
            self.state.return_code = return_code
            self.state.exited_at = _now_iso()
            if self.state.status != "error":
                self.state.status = "exited" if return_code == 0 else "error"
            self.process = None

    async def start(self, payload: NodeLaunchPayload) -> Dict[str, Any]:
        async with self._lock:
            if self.process and self.process.returncode is None:
                raise HTTPException(status_code=409, detail={"error": "Node process already running."})

            api_host = "127.0.0.1" if payload.routing.local_only else payload.host
            api_addr = payload.api_addr or f"{api_host}:{payload.port}"
            api_token = payload.api_token or f"node-{uuid.uuid4().hex[:8]}"
            db_path = payload.db_path or "node.db"
            db_path_path = Path(db_path)
            db_path_path.parent.mkdir(parents=True, exist_ok=True)
            db_path = str(db_path_path)

            node_url = _build_node_url(api_host, payload.port, payload.routing.tls)
            command = [
                "cargo",
                "run",
                "-p",
                "node",
                "--bin",
                "hegemon",
                "--",
                "--db-path",
                db_path,
                "--api-addr",
                api_addr,
                "--api-token",
                api_token,
            ]
            if payload.routing.tls:
                command.append("--tls")

            if payload.miner_workers is not None:
                command.extend(["--miner-workers", str(payload.miner_workers)])
            if payload.note_tree_depth is not None:
                command.extend(["--note-tree-depth", str(payload.note_tree_depth)])
            if payload.miner_seed is not None:
                command.extend(["--miner-seed", payload.miner_seed])
            if payload.wallet_store is not None:
                command.extend(["--wallet-store", payload.wallet_store])
            if payload.wallet_passphrase is not None:
                command.extend(["--wallet-passphrase", payload.wallet_passphrase])

            _record_lifecycle(payload)
            sanitized_command = list(command)
            if payload.wallet_passphrase:
                sanitized_command = [
                    "<redacted>" if arg == payload.wallet_passphrase else arg for arg in sanitized_command
                ]
            self.state = NodeProcessState(
                status="starting",
                pid=None,
                started_at=_now_iso(),
                stderr_tail=[],
                node_url=node_url,
                api_addr=api_addr,
                api_token=api_token,
                db_path=db_path,
                last_error=None,
                command=sanitized_command,
            )

            cargo_path = shutil.which(command[0])
            if not cargo_path:
                default_cargo = Path.home() / ".cargo" / "bin" / "cargo"
                if default_cargo.exists():
                    cargo_path = str(default_cargo)

            if not cargo_path:
                message = (
                    "Required command 'cargo' not found. If Rust is already installed via rustup, "
                    'add "$HOME/.cargo/bin" to your PATH (e.g., export PATH="$HOME/.cargo/bin:$PATH") '
                    "and retry. Otherwise install the toolchain with `./scripts/dev-setup.sh`."
                )
                self.state.status = "error"
                self.state.last_error = message
                raise HTTPException(status_code=500, detail={"error": message})

            try:
                self.process = await asyncio.create_subprocess_exec(
                    cargo_path,
                    *command[1:],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(REPO_ROOT),
                )
            except FileNotFoundError as exc:
                self.state.status = "error"
                self.state.last_error = str(exc)
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error": (
                            "Failed to start node process. Ensure the Rust toolchain is installed "
                            "and retry `make quickstart` to download dependencies."
                        )
                    },
                ) from exc

            self.state.pid = self.process.pid
            _set_node_rpc(node_url, api_token)

            asyncio.create_task(self._capture_output(self.process))
            asyncio.create_task(self._wait_for_exit(self.process))

        await asyncio.sleep(0.4)
        if self.process and self.process.returncode is not None:
            last_line = self.state.stderr_tail[-1] if self.state.stderr_tail else None
            last_hint = f" Last stderr: {last_line}" if last_line else ""
            message = (
                "Node process exited during startup." f"{last_hint}"
                f" See {self.state.log_path} for the full log."
            )
            async with self._lock:
                self.state.status = "error"
                self.state.last_error = message
                self.state.exited_at = _now_iso()
                self.state.return_code = self.process.returncode
                self.process = None
            raise HTTPException(
                status_code=500,
                detail={
                    "error": message,
                    "stderr": self.state.stderr_tail,
                    "log_path": self.state.log_path,
                    "return_code": self.state.return_code,
                },
            )

        async with self._lock:
            if self.state.status == "starting":
                self.state.status = "running"
        return self.snapshot()

    async def stop(self) -> None:
        async with self._lock:
            process = self.process
        if not process or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        async with self._lock:
            self.state.status = "exited"
            self.state.exited_at = _now_iso()
            self.state.return_code = process.returncode
            self.process = None


NODE_PROCESS = NodeProcessSupervisor()


def _persist_wallet_metadata(payload: Dict[str, Any]) -> None:
    WALLET_META_PATH.parent.mkdir(parents=True, exist_ok=True)
    WALLET_META_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(WALLET_META_PATH, 0o600)
    except OSError:
        pass


def _load_wallet_material() -> WalletMaterial:
    if WALLET_META_PATH.exists():
        try:
            data = json.loads(WALLET_META_PATH.read_text(encoding="utf-8"))
            return WalletMaterial(
                seed_hex=str(data.get("seed_hex") or "").strip() or (AUTOSTART_WALLET_SEED or secrets.token_hex(32)),
                passphrase=str(
                    (AUTOSTART_WALLET_PASSPHRASE or "").strip()
                    or data.get("passphrase")
                    or secrets.token_urlsafe(16)
                ),
                store_path=str(WALLET_STORE_PATH),
                meta_path=str(WALLET_META_PATH),
                api_host=str(data.get("api_host") or AUTOSTART_WALLET_HOST),
                api_port=int(data.get("api_port") or AUTOSTART_WALLET_PORT),
                created_at=str(data.get("created_at") or data.get("createdAt") or _now_iso()),
            )
        except (ValueError, OSError, TypeError):
            # fall through to regenerate metadata
            pass
    seed_hex = (AUTOSTART_WALLET_SEED or secrets.token_hex(32)).lower()
    passphrase = AUTOSTART_WALLET_PASSPHRASE or secrets.token_urlsafe(16)
    material = WalletMaterial(
        seed_hex=seed_hex,
        passphrase=passphrase,
        store_path=str(WALLET_STORE_PATH),
        meta_path=str(WALLET_META_PATH),
        api_host=AUTOSTART_WALLET_HOST,
        api_port=AUTOSTART_WALLET_PORT,
        created_at=_now_iso(),
    )
    _persist_wallet_metadata(
        {
            "seed_hex": material.seed_hex,
            "passphrase": material.passphrase,
            "store_path": material.store_path,
            "api_host": material.api_host,
            "api_port": material.api_port,
            "created_at": material.created_at,
        }
    )
    return material


def _init_wallet_store(material: WalletMaterial) -> None:
    store_path = Path(material.store_path)
    if store_path.exists():
        return
    store_path.parent.mkdir(parents=True, exist_ok=True)
    cargo_path = shutil.which("cargo")
    if not cargo_path:
        default_cargo = Path.home() / ".cargo" / "bin" / "cargo"
        if default_cargo.exists():
            cargo_path = str(default_cargo)
    if not cargo_path:
        raise RuntimeError(
            "Required command 'cargo' not found. Install the Rust toolchain or add $HOME/.cargo/bin to PATH."
        )
    command = [
        cargo_path,
        "run",
        "-p",
        "wallet",
        "--bin",
        "wallet",
        "--",
        "init",
        "--store",
        str(store_path),
        "--passphrase",
        material.passphrase,
        "--root-hex",
        material.seed_hex,
    ]
    result = subprocess.run(command, cwd=str(REPO_ROOT), capture_output=True, text=True)
    if result.returncode != 0:
        stderr = result.stderr or ""
        stdout = result.stdout or ""
        raise RuntimeError(f"wallet init failed ({result.returncode}): {stderr or stdout}")


@dataclass
class WalletProcessState:
    status: Literal["idle", "starting", "running", "exited", "error"] = "idle"
    pid: Optional[int] = None
    started_at: Optional[str] = None
    exited_at: Optional[str] = None
    return_code: Optional[int] = None
    stderr_tail: List[str] = field(default_factory=list)
    api_url: Optional[str] = None
    last_error: Optional[str] = None
    command: Optional[List[str]] = None
    log_path: str = str(WALLET_LOG_PATH)


class WalletProcessSupervisor:
    def __init__(self) -> None:
        self.process: Optional[asyncio.subprocess.Process] = None
        self.state = WalletProcessState()
        self._lock = asyncio.Lock()

    def snapshot(self) -> Dict[str, Any]:
        return asdict(self.state)

    def _append_log(self, line: str) -> None:
        timestamped = f"[{_now_iso()}] {line.rstrip()}"
        tail = self.state.stderr_tail + [timestamped]
        self.state.stderr_tail = tail[-100:]
        try:
            with WALLET_LOG_PATH.open("a", encoding="utf-8") as log_file:
                log_file.write(timestamped + "\n")
        except OSError:
            pass

    async def _capture_output(self, process: asyncio.subprocess.Process) -> None:
        async def drain(stream: Optional[asyncio.StreamReader]) -> None:
            if not stream:
                return
            while True:
                line = await stream.readline()
                if not line:
                    break
                self._append_log(line.decode(errors="replace"))

        await asyncio.gather(drain(process.stderr), drain(process.stdout))

    async def _wait_for_exit(self, process: asyncio.subprocess.Process) -> None:
        return_code = await process.wait()
        async with self._lock:
            if process is not self.process:
                return
            self.state.return_code = return_code
            self.state.exited_at = _now_iso()
            if self.state.status != "error":
                self.state.status = "exited" if return_code == 0 else "error"
            self.process = None

    async def start(self, material: WalletMaterial, node_url: str, node_token: str) -> Dict[str, Any]:
        async with self._lock:
            if self.process and self.process.returncode is None:
                raise HTTPException(status_code=409, detail={"error": "Wallet process already running."})

            api_url = f"http://{material.api_host}:{material.api_port}"
            command = [
                "cargo",
                "run",
                "-p",
                "wallet",
                "--bin",
                "wallet",
                "--",
                "daemon",
                "--store",
                material.store_path,
                "--passphrase",
                material.passphrase,
                "--rpc-url",
                node_url,
                "--auth-token",
                node_token,
                "--http-listen",
                f"{material.api_host}:{material.api_port}",
            ]
            cargo_path = shutil.which(command[0])
            if not cargo_path:
                fallback = Path.home() / ".cargo" / "bin" / "cargo"
                if fallback.exists():
                    cargo_path = str(fallback)
            if not cargo_path:
                message = (
                    "Required command 'cargo' not found. Install the Rust toolchain and retry "
                    "or add $HOME/.cargo/bin to PATH."
                )
                self.state.status = "error"
                self.state.last_error = message
                raise HTTPException(status_code=500, detail={"error": message})

            try:
                self.process = await asyncio.create_subprocess_exec(
                    cargo_path,
                    *command[1:],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(REPO_ROOT),
                )
            except FileNotFoundError as exc:
                self.state.status = "error"
                self.state.last_error = str(exc)
                raise HTTPException(status_code=500, detail={"error": str(exc)}) from exc

            self.state = WalletProcessState(
                status="starting",
                pid=self.process.pid,
                started_at=_now_iso(),
                stderr_tail=[],
                api_url=api_url,
                command=command,
            )

            asyncio.create_task(self._capture_output(self.process))
            asyncio.create_task(self._wait_for_exit(self.process))

        await asyncio.sleep(0.4)
        if self.process and self.process.returncode is not None:
            last_line = self.state.stderr_tail[-1] if self.state.stderr_tail else None
            last_hint = f" Last stderr: {last_line}" if last_line else ""
            message = f"Wallet process exited during startup.{last_hint} See {self.state.log_path} for details."
            async with self._lock:
                self.state.status = "error"
                self.state.last_error = message
                self.state.exited_at = _now_iso()
                self.state.return_code = self.process.returncode
                self.process = None
            raise HTTPException(
                status_code=500,
                detail={"error": message, "stderr": self.state.stderr_tail, "log_path": self.state.log_path},
            )

        async with self._lock:
            if self.state.status == "starting":
                self.state.status = "running"
        return self.snapshot()

    async def stop(self) -> None:
        async with self._lock:
            process = self.process
        if not process or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        async with self._lock:
            self.state.status = "exited"
            self.state.exited_at = _now_iso()
            self.state.return_code = process.returncode
            self.process = None


WALLET_PROCESS = WalletProcessSupervisor()


def _prepare_dashboard_wallet() -> Optional[WalletMaterial]:
    if not AUTOSTART_WALLET:
        return None
    try:
        material = _load_wallet_material()
        if not AUTOSTART_NODE_SEED:
            # Ensure miner payout tracks the same seed as the wallet store.
            globals()["AUTOSTART_NODE_SEED"] = material.seed_hex
        if not WALLET_API_URL:
            _set_wallet_api(f"http://{material.api_host}:{material.api_port}", WALLET_API_TOKEN)
        return material
    except Exception as exc:
        print(f"[dashboard] Wallet bootstrap failed: {exc}", file=sys.stderr)
        return None


def _build_autostart_payload() -> Optional[NodeLaunchPayload]:
    try:
        return NodeLaunchPayload(
            mode="genesis",
            host=AUTOSTART_NODE_HOST,
            port=AUTOSTART_NODE_PORT,
            peer_url=None,
            routing=NodeRoutingPayload(local_only=True),
            db_path=AUTOSTART_NODE_DB_PATH,
            api_addr=AUTOSTART_NODE_API_ADDR,
            api_token=AUTOSTART_NODE_TOKEN,
            miner_workers=AUTOSTART_NODE_WORKERS,
            note_tree_depth=AUTOSTART_NODE_TREE_DEPTH,
            miner_seed=AUTOSTART_NODE_SEED.strip() if AUTOSTART_NODE_SEED else None,
            wallet_store=str(WALLET_STORE_PATH),
            wallet_passphrase=AUTOSTART_WALLET_PASSPHRASE,
        )
    except ValidationError as exc:
        print(f"[dashboard] Autostart node config invalid: {exc}", file=sys.stderr)
        return None


async def _maybe_autostart_node() -> None:
    if not AUTOSTART_NODE:
        return
    payload = _build_autostart_payload()
    if not payload:
        return
    try:
        await NODE_PROCESS.start(payload)
        node_url = _build_node_url(payload.host, payload.port, payload.routing.tls)
        print(f"[dashboard] Autostarted local node at {node_url}", file=sys.stderr)
    except HTTPException as exc:
        detail = exc.detail.get("error") if isinstance(exc.detail, dict) else exc.detail
        print(f"[dashboard] Autostart failed: {detail}", file=sys.stderr)
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"[dashboard] Autostart crashed: {exc}", file=sys.stderr)


async def _maybe_autostart_wallet(material: Optional[WalletMaterial]) -> None:
    if not AUTOSTART_WALLET or not material:
        return
    if not NODE_RPC_URL:
        print("[dashboard] Skipping wallet autostart: NODE_RPC_URL is not configured.", file=sys.stderr)
        return
    try:
        await WALLET_PROCESS.start(material, NODE_RPC_URL, NODE_RPC_TOKEN)
        if not WALLET_API_URL:
            _set_wallet_api(f"http://{material.api_host}:{material.api_port}", WALLET_API_TOKEN)
        print(f"[dashboard] Autostarted wallet daemon at http://{material.api_host}:{material.api_port}", file=sys.stderr)
    except HTTPException as exc:
        detail = exc.detail.get("error") if isinstance(exc.detail, dict) else exc.detail
        print(f"[dashboard] Wallet autostart failed: {detail}", file=sys.stderr)
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"[dashboard] Wallet autostart crashed: {exc}", file=sys.stderr)


async def _autostart_stack() -> None:
    wallet_material = _prepare_dashboard_wallet()
    if wallet_material:
        try:
            await asyncio.to_thread(_init_wallet_store, wallet_material)
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"[dashboard] Wallet store init failed: {exc}", file=sys.stderr)
            wallet_material = None
    await _maybe_autostart_node()
    if wallet_material:
        await _maybe_autostart_wallet(wallet_material)


@app.on_event("startup")
async def _startup_autostart() -> None:
    asyncio.create_task(_autostart_stack())


@app.on_event("shutdown")
async def _shutdown_cleanup() -> None:
    await NODE_PROCESS.stop()
    await WALLET_PROCESS.stop()


def _node_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if NODE_RPC_TOKEN:
        headers["x-auth-token"] = NODE_RPC_TOKEN
    return headers


async def _fetch_node_json(path: str) -> Dict[str, Any]:
    if not NODE_RPC_URL:
        raise RuntimeError("NODE_RPC_URL is not configured")
    url = f"{NODE_RPC_URL}{path}"
    
    verify_ssl: bool | str = True
    cert_path = REPO_ROOT / "cert.pem"
    if cert_path.exists():
        verify_ssl = str(cert_path)

    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0), verify=verify_ssl) as client:
        response = await client.get(url, headers=_node_headers())
    response.raise_for_status()
    return response.json()


def _wallet_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if WALLET_API_TOKEN:
        headers["x-wallet-token"] = WALLET_API_TOKEN
    return headers


async def _wallet_request(method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not WALLET_API_URL:
        raise RuntimeError("WALLET_API_URL is not configured")
    url = f"{WALLET_API_URL}{path}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        response = await client.request(method, url, headers=_wallet_headers(), json=payload)
    response.raise_for_status()
    return response.json()


def _build_node_url(host: str, port: int, tls_enabled: bool) -> str:
    scheme = "https" if tls_enabled else "http"
    return f"{scheme}://{host}:{port}"


def _routing_overlays(routing: NodeRoutingPayload) -> List[str]:
    overlays: List[str] = []
    if routing.vpn:
        overlays.append("vpn")
    if routing.tor:
        overlays.append("tor")
    if routing.doh:
        overlays.append("doh")
    return overlays


def _validate_lifecycle_payload(payload: NodeLifecyclePayload) -> None:
    if payload.mode == "join" and not payload.peer_url:
        raise HTTPException(status_code=422, detail={"error": "Joining a network requires a peer node_url."})
    if payload.routing.mtls and not payload.routing.tls:
        raise HTTPException(status_code=422, detail={"error": "Mutual TLS requires TLS to be enabled."})
    if payload.routing.local_only and (payload.routing.vpn or payload.routing.tor):
        raise HTTPException(
            status_code=422,
            detail={"error": "Local-only RPC cannot be combined with Tor or VPN relays."},
        )


def _record_lifecycle(payload: NodeLifecyclePayload) -> Dict[str, Any]:
    node_url = _build_node_url(payload.host, payload.port, payload.routing.tls)
    NODE_LIFECYCLE_STATE.update(
        {
            "mode": payload.mode,
            "host": payload.host,
            "port": payload.port,
            "peer_url": payload.peer_url,
            "routing": payload.routing.model_dump(),
            "node_url": node_url,
            "applied_at": _now_iso(),
            "overlays": _routing_overlays(payload.routing),
        }
    )
    return {
        "node_url": node_url,
        "routing": NODE_LIFECYCLE_STATE["routing"],
        "overlays": NODE_LIFECYCLE_STATE["overlays"],
        "applied_at": NODE_LIFECYCLE_STATE["applied_at"],
    }


async def _proxy_metrics() -> Dict[str, Any]:
    if not NODE_RPC_URL:
        return _with_mock_flag(SAMPLE_TELEMETRY)
    try:
        return await _fetch_node_json("/metrics")
    except httpx.HTTPError:
        return _with_mock_flag(SAMPLE_TELEMETRY)


async def _proxy_note_status() -> Dict[str, Any]:
    if not NODE_RPC_URL:
        return _with_mock_flag(SAMPLE_NOTE_STATUS)
    try:
        return await _fetch_node_json("/wallet/notes")
    except httpx.HTTPError:
        return _with_mock_flag(SAMPLE_NOTE_STATUS)


async def _node_event_messages() -> AsyncIterator[str]:
    while True:
        if not NODE_WS_URL:
            warning = json.dumps(
                {
                    "type": "warning",
                    "message": "Node RPC URL is not configured; start a node to stream live events.",
                    "timestamp": _now_iso(),
                }
            )
            yield warning
            await asyncio.sleep(STREAM_RECONNECT_SECONDS)
            continue
        try:
            ssl_context = None
            if NODE_WS_URL.startswith("wss://"):
                ssl_context = ssl.create_default_context()
                cert_path = REPO_ROOT / "cert.pem"
                if cert_path.exists():
                    ssl_context.load_verify_locations(str(cert_path))

            async with websockets.connect(
                NODE_WS_URL,
                extra_headers=_node_headers(),
                ping_interval=20,
                ping_timeout=20,
                ssl=ssl_context,
            ) as ws:
                async for message in ws:
                    yield message
        except Exception as exc:  # pragma: no cover - runtime resilience
            warning = json.dumps(
                {
                    "type": "warning",
                    "message": f"Event stream disconnected: {exc}",
                    "timestamp": _now_iso(),
                }
            )
            yield warning
            await asyncio.sleep(STREAM_RECONNECT_SECONDS)


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


@app.post("/node/lifecycle")
async def node_lifecycle(payload: NodeLifecyclePayload) -> Dict[str, Any]:
    _validate_lifecycle_payload(payload)
    record = _record_lifecycle(payload)
    response = {
        "status": "ok",
        "mode": payload.mode,
        "node_url": record["node_url"],
        "peer_url": payload.peer_url,
        "routing": record["routing"],
        "local_rpc_only": payload.routing.local_only,
        "overlays": record["overlays"],
        "applied_at": record["applied_at"],
    }
    return response


@app.post("/node/process/start")
async def node_process_start(payload: NodeLaunchPayload) -> Dict[str, Any]:
    _validate_lifecycle_payload(payload)
    return await NODE_PROCESS.start(payload)


@app.get("/node/process")
async def node_process_status() -> Dict[str, Any]:
    return NODE_PROCESS.snapshot()


@app.get("/node/metrics")
async def node_metrics() -> Dict[str, Any]:
    return await _proxy_metrics()


@app.get("/node/wallet/notes")
async def node_wallet_notes() -> Dict[str, Any]:
    return await _proxy_note_status()


@app.get("/node/miner/status")
async def node_miner_status() -> Dict[str, Any]:
    metrics = await _proxy_metrics()
    mock_flag = bool(metrics.pop("__mock_source", False))
    payload = MINER_STATE.as_dict()
    payload["metrics"] = metrics
    if mock_flag:
        payload["__mock_source"] = True
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


@app.get("/node/wallet/status")
async def node_wallet_status() -> Dict[str, Any]:
    if not WALLET_API_URL:
        return _with_mock_flag(dict(MOCK_WALLET_STATUS))
    try:
        return await _wallet_request("GET", "/status")
    except httpx.HTTPStatusError as exc:  # pragma: no cover - bubble status
        detail = (
            exc.response.json()
            if exc.response.headers.get("content-type", "").startswith("application/json")
            else {"error": exc.response.text}
        )
        raise HTTPException(status_code=exc.response.status_code, detail=detail)
    except httpx.HTTPError:
        return _with_mock_flag(dict(MOCK_WALLET_STATUS))


@app.get("/node/wallet/transfers")
async def node_transfer_history() -> Dict[str, Any]:
    if not WALLET_API_URL:
        return _with_mock_flag({"transfers": MOCK_TRANSFERS})
    try:
        return await _wallet_request("GET", "/transfers")
    except httpx.HTTPStatusError as exc:  # pragma: no cover - bubble status
        detail = exc.response.json() if exc.response.headers.get("content-type", "").startswith("application/json") else {"error": exc.response.text}
        raise HTTPException(status_code=exc.response.status_code, detail=detail)
    except httpx.HTTPError:
        return _with_mock_flag({"transfers": MOCK_TRANSFERS})


@app.post("/node/wallet/transfers")
async def node_submit_transfer(payload: TransferPayload) -> Dict[str, Any]:
    wallet_payload = {
        "recipients": [
            {
                "address": payload.address,
                "value": int(payload.amount),
                "asset_id": 1,
                "memo": payload.memo,
            }
        ],
        "fee": int(payload.fee),
    }
    if not WALLET_API_URL:
        mock = MOCK_TRANSFERS.copy()
        tx_id = uuid.uuid4().hex
        mock.insert(
            0,
            {
                "id": tx_id,
                "tx_id": tx_id,
                "direction": "outgoing",
                "address": payload.address,
                "memo": payload.memo,
                "amount": float(payload.amount),
                "fee": float(payload.fee),
                "status": "pending",
                "confirmations": 0,
                "created_at": _now_iso(),
            },
        )
        return {"transfer": mock[0]}
    try:
        return await _wallet_request("POST", "/transfers", wallet_payload)
    except httpx.HTTPStatusError as exc:
        detail = exc.response.json() if exc.response.headers.get("content-type", "").startswith("application/json") else {"error": exc.response.text}
        raise HTTPException(status_code=exc.response.status_code, detail=detail)
    except httpx.HTTPError:
        return {"transfer": MOCK_TRANSFERS[0]}


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


def _with_mock_flag(payload: Dict[str, Any]) -> Dict[str, Any]:
    body = dict(payload)
    body["__mock_source"] = True
    return body
