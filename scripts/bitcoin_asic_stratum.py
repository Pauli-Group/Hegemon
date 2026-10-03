#!/usr/bin/env python3
"""Small, fixed-version Stratum V1 bridge for Hegemon Bitcoin80 work.

This is a local pool adapter, not a Bitcoin wallet or ledger. The native node
owns block templates, consensus targets, and final block admission.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import queue
import secrets
import socket
import socketserver
import threading
import time
from typing import Any
from urllib.request import Request, urlopen


LOG = logging.getLogger("hegemon.stratum")
MAX_LINE = 8192
MAX_RPC_RESPONSE = 65536
MAX_SEEN_SHARES = 262144
MAX_JOBS = 64
MAX_NETWORK_SUCCESS = 4096
MAX_OUTBOUND_MESSAGES = 8
DIFF1_TARGET = int("00000000ffff" + "00" * 26, 16)
MAX_TARGET = (1 << 256) - 1
MAX_POW_TARGET = 0x7FFFFF << 232  # canonical Bitcoin compact 0x207fffff
EXTRANONCE1_BYTES = 24
EXTRANONCE2_BYTES = 4


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def fixed_hex(value: Any, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length:
        raise ValueError(f"{label} must be {length} hex characters")
    if not all(ch in "0123456789abcdefABCDEF" for ch in value):
        raise ValueError(f"{label} must be hex")
    return value.lower()


def compact_target(nbits: str) -> int:
    bits = int(nbits, 16)
    exponent, mantissa = bits >> 24, bits & 0x00FFFFFF
    if not mantissa or mantissa & 0x00800000 or exponent > 32:
        raise ValueError("invalid compact target")
    target = (mantissa >> (8 * (3 - exponent)) if exponent <= 3
              else mantissa << (8 * (exponent - 3)))
    if not target or target > MAX_POW_TARGET:
        raise ValueError("invalid compact target")
    size = (target.bit_length() + 7) // 8
    encoded_mantissa = (target << (8 * (3 - size)) if size <= 3
                        else target >> (8 * (size - 3)))
    if encoded_mantissa & 0x00800000:
        encoded_mantissa >>= 8
        size += 1
    if (size << 24) | encoded_mantissa != bits:
        raise ValueError("noncanonical compact target")
    return target


def share_target(difficulty: str) -> int:
    try:
        value = Decimal(difficulty)
        if not value.is_finite() or not Decimal("1e-12") <= value <= Decimal("1e12"):
            raise ValueError("share difficulty must be between 1e-12 and 1e12")
        ratio = Fraction(value)
    except InvalidOperation as exc:
        raise ValueError("invalid share difficulty") from exc
    target = DIFF1_TARGET * ratio.denominator // ratio.numerator
    return min(MAX_TARGET, target)


def stratum_prevhash(parent_display_hex: str) -> str:
    """Reverse 4-byte word order; Bitaxe reverses bytes within each word."""
    raw = bytes.fromhex(fixed_hex(parent_display_hex, 64, "parent_hash"))
    return b"".join(raw[i : i + 4] for i in range(28, -1, -4)).hex()


@dataclass(frozen=True)
class Job:
    job_id: str
    parent_hash: str
    version: str
    ntime: str
    nbits: str
    network_target: int
    coinbase_prefix: bytes
    coinbase_suffix: bytes
    expires_at: float

    @classmethod
    def from_rpc(cls, obj: Any, now: float) -> "Job | None":
        if not isinstance(obj, dict):
            raise ValueError("poolWork result must be an object")
        if obj.get("available") is False:
            return None
        if obj.get("available") is not True or obj.get("algorithm") != "sha256d-bitcoin80":
            raise ValueError("poolWork has no supported Bitcoin80 work")
        jid = obj.get("job_id")
        if not isinstance(jid, str) or not (1 <= len(jid) <= 128):
            raise ValueError("invalid job_id")
        prefix = obj.get("coinbase_prefix")
        suffix = obj.get("coinbase_suffix")
        if (not isinstance(prefix, str) or len(prefix) > 4096 or len(prefix) % 2
                or not all(ch in "0123456789abcdefABCDEF" for ch in prefix)):
            raise ValueError("invalid coinbase_prefix")
        if (not isinstance(suffix, str) or len(suffix) > 4096 or len(suffix) % 2
                or not all(ch in "0123456789abcdefABCDEF" for ch in suffix)):
            raise ValueError("invalid coinbase_suffix")
        try:
            prefix_bytes, suffix_bytes = bytes.fromhex(prefix), bytes.fromhex(suffix)
        except ValueError as exc:
            raise ValueError("invalid coinbase hex") from exc
        if obj.get("extranonce_bytes") != 28:
            raise ValueError("Bitcoin80 work requires 28 extranonce bytes")
        reference_header = fixed_hex(obj.get("header80"), 160, "header80")
        version = fixed_hex(obj.get("version"), 8, "version")
        ntime = fixed_hex(obj.get("ntime"), 8, "ntime")
        nbits = fixed_hex(obj.get("nbits"), 8, "nbits")
        parent_hex = obj.get("parent_hash")
        if not isinstance(parent_hex, str):
            raise ValueError("parent_hash must be hex")
        parent = fixed_hex(parent_hex.removeprefix("0x"), 64, "parent_hash")
        target_hex = obj.get("target")
        if not isinstance(target_hex, str):
            raise ValueError("target must be hex")
        target = int(fixed_hex(target_hex.removeprefix("0x"), 64, "target"), 16)
        if target != compact_target(nbits):
            raise ValueError("network target does not match nbits")
        expires = obj.get("expires_in")
        if (not isinstance(expires, (int, float)) or isinstance(expires, bool)
                or not math.isfinite(expires) or expires <= 0):
            raise ValueError("invalid work expiry")
        # The RPC expiry is a TTL in seconds, capped locally to bound stale work.
        job = cls(jid, parent, version, ntime, nbits, target, prefix_bytes,
                  suffix_bytes, now + min(float(expires), 120.0))
        if job.header(bytes(28), "00000000").hex() != reference_header:
            raise ValueError("header80 does not match independent Bitcoin header")
        return job

    def notify(self, clean_jobs: bool = True) -> list[Any]:
        return [self.job_id, stratum_prevhash(self.parent_hash),
                self.coinbase_prefix.hex(), self.coinbase_suffix.hex(), [],
                self.version, self.nbits, self.ntime, clean_jobs]

    def header(self, extranonce: bytes, nonce: str) -> bytes:
        if len(extranonce) != 28:
            raise ValueError("extranonce must be 28 bytes")
        merkle_root = sha256d(self.coinbase_prefix + extranonce + self.coinbase_suffix)
        header = (int(self.version, 16).to_bytes(4, "little")
                  + bytes.fromhex(self.parent_hash)[::-1] + merkle_root
                  + int(self.ntime, 16).to_bytes(4, "little")
                  + int(self.nbits, 16).to_bytes(4, "little")
                  + int(nonce, 16).to_bytes(4, "little"))
        assert len(header) == 80
        return header


class NodeRPC:
    def __init__(self, url: str, token: str | None = None) -> None:
        self.url, self.token = url, token

    def call(self, method: str, param: dict[str, Any] | None = None) -> Any:
        payload = dict(param or {})
        if self.token:
            payload["auth_token"] = self.token
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": [payload]}, separators=(",", ":")).encode()
        request = Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            raw = response.read(MAX_RPC_RESPONSE + 1)
        if len(raw) > MAX_RPC_RESPONSE:
            raise ValueError("node RPC response too large")
        message = json.loads(raw)
        if not isinstance(message, dict) or message.get("error") is not None:
            raise ValueError(f"node RPC error: {message.get('error') if isinstance(message, dict) else 'malformed'}")
        return message.get("result")


@dataclass(eq=False)
class Client:
    sock: socket.socket
    outbound: queue.Queue[bytes | None] = field(
        default_factory=lambda: queue.Queue(MAX_OUTBOUND_MESSAGES))
    writer_thread: threading.Thread | None = None
    closed: threading.Event = field(default_factory=threading.Event)
    extranonce1: bytes = field(default_factory=lambda: secrets.token_bytes(EXTRANONCE1_BYTES))
    subscribed: bool = False
    authorized: bool = False
    job_ids: set[str] = field(default_factory=set)

    def start_writer(self) -> None:
        self.writer_thread = threading.Thread(target=self._write_loop, daemon=True)
        self.writer_thread.start()

    def _write_loop(self) -> None:
        try:
            while True:
                packet = self.outbound.get()
                if packet is None:
                    return
                self.sock.sendall(packet)
        except OSError:
            self.close()

    def send(self, message: dict[str, Any]) -> None:
        if self.closed.is_set():
            raise OSError("miner disconnected")
        raw = (json.dumps(message, separators=(",", ":")) + "\n").encode()
        try:
            self.outbound.put_nowait(raw)
        except queue.Full as exc:
            raise TimeoutError("miner outbound queue full") from exc

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.outbound.put_nowait(None)
        except queue.Full:
            pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def event(self, method: str, params: list[Any]) -> None:
        self.send({"id": None, "method": method, "params": params})


class Pool:
    def __init__(self, rpc: Any, worker: str, password: str, difficulty: str,
                 max_clients: int = 32) -> None:
        if not worker or not password or max_clients < 1:
            raise ValueError("worker, password and positive max_clients are required")
        self.rpc, self.worker, self.password = rpc, worker, password
        self.difficulty, self.target = difficulty, share_target(difficulty)
        self.difficulty_float = float(Decimal(difficulty))
        if not math.isfinite(self.difficulty_float) or self.difficulty_float <= 0:
            raise ValueError("share difficulty is not representable")
        self.lock = threading.RLock()
        self.clients: set[Client] = set()
        self.jobs: dict[str, Job] = {}
        self.current: Job | None = None
        self.seen: OrderedDict[tuple[str, bytes, str, str], None] = OrderedDict()
        self.network_pending: set[tuple[str, bytes, str, str]] = set()
        self.network_success: OrderedDict[tuple[str, bytes, str, str], None] = OrderedDict()
        self.slots = threading.BoundedSemaphore(max_clients)
        self.max_clients = max_clients

    def announced_difficulty(self, job: Job | None) -> float:
        if job is None:
            return self.difficulty_float
        return min(self.difficulty_float, DIFF1_TARGET / job.network_target)

    def poll_once(self) -> None:
        new = Job.from_rpc(self.rpc.call("hegemon_poolWork"), time.time())
        with self.lock:
            if new is None:
                self.current = None
                self.jobs.clear()
                self.seen.clear()
                self.network_pending.clear()
                self.network_success.clear()
                for client in self.clients:
                    client.job_ids.clear()
                return
            old = self.current
            parent_changed = old is None or old.parent_hash != new.parent_hash
            if parent_changed:
                self.jobs.clear()
                self.seen.clear()
                self.network_pending.clear()
                self.network_success.clear()
                for client in self.clients:
                    client.job_ids.clear()
            existing = self.jobs.get(new.job_id)
            if existing is not None and existing != new:
                # Expiry changes as the node's remaining TTL counts down. All
                # other bytes must stay immutable for a given job identifier.
                if (existing.parent_hash, existing.version, existing.ntime,
                    existing.nbits, existing.network_target, existing.coinbase_prefix,
                    existing.coinbase_suffix) != (
                    new.parent_hash, new.version, new.ntime, new.nbits,
                    new.network_target, new.coinbase_prefix, new.coinbase_suffix):
                    raise ValueError("job_id reused for different work")
            changed = old is None or old.job_id != new.job_id or parent_changed
            self.current = new
            now = time.time()
            for jid, job in tuple(self.jobs.items()):
                if job.expires_at <= now:
                    del self.jobs[jid]
            self.jobs[new.job_id] = new
            while len(self.jobs) > MAX_JOBS:
                self.jobs.pop(next(iter(self.jobs)))
            retained_ids = self.jobs.keys()
            for client in self.clients:
                client.job_ids.intersection_update(retained_ids)
            clients = tuple(c for c in self.clients if c.authorized) if changed else ()
        for client in clients:
            try:
                client.job_ids.add(new.job_id)
                client.event("mining.set_difficulty", [self.announced_difficulty(new)])
                client.event("mining.notify", new.notify(parent_changed))
            except (OSError, ValueError):
                LOG.debug("could not notify disconnected miner", exc_info=True)
                client.close()
                self.stop_client(client)

    def start_client(self, client: Client) -> None:
        with self.lock:
            used = {active.extranonce1 for active in self.clients}
            while client.extranonce1 in used:
                client.extranonce1 = secrets.token_bytes(EXTRANONCE1_BYTES)
            client.start_writer()
            self.clients.add(client)

    def stop_client(self, client: Client) -> None:
        with self.lock:
            self.clients.discard(client)

    def handle(self, client: Client, request: Any) -> dict[str, Any] | None:
        if not isinstance(request, dict) or not isinstance(request.get("method"), str):
            return {"id": None, "result": None, "error": [20, "invalid request", None]}
        rid, method, params = request.get("id"), request["method"], request.get("params", [])
        if not isinstance(params, list) or len(params) > 8:
            return {"id": rid, "result": None, "error": [20, "invalid params", None]}

        def reply(result: Any = None, error: str | None = None) -> dict[str, Any]:
            return {"id": rid, "result": result,
                    "error": [20, error, None] if error else None}

        if method == "mining.configure":
            if not params or not isinstance(params[0], list):
                return reply(error="invalid configure request")
            return reply({extension: ("00000000" if extension == "version-rolling.mask" else False)
                          for extension in params[0] if isinstance(extension, str)}
                         | ({"version-rolling.mask": "00000000"}
                            if "version-rolling" in params[0] else {}))
        if method == "mining.subscribe":
            client.subscribed = True
            return reply([[ ["mining.set_difficulty", "hegemon"],
                            ["mining.notify", "hegemon"] ],
                          client.extranonce1.hex(), EXTRANONCE2_BYTES])
        if method == "mining.authorize":
            ok = (client.subscribed and len(params) == 2
                  and isinstance(params[0], str) and isinstance(params[1], str)
                  and hmac.compare_digest(params[0].encode(), self.worker.encode())
                  and hmac.compare_digest(params[1].encode(), self.password.encode()))
            client.authorized = ok
            return reply(ok, None if ok else "unauthorized")
        if method == "mining.submit":
            if not client.authorized:
                return reply(False, "unauthorized")
            if len(params) != 5 or params[0] != self.worker:
                return reply(False, "invalid submit parameters")
            try:
                job_id = params[1]
                ex2 = fixed_hex(params[2], 8, "extranonce2")
                ntime = fixed_hex(params[3], 8, "ntime")
                nonce = fixed_hex(params[4], 8, "nonce")
            except ValueError as exc:
                return reply(False, str(exc))
            if not isinstance(job_id, str):
                return reply(False, "invalid job id")
            with self.lock:
                job = self.jobs.get(job_id)
                if (job is None or job_id != job.job_id or job_id not in client.job_ids
                        or job.expires_at <= time.time()):
                    return reply(False, "stale job")
                if ntime != job.ntime:
                    return reply(False, "ntime rolling is disabled")
                extranonce = client.extranonce1 + bytes.fromhex(ex2)
                key = (job_id, extranonce, ntime, nonce)
                header = job.header(extranonce, nonce)
                value = int.from_bytes(sha256d(header), "little")
                is_network_solution = value <= job.network_target
                if (key in self.seen or key in self.network_pending
                        or key in self.network_success):
                    return reply(False, "duplicate share")
                if value > max(self.target, job.network_target):
                    return reply(False, "low difficulty share")
                if is_network_solution:
                    if len(self.network_pending) >= self.max_clients:
                        return reply(False, "network submission capacity reached")
                    self.network_pending.add(key)
                else:
                    self.seen[key] = None
                    if len(self.seen) > MAX_SEEN_SHARES:
                        self.seen.popitem(last=False)
            if is_network_solution:
                try:
                    result = self.rpc.call("hegemon_submitPoolShare", {
                        "job_id": job_id, "nonce": nonce, "extranonce": extranonce.hex(),
                        "ntime": ntime,
                    })
                except Exception as exc:
                    LOG.warning("node rejected solution RPC: %s", exc)
                    with self.lock:
                        self.network_pending.discard(key)
                    return reply(False, "node RPC unavailable")
                if not isinstance(result, dict) or result.get("accepted") is not True:
                    reason = result.get("error") if isinstance(result, dict) else None
                    with self.lock:
                        self.network_pending.discard(key)
                    return reply(False, str(reason or "node rejected solution"))
                with self.lock:
                    self.network_pending.discard(key)
                    self.network_success[key] = None
                    if len(self.network_success) > MAX_NETWORK_SUCCESS:
                        self.network_success.popitem(last=False)
            return reply(True)
        if method in ("mining.extranonce.subscribe", "mining.suggest_difficulty"):
            return reply(False)
        return reply(error="unsupported method")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address: tuple[str, int], pool: Pool):
        self.pool = pool
        super().__init__(address, _Handler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self.pool.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.pool.slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.pool.slots.release()


class _Handler(socketserver.StreamRequestHandler):
    timeout = 120

    def handle(self) -> None:
        client = Client(self.request)
        self.server.pool.start_client(client)
        try:
            while True:
                line = self.rfile.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE or not line.endswith(b"\n"):
                    break
                try:
                    request = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    client.send({"id": None, "result": None,
                                 "error": [20, "invalid JSON", None]})
                    continue
                response = self.server.pool.handle(client, request)
                if response is not None:
                    client.send(response)
                    if (isinstance(request, dict) and request.get("method") == "mining.authorize"
                            and response.get("result") is True):
                        with self.server.pool.lock:
                            job = self.server.pool.current
                        client.event("mining.set_difficulty",
                                     [self.server.pool.announced_difficulty(job)])
                        if job is not None and job.expires_at > time.time():
                            client.job_ids.add(job.job_id)
                            client.event("mining.notify", job.notify())
        except (TimeoutError, OSError, BrokenPipeError):
            pass
        finally:
            client.close()
            self.server.pool.stop_client(client)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", help="Stratum bind address")
    parser.add_argument("--port", type=int, default=3333)
    parser.add_argument("--allow-public-bind", action="store_true")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:9944")
    parser.add_argument("--worker", required=True, help="exact authorized worker name")
    parser.add_argument("--password-env", default="HEGEMON_STRATUM_PASSWORD")
    parser.add_argument("--rpc-token-env", default="HEGEMON_POOL_RPC_TOKEN")
    parser.add_argument("--share-difficulty", default="0.001")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--max-clients", type=int, default=32)
    args = parser.parse_args()
    if not ipaddress.ip_address(args.bind).is_loopback and not args.allow_public_bind:
        parser.error("non-loopback bind requires --allow-public-bind")
    if args.poll_seconds <= 0 or args.poll_seconds > 60:
        parser.error("poll-seconds must be in (0, 60]")
    password = os.environ.get(args.password_env, "")
    if not password:
        parser.error(f"set nonempty {args.password_env}")
    try:
        pool = Pool(NodeRPC(args.rpc_url, os.environ.get(args.rpc_token_env)),
                    args.worker, password, args.share_difficulty, args.max_clients)
    except ValueError as exc:
        parser.error(str(exc))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = _Server((args.bind, args.port), pool)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    LOG.info("Stratum listening on %s:%d for worker %s", *server.server_address, args.worker)
    try:
        while True:
            try:
                pool.poll_once()
            except Exception as exc:
                LOG.warning("pool work poll failed: %s", exc)
            time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
