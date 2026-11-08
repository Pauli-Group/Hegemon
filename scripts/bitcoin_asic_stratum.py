#!/usr/bin/env python3
"""Bounded Stratum V1 bridge for Hegemon Bitcoin80 work.

This is a local pool adapter, not a Bitcoin wallet or ledger. The native node
owns block templates, consensus targets, and final block admission.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass, field, replace
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
MAX_BUSY_SUBMISSION_ATTEMPTS = 241
BUSY_SUBMISSION_DELAY_SECONDS = 0.5
BUSY_SUBMISSION_MESSAGE = "ASIC block import busy; retry solution"
FUTURE_SUBMISSION_MESSAGE = "ASIC solution temporarily future-dated; retry solution"
TEMPORARY_FUTURE_WORK_REASON = "timestamp is temporarily ahead of local clock"
MAX_OUTBOUND_MESSAGES = 8
DIFF1_TARGET = int("00000000ffff" + "00" * 26, 16)
MAX_TARGET = (1 << 256) - 1
MAX_POW_TARGET = 0x7FFFFF << 232  # canonical Bitcoin compact 0x207fffff
EXTRANONCE_BYTES = 28
EXTRANONCE1_BYTES = 20
EXTRANONCE2_BYTES = 8
VERSION_ROLLING_MASK = 0x1FFFFFE0
ShareKey = tuple[str, bytes, str, str, str]


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
    version_rolling_mask: int
    ntime: str
    nbits: str
    network_target: int
    coinbase_prefix: bytes
    coinbase_suffix: bytes
    expires_at: float
    expires_monotonic: float

    def expired(self) -> bool:
        return self.expires_monotonic <= time.monotonic()

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
        version_mask = int(fixed_hex(obj.get("version_rolling_mask", "00000000"),
                                     8, "version_rolling_mask"), 16)
        if version_mask & ~VERSION_ROLLING_MASK:
            raise ValueError("unsupported version rolling bits")
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
        job = cls(jid, parent, version, version_mask, ntime, nbits, target, prefix_bytes,
                  suffix_bytes, now + min(float(expires), 120.0),
                  time.monotonic() + min(float(expires), 120.0))
        if job.header(bytes(28), "00000000").hex() != reference_header:
            raise ValueError("header80 does not match independent Bitcoin header")
        return job

    def notify(self, clean_jobs: bool = True) -> list[Any]:
        return [self.job_id, stratum_prevhash(self.parent_hash),
                self.coinbase_prefix.hex(), self.coinbase_suffix.hex(), [],
                self.version, self.nbits, self.ntime, clean_jobs]

    def header(self, extranonce: bytes, nonce: str, mining_version: str | None = None) -> bytes:
        if len(extranonce) != 28:
            raise ValueError("extranonce must be 28 bytes")
        merkle_root = sha256d(self.coinbase_prefix + extranonce + self.coinbase_suffix)
        version = self.version if mining_version is None else fixed_hex(mining_version, 8, "mining_version")
        if (int(version, 16) ^ int(self.version, 16)) & ~self.version_rolling_mask:
            raise ValueError("version changes bits outside job mask")
        header = (int(version, 16).to_bytes(4, "little")
                  + bytes.fromhex(self.parent_hash)[::-1] + merkle_root
                  + int(self.ntime, 16).to_bytes(4, "little")
                  + int(self.nbits, 16).to_bytes(4, "little")
                  + int(nonce, 16).to_bytes(4, "little"))
        assert len(header) == 80
        return header


class NodeRPCError(ValueError):
    """An authoritative JSON-RPC rejection, distinct from transport ambiguity."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


class NodeRPC:
    def __init__(self, url: str, token: str | None = None) -> None:
        if token:
            raise ValueError("native RPC does not authenticate tokens; unset the RPC token and use a loopback listener through an authenticated SSH tunnel")
        self.url = url

    def call(self, method: str, param: dict[str, Any] | None = None) -> Any:
        payload = dict(param or {})
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": [payload]}, separators=(",", ":")).encode()
        request = Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            raw = response.read(MAX_RPC_RESPONSE + 1)
        if len(raw) > MAX_RPC_RESPONSE:
            raise ValueError("node RPC response too large")
        message = json.loads(raw)
        if not isinstance(message, dict):
            raise ValueError("malformed node RPC response")
        error = message.get("error")
        if error is not None:
            if (isinstance(error, dict) and type(error.get("code")) is int
                    and isinstance(error.get("message"), str)):
                raise NodeRPCError(error["code"], error["message"])
            raise ValueError("malformed node RPC error")
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
    version_rolling: bool = False
    miner_version_mask: int = 0xFFFFFFFF
    version_rolling_mask: int = 0
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
                 max_clients: int = 32, extranonce2_bytes: int = EXTRANONCE2_BYTES) -> None:
        if not worker or not password or max_clients < 1:
            raise ValueError("worker, password and positive max_clients are required")
        if type(extranonce2_bytes) is not int or not 1 <= extranonce2_bytes < EXTRANONCE_BYTES:
            raise ValueError("extranonce2-bytes must be between 1 and 27")
        self.extranonce2_bytes = extranonce2_bytes
        self.extranonce1_bytes = EXTRANONCE_BYTES - extranonce2_bytes
        if max_clients > 1 << (8 * self.extranonce1_bytes):
            raise ValueError("extranonce1 namespace is smaller than max-clients")
        self.rpc, self.worker, self.password = rpc, worker, password
        self.difficulty, self.target = difficulty, share_target(difficulty)
        self.difficulty_float = float(Decimal(difficulty))
        if not math.isfinite(self.difficulty_float) or self.difficulty_float <= 0:
            raise ValueError("share difficulty is not representable")
        self.lock = threading.RLock()
        # Serialize the RPC snapshot, state publication and miner notifications.
        # Retry handlers and the main poller must not publish reordered work.
        self.poll_lock = threading.Lock()
        self.clients: set[Client] = set()
        self.jobs: dict[str, Job] = {}
        self.current: Job | None = None
        self.paused_parent: str | None = None
        self.seen: OrderedDict[ShareKey, None] = OrderedDict()
        self.network_pending: set[ShareKey] = set()
        self.network_pending_tokens: dict[ShareKey, object] = {}
        self.work_epoch = 0
        self.network_success: OrderedDict[ShareKey, None] = OrderedDict()
        self.slots = threading.BoundedSemaphore(max_clients)
        self.max_clients = max_clients

    def announced_difficulty(self, job: Job | None) -> float:
        if job is None:
            return self.difficulty_float
        return min(self.difficulty_float, DIFF1_TARGET / job.network_target)

    def poll_once(self, deadline: float | None = None) -> bool:
        if deadline is None:
            self.poll_lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.poll_lock.acquire(timeout=remaining):
                return False
        try:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            self._poll_once()
            return True
        finally:
            self.poll_lock.release()

    def _poll_once(self) -> None:
        raw = self.rpc.call("hegemon_poolWork")
        # Only the node's explicit temporary-clock response can retain an
        # existing same-parent epoch. Ordinary unavailability still withdraws
        # authority immediately. No refresh extends any original job expiry.
        if (isinstance(raw, dict) and raw.get("available") is False
                and raw.get("reason") == TEMPORARY_FUTURE_WORK_REASON
                and raw.get("reason_code") == "future_timestamp"):
            raw_parent = raw.get("parent_hash")
            if not isinstance(raw_parent, str):
                raise ValueError("parent_hash must be hex")
            parent = fixed_hex(raw_parent.removeprefix("0x"), 64, "parent_hash")
            retained = raw.get("retained_job_ids")
            if (not isinstance(retained, list) or len(retained) > MAX_JOBS
                    or not all(isinstance(jid, str) and 1 <= len(jid) <= 128 for jid in retained)
                    or len(set(retained)) != len(retained)):
                raise ValueError("invalid retained_job_ids")
            with self.lock:
                prior_parent = self.current.parent_hash if self.current else self.paused_parent
                eligible = {jid: job for jid, job in self.jobs.items()
                            if jid in retained and job.parent_hash == parent and not job.expired()}
                if prior_parent == parent and eligible:
                    self.jobs = eligible
                    self.current = None
                    self.paused_parent = parent
                    for key in tuple(self.network_pending):
                        if key[0] not in eligible:
                            self.network_pending.discard(key)
                            self.network_pending_tokens.pop(key, None)
                    for client in self.clients:
                        client.job_ids.intersection_update(eligible.keys())
                    return
        new = Job.from_rpc(raw, time.time())
        with self.lock:
            prior_parent = self.current.parent_hash if self.current else self.paused_parent
            was_paused = self.paused_parent is not None
            self.paused_parent = None
            if new is None:
                self.current = None
                self.jobs.clear()
                self.seen.clear()
                self.network_pending.clear()
                self.network_pending_tokens.clear()
                self.work_epoch += 1
                self.network_success.clear()
                for client in self.clients:
                    client.job_ids.clear()
                return
            old = self.current
            parent_changed = prior_parent != new.parent_hash
            if parent_changed:
                self.jobs.clear()
                self.seen.clear()
                self.network_pending.clear()
                self.network_pending_tokens.clear()
                self.work_epoch += 1
                self.network_success.clear()
                for client in self.clients:
                    client.job_ids.clear()
            existing = self.jobs.get(new.job_id)
            if existing is not None and existing != new:
                # Expiry changes as the node's remaining TTL counts down. All
                # other bytes must stay immutable for a given job identifier.
                if (existing.parent_hash, existing.version, existing.version_rolling_mask, existing.ntime,
                    existing.nbits, existing.network_target, existing.coinbase_prefix,
                    existing.coinbase_suffix) != (
                    new.parent_hash, new.version, new.version_rolling_mask, new.ntime, new.nbits,
                    new.network_target, new.coinbase_prefix, new.coinbase_suffix):
                    raise ValueError("job_id reused for different work")
            if existing is not None:
                new = replace(new, expires_at=min(existing.expires_at, new.expires_at),
                              expires_monotonic=min(existing.expires_monotonic, new.expires_monotonic))
            changed = old is None or old.job_id != new.job_id or parent_changed or was_paused
            self.current = new
            for jid, job in tuple(self.jobs.items()):
                if job.expired():
                    del self.jobs[jid]
            self.jobs[new.job_id] = new
            while len(self.jobs) > MAX_JOBS:
                self.jobs.pop(next(iter(self.jobs)))
            retained_ids = self.jobs.keys()
            for client in self.clients:
                client.job_ids.intersection_update(retained_ids)
            clients = tuple(self.clients) if changed else ()
        for client in clients:
            try:
                with self.lock:
                    mask = new.version_rolling_mask & client.miner_version_mask
                    changed_mask = client.version_rolling and mask != client.version_rolling_mask
                    if changed_mask:
                        client.version_rolling_mask = mask
                if changed_mask:
                    client.event("mining.set_version_mask", [f"{mask:08x}"])
                if not client.authorized:
                    continue
                client.job_ids.add(new.job_id)
                client.event("mining.set_difficulty", [self.announced_difficulty(new)])
                client.event("mining.notify", new.notify(parent_changed))
            except (OSError, ValueError):
                LOG.debug("could not notify disconnected miner", exc_info=True)
                client.close()
                self.stop_client(client)

    @staticmethod
    def _work_bytes(job: Job) -> tuple[Any, ...]:
        return (job.parent_hash, job.version, job.version_rolling_mask, job.ntime, job.nbits,
                job.network_target, job.coinbase_prefix, job.coinbase_suffix)

    def _submit_network_solution(self, key: ShareKey,
                                 job: Job, token: object, epoch: int,
                                 payload: dict[str, str]) -> tuple[bool, str | None]:
        # A bounded client handler owns this retry and keeps its server slot
        # even if an epoch change clears the reservation maps. No worker/timer
        # is created. The first job expiry remains fixed across work refreshes.
        # The deadline bounds retry admission; an in-flight RPC retains its
        # existing socket timeout and may finish after that deadline.
        deadline = min(job.expires_monotonic, time.monotonic() + 120.0)
        for attempt in range(MAX_BUSY_SUBMISSION_ATTEMPTS):
            with self.lock:
                cached = self.jobs.get(job.job_id)
                if (self.work_epoch != epoch
                        or self.network_pending_tokens.get(key) is not token
                        or cached is None
                        or (self.current.parent_hash if self.current else self.paused_parent) != job.parent_hash
                        or self._work_bytes(cached) != self._work_bytes(job)
                        or cached.expired()
                        or job.expired()
                        or time.monotonic() >= deadline):
                    return False, "stale job"
            try:
                result = self.rpc.call("hegemon_submitPoolShare", dict(payload))
            except NodeRPCError as exc:
                if (exc.code != -32602 or exc.message not in
                        (BUSY_SUBMISSION_MESSAGE, FUTURE_SUBMISSION_MESSAGE)):
                    return False, exc.message
                if attempt + 1 == MAX_BUSY_SUBMISSION_ATTEMPTS:
                    return False, "node import busy; retry budget exhausted"
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False, "stale job"
                time.sleep(min(BUSY_SUBMISSION_DELAY_SECONDS, remaining))
                # Refresh availability, parent and retained-job cache before
                # every retry. Same-parent older snapshots remain eligible.
                try:
                    if time.monotonic() >= deadline or not self.poll_once(deadline):
                        return False, "stale job"
                except Exception as error:
                    LOG.warning("solution retry work refresh failed: %s", error)
                    return False, "node RPC unavailable"
                continue
            except Exception as exc:
                LOG.warning("node rejected solution RPC: %s", exc)
                return False, "node RPC unavailable"
            if not isinstance(result, dict) or result.get("accepted") is not True:
                reason = result.get("error") if isinstance(result, dict) else None
                return False, str(reason or "node rejected solution")
            return True, None
        return False, "node import busy; retry budget exhausted"

    def start_client(self, client: Client) -> None:
        with self.lock:
            used = {active.extranonce1 for active in self.clients}
            while len(client.extranonce1) != self.extranonce1_bytes or client.extranonce1 in used:
                client.extranonce1 = secrets.token_bytes(self.extranonce1_bytes)
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
            if (len(params) != 2 or not isinstance(params[0], list)
                    or not all(isinstance(code, str) and code for code in params[0])
                    or not isinstance(params[1], dict)):
                return reply(error="invalid configure request")
            result = {extension: False for extension in params[0]}
            if "version-rolling" in params[0]:
                try:
                    requested = int(fixed_hex(params[1].get("version-rolling.mask", "ffffffff"),
                                              8, "version-rolling.mask"), 16)
                    minimum = params[1].get("version-rolling.min-bit-count")
                    if type(minimum) is not int or minimum < 0:
                        raise ValueError("version-rolling.min-bit-count must be a nonnegative integer")
                except ValueError as exc:
                    result["version-rolling"] = str(exc)
                    return reply(result)
                with self.lock:
                    # A zero mask still negotiates the extension. An activation
                    # or reorganization can update it with set_version_mask.
                    server_mask = self.current.version_rolling_mask if self.current else 0
                    mask = requested & server_mask
                    client.version_rolling = True
                    client.miner_version_mask = requested
                    client.version_rolling_mask = mask
                result.update({"version-rolling": True, "version-rolling.mask": f"{mask:08x}"})
                if mask.bit_count() < minimum:
                    # BIP310 treats the minimum as diagnostic; the miner may
                    # choose degraded operation and remains connected.
                    LOG.info("miner requests %d version bits; available intersection has %d",
                             minimum, mask.bit_count())
            return reply(result)
        if method == "mining.subscribe":
            client.subscribed = True
            return reply([[ ["mining.set_difficulty", "hegemon"],
                            ["mining.notify", "hegemon"] ],
                          client.extranonce1.hex(), self.extranonce2_bytes])
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
            if len(params) != (6 if client.version_rolling else 5) or params[0] != self.worker:
                return reply(False, "invalid submit parameters")
            try:
                job_id = params[1]
                ex2 = fixed_hex(params[2], self.extranonce2_bytes * 2, "extranonce2")
                ntime = fixed_hex(params[3], 8, "ntime")
                nonce = fixed_hex(params[4], 8, "nonce")
                bits = int(fixed_hex(params[5], 8, "version_bits"), 16) if client.version_rolling else 0
            except ValueError as exc:
                return reply(False, str(exc))
            if not isinstance(job_id, str):
                return reply(False, "invalid job id")
            with self.lock:
                job = self.jobs.get(job_id)
                if (job is None or job_id != job.job_id or job_id not in client.job_ids
                        or job.expired()):
                    return reply(False, "stale job")
                if ntime != job.ntime:
                    return reply(False, "ntime rolling is disabled")
                if bits & ~client.version_rolling_mask:
                    return reply(False, "version bits exceed negotiated mask")
                mask = client.version_rolling_mask if client.version_rolling else 0
                mining_version = f"{(int(job.version, 16) & ~mask) | bits:08x}"
                extranonce = client.extranonce1 + bytes.fromhex(ex2)
                key = (job_id, extranonce, ntime, nonce, mining_version)
                try:
                    header = job.header(extranonce, nonce, mining_version)
                except ValueError as exc:
                    return reply(False, str(exc))
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
                    token, epoch = object(), self.work_epoch
                    self.network_pending_tokens[key] = token
                else:
                    self.seen[key] = None
                    if len(self.seen) > MAX_SEEN_SHARES:
                        self.seen.popitem(last=False)
            if is_network_solution:
                accepted, reason = self._submit_network_solution(key, job, token, epoch, {
                    "job_id": job_id, "nonce": nonce, "extranonce": extranonce.hex(),
                    "ntime": ntime, "mining_version": mining_version,
                })
                with self.lock:
                    # A parent/unavailable transition may have cleared the old
                    # reservation during RPC. Never populate the new epoch.
                    if self.network_pending_tokens.get(key) is token:
                        self.network_pending_tokens.pop(key)
                        self.network_pending.discard(key)
                        if accepted and self.work_epoch == epoch:
                            self.network_success[key] = None
                            if len(self.network_success) > MAX_NETWORK_SUCCESS:
                                self.network_success.popitem(last=False)
                if not accepted:
                    return reply(False, reason)
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
                if isinstance(request, dict) and request.get("method") == "mining.configure":
                    # Keep a negotiated mask's response ordered with poller
                    # mask updates. Solution handlers must not hold this lock:
                    # their bounded import-busy retries refresh work themselves.
                    with self.server.pool.poll_lock:
                        response = self.server.pool.handle(client, request)
                        if response is not None:
                            client.send(response)
                else:
                    response = self.server.pool.handle(client, request)
                    if response is not None:
                        client.send(response)
                if response is not None:
                    if (isinstance(request, dict) and request.get("method") == "mining.authorize"
                            and response.get("result") is True):
                        with self.server.pool.lock:
                            job = self.server.pool.current
                        client.event("mining.set_difficulty",
                                     [self.server.pool.announced_difficulty(job)])
                        if job is not None and not job.expired():
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
    parser.add_argument("--rpc-token-env", default="HEGEMON_POOL_RPC_TOKEN",
                        help="legacy option: a nonempty token is rejected; use authenticated SSH forwarding")
    parser.add_argument("--share-difficulty", default="0.001")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--max-clients", type=int, default=32)
    parser.add_argument("--extranonce2-bytes", type=int, default=EXTRANONCE2_BYTES,
                        help="miner extranonce bytes (default 8; use 4 for 24+4 compatibility; total stays 28)")
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
                    args.worker, password, args.share_difficulty, args.max_clients,
                    args.extranonce2_bytes)
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
