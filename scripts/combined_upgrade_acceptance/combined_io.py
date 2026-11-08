"""Bounded loopback I/O for the disposable combined-upgrade acceptance runner."""
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import termios
import time

MAX_RPC = 12 * 1024 * 1024
PASS_PROMPT = b"Encrypted wallet passphrase: "
PREIMAGE_PROMPT = b"Private 32-byte preimage (hex): "
IDENTITY = bytes.fromhex("01000c00070001000f000800020c0100")
FIXED_BYTES = 5784


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    private(temporary, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
    os.replace(temporary, path)


def clean_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("HEGEMON_")}
    env.update(RAYON_NUM_THREADS="1", RUST_LOG="warn")
    return env


def rpc(port, method, params=None, timeout=30):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("POST", "/", json.dumps({"jsonrpc": "2.0", "id": 1,
            "method": method, "params": [] if params is None else params}),
            {"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_RPC + 1)
        require(len(raw) <= MAX_RPC, "RPC response exceeded byte bound")
        data = json.loads(raw)
        if response.status != 200 or data.get("error") is not None:
            raise RuntimeError(f"RPC {method}: {data.get('error', response.status)}")
        return data["result"]
    finally:
        connection.close()


def stop_process(proc, grace=20):
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
    forced = False
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        forced = True
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
    return {"pid": proc.pid, "exit_code": proc.returncode, "reaped": True, "forced": forced}


def wallet_cli(binary, arguments, prompts, log_path, timeout, check=True):
    """Use hidden TTY prompts; neither argv nor retained output contains secrets."""
    master, slave = pty.openpty()
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attrs)

    def attach():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen([str(binary), *map(str, arguments)], stdin=slave,
        stdout=slave, stderr=slave, close_fds=True, preexec_fn=attach, env=clean_env())
    os.close(slave)
    started = time.monotonic()
    output = bytearray()
    remaining = [(needle, bytes(secret)) for needle, secret in prompts]
    sent = 0
    peak = 0
    next_rss = 0
    failure = None
    try:
        while proc.poll() is None:
            if time.monotonic() - started > timeout:
                raise TimeoutError(f"private-spend exceeded {timeout}s")
            ready, _, _ = select.select([master], [], [], .15)
            if ready:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    block = b""
                output.extend(block)
                require(len(output) <= 4 * 1024 * 1024, "wallet output exceeds 4 MiB")
            if remaining and remaining[0][0] in output:
                needle, secret = remaining.pop(0)
                # Earlier prompts remain in output; prompts are intentionally distinct.
                os.write(master, secret + b"\n")
                sent += 1
            if time.monotonic() >= next_rss:
                sample = subprocess.run(["ps", "-o", "rss=", "-p", str(proc.pid)],
                    capture_output=True, text=True, timeout=3)
                if sample.stdout.strip().isdigit():
                    peak = max(peak, int(sample.stdout.strip()))
                next_rss = time.monotonic() + 1
        while True:
            ready, _, _ = select.select([master], [], [], 0)
            if not ready:
                break
            try:
                block = os.read(master, 65536)
            except OSError:
                break
            if not block:
                break
            output.extend(block)
    except BaseException as exc:
        failure = exc
        stop_process(proc, grace=5)
    finally:
        os.close(master)
        for _, secret in prompts:
            if secret:
                output = output.replace(bytes(secret), b"<redacted>")
        private(log_path, output)
    metrics = {"pid": proc.pid, "exit_code": proc.returncode,
        "elapsed_seconds": time.monotonic() - started, "prompts_answered": sent,
        "sampled_peak_rss_kib": peak, "log_sha256": sha(log_path)}
    if failure is not None:
        raise failure
    if check:
        require(proc.returncode == 0, f"private-spend failed; see {Path(log_path).name}")
        require(not remaining, "wallet exited without answering expected prompt")
    return output.decode("utf8", "replace"), metrics


def compact(raw, pos):
    require(pos < len(raw), "truncated SCALE length")
    mode = raw[pos] & 3
    width = (1, 2, 4)[mode] if mode < 3 else (raw[pos] >> 2) + 5
    require(width <= 5 and pos + width <= len(raw), "SCALE length exceeds u32")
    number = int.from_bytes(raw[pos:pos + width], "little") >> 2 if mode < 3 else int.from_bytes(raw[pos + 1:pos + width], "little")
    require(mode == 0 or number >= (64, 16384, 1 << 30)[mode - 1], "noncanonical SCALE length")
    return number, pos + width


def decode_action_vec(raw):
    count, position = compact(raw, 0)
    require(count <= 1024, "action count exceeds bound")
    actions = []
    for _ in range(count):
        length, position = compact(raw, position)
        require(length <= MAX_RPC and position + length <= len(raw), "action exceeds available bytes")
        actions.append(raw[position:position + length])
        position += length
    require(position == len(raw), "trailing action body bytes")
    return actions


def action_payload(raw):
    require(len(raw) >= 104, "short PendingActionWire")
    position = 104
    for width in (48, 48, 48, 4):
        count, position = compact(raw, position)
        require(count <= (len(raw) - position) // width, "truncated action vector")
        position += count * width
    length, position = compact(raw, position)
    end = position + length
    require(end + 9 == len(raw) and raw[end + 8] == 0, "noncanonical independent action framing")
    return raw[position:end], int.from_bytes(raw[end:end + 8], "little")


def public_args(raw):
    require(raw[48:56] == bytes.fromhex("0c00070001000f00"), "action route is not circuit12/crypto7/family1/action15")
    carrier, fee = action_payload(raw)
    require(len(carrier) <= 177632 and carrier[:8] == b"HGPSLC02" and carrier[8:24] == IDENTITY, "not the current PrivateSpend carrier")
    require(carrier[FIXED_BYTES:FIXED_BYTES + 4] == b"SMZL", "not current SMZL proof")
    require(fee == int.from_bytes(carrier[200:208], "little"), "outer/inner fee mismatch")
    return carrier


def action_commitments(raw):
    """Outer canonical output commitments, in the same global leaf order."""
    position = 104
    count, position = compact(raw, position)  # nullifiers
    position += count * 48
    count, position = compact(raw, position)
    require(position + count * 48 <= len(raw), "truncated outer commitments")
    return [raw[position + i * 48:position + (i + 1) * 48] for i in range(count)]


def chunks(port, block_hash):
    first = rpc(port, "chain_getBlockActionsChunk", [block_hash, 0])
    require(first.get("schema") == "hegemon.native.action-body-chunk-v1", "canonical body schema")
    meta = {k: first[k] for k in ("height", "parent_hash", "tx_count", "extrinsics_root", "action_body_hash", "action_body_len", "chunk_count")}
    require(0 < first["chunk_count"] <= 512, "canonical chunk count bound")
    body = bytearray()
    for index in range(first["chunk_count"]):
        row = first if index == 0 else rpc(port, "chain_getBlockActionsChunk", [block_hash, index])
        require(row.get("chunk_index") == index and row.get("block_hash") == block_hash, "canonical chunk identity")
        require(all(row.get(k) == v for k, v in meta.items()), "canonical body metadata changed")
        part = bytes.fromhex(row["chunk"].removeprefix("0x"))
        require(len(part) == row["chunk_len"], "canonical chunk length mismatch")
        body.extend(part)
        require(len(body) <= MAX_RPC, "canonical body byte bound")
    require(len(body) == meta["action_body_len"], "canonical body incomplete")
    return decode_action_vec(bytes(body)), meta, bytes(body)


def pending(port, tx):
    output = bytearray()
    total = None
    while total is None or len(output) < total:
        row = rpc(port, "hegemon_developmentPendingActionChunk", [tx, len(output), 262144])
        if row is None:
            return None
        require(row.get("schema") == "hegemon.development-pending-action-chunk-v1", "Development pending schema")
        require(row["tx_hash"] == tx and row["offset"] == len(output), "pending binding mismatch")
        part = bytes.fromhex(row["chunk"].removeprefix("0x"))
        require(part and len(part) == row["chunk_len"], "pending chunk malformed")
        require(total is None or total == row["total_len"], "pending total changed")
        total = row["total_len"]
        require(total <= 177900, "pending byte cap")
        output.extend(part)
    require(len(output) == total, "pending bytes exceeded total")
    return bytes(output)


def request(carrier):
    return {"binding_circuit": 12, "binding_crypto": 7, "family_id": 1,
        "action_id": 15, "object_refs": [], "new_nullifiers": [],
        "public_args": base64.b64encode(carrier).decode(), "authorization_proof": None,
        "authorization_signatures": [], "aux_data": None}


def target_from_bits(bits):
    exponent, mantissa = bits >> 24, bits & 0x7fffff
    require(bits & 0x800000 == 0 and 0 < exponent <= 32 and mantissa > 0, "invalid positive compact target")
    value = mantissa << (8 * (exponent - 3)) if exponent >= 3 else mantissa >> (8 * (3 - exponent))
    require(0 < value < 1 << 256, "compact target outside positive 256-bit range")
    return value


def bits_from_target(value):
    size = (value.bit_length() + 7) // 8
    encoded = value << (8 * (3 - size)) if size <= 3 else value >> (8 * (size - 3))
    if encoded & 0x800000:
        encoded >>= 8
        size += 1
    return size << 24 | encoded


def asert_bits(anchor_height, anchor_parent_ms, anchor_bits, parent_height, parent_ms,
        spacing_ms=60000, half_life_ms=3600000):
    """Separate Python bigint oracle; truncate signed division, then floor Q16 shift."""
    require(anchor_height > 0 and parent_height >= anchor_height, "ASERT anchor ancestry")
    require(spacing_ms > 0 and half_life_ms > 0, "ASERT parameters")
    deviation = (parent_ms - anchor_parent_ms - spacing_ms * (parent_height - anchor_height + 1)) * 65536
    exponent = abs(deviation) // half_life_ms * (-1 if deviation < 0 else 1)
    shifts = exponent >> 16
    fraction = exponent - shifts * 65536
    factor = 65536 + ((195766423245049 * fraction + 971821376 * fraction**2
        + 5127 * fraction**3 + (1 << 47)) >> 48)
    product = target_from_bits(anchor_bits) * factor
    limit = target_from_bits(0x207fffff)
    shift = shifts - 16
    if shift >= 256:
        return 0x207fffff
    if shift <= -272:
        return 0x01010000
    value = product << shift if shift >= 0 else product >> -shift
    return bits_from_target(max(1, min(limit, value)))


def solve_job(job, version, limit, seconds, solver=None):
    require(job.get("algorithm") == "sha256d-bitcoin80", "unsupported pool algorithm")
    header = bytearray.fromhex(job["header80"])
    require(len(header) == 80, "pool header length")
    require(header[36:68] == hashlib.sha256(hashlib.sha256(bytes.fromhex(job["coinbase_prefix"]) + bytes(28) + bytes.fromhex(job["coinbase_suffix"])).digest()).digest(), "pool coinbase does not reproduce Merkle root")
    require(int.from_bytes(header[68:72], "little") == int(job["ntime"], 16), "pool nTime mismatch")
    require(int.from_bytes(header[72:76], "little") == int(job["nbits"], 16), "pool bits mismatch")
    header[:4] = version.to_bytes(4, "little")
    target = bytes.fromhex(job["target"].removeprefix("0x"))
    require(int.from_bytes(target, "big") == target_from_bits(int(job["nbits"], 16)), "pool target differs from compact bits")
    started = time.monotonic()
    if solver is not None:
        command = [str(solver), "--header80", header.hex(), "--target", target.hex(),
            "--max-attempts", str(limit), "--timeout-ms", str(max(1, int(seconds * 1000)))]
        child = subprocess.run(command, capture_output=True, text=True, timeout=seconds + 2,
            stdin=subprocess.DEVNULL, env=clean_env())
        require(len(child.stdout) < 65536 and len(child.stderr) < 65536, "solver output bound")
        require(child.returncode == 0, f"bounded external nonce solver exit {child.returncode}: {child.stderr.strip()[:1000]}")
        row = json.loads(child.stdout)
        nonce = row["nonce"]
        require(type(nonce) is int and 0 <= nonce < limit and nonce <= 0xffffffff, "solver nonce outside bound")
        header[76:80] = nonce.to_bytes(4, "little")
        digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]
        require(row["header80"] == header.hex() and row["work_hash"] == "0x" + digest.hex()
            and digest <= target, "external solver output failed independent Python hash/target validation")
        require(row["attempts"] == nonce + 1, "external solver attempt count differs")
        return {"job_id": job["job_id"], "nonce": f"{nonce:08x}",
            "extranonce": "00" * 28, "ntime": job["ntime"], "mining_version": f"{version:08x}"}, {
            "attempts": nonce + 1, "seconds": time.monotonic() - started,
            "solver_reported_seconds": row["seconds"], "solver": "external-single-thread-exact80",
            "independent_python_hash_verified": True, "header80": header.hex(),
            "work_hash": "0x" + digest.hex()}
    for nonce in range(limit):
        if nonce % 4096 == 0 and time.monotonic() - started > seconds:
            raise TimeoutError("bounded single-thread nonce search expired")
        header[76:80] = nonce.to_bytes(4, "little")
        work_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]
        if work_hash <= target:
            return {"job_id": job["job_id"], "nonce": f"{nonce:08x}",
                "extranonce": "00" * 28, "ntime": job["ntime"],
                "mining_version": f"{version:08x}"}, {"attempts": nonce + 1,
                "seconds": time.monotonic() - started, "header80": header.hex(),
                "work_hash": "0x" + work_hash.hex(), "solver": "python-single-thread-exact80"}
    raise RuntimeError("bounded nonce search exhausted")
