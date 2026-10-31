#!/usr/bin/env python3
"""Shared local HTLC helpers for the Development rehearsal and the fresh-chain end-to-end test.

Bitcoin RPC is accepted only on loopback. Wallet passphrases stay in mode-0600 files
and are typed into the wallet's terminal prompts; they are not command arguments.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import json
import os
import pty
import re
import select
import signal
import stat
import subprocess
import sys
import termios
import time
import urllib.parse
from decimal import Decimal
from pathlib import Path

HGN_BLOCK_SECONDS = 10
BTC_BLOCK_SECONDS = 600
SAFETY_SECONDS = 600
EASY_POW_BITS = 0x207FFFFF
# circuits/transaction smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES:
# candidate header 417 + ciphertext 2147 + 2 MiB SMZC proof. A private-spend-only
# manifest's smaller cap rejects HTLC proofs.
HTLC_MAX_PROOF_BYTES = 417 + 2147 + 2 * 1024 * 1024

class RehearsalError(RuntimeError):
    pass


def descriptor_checksum(descriptor: str) -> str:
    """BIP380 checksum encoding for Core importdescriptors input."""
    input_charset = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\\\" "
    checksum_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    generators = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)

    def polymod(c: int, value: int) -> int:
        top = c >> 35
        c = ((c & 0x7FFFFFFFF) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                c ^= generator
        return c

    c = 1
    cls = cls_count = 0
    for char in descriptor:
        pos = input_charset.find(char)
        if pos < 0:
            raise RehearsalError("Bitcoin descriptor contains a character outside BIP380")
        c = polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        cls_count += 1
        if cls_count == 3:
            c = polymod(c, cls)
            cls = cls_count = 0
    if cls_count:
        c = polymod(c, cls)
    for _ in range(8):
        c = polymod(c, 0)
    c ^= 1
    return "".join(checksum_charset[(c >> (5 * (7 - i))) & 31] for i in range(8))


def compact_size(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def psbt_add_input_fields(psbt64: str, fields: list[tuple[bytes, bytes]]) -> str:
    """Add standard PSBT input fields; Core still creates every signature."""
    raw = bytearray(base64.b64decode(psbt64, validate=True))
    if raw[:5] != b"psbt\xff":
        raise RehearsalError("Bitcoin Core returned an invalid PSBT")

    def read_varint(pos: int) -> tuple[int, int]:
        marker = raw[pos]
        if marker < 253:
            return marker, pos + 1
        width = {253: 2, 254: 4, 255: 8}[marker]
        return int.from_bytes(raw[pos + 1:pos + 1 + width], "little"), pos + 1 + width

    def map_end(pos: int) -> int:
        while True:
            key_len, pos = read_varint(pos)
            if key_len == 0:
                return pos - 1
            pos += key_len
            value_len, pos = read_varint(pos)
            pos += value_len
            if pos > len(raw):
                raise RehearsalError("Malformed PSBT map")

    input_end = map_end(map_end(5) + 1)
    insert = b"".join(compact_size(len(key)) + key + compact_size(len(value)) + value
                       for key, value in fields)
    raw[input_end:input_end] = insert
    return base64.b64encode(raw).decode("ascii")


def private_file(path: Path, maximum: int = 16 * 1024) -> bytes:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > maximum:
        raise RehearsalError(f"private input must be a bounded regular mode-0600 file: {path.name}")
    data = path.read_bytes()
    if len(data) > maximum:
        raise RehearsalError("private input exceeded its bound while reading")
    return data


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class BitcoinRPC:
    def __init__(self, endpoint: str, cookie: Path):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise RehearsalError("Bitcoin RPC must be plain HTTP on loopback")
        self.host = parsed.hostname
        self.port = parsed.port or 80
        self.cookie = cookie
        self.counter = 0

    def call(self, method: str, *params, wallet: str | None = None, sensitive: bool = False):
        user, password = self.cookie.read_text().strip().split(":", 1)
        path = "/" if wallet is None else "/wallet/" + urllib.parse.quote(wallet)
        self.counter += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.counter,
                           "method": method, "params": params}).encode()
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=20)
        try:
            conn.request("POST", path, body, {"Authorization": "Basic " + auth,
                         "Content-Type": "application/json"})
            response = conn.getresponse()
            result = json.loads(response.read(4 * 1024 * 1024 + 1))
        finally:
            conn.close()
        if "error" in result and result["error"] is not None:
            detail = "sensitive RPC failed" if sensitive else result["error"].get("message", "RPC error")
            raise RehearsalError(f"Bitcoin Core {method} rejected request: {detail}")
        return result.get("result")


def btc_amount(sats: int) -> str:
    return format(Decimal(sats) / Decimal(100_000_000), ".8f")


def rehearsal_bitcoin_key() -> tuple[str, str]:
    """Generate a compressed key with OpenSSL-backed cryptography, then WIF-encode it."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as error:
        raise RehearsalError("Python cryptography with SECP256K1 support is required") from error
    key = ec.generate_private_key(ec.SECP256K1())
    secret = key.private_numbers().private_value.to_bytes(32, "big")
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    payload = b"\xef" + secret + b"\x01"
    encoded = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(encoded, "big")
    wif = ""
    while number:
        number, remainder = divmod(number, 58)
        wif = alphabet[remainder] + wif
    wif = "1" * (len(encoded) - len(encoded.lstrip(b"\0"))) + wif
    return public.hex(), wif


def btc_height(btc: BitcoinRPC) -> int:
    return btc.call("getblockcount")


def wait_bitcoin_confirmations(btc: BitcoinRPC, txid: str, wallet: str, confirmations: int,
                               miner_address: str) -> dict:
    for _ in range(600):
        tx = btc.call("gettransaction", txid, wallet=wallet)
        if tx.get("confirmations", 0) >= confirmations:
            return tx
        btc.call("generatetoaddress", 1, miner_address)
        time.sleep(0.1)
    raise RehearsalError("Bitcoin Core transaction did not reach requested confirmations")


def spend_contract(btc: BitcoinRPC, wallet: str, txid: str, vout: int, amount_sat: int,
                   script_pubkey: bytes, witness_script: bytes, destination: str,
                   sequence: int, locktime: int, preimage: bytes | None = None,
                   broadcast: bool = True) -> str:
    fee_sat = 500
    if amount_sat <= fee_sat:
        raise RehearsalError("Bitcoin contract amount is below the fixed rehearsal fee")
    raw = btc.call("createrawtransaction", [{"txid": txid, "vout": vout, "sequence": sequence}],
                   {destination: btc_amount(amount_sat - fee_sat)}, locktime)
    psbt = btc.call("converttopsbt", raw, True)
    txout = amount_sat.to_bytes(8, "little") + compact_size(len(script_pubkey)) + script_pubkey
    fields = [(b"\x01", txout), (b"\x05", witness_script)]
    if preimage is not None:
        fields.append((b"\x0b" + hashlib.sha256(preimage).digest(), preimage))
    psbt = psbt_add_input_fields(psbt, fields)
    processed = btc.call("walletprocesspsbt", psbt, True, "ALL", True, wallet=wallet)
    if not processed.get("complete"):
        raise RehearsalError("Bitcoin Core wallet could not sign the exact HTLC branch")
    final = btc.call("finalizepsbt", processed["psbt"], True)
    if not final.get("complete") or not final.get("hex"):
        raise RehearsalError("Bitcoin Core could not finalize the HTLC spend")
    return btc.call("sendrawtransaction", final["hex"]) if broadcast else final["hex"]


def confirmed_bitcoin_preimage(btc: BitcoinRPC, txid: str, wallet: str,
                               expected_hash: bytes) -> bytes:
    tx_info = btc.call("gettransaction", txid, wallet=wallet)
    if tx_info.get("confirmations", 0) < 1 or not tx_info.get("blockhash"):
        raise RehearsalError("Bitcoin claim is not confirmed in the active chain")
    decoded = btc.call("getrawtransaction", txid, True, tx_info["blockhash"])
    for item in decoded.get("vin", [{}])[0].get("txinwitness", []):
        try:
            candidate = bytes.fromhex(item)
        except ValueError:
            continue
        if len(candidate) == 32 and hashlib.sha256(candidate).digest() == expected_hash:
            return candidate
    raise RehearsalError("Confirmed Bitcoin claim witness contains no matching 32-byte preimage")


def require_rejected_contract_spend(btc: BitcoinRPC, wallet: str, funding_tx: str, vout: int,
                                    amount: int, script: bytes, witness: bytes, destination: str,
                                    sequence: int, locktime: int, preimage: bytes | None,
                                    label: str, receipt: dict) -> None:
    try:
        raw = spend_contract(btc, wallet, funding_tx, vout, amount, script, witness,
                             destination, sequence, locktime, preimage, broadcast=False)
    except RehearsalError:
        result = "sign-or-finalize-rejected"
    else:
        result = btc.call("testmempoolaccept", [raw])[0]
        if result.get("allowed"):
            raise RehearsalError(f"Bitcoin accepted invalid {label} HTLC spend")
        result = result.get("reject-reason", "mempool-rejected")
    if btc.call("gettxout", funding_tx, vout, True) is None:
        raise RehearsalError(f"invalid {label} spend consumed the funding output")
    receipt.setdefault("bitcoin_negative_tests", {})[label] = {
        "rejected": True, "stage": result, "funding_utxo_unspent": True}


def run_wallet_cli(binary: Path, args: list[str], passfiles: list[Path], approve: bool = False) -> str:
    """Drive TTY-only wallet prompts; never echo or log secret file contents."""
    passwords = [private_file(path, 4096).decode("utf-8").rstrip("\r\n") for path in passfiles]
    master, slave = pty.openpty()
    def attach_controlling_terminal() -> None:
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    env = os.environ.copy()
    # One prover thread keeps the resident set inside a 16 GiB machine.
    env["RAYON_NUM_THREADS"] = "1"
    env.setdefault("MALLOC_ARENA_MAX", "2")
    # The shared bounded-commit prover drops the extra rotated-row matrix.
    env["HEGEMON_SMALLWOOD_LOW_RAM"] = "1"
    proc = subprocess.Popen([str(binary), *args], stdin=slave, stdout=slave, stderr=slave,
                            close_fds=True, preexec_fn=attach_controlling_terminal, env=env)
    os.close(slave)
    transcript = bytearray()
    sent_pass = 0
    sent_confirm = 0
    approval_sent = False
    try:
        deadline = time.monotonic() + 3600
        while proc.poll() is None:
            if time.monotonic() > deadline:
                raise RehearsalError("wallet CLI exceeded one-hour bounded operation timeout")
            ready, _, _ = select.select([master], [], [], 0.25)
            if ready:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    chunk = b""
                if chunk:
                    transcript.extend(chunk)
                    for line in chunk.splitlines():
                        if b"[smallwood/low-ram]" in line:
                            print(line.decode("utf-8", "replace"), file=sys.stderr, flush=True)
                    if len(transcript) > 2 * 1024 * 1024:
                        raise RehearsalError("wallet CLI output exceeded 2 MiB")
            text = transcript.decode("utf-8", "ignore")
            prompt_count = len(re.findall(r"Enter (?:new )?wallet passphrase:", text))
            if sent_pass < min(prompt_count, len(passwords)):
                os.write(master, passwords[sent_pass].encode() + b"\n")
                sent_pass += 1
                continue
            confirm_count = len(re.findall(r"Confirm passphrase:", text))
            if passwords and sent_confirm < confirm_count:
                os.write(master, passwords[min(sent_confirm, len(passwords) - 1)].encode() + b"\n")
                sent_confirm += 1
                continue
            digest_match = re.search(r"Type the exact review digest (0x[0-9a-f]{64}) to approve", text)
            if approve and digest_match and not approval_sent:
                os.write(master, digest_match.group(1).encode() + b"\n")
                approval_sent = True
        tail = b""
        try:
            tail = os.read(master, 65536)
        except OSError:
            pass
        transcript.extend(tail)
        code = proc.wait(timeout=10)
    except Exception:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise
    finally:
        os.close(master)
        for i in range(len(passwords)):
            passwords[i] = ""
    text = transcript.decode("utf-8", "replace")
    if code:
        # CLI diagnostics may include public review data; omit transcript to keep
        # future CLI errors from accidentally exposing private input.
        tail = next((line.strip() for line in reversed(text.splitlines()) if line.strip()), "")
        tail = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", tail)
        tail = re.sub(r"(?i)\b(?:xprv|tprv|xpriv|tpriv)[1-9A-HJ-NP-Za-km-z]+", "<redacted-key>", tail)
        tail = re.sub(r"\b[KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b", "<redacted-key>", tail)
        tail = re.sub(r"\b(?:0x)?[0-9a-fA-F]{64,}\b", "<redacted-hex>", tail)
        if re.search(r"(?i)passphrase|seed phrase|mnemonic|preimage|private key|secret", tail):
            tail = "sensitive CLI diagnostic suppressed"
        raise RehearsalError(f"wallet CLI failed with exit code {code}" +
                             (f": {tail[:240]}" if tail else ""))
    return text


def last_json(text: str) -> dict:
    decoder = json.JSONDecoder()
    candidates = []
    pos = 0
    while pos < len(text):
        if text[pos] != "{":
            pos += 1
            continue
        try:
            value, end = decoder.raw_decode(text, pos)
            if isinstance(value, dict):
                candidates.append(value)
                pos = end
                continue
        except json.JSONDecodeError:
            pass
        pos += 1
    if candidates:
        return candidates[-1]
    raise RehearsalError("wallet CLI did not return a JSON receipt")


def rpc_call(endpoint: str, method: str, params: list | None = None):
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise RehearsalError("Hegemon rehearsal RPC must use loopback HTTP")
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=20)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
    try:
        conn.request("POST", parsed.path or "/", body, {"Content-Type": "application/json"})
        response = json.loads(conn.getresponse().read(2 * 1024 * 1024 + 1))
    finally:
        conn.close()
    if response.get("error"):
        message = ""
        err = response["error"]
        if isinstance(err, dict):
            message = str(err.get("message", ""))[:240]
        raise RehearsalError(f"Hegemon RPC {method} failed: {message}".rstrip())
    return response.get("result")


def hgn_height(endpoint: str) -> int:
    header = rpc_call(endpoint, "chain_getHeader")
    number = header.get("number", "")
    return int(number[2:], 16) if isinstance(number, str) and number.startswith("0x") else int(number)


def hgn_mine_to(endpoint: str, target: int, timeout_seconds: int = 600) -> None:
    rpc_call(endpoint, "hegemon_stopMining")
    if hgn_height(endpoint) >= target:
        return
    rpc_call(endpoint, "hegemon_startMining", [{"threads": 1}])
    try:
        deadline = time.monotonic() + timeout_seconds
        while hgn_height(endpoint) < target:
            if time.monotonic() > deadline:
                raise RehearsalError("Hegemon development chain did not reach the requested height")
            time.sleep(0.25)
    finally:
        rpc_call(endpoint, "hegemon_stopMining")


def wallet_common(store: Path, context: Path, rpc: str) -> list[str]:
    return ["--store", str(store), "--context", str(context), "--rpc", rpc, "--retained-test"]


def hgn_status(binary: Path, store: Path, passfile: Path, context: Path,
               endpoint: str, swap_id: str | None = None, max_blocks: int = 1000) -> dict:
    command = ["htlc", "status", *wallet_common(store, context, endpoint),
               "--max-blocks", str(max_blocks)]
    if swap_id is not None:
        command.extend(["--swap-id", swap_id])
    output = run_wallet_cli(binary, command, [passfile])
    return last_json(output)


def hgn_confirmation(binary: Path, store: Path, passfile: Path, context: Path,
                     endpoint: str, swap_id: str, attempt_id: str, max_blocks: int = 1000) -> dict:
    for _ in range(600):
        status = hgn_status(binary, store, passfile, context, endpoint, swap_id, max_blocks)
        for swap in status.get("swaps", []):
            for attempt in swap.get("attempts", []):
                if attempt.get("attempt_id") == attempt_id:
                    confirmation = attempt.get("canonical_confirmation")
                    if confirmation:
                        return confirmation
        time.sleep(0.25)
    raise RehearsalError("Hegemon wallet never observed canonical HTLC inclusion")


def hgn_action(binary: Path, store: Path, passfile: Path, context: Path,
               endpoint: str, swap_id: str, action: str, input_position: int,
               destination: str, root: Path, runtime_manifest: Path,
               max_blocks: int = 1000) -> dict:
    # Strict Lock age is zero: mining is stopped before the wallet captures its parent.
    rpc_call(endpoint, "hegemon_stopMining")
    artifact = root / f"{action}-{time.time_ns()}.json"
    command = ["htlc", f"prepare-{action}", *wallet_common(store, context, endpoint),
        "--swap-id", swap_id, "--input-position", str(input_position), "--fee", "1",
        "--to", destination, "--out", str(artifact)]
    receipt = last_json(run_wallet_cli(binary, command, [passfile], approve=True))
    attempt = receipt["attempt_id"]
    # Force a fresh CLI process to recover the held attempt before submission.
    # Compare the full canonical carrier, not just its digest or summary fields.
    prepared = json.loads(artifact.read_text())
    recovered_path = root / f"recover-{action}-{time.time_ns()}.json"
    recovered_output = last_json(run_wallet_cli(binary, [
        "htlc", "recover", *wallet_common(store, context, endpoint),
        "--attempt-id", attempt, "--out", str(recovered_path)], [passfile]))
    recovered = json.loads(recovered_path.read_text())
    try:
        original_carrier = base64.b64decode(prepared["inline_args_base64"], validate=True)
        recovered_carrier = base64.b64decode(recovered["inline_args_base64"], validate=True)
    except (KeyError, ValueError) as error:
        raise RehearsalError("prepared or recovered HTLC artifact lacks a valid carrier") from error
    if (recovered_output.get("attempt_id") != attempt
            or original_carrier != recovered_carrier
            or prepared.get("carrier_sha512") != recovered.get("carrier_sha512")):
        raise RehearsalError("HTLC restart recovery changed the attempt or carrier bytes")
    receipt["restart_recovery_same_carrier"] = True
    receipt["output_commitment"] = prepared["output_commitment"]
    run_wallet_cli(binary, ["htlc", "submit", *wallet_common(store, context, endpoint),
        "--runtime-manifest", str(runtime_manifest), "--attempt-id", attempt], [passfile])
    hgn_mine_to(endpoint, hgn_height(endpoint) + 1)
    confirmation = hgn_confirmation(
        binary, store, passfile, context, endpoint, swap_id, attempt, max_blocks)
    receipt["canonical_confirmation"] = confirmation
    return receipt


def require_cli_rejection(binary: Path, args: list[str], passfiles: list[Path], artifact: Path,
                          label: str) -> None:
    try:
        run_wallet_cli(binary, args, passfiles, approve=True)
    except RehearsalError:
        pass
    else:
        raise RehearsalError(f"wallet accepted invalid {label}")
    if artifact.exists():
        raise RehearsalError(f"wallet wrote an artifact for rejected {label}")


def require_exact_owned_note(status: dict, value: int, commitment: int | str) -> None:
    expected = str(commitment)
    if not any(n.get("native_value_base_units") == value
               and str(n.get("commitment")) == expected
               for n in status.get("ordinary_native_notes", [])):
        raise RehearsalError("wallet lacks the exact carrier output commitment and value as an owned note")


def require_bitcoin_receive(btc: BitcoinRPC, txid: str, wallet: str,
                            address: str, expected_sat: int) -> dict:
    info = btc.call("getaddressinfo", address, wallet=wallet)
    tx = btc.call("gettransaction", txid, wallet=wallet)
    if tx.get("confirmations", 0) < 1 or not tx.get("blockhash"):
        raise RehearsalError("Bitcoin destination transaction is not confirmed in the active chain")
    block = btc.call("getblockheader", tx["blockhash"])
    if block.get("confirmations", 0) < 1:
        raise RehearsalError("Bitcoin destination transaction block is not in the active chain")
    raw = btc.call("getrawtransaction", txid, True, tx["blockhash"])
    for output in raw["vout"]:
        if output["scriptPubKey"].get("hex") == info.get("scriptPubKey"):
            utxo = btc.call("gettxout", txid, output["n"], True)
            sats = int(Decimal(str(utxo["value"])) * Decimal(100_000_000)) if utxo else 0
            if info.get("ismine") and sats == expected_sat:
                return {"address": address, "unspent_sat": sats, "ismine": True,
                        "confirmations": tx["confirmations"], "active_block_confirmations": block["confirmations"]}
    raise RehearsalError("Bitcoin destination is not an owned unspent output of the expected value")


def checked_swap_notes(status: dict, action_id: str, expected_value: int) -> None:
    attempt = next((a for s in status.get("swaps", []) for a in s.get("attempts", [])
                    if a.get("action_id") == action_id), None)
    if attempt is not None and not attempt.get("canonical_confirmation"):
        raise RehearsalError("wallet lacks canonical confirmation for the HTLC action")
    if not any(n.get("native_value_base_units") == expected_value
               for n in status.get("ordinary_native_notes", [])):
        raise RehearsalError("recipient wallet has no unspent ordinary note for the HTLC value")


def require_loopback_http(endpoint: str) -> None:
    parsed = urllib.parse.urlsplit(endpoint)
    if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            or parsed.username is not None or parsed.password is not None):
        raise RehearsalError("RPC must be plain HTTP on loopback")


def require_fresh_directory(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise RehearsalError("private root must be a real directory, never a symlink")
        if any(path.iterdir()):
            raise RehearsalError("private root must be empty; existing data is never overwritten")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def timeout_margin_holds(
    hegemon_height: int,
    bitcoin_height: int,
    timeout_height: int,
    refund_height: int,
    hegemon_block_seconds: int = HGN_BLOCK_SECONDS,
    bitcoin_block_seconds: int = BTC_BLOCK_SECONDS,
    safety_seconds: int = SAFETY_SECONDS,
) -> bool:
    """Same inequality as HtlcOffer::check_timeout_margin. Heights are never compared raw."""
    if (hegemon_block_seconds <= 0 or bitcoin_block_seconds <= 0 or safety_seconds <= 0
            or timeout_height < hegemon_height or refund_height <= bitcoin_height):
        return False
    remaining_hgn = timeout_height - hegemon_height
    remaining_btc = refund_height - bitcoin_height
    return (remaining_hgn * hegemon_block_seconds
            > remaining_btc * bitcoin_block_seconds + safety_seconds)


def plan_swap_deadlines(
    hegemon_height: int,
    bitcoin_height: int,
    lifetime_exclusive: int = 10_001,
    bitcoin_window: int = 8,
    hegemon_block_seconds: int = HGN_BLOCK_SECONDS,
    bitcoin_block_seconds: int = BTC_BLOCK_SECONDS,
    safety_seconds: int = SAFETY_SECONDS,
) -> tuple[int, int]:
    """Bitcoin refund is a few blocks ahead. Hegemon's refund is the longer leg."""
    if bitcoin_window <= 0:
        raise RehearsalError("Bitcoin refund window must be positive")
    refund_height = bitcoin_height + bitcoin_window
    extra = 1
    while not timeout_margin_holds(
        hegemon_height, bitcoin_height, hegemon_height + extra, refund_height,
        hegemon_block_seconds, bitcoin_block_seconds, safety_seconds,
    ):
        extra += 1
        if hegemon_height + extra >= lifetime_exclusive:
            raise RehearsalError("HTLC timeouts do not fit the Development lifetime")
    return hegemon_height + extra, refund_height


def party_bitcoin_descriptors(hashlock_hex: str, alice_pub: str, alice_wif: str,
                              bob_pub: str, bob_wif: str, refund_height: int) -> dict[str, str]:
    """Alice can claim with the secret. Bob can refund after the Bitcoin height."""
    alice = (f"wsh(or_i(and_v(v:sha256({hashlock_hex}),pk({alice_wif})),"
             f"and_v(v:after({refund_height}),pk({bob_pub}))))")
    bob = (f"wsh(or_i(and_v(v:sha256({hashlock_hex}),pk({alice_pub})),"
           f"and_v(v:after({refund_height}),pk({bob_wif}))))")
    public = (f"wsh(or_i(and_v(v:sha256({hashlock_hex}),pk({alice_pub})),"
              f"and_v(v:after({refund_height}),pk({bob_pub}))))")
    return {"alice": alice, "bob": bob, "public": public}


def htlc_capable_manifest(printed: dict) -> dict:
    """Drop the private-spend-only pin so this fresh Development chain admits HTLC."""
    manifest = json.loads(json.dumps(printed))
    candidate = manifest.get("development_candidate")
    if manifest.get("profile") != "development" or not isinstance(candidate, dict):
        raise RehearsalError("node did not print a Development candidate manifest")
    for key in ("private_spend_only", "private_spend_source", "assets", "recovery"):
        candidate.pop(key, None)
    if candidate.get("private_spend_only") or candidate.get("private_spend_source"):
        raise RehearsalError("HTLC manifest still selects private-spend-only")
    # The printed private-spend cap is smaller than an HTLC candidate carrier.
    # The node accepts this ceiling: it is MAX_CANDIDATE_CARRIER_BYTES.
    candidate["max_proof_bytes"] = HTLC_MAX_PROOF_BYTES
    manifest["pow_bits"] = EASY_POW_BITS
    manifest["development_candidate"] = candidate
    return manifest

