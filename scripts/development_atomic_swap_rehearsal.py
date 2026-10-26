#!/usr/bin/env python3
"""Run a real two-chain HTLC rehearsal against local Bitcoin Core regtest and Hegemon RPC.

This orchestrator never fabricates balances or block observations. The Hegemon
wallet CLI prepares every carrier and submits through its durable journal. The
Bitcoin signatures are produced by Bitcoin Core's descriptor wallet. Private
inputs and the private Core datadir live only below the caller's mode-0700 root.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import http.client
import json
import os
import pty
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import termios
import time
import urllib.parse
from decimal import Decimal
from pathlib import Path


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

    proc = subprocess.Popen([str(binary), *args], stdin=slave, stdout=slave, stderr=slave,
                            close_fds=True, preexec_fn=attach_controlling_terminal)
    os.close(slave)
    transcript = bytearray()
    sent_pass = 0
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
                    if len(transcript) > 2 * 1024 * 1024:
                        raise RehearsalError("wallet CLI output exceeded 2 MiB")
            text = transcript.decode("utf-8", "ignore")
            prompt_count = len(re.findall(r"Enter (?:new )?wallet passphrase:", text))
            if sent_pass < min(prompt_count, len(passwords)):
                os.write(master, passwords[sent_pass].encode() + b"\n")
                sent_pass += 1
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
        raise RehearsalError(f"Hegemon RPC {method} failed")
    return response.get("result")


def hgn_height(endpoint: str) -> int:
    header = rpc_call(endpoint, "chain_getHeader")
    number = header.get("number", "")
    return int(number[2:], 16) if isinstance(number, str) and number.startswith("0x") else int(number)


def hgn_mine_to(endpoint: str, target: int) -> None:
    rpc_call(endpoint, "hegemon_stopMining")
    if hgn_height(endpoint) >= target:
        return
    rpc_call(endpoint, "hegemon_startMining", [{"threads": 1}])
    try:
        deadline = time.monotonic() + 600
        while hgn_height(endpoint) < target:
            if time.monotonic() > deadline:
                raise RehearsalError("Hegemon development chain did not reach the requested height")
            time.sleep(0.25)
    finally:
        rpc_call(endpoint, "hegemon_stopMining")


def wallet_common(store: Path, context: Path, rpc: str) -> list[str]:
    return ["--store", str(store), "--context", str(context), "--rpc", rpc, "--retained-test"]


def hgn_status(binary: Path, store: Path, passfile: Path, context: Path,
               endpoint: str, swap_id: str) -> dict:
    output = run_wallet_cli(binary, ["htlc", "status", *wallet_common(store, context, endpoint),
        "--swap-id", swap_id], [passfile])
    return last_json(output)


def hgn_confirmation(binary: Path, store: Path, passfile: Path, context: Path,
                     endpoint: str, swap_id: str, attempt_id: str) -> dict:
    for _ in range(600):
        status = hgn_status(binary, store, passfile, context, endpoint, swap_id)
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
               destination: str, root: Path, runtime_manifest: Path) -> dict:
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
    confirmation = hgn_confirmation(binary, store, passfile, context, endpoint, swap_id, attempt)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--bitcoin-cli", type=Path, required=True)
    parser.add_argument("--wallet-cli", type=Path, required=True)
    parser.add_argument("--public-fixture", type=Path, required=True)
    parser.add_argument("--hgn-rpc", required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--claim-store", type=Path, required=True)
    parser.add_argument("--refund-store", type=Path, required=True)
    parser.add_argument("--claim-passfile", type=Path, required=True)
    parser.add_argument("--refund-passfile", type=Path, required=True)
    parser.add_argument("--lock-input-position", type=int, required=True)
    parser.add_argument("--miner-address", required=True, help="Configured disposable Hegemon development miner address")
    parser.add_argument("--value", type=int, required=True, help="Hegemon base units; lock input must equal value plus fee")
    parser.add_argument("--timeout-height", type=int, required=True, help="Absolute Hegemon refund parent height")
    parser.add_argument("--bitcoin-amount-sat", type=int, default=100000)
    parser.add_argument("--bitcoin-refund-height", type=int, default=120)
    parser.add_argument("--private-root", type=Path, required=True, help="Must be a new or empty mode-0700 directory")
    parser.add_argument("--bitcoin-rpc-port", type=int, default=18443)
    parser.add_argument("--scenario", choices=("claim", "timeout"), required=True)
    args = parser.parse_args()
    for path in (args.bitcoind, args.bitcoin_cli, args.wallet_cli, args.public_fixture):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RehearsalError(f"required executable is not executable: {path}")
    for path in (args.claim_passfile, args.refund_passfile):
        private_file(path, 4096)
    if args.private_root.exists():
        if args.private_root.is_symlink() or not args.private_root.is_dir():
            raise RehearsalError("private root must be a real directory, never a symlink")
        if any(args.private_root.iterdir()):
            raise RehearsalError("private root must be empty; existing data is never overwritten")
    args.private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.private_root, 0o700)
    datadir = args.private_root / "bitcoin-regtest"
    datadir.mkdir(mode=0o700)
    manifest = json.loads(args.runtime_manifest.read_text())
    context = json.loads(args.context.read_text())
    if manifest.get("profile") != "development":
        raise RehearsalError("atomic rehearsal accepts only a Development manifest")

    daemon = subprocess.Popen([str(args.bitcoind), "-regtest", f"-datadir={datadir}", "-server=1",
        "-listen=0", "-connect=0", "-discover=0", "-dnsseed=0", "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1", "-fallbackfee=0.0002",
        f"-rpcport={args.bitcoin_rpc_port}", "-printtoconsole=0"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    receipt: dict = {"schema": "hegemon-bitcoin-regtest-atomic-swap-rehearsal-v1", "scenario": args.scenario,
                     "hegemon_miner_payout_address": args.miner_address,
                     "proof": "execution receipt only; no formal or release authority"}
    try:
        cookie = datadir / "regtest" / ".cookie"
        endpoint = f"http://127.0.0.1:{args.bitcoin_rpc_port}"
        btc = None
        for _ in range(200):
            if daemon.poll() is not None:
                raise RehearsalError("Bitcoin Core exited before regtest RPC became ready")
            if cookie.exists():
                try:
                    btc = BitcoinRPC(endpoint, cookie)
                    if btc.call("getblockchaininfo")["chain"] == "regtest":
                        break
                except Exception:
                    pass
            time.sleep(0.1)
        if btc is None:
            raise RehearsalError("Bitcoin Core regtest RPC did not become ready")
        if btc.call("getpeerinfo"):
            raise RehearsalError("private regtest unexpectedly has external peers")
        # Each Core descriptor wallet receives exactly its own ephemeral branch
        # key. The opposite branch key enters its counterpart's wallet only.
        for name in ("claim", "refund", "miner"):
            btc.call("createwallet", name, False, False, "", False, True)
        claim_pub, claim_wif = rehearsal_bitcoin_key()
        refund_pub, refund_wif = rehearsal_bitcoin_key()
        claim_key_desc = f"wpkh({claim_wif})"
        refund_key_desc = f"wpkh({refund_wif})"
        for wallet, desc in (("claim", claim_key_desc), ("refund", refund_key_desc)):
            imported = btc.call("importdescriptors", [{"desc": desc + "#" + descriptor_checksum(desc),
                "timestamp": "now", "active": False}], wallet=wallet, sensitive=True)
            if not imported or not imported[0].get("success"):
                raise RehearsalError("Bitcoin Core could not import a private party key descriptor")
        secret = bytearray(os.urandom(32))
        secret_path = args.private_root / "bitcoin-preimage.bin"
        write_private(secret_path, bytes(secret))
        hashlock = hashlib.sha256(secret).hexdigest()
        # The offer CLI uses two unlocked, context-pinned wallet stores and writes
        # a mode-0600 public offer; no private key or preimage enters that file.
        offer_path = args.private_root / "offer.json"
        out = run_wallet_cli(args.wallet_cli, ["htlc", "offer-create", "--context", str(args.context),
            "--claim-store", str(args.claim_store), "--refund-store", str(args.refund_store),
            "--hashlock", "0x" + hashlock, "--value", str(args.value),
            "--maximum-fee", "10", "--timeout-height", str(args.timeout_height),
            "--bitcoin-amount-sat", str(args.bitcoin_amount_sat), "--bitcoin-claim-public-key", "0x" + claim_pub,
            "--bitcoin-refund-public-key", "0x" + refund_pub, "--bitcoin-refund-height", str(args.bitcoin_refund_height),
            "--bitcoin-required-confirmations", "1", "--out", str(offer_path), "--retained-test"],
            [args.claim_passfile, args.refund_passfile])
        offer_info = last_json(out)
        offer = json.loads(offer_path.read_text())
        swap_id = offer_info["swap_id"]
        bitcoin_terms = {"amount_sat": offer["bitcoin"]["amount_sat"],
            "claim_public_key": offer["bitcoin"]["claim_public_key"],
            "refund_public_key": offer["bitcoin"]["refund_public_key"],
            "refund_height": offer["bitcoin"]["refund_height"],
            "required_confirmations": offer["bitcoin"]["required_confirmations"]}
        terms_path = args.private_root / "terms.json"
        write_private(terms_path, json.dumps({"hashlock": list(bytes.fromhex(hashlock)), "bitcoin": bitcoin_terms}).encode())
        fixture = json.loads(subprocess.check_output([str(args.public_fixture), str(terms_path)], timeout=60))
        witness_script = bytes.fromhex(fixture["witness_script_hex"])
        contract_script_pubkey = bytes.fromhex(fixture["script_pubkey_hex"])
        decoded = btc.call("decodescript", witness_script.hex())
        contract_address = decoded["segwit"]["address"]
        if decoded["segwit"].get("hex") != contract_script_pubkey.hex():
            raise RehearsalError("Bitcoin Core decoded a different witness program than the wallet fixture")
        public_descriptor = (f"wsh(or_i(and_v(v:sha256({hashlock}),pk({claim_pub})),"
                            f"and_v(v:after({bitcoin_terms['refund_height']}),pk({refund_pub}))))")
        public_descriptor = btc.call("getdescriptorinfo", public_descriptor)["descriptor"]
        if btc.call("deriveaddresses", public_descriptor)[0] != contract_address:
            raise RehearsalError("Bitcoin Core public miniscript does not match the wallet witness script")
        claim_descriptor = (f"wsh(or_i(and_v(v:sha256({hashlock}),pk({claim_wif})),"
                           f"and_v(v:after({bitcoin_terms['refund_height']}),pk({refund_pub}))))")
        refund_descriptor = (f"wsh(or_i(and_v(v:sha256({hashlock}),pk({claim_pub})),"
                            f"and_v(v:after({bitcoin_terms['refund_height']}),pk({refund_wif}))))")
        for wallet, descriptor in (("claim", claim_descriptor), ("refund", refund_descriptor)):
            imported = btc.call("importdescriptors", [{"desc": descriptor + "#" + descriptor_checksum(descriptor),
                "timestamp": "now", "active": False}], wallet=wallet, sensitive=True)
            if not imported or not imported[0].get("success"):
                raise RehearsalError("Bitcoin Core could not import a private HTLC branch descriptor")
        miner = btc.call("getnewaddress", "regtest-miner", "bech32", wallet="miner")
        btc.call("generatetoaddress", 101, miner)
        funding_tx = btc.call("sendtoaddress", contract_address,
                              str(Decimal(bitcoin_terms["amount_sat"]) / Decimal(100_000_000)), wallet="miner")
        btc.call("generatetoaddress", 1, miner)
        funding = btc.call("gettransaction", funding_tx, wallet="miner")
        raw_funding = btc.call("getrawtransaction", funding_tx, True, funding["blockhash"])
        vout = next(x["n"] for x in raw_funding["vout"] if x["scriptPubKey"]["hex"] == contract_script_pubkey.hex())
        if btc.call("gettxout", funding_tx, vout, True) is None:
            raise RehearsalError("Bitcoin contract output is not an actual unspent chain output")
        receipt["bitcoin_contract"] = {"funding_txid": funding_tx, "contract_address": contract_address,
            "witness_script_sha256": hashlib.sha256(witness_script).hexdigest(), "confirmations": funding["confirmations"]}
        invalid_preimage = os.urandom(32)
        while hashlib.sha256(invalid_preimage).hexdigest() == hashlock:
            invalid_preimage = os.urandom(32)
        probe_address = btc.call("getnewaddress", "negative-probe", "bech32", wallet="miner")
        require_rejected_contract_spend(btc, "claim", funding_tx, vout, bitcoin_terms["amount_sat"],
            contract_script_pubkey, witness_script, probe_address, 0xFFFFFFFF, 0, invalid_preimage,
            "wrong_secret", receipt)
        require_rejected_contract_spend(btc, "refund", funding_tx, vout, bitcoin_terms["amount_sat"],
            contract_script_pubkey, witness_script, probe_address, 0xFFFFFFFE,
            bitcoin_terms["refund_height"], None, "premature_refund", receipt)
        for store, passfile in ((args.claim_store, args.claim_passfile), (args.refund_store, args.refund_passfile)):
            run_wallet_cli(args.wallet_cli, ["htlc", "offer-accept", *wallet_common(store, args.context, args.hgn_rpc),
                "--offer", str(offer_path)], [passfile])
        encrypted_agreement = args.private_root / "encrypted-agreement.bin"
        run_wallet_cli(args.wallet_cli, ["htlc", "agreement-create", *wallet_common(args.refund_store, args.context, args.hgn_rpc),
            "--swap-id", swap_id, "--to", offer_info["claim_address"]], [args.refund_passfile])
        run_wallet_cli(args.wallet_cli, ["htlc", "agreement-export", *wallet_common(args.refund_store, args.context, args.hgn_rpc),
            "--swap-id", swap_id, "--to", offer_info["claim_address"], "--out", str(encrypted_agreement)], [args.refund_passfile])
        run_wallet_cli(args.wallet_cli, ["htlc", "agreement-import", *wallet_common(args.claim_store, args.context, args.hgn_rpc),
            "--swap-id", swap_id, "--input", str(encrypted_agreement), "--diversifier-index", "0"], [args.claim_passfile])
        receipt["hegemon_lock"] = hgn_action(args.wallet_cli, args.refund_store, args.refund_passfile,
            args.context, args.hgn_rpc, swap_id, "lock", args.lock_input_position,
            offer_info["claim_address"], args.private_root, args.runtime_manifest)

        wrong_path = args.private_root / "wrong-preimage.bin"
        write_private(wrong_path, invalid_preimage)
        require_cli_rejection(args.wallet_cli, ["htlc", "secret-import",
            *wallet_common(args.claim_store, args.context, args.hgn_rpc), "--swap-id", swap_id,
            "--input", str(wrong_path)], [args.claim_passfile],
            args.private_root / "wrong-secret.json", "wrong Hegemon secret")
        refund_before = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
            args.context, args.hgn_rpc, swap_id)
        locked_positions = refund_before["swaps"][0]["locked_note_positions"]
        if not locked_positions:
            raise RehearsalError("refund wallet has no canonical locked-note occurrence")
        premature_path = args.private_root / "premature-refund.json"
        require_cli_rejection(args.wallet_cli, ["htlc", "prepare-refund",
            *wallet_common(args.refund_store, args.context, args.hgn_rpc), "--swap-id", swap_id,
            "--input-position", str(locked_positions[0]), "--fee", "1", "--to", offer_info["refund_address"],
            "--out", str(premature_path)], [args.refund_passfile], premature_path,
            "premature Hegemon refund")
        refund_after = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
            args.context, args.hgn_rpc, swap_id)
        if len(refund_after["swaps"][0]["attempts"]) != len(refund_before["swaps"][0]["attempts"]):
            raise RehearsalError("rejected premature refund created an accepted HTLC attempt")
        receipt["hegemon_negative_tests"] = {
            "wrong_secret_import_rejected": True,
            "premature_refund_rejected_before_artifact": True,
            "premature_refund_created_no_attempt": True}

        if args.scenario == "claim":
            btc_destination = btc.call("getnewaddress", "claimed-contract", "bech32", wallet="claim")
            secret_for_spend = bytes(private_file(secret_path, 32))
            btc_claim = spend_contract(btc, "claim", funding_tx, vout, bitcoin_terms["amount_sat"],
                contract_script_pubkey, witness_script, btc_destination,
                0xFFFFFFFF, 0, secret_for_spend)
            btc_claim_confirmed = wait_bitcoin_confirmations(btc, btc_claim, "claim", 1, miner)
            revealed = confirmed_bitcoin_preimage(btc, btc_claim, "claim", bytes.fromhex(hashlock))
            if revealed != secret_for_spend:
                raise RehearsalError("Bitcoin chain witness differs from the original private secret")
            revealed_path = args.private_root / "revealed-on-bitcoin-chain-secret.bin"
            for i in range(len(secret)):
                secret[i] = 0
            claim_status = hgn_status(args.wallet_cli, args.claim_store, args.claim_passfile,
                args.context, args.hgn_rpc, swap_id)
            positions = claim_status["swaps"][0]["locked_note_positions"]
            if not positions:
                raise RehearsalError("claim wallet has no canonical locked-note occurrence")
            receipt["bitcoin_claim"] = {"txid": btc_claim, "confirmations": btc_claim_confirmed["confirmations"],
                "received_sat": bitcoin_terms["amount_sat"] - 500, "secret_source": "confirmed Bitcoin witness"}
            receipt["bitcoin_claim"]["destination"] = require_bitcoin_receive(
                btc, btc_claim, "claim", btc_destination, bitcoin_terms["amount_sat"] - 500)
            claim_block = btc_claim_confirmed["blockhash"]
            btc.call("invalidateblock", claim_block)
            try:
                confirmed_bitcoin_preimage(btc, btc_claim, "claim", bytes.fromhex(hashlock))
            except RehearsalError:
                receipt["bitcoin_claim"]["orphan_witness_refused"] = True
            else:
                raise RehearsalError("wallet treated orphaned Bitcoin claim witness as confirmed")
            btc.call("reconsiderblock", claim_block)
            restored = wait_bitcoin_confirmations(btc, btc_claim, "claim", 1, miner)
            revealed = confirmed_bitcoin_preimage(btc, btc_claim, "claim", bytes.fromhex(hashlock))
            if revealed != secret_for_spend:
                raise RehearsalError("reconsidered active-chain witness differs from the original secret")
            write_private(revealed_path, revealed)
            receipt["bitcoin_claim"]["reconsidered_confirmations"] = restored["confirmations"]
            run_wallet_cli(args.wallet_cli, ["htlc", "secret-import", *wallet_common(args.claim_store, args.context, args.hgn_rpc),
                "--swap-id", swap_id, "--input", str(revealed_path)], [args.claim_passfile])
            receipt["hegemon_claim"] = hgn_action(args.wallet_cli, args.claim_store, args.claim_passfile,
                args.context, args.hgn_rpc, swap_id, "claim", positions[0],
                offer_info["claim_address"], args.private_root, args.runtime_manifest)
            claim_status = hgn_status(args.wallet_cli, args.claim_store, args.claim_passfile,
                args.context, args.hgn_rpc, swap_id)
            require_exact_owned_note(claim_status, args.value - 1,
                                     receipt["hegemon_claim"]["output_commitment"])
            receipt["hegemon_claim"]["received_base_units"] = args.value - 1
            receipt["outcome"] = "confirmed Bitcoin and Hegemon claimant ownership changes"
        else:
            current_btc = btc_height(btc)
            refund_height = bitcoin_terms["refund_height"]
            if current_btc < refund_height:
                btc.call("generatetoaddress", refund_height - current_btc, miner)
            btc_destination = btc.call("getnewaddress", "refunded-contract", "bech32", wallet="refund")
            btc_refund = spend_contract(btc, "refund", funding_tx, vout, bitcoin_terms["amount_sat"],
                contract_script_pubkey, witness_script, btc_destination,
                0xFFFFFFFE, refund_height)
            btc_refund_confirmed = wait_bitcoin_confirmations(btc, btc_refund, "refund", 1, miner)
            refund_destination = require_bitcoin_receive(
                btc, btc_refund, "refund", btc_destination, bitcoin_terms["amount_sat"] - 500)
            if hgn_height(args.hgn_rpc) < args.timeout_height:
                hgn_mine_to(args.hgn_rpc, args.timeout_height)
            refund_status = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
                args.context, args.hgn_rpc, swap_id)
            positions = refund_status["swaps"][0]["locked_note_positions"]
            if not positions:
                raise RehearsalError("refund wallet has no canonical locked-note occurrence")
            receipt["bitcoin_refund"] = {"txid": btc_refund, "confirmations": btc_refund_confirmed["confirmations"],
                "returned_sat": bitcoin_terms["amount_sat"] - 500, "claim_branch_absent": True,
                "destination": refund_destination}
            receipt["hegemon_refund"] = hgn_action(args.wallet_cli, args.refund_store, args.refund_passfile,
                args.context, args.hgn_rpc, swap_id, "refund", positions[0],
                offer_info["refund_address"], args.private_root, args.runtime_manifest)
            refund_status = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
                args.context, args.hgn_rpc, swap_id)
            require_exact_owned_note(refund_status, args.value - 1,
                                     receipt["hegemon_refund"]["output_commitment"])
            receipt["hegemon_refund"]["returned_base_units"] = args.value - 1
            receipt["outcome"] = "counterparty absent; both chain assets returned after their own timeouts"
        receipt["swap_id"] = swap_id
        receipt["offer_hashlock"] = "0x" + hashlock
        receipt["private_artifacts"] = "mode-0600 files retained under the caller-owned private root"
        receipt["unrun"] = ["Hegemon canonical reorg recovery"]
        print(json.dumps(receipt, sort_keys=True))
        for i in range(len(secret)):
            secret[i] = 0
        _ = (endpoint, context)
        return 0
    finally:
        daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RehearsalError as error:
        print(f"atomic rehearsal stopped: {error}", file=sys.stderr)
        raise SystemExit(2)
