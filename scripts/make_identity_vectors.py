#!/usr/bin/env python3
"""Generate config/swap/identity-vectors.json with signers independent of the verifier code.

Ethereum uses eth_account, Cardano builds the COSE structures with cbor2 and signs with PyNaCl, Bitcoin builds the BIP-322
transactions and sighash with embit and signs with embit's libsecp256k1 binding, and the BIP-137 signature with ecdsa. The
JavaScript (swap-ui/identity.test.mjs) and Python (swap_engine/test_identity.py) verifiers both check these vectors.
The keys are fixed test keys with no value. Re-running reproduces the file exactly.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import cbor2
import ecdsa
from eth_account import Account
from eth_account.messages import encode_defunct
from embit import ec, script
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "config" / "swap" / "identity-vectors.json"
PREFIX = "hegemon.swap.identity.v1\n"
NOW = 1_800_000_000
OFFER = "11" * 32
RESERVATION = "22" * 32
OWNER_INBOX = "33" * 32
TAKER_INBOX = "44" * 32
ETH_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
BTC_KEY = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
ADA_SEED = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")
BTC_KEY2 = bytes.fromhex("3333333333333333333333333333333333333333333333333333333333333333")
OTHER_ETH = "0x" + "ab" * 20
OTHER_ADA = "cd" * 28
OTHER_BTC = "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def statement_text(statement: dict) -> str:
    return PREFIX + canonical(statement)


def eth_proof(text: str) -> dict:
    account = Account.from_key(ETH_KEY)
    signed = account.sign_message(encode_defunct(text=text))
    return {"chain": "ethereum", "scheme": "eip191", "signer": account.address.lower(), "signature": "0x" + signed.signature.hex().removeprefix("0x")}


def ada_identity(address_type: str = "enterprise"):
    key = SigningKey(ADA_SEED)
    pub = bytes(key.verify_key)
    key_hash = hashlib.blake2b(pub, digest_size=28).digest()
    if address_type == "base":
        address = bytes([0x00]) + key_hash + bytes.fromhex("ee" * 28)
    else:
        address = bytes([0x60]) + key_hash
    return key, pub, key_hash, address


def cardano_proof(text: str, address_type: str = "enterprise", payload: bytes | None = None) -> dict:
    key, pub, key_hash, address = ada_identity(address_type)
    protected = cbor2.dumps({1: -8, "address": address})
    body = text.encode() if payload is None else payload
    sig_structure = cbor2.dumps(["Signature1", protected, b"", body])
    signature = key.sign(sig_structure).signature
    sign1 = cbor2.dumps([protected, {"hashed": False}, body, signature])
    cose_key = cbor2.dumps({1: 1, 3: -8, -1: 6, -2: pub})
    return {"chain": "cardano", "scheme": "cip8", "signer": key_hash.hex(), "signature": sign1.hex(), "key": cose_key.hex()}


def btc_public() -> str:
    return ec.PrivateKey(BTC_KEY).get_public_key().sec().hex()


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    assert n <= 0xFFFF
    return b"\xfd" + n.to_bytes(2, "little")


def bip322_sign(private_key: ec.PrivateKey, text: str) -> str:
    pub = private_key.get_public_key()
    tag = hashlib.sha256(b"BIP0322-signed-message").digest()
    message_hash = hashlib.sha256(tag + tag + text.encode()).digest()
    spk = script.p2wpkh(pub)
    to_spend = Transaction(
        version=0,
        vin=[TransactionInput(bytes(32), 0xFFFFFFFF, script.Script(b"\x00\x20" + message_hash), 0)],
        vout=[TransactionOutput(0, spk)],
        locktime=0,
    )
    to_sign = Transaction(
        version=0,
        vin=[TransactionInput(to_spend.txid(), 0, script.Script(b""), 0)],
        vout=[TransactionOutput(0, script.Script(b"\x6a"))],
        locktime=0,
    )
    # The segwit v0 script code for a P2WPKH input is the equivalent P2PKH script.
    sighash = to_sign.sighash_segwit(0, script.p2pkh_from_p2wpkh(spk), 0)
    signature = private_key.sign(sighash).serialize() + b"\x01"
    witness = b"\x02" + varint(len(signature)) + signature + varint(33) + pub.sec()
    return base64.b64encode(witness).decode()


def bip137_sign(key: bytes, text: str) -> str:
    magic = b"Bitcoin Signed Message:\n"
    digest = hashlib.sha256(hashlib.sha256(varint(len(magic)) + magic + varint(len(text.encode())) + text.encode()).digest()).digest()
    signing = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
    pub = signing.get_verifying_key().to_string("compressed")
    sig = signing.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string)
    r, s = sig[:32], int.from_bytes(sig[32:], "big")
    order = ecdsa.SECP256k1.order
    if s > order // 2:
        s = order - s
    sig = r + s.to_bytes(32, "big")
    candidates = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(sig, digest, ecdsa.SECP256k1, sigdecode=ecdsa.util.sigdecode_string)
    for index, candidate in enumerate(candidates):
        if candidate.to_string("compressed") == pub:
            # python-ecdsa enumerates the candidates in recovery-id order (0..3), the order the header byte encodes.
            return base64.b64encode(bytes([31 + index]) + sig).decode()
    raise SystemExit("could not find a recovery id")


def btc_proofs(text: str) -> list[dict]:
    pub = btc_public()
    return [
        {"chain": "bitcoin", "scheme": "bip322-simple", "signer": pub, "signature": bip322_sign(ec.PrivateKey(BTC_KEY), text)},
        {"chain": "bitcoin", "scheme": "bip137", "signer": pub, "signature": bip137_sign(BTC_KEY, text)},
    ]


def statement(role: str, legs: dict, reservation: str, inbox: str, nonce: str) -> dict:
    fields = {"owner": {"give": "refund", "receive": "claim"}, "taker": {"give": "claim", "receive": "refund"}}[role]
    return {
        "version": 1, "kind": "hegemon.swap.identity", "role": role, "offer": OFFER, "reservation": reservation, "inbox": inbox,
        "legs": {side: {"chain": legs[side][0], fields[side]: legs[side][1]} for side in ("give", "receive")},
        "nonce": nonce, "issued": NOW - 60, "expires": NOW + 3600,
    }


def case(name: str, role: str, st: dict, proofs: list[dict], reservation: str, inbox: str) -> dict:
    return {
        "name": name,
        "expected": {"offer": OFFER, "role": role, "reservation": reservation, "inbox": inbox,
                     "give": {"chain": st["legs"]["give"]["chain"]}, "receive": {"chain": st["legs"]["receive"]["chain"]}},
        "now": NOW,
        "blob": json.dumps({"statement": st, "proofs": proofs}, separators=(",", ":")),
        "statement_text": statement_text(st),
        "proven": {side: any(p["chain"] == st["legs"][side]["chain"] and p["signer"] == list(st["legs"][side].values())[1] for p in proofs) for side in ("give", "receive")},
        "addresses": {side: [v for k, v in st["legs"][side].items() if k != "chain"][0] for side in ("give", "receive")},
    }


def main() -> None:
    eth = Account.from_key(ETH_KEY).address.lower()
    ada = ada_identity()[2].hex()
    btc = btc_public()
    cases = []
    # Owner gives BTC, receives ETH; the owner proves with both wallets.
    st = statement("owner", {"give": ("bitcoin", btc), "receive": ("ethereum", eth)}, "", OWNER_INBOX, "a1" * 16)
    text = statement_text(st)
    cases.append(case("owner-btc-eth-eip191-bip322", "owner", st, [btc_proofs(text)[0], eth_proof(text)], "", OWNER_INBOX))
    cases.append(case("owner-btc-eth-bip137-only", "owner", st, [btc_proofs(text)[1]], "", OWNER_INBOX))
    # Taker claims the BTC leg and refunds on Cardano.
    st = statement("taker", {"give": ("bitcoin", btc), "receive": ("cardano", ada)}, RESERVATION, TAKER_INBOX, "b2" * 16)
    text = statement_text(st)
    cases.append(case("taker-btc-ada-cip8-enterprise", "taker", st, [cardano_proof(text)], RESERVATION, TAKER_INBOX))
    cases.append(case("taker-btc-ada-cip8-base-address", "taker", st, [cardano_proof(text, "base")], RESERVATION, TAKER_INBOX))
    # Ethereum on both legs with a different counterpart address on the other leg.
    st = statement("taker", {"give": ("ethereum", OTHER_ETH), "receive": ("ethereum", eth)}, RESERVATION, TAKER_INBOX, "c3" * 16)
    text = statement_text(st)
    cases.append(case("taker-eth-eth-one-leg-proven", "taker", st, [eth_proof(text)], RESERVATION, TAKER_INBOX))
    # Hegemon leg: never proven.
    st = statement("owner", {"give": ("hegemon", "pending"), "receive": ("cardano", ada)}, "", OWNER_INBOX, "d4" * 16)
    text = statement_text(st)
    cases.append(case("owner-hegemon-pending-ada", "owner", st, [cardano_proof(text)], "", OWNER_INBOX))

    # A matched pair: the owner gives BTC and receives ETH; the taker (a different BTC key) claims the BTC and refunds ETH.
    taker_btc = ec.PrivateKey(BTC_KEY2).get_public_key().sec().hex()
    owner_st = statement("owner", {"give": ("bitcoin", btc), "receive": ("ethereum", eth)}, "", OWNER_INBOX, "e5" * 16)
    owner_case = case("pair-owner", "owner", owner_st, [{"chain": "bitcoin", "scheme": "bip322-simple", "signer": btc, "signature": bip322_sign(ec.PrivateKey(BTC_KEY), statement_text(owner_st))}], "", OWNER_INBOX)
    taker_st = statement("taker", {"give": ("bitcoin", taker_btc), "receive": ("ethereum", OTHER_ETH)}, RESERVATION, TAKER_INBOX, "f6" * 16)
    taker_case = case("pair-taker", "taker", taker_st, [{"chain": "bitcoin", "scheme": "bip322-simple", "signer": taker_btc, "signature": bip322_sign(ec.PrivateKey(BTC_KEY2), statement_text(taker_st))}], RESERVATION, TAKER_INBOX)
    pairs = [{"name": "btc-eth", "owner": owner_case, "taker": taker_case, "context": {"offer": OFFER, "reservation": RESERVATION, "owner_inbox": OWNER_INBOX, "taker_inbox": TAKER_INBOX}}]

    # Official BIP-322 vectors (bitcoin/bips bip-0322.mediawiki) for the P2WPKH address bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l.
    official_key = ec.PrivateKey.from_wif("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k")
    official = {
        "public_key": official_key.get_public_key().sec().hex(),
        "signatures": {
            "": "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
            "Hello World": "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
        },
    }
    for message, expected in official["signatures"].items():
        produced = bip322_sign(official_key, message)
        if produced != expected:
            sys.exit(f"embit BIP-322 signing disagrees with the official vector for {message!r}:\n {produced}\n {expected}")
    OUT.write_text(json.dumps({
        "about": "Generated by scripts/make_identity_vectors.py; test keys only. See .agent/SWAP_RELAY_IDENTITY_EXECPLAN.md.",
        "prefix": PREFIX, "other": {"ethereum": OTHER_ETH, "cardano": OTHER_ADA, "bitcoin": OTHER_BTC},
        "bip322_official": official, "cases": cases, "pairs": pairs,
    }, indent=1, sort_keys=True) + "\n")
    print("wrote", OUT.relative_to(ROOT), len(cases), "cases")


if __name__ == "__main__":
    main()
