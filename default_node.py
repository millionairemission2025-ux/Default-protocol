#!/usr/bin/env python3
"""
DEFAULT Protocol – Reference Node v1.1
Minimal open standard for Digital Decision Certification.

Features:
- Creates DEFAULT records (6 fields, signatures as array)
- Signs them with Ed25519, so anyone can verify them with the node's public key
- Stores them in a SQLite ledger
- Exposes a simple HTTP API
- Periodically verifies stored records

See SPEC.md for the canonical serialization and verification rules.

License: CC0-1.0 (Public Domain)
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import hmac
import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────

PROTOCOL_VERSION = "1.1"

NODE_ID = os.environ.get("DEFAULT_NODE_ID", "default-node-issuer")
KEY_PATH = os.environ.get("DEFAULT_KEY_PATH", "default_node_key.pem")
# Only used to verify legacy v1.0 HMAC records; never used to sign.
LEGACY_HMAC_SECRET = os.environ.get("DEFAULT_ISSUER_SECRET")

DB_PATH = os.environ.get("DEFAULT_DB", "default_ledger.db")
HOST = os.environ.get("DEFAULT_HOST", "0.0.0.0")
PORT = int(os.environ.get("DEFAULT_PORT", 8080))
VERIFY_INTERVAL = int(os.environ.get("DEFAULT_VERIFY_INTERVAL", 60) or 60)
MAX_BODY_BYTES = int(os.environ.get("DEFAULT_MAX_BODY_BYTES", 64 * 1024))
MAX_SUBJECT_ID_LEN = 256

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DEFAULT] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)

# ─────────────────────────────────────────
#  CRYPTO HELPERS
# ─────────────────────────────────────────

BASE_FIELDS = ("decision_id", "subject_id", "values_hash", "context_hash", "timestamp")

def canonical_json(d) -> str:
    """Canonical JSON: sorted keys, no whitespace, UTF-8 (see SPEC.md)."""
    return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def hash_dict(d: dict) -> str:
    """Deterministic SHA-256 hash of a dict (canonical JSON)."""
    return sha256_hex(canonical_json(d))

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def load_or_create_key(path: str) -> Ed25519PrivateKey:
    """Load the node's Ed25519 key, generating and persisting it on first run."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    logging.info(f"Generated new Ed25519 node key → {path}")
    return key

def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64url(raw)

_signing_key = None

def signing_key() -> Ed25519PrivateKey:
    global _signing_key
    if _signing_key is None:
        _signing_key = load_or_create_key(KEY_PATH)
    return _signing_key

def base_payload(record: dict) -> dict:
    return {k: record[k] for k in BASE_FIELDS}

def sign_payload(payload: dict, role: str) -> dict:
    key = signing_key()
    sig = key.sign(canonical_json(payload).encode("utf-8"))
    return {
        "role": role,                       # e.g. "issuer"
        "signer_id": NODE_ID,               # node identifier
        "alg": "Ed25519",
        "public_key": public_key_b64(key),  # base64url, raw 32 bytes
        "signature": b64url(sig)            # base64url, raw 64 bytes
    }

def verify_signature(payload: dict, signature_obj: dict) -> bool:
    alg = signature_obj.get("alg")
    message = canonical_json(payload).encode("utf-8")
    if alg == "Ed25519":
        try:
            pub = Ed25519PublicKey.from_public_bytes(
                b64url_decode(signature_obj.get("public_key", ""))
            )
            pub.verify(b64url_decode(signature_obj.get("signature", "")), message)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
    if alg == "HMAC-SHA256" and LEGACY_HMAC_SECRET:
        expected = hmac.new(
            LEGACY_HMAC_SECRET.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature_obj.get("signature", ""), expected)
    return False

# ─────────────────────────────────────────
#  LEDGER (SQLite)
# ─────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS records (
            decision_id   TEXT PRIMARY KEY,
            raw_json      TEXT NOT NULL,
            verified      INTEGER DEFAULT 1,
            created_at    TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    logging.info(f"Ledger initialized → {DB_PATH}")

def save_record(record: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO records (decision_id, raw_json, verified, created_at) VALUES (?, ?, ?, ?)",
        (
            record["decision_id"],
            json.dumps(record, ensure_ascii=False, separators=(",", ":")),
            1,
            record["timestamp"]
        )
    )
    conn.commit()
    conn.close()

def get_all_records() -> list:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT raw_json FROM records ORDER BY created_at DESC").fetchall()
    conn.close()
    return [json.loads(r[0]) for r in rows]

def get_record(decision_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT raw_json, verified FROM records WHERE decision_id = ?", (decision_id,)).fetchone()
    conn.close()
    if not row:
        return None
    data = json.loads(row[0])
    data["_verified_flag"] = bool(row[1])
    return data

def mark_tampered(decision_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE records SET verified = 0 WHERE decision_id = ?", (decision_id,))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────
#  DEFAULT RECORD CREATION
# ─────────────────────────────────────────

def create_default_record(subject_id: str, values: dict, context: dict) -> dict:
    """
    Create a DEFAULT record with 6 main fields:
      decision_id, subject_id, values_hash, context_hash, timestamp, signatures[]
    """
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    values_hash = hash_dict(values)
    context_hash = hash_dict(context)

    # decision_id: subject_id + timestamp + random nonce, so ids never collide
    decision_id = hash_dict({
        "subject_id": subject_id,
        "timestamp": timestamp,
        "nonce": secrets.token_hex(16)
    })

    base = {
        "decision_id": decision_id,
        "subject_id": subject_id,
        "values_hash": values_hash,
        "context_hash": context_hash,
        "timestamp": timestamp
    }

    # Signatures is an array – first signer is the issuer (this node)
    issuer_signature = sign_payload(base, role="issuer")

    record = {
        **base,
        "signatures": [issuer_signature]
    }

    save_record(record)
    logging.info(f"New DEFAULT record → {decision_id[:16]}...")
    return record

def verify_record_integrity(record: dict, trusted_keys=None) -> bool:
    """
    Verify every signature against the base payload.
    If trusted_keys is given, at least one valid signature must come from one
    of those public keys (otherwise a forger could just sign with their own key).
    """
    try:
        base = base_payload(record)
    except KeyError:
        return False
    sigs = record.get("signatures", [])
    if not isinstance(sigs, list) or not sigs:
        return False
    trusted_ok = trusted_keys is None
    for s in sigs:
        if not isinstance(s, dict) or not verify_signature(base, s):
            # one invalid signature is enough to flag tampering
            return False
        if s.get("alg") == "HMAC-SHA256" or (
            trusted_keys is not None and s.get("public_key") in trusted_keys
        ):
            # a valid legacy HMAC can only come from the holder of our secret
            trusted_ok = True
    return trusted_ok

def verify_values(record: dict, values=None, context=None) -> bool:
    """Check that the original values/context match the hashes in the record."""
    if values is not None and hash_dict(values) != record.get("values_hash"):
        return False
    if context is not None and hash_dict(context) != record.get("context_hash"):
        return False
    return True

# ─────────────────────────────────────────
#  WATCHDOG
# ─────────────────────────────────────────

def node_trusted_keys():
    return {public_key_b64(signing_key())}

def watchdog_loop():
    logging.info(f"Watchdog started – verify every {VERIFY_INTERVAL} seconds")
    while True:
        time.sleep(VERIFY_INTERVAL)
        records = get_all_records()
        ok = 0
        bad = 0
        for r in records:
            if verify_record_integrity(r, trusted_keys=node_trusted_keys()):
                ok += 1
            else:
                bad += 1
                mark_tampered(r["decision_id"])
                logging.warning(f"⚠ Tampering detected → {r['decision_id'][:16]}...")
        logging.info(f"Watchdog check → {ok} valid, {bad} tampered")

def start_watchdog():
    t = threading.Thread(target=watchdog_loop, daemon=True)
    t.start()

# ─────────────────────────────────────────
#  HTTP API
# ─────────────────────────────────────────

class BadRequest(Exception):
    pass

class DefaultHandler(BaseHTTPRequestHandler):

    server_version = f"DEFAULT/{PROTOCOL_VERSION}"

    def log_message(self, fmt, *args):
        # Silence default HTTP log; we use logging module instead
        logging.info("HTTP %s - %s", self.command, self.path)

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise BadRequest("invalid Content-Length")
        if length > MAX_BODY_BYTES:
            raise BadRequest(f"body too large (max {MAX_BODY_BYTES} bytes)")
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            raise BadRequest("invalid JSON body")
        if not isinstance(payload, dict):
            raise BadRequest("JSON body must be an object")
        return payload

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/status":
            records = get_all_records()
            self.send_json({
                "node_id": NODE_ID,
                "version": PROTOCOL_VERSION,
                "public_key": public_key_b64(signing_key()),
                "records_total": len(records),
                "verify_interval_seconds": VERIFY_INTERVAL
            })

        elif parsed.path in ("/pubkey", "/.well-known/default-node.json"):
            self.send_json({
                "node_id": NODE_ID,
                "alg": "Ed25519",
                "public_key": public_key_b64(signing_key()),
                "version": PROTOCOL_VERSION
            })

        elif parsed.path == "/records":
            self.send_json({"records": get_all_records()})

        elif parsed.path == "/record":
            decision_id = params.get("id", [None])[0]
            if not decision_id:
                self.send_json({"error": "missing ?id="}, status=400)
                return
            rec = get_record(decision_id)
            if not rec:
                self.send_json({"error": "record not found"}, status=404)
                return
            self.send_json(rec)

        elif parsed.path == "/verify":
            decision_id = params.get("id", [None])[0]
            if not decision_id:
                self.send_json({"error": "missing ?id="}, status=400)
                return
            rec = get_record(decision_id)
            if not rec:
                self.send_json({"error": "record not found"}, status=404)
                return
            valid = verify_record_integrity(rec, trusted_keys=node_trusted_keys())
            self.send_json({
                "decision_id": decision_id,
                "valid": valid,
                "timestamp": rec["timestamp"],
                "subject_id": rec["subject_id"]
            })

        else:
            self.send_json({"error": "not found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            payload = self.read_json_body()
        except BadRequest as e:
            self.send_json({"error": str(e)}, status=400)
            return

        if parsed.path == "/record":
            subject_id = payload.get("subject_id", "anonymous")
            values = payload.get("values", {})
            context = payload.get("context", {})
            if not isinstance(subject_id, str) or not subject_id or len(subject_id) > MAX_SUBJECT_ID_LEN:
                self.send_json({"error": f"subject_id must be a non-empty string (max {MAX_SUBJECT_ID_LEN} chars)"}, status=400)
                return
            if not isinstance(values, dict) or not isinstance(context, dict):
                self.send_json({"error": "values and context must be JSON objects"}, status=400)
                return

            try:
                record = create_default_record(subject_id, values, context)
                self.send_json({"status": "created", "record": record}, status=201)
            except Exception:
                logging.exception("Error creating record")
                self.send_json({"error": "internal error"}, status=500)

        elif parsed.path == "/verify":
            # Verify any record (from any node) plus, optionally, its original data.
            record = payload.get("record")
            if not isinstance(record, dict):
                self.send_json({"error": "missing record object"}, status=400)
                return
            signatures_valid = verify_record_integrity(record)
            data_valid = verify_values(record, payload.get("values"), payload.get("context"))
            signers = [s.get("public_key") for s in record.get("signatures", []) if isinstance(s, dict)]
            self.send_json({
                "decision_id": record.get("decision_id"),
                "signatures_valid": signatures_valid,
                "data_valid": data_valid,
                "valid": signatures_valid and data_valid,
                "signed_by_this_node": public_key_b64(signing_key()) in signers
            })

        else:
            self.send_json({"error": "not found"}, status=404)

# ─────────────────────────────────────────
#  SERVER START
# ─────────────────────────────────────────

def start_server():
    server = ThreadingHTTPServer((HOST, PORT), DefaultHandler)
    logging.info(f"API listening on http://{HOST}:{PORT}")
    logging.info(f"Node public key (Ed25519) → {public_key_b64(signing_key())}")
    server.serve_forever()

# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    signing_key()
    init_db()
    start_watchdog()

    # create a self-record to prove the node started
    _ = create_default_record(
        subject_id=NODE_ID,
        values={"protocol": "DEFAULT", "node_status": "started"},
        context={"event": "node_boot"}
    )

    logging.info("DEFAULT node running")
    start_server()
