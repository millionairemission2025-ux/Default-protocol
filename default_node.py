#!/usr/bin/env python3
"""
DEFAULT Protocol – Reference Node v1.0
Minimal open standard for Digital Decision Certification.

Features:
- Creates DEFAULT records (6 fields, signatures as array)
- Stores them in a SQLite ledger
- Exposes a simple HTTP API
- Periodically verifies stored records

License: CC0-1.0 (Public Domain)
"""

import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import hmac
import logging

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────

SECRET_ISSUER = os.environ.get("DEFAULT_ISSUER_SECRET", "change-this-issuer-secret")
NODE_ID = os.environ.get("DEFAULT_NODE_ID", "default-node-issuer")

DB_PATH = os.environ.get("DEFAULT_DB", "default_ledger.db")
PORT = int(os.environ.get("DEFAULT_PORT", 8080))
VERIFY_INTERVAL = int(os.environ.get("DEFAULT_VERIFY_INTERVAL", 60) or 60)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DEFAULT] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)

# ─────────────────────────────────────────
#  CRYPTO HELPERS
# ─────────────────────────────────────────

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def hash_dict(d: dict) -> str:
    """Deterministic SHA-256 hash of a dict (JSON, sorted keys)."""
    serialized = json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return sha256_hex(serialized)

def sign_payload(payload: dict, role: str) -> dict:
    """
    Simple HMAC-SHA256 signature.
    In a real deployment you would replace this with asymmetric signatures.
    """
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    sig = hmac.new(
        SECRET_ISSUER.encode("utf-8"),
        serialized.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return {
        "role": role,           # e.g. "issuer"
        "signer_id": NODE_ID,   # node identifier
        "alg": "HMAC-SHA256",
        "signature": sig
    }

def verify_signature(payload: dict, signature_obj: dict) -> bool:
    if signature_obj.get("alg") != "HMAC-SHA256":
        return False
    expected = sign_payload(payload, role=signature_obj.get("role", "issuer"))
    # compare only signature string
    return hmac.compare_digest(
        signature_obj.get("signature", ""),
        expected.get("signature", "")
    )

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
    timestamp = datetime.now(timezone.utc).isoformat()

    values_hash = hash_dict(values)
    context_hash = hash_dict(context)

    # decision_id can be derived from subject_id + timestamp
    decision_id = hash_dict({"subject_id": subject_id, "timestamp": timestamp})

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

def verify_record_integrity(record: dict) -> bool:
    """Recompute and verify all signatures against the base payload."""
    base = {
        "decision_id": record["decision_id"],
        "subject_id": record["subject_id"],
        "values_hash": record["values_hash"],
        "context_hash": record["context_hash"],
        "timestamp": record["timestamp"]
    }
    sigs = record.get("signatures", [])
    if not isinstance(sigs, list) or not sigs:
        return False
    # For this reference node we only check signatures created with our secret
    ok_any = False
    for s in sigs:
        if s.get("alg") == "HMAC-SHA256":
            if verify_signature(base, s):
                ok_any = True
            else:
                # one invalid HMAC signature is enough to flag tampering
                return False
    return ok_any

# ─────────────────────────────────────────
#  WATCHDOG
# ─────────────────────────────────────────

def watchdog_loop():
    logging.info(f"Watchdog started – verify every {VERIFY_INTERVAL} seconds")
    while True:
        time.sleep(VERIFY_INTERVAL)
        records = get_all_records()
        ok = 0
        bad = 0
        for r in records:
            if verify_record_integrity(r):
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

class DefaultHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Silence default HTTP log; we use logging module instead
        logging.info("HTTP %s - %s", self.command, self.path)

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/status":
            records = get_all_records()
            self.send_json({
                "node_id": NODE_ID,
                "version": "1.0",
                "records_total": len(records),
                "verify_interval_seconds": VERIFY_INTERVAL
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
            valid = verify_record_integrity(rec)
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

        if parsed.path == "/record":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_json({"error": "invalid JSON body"}, status=400)
                return

            subject_id = payload.get("subject_id", "anonymous")
            values = payload.get("values", {})
            context = payload.get("context", {})

            try:
                record = create_default_record(subject_id, values, context)
                self.send_json({"status": "created", "record": record}, status=201)
            except Exception as e:
                logging.exception("Error creating record")
                self.send_json({"error": str(e)}, status=500)
        else:
            self.send_json({"error": "not found"}, status=404)

# ─────────────────────────────────────────
#  SERVER START
# ─────────────────────────────────────────

def start_server():
    server = HTTPServer(("0.0.0.0", PORT), DefaultHandler)
    logging.info(f"API listening on http://0.0.0.0:{PORT}")
    server.serve_forever()

# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
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
