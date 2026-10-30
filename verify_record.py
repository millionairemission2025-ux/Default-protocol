#!/usr/bin/env python3
"""
DEFAULT Protocol – Offline Verifier

Verifies a DEFAULT record without contacting any node, following SPEC.md.

Usage:
  python3 verify_record.py record.json
  python3 verify_record.py record.json --values values.json --context context.json
  python3 verify_record.py record.json --trust <issuer public key>

Exit code 0 = valid, 1 = invalid.

License: CC0-1.0 (Public Domain)
"""

import argparse
import base64
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE_FIELDS = ("decision_id", "subject_id", "values_hash", "context_hash", "timestamp")

def canonical_json(d) -> bytes:
    return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def verify(record: dict, values=None, context=None, trusted=None) -> list:
    """Return a list of problems; an empty list means the record is valid."""
    problems = []
    missing = [k for k in BASE_FIELDS if k not in record]
    if missing:
        return [f"missing fields: {', '.join(missing)}"]
    message = canonical_json({k: record[k] for k in BASE_FIELDS})

    sigs = record.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return ["no signatures"]
    signers = set()
    for i, s in enumerate(sigs):
        if not isinstance(s, dict) or s.get("alg") != "Ed25519":
            problems.append(f"signature {i}: unsupported alg {s.get('alg') if isinstance(s, dict) else s!r}")
            continue
        try:
            Ed25519PublicKey.from_public_bytes(b64url_decode(s["public_key"])).verify(
                b64url_decode(s["signature"]), message
            )
            signers.add(s["public_key"])
        except (InvalidSignature, KeyError, ValueError, TypeError):
            problems.append(f"signature {i} ({s.get('role')}): INVALID")

    if trusted and not signers & set(trusted):
        problems.append("no valid signature from a trusted public key")
    if values is not None and hashlib.sha256(canonical_json(values)).hexdigest() != record["values_hash"]:
        problems.append("values do not match values_hash")
    if context is not None and hashlib.sha256(canonical_json(context)).hexdigest() != record["context_hash"]:
        problems.append("context does not match context_hash")
    return problems

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def main():
    p = argparse.ArgumentParser(description="Verify a DEFAULT record offline.")
    p.add_argument("record", help="record JSON file (a bare record or the node's {\"record\": ...} response)")
    p.add_argument("--values", help="original values JSON file")
    p.add_argument("--context", help="original context JSON file")
    p.add_argument("--trust", action="append", help="trusted issuer public key (repeatable)")
    a = p.parse_args()

    record = load(a.record)
    record = record.get("record", record)
    problems = verify(
        record,
        values=load(a.values) if a.values else None,
        context=load(a.context) if a.context else None,
        trusted=a.trust,
    )
    if problems:
        print("INVALID")
        for pr in problems:
            print(f"  - {pr}")
        sys.exit(1)
    print(f"VALID  decision_id={record['decision_id']}  timestamp={record['timestamp']}")
    if not a.trust:
        print("  note: signer not checked against a trusted key (use --trust)")

if __name__ == "__main__":
    main()
