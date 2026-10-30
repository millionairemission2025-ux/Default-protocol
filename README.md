# DEFAULT Protocol (v1.1)
### The Minimal Open Standard for Digital Decision Certification.

DEFAULT is a neutral, minimal protocol designed to certify that a digital decision was made with explicit consent, at a specific time, within a specific context.

## Why DEFAULT?
Digital disputes often arise from ambiguity: *"I didn't agree"*, *"It wasn't clear"*, *"The terms changed"*. 
DEFAULT eliminates this by creating a standardized, 6-field cryptographic record of any digital agreement.

## The Record Structure
A DEFAULT record consists of exactly 6 fields:

1. **decision_id**: Unique identifier for the decision.
2. **subject_id**: Identifier of the decider (can be anonymized).
3. **values_hash**: SHA-256 hash of the declared values/terms.
4. **context_hash**: SHA-256 hash of the environment/context.
5. **timestamp**: ISO 8601 UTC synchronized time.
6. **signatures**: An array of Ed25519 digital signatures (Issuer, Subject, Timestamp Authority, etc.).

The full, language-independent rules are in [SPEC.md](SPEC.md).

## Core Principles
- **Minimalist**: Only 6 fields. No bloat.
- **Neutral**: Does not decide what is right; only certifies what was agreed.
- **Verifiable**: Anyone can re-hash the data and check the signatures with the issuer's public key, offline.
- **Open Source**: Released under CC0 (Public Domain). No licenses, no lock-in.

## Quick start

```bash
pip install -r requirements.txt
python3 default_node.py          # API on http://localhost:8080
```

Or with Docker (ledger and key kept in a volume):

```bash
docker build -t default-node .
docker run -p 8080:8080 -v default-data:/data default-node
```

Create a record:

```bash
curl -X POST localhost:8080/record -H 'Content-Type: application/json' \
  -d '{"subject_id":"user-42","values":{"terms":"v2"},"context":{"app":"checkout"}}' > record.json
```

Verify it offline, without trusting the server:

```bash
echo '{"terms":"v2"}' > values.json
python3 verify_record.py record.json --values values.json \
  --trust "$(curl -s localhost:8080/pubkey | python3 -c 'import sys,json;print(json.load(sys.stdin)["public_key"])')"
```

### Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `DEFAULT_NODE_ID` | `default-node-issuer` | Name written in signatures |
| `DEFAULT_KEY_PATH` | `default_node_key.pem` | Ed25519 private key (created on first run, mode 600). **Back it up and never commit it.** |
| `DEFAULT_DB` | `default_ledger.db` | SQLite ledger |
| `DEFAULT_HOST` / `DEFAULT_PORT` | `0.0.0.0` / `8080` | Listen address |
| `DEFAULT_VERIFY_INTERVAL` | `60` | Watchdog interval (seconds) |
| `DEFAULT_ISSUER_SECRET` | unset | Only to verify legacy v1.0 HMAC records |

For public deployment, put the node behind HTTPS (e.g. Caddy or nginx) and publish its public key.

### Tests

```bash
python3 -m unittest discover -s tests
```

## License
This project is dedicated to the public domain under CC0.
