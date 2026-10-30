# DEFAULT Protocol – Specification v1.1

This document is the normative definition of a DEFAULT record. Any
implementation, in any language, that follows it can create and verify
records interoperably. The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Record

A record is a JSON object with exactly these 6 fields:

| Field          | Type   | Content |
|----------------|--------|---------|
| `decision_id`  | string | Unique id, lowercase hex. Issuers SHOULD use SHA-256 over canonical JSON of `{subject_id, timestamp, nonce}` with a random 128-bit `nonce`. |
| `subject_id`   | string | Identifier of the decider, 1–256 chars. MAY be a pseudonym or a hash. |
| `values_hash`  | string | `SHA-256(canonical_json(values))`, lowercase hex. |
| `context_hash` | string | `SHA-256(canonical_json(context))`, lowercase hex. |
| `timestamp`    | string | ISO 8601 UTC with `Z` suffix, e.g. `2026-10-30T15:28:44.431786Z`. |
| `signatures`   | array  | One or more signature objects (section 3). The first SHOULD have role `issuer`. |

`values` and `context` are JSON objects. They are **not** part of the record:
only their hashes are. Whoever holds the originals can prove they match.
Do not put personal data in `subject_id`: hash or pseudonymize it.

## 2. Canonical JSON

All hashing and signing uses canonical JSON:

- object keys sorted by Unicode code point, recursively;
- no insignificant whitespace (separators `,` and `:`);
- strings as UTF-8, non-ASCII characters not escaped;
- integers SHOULD be used instead of floats, because float formatting
  differs between languages.

Python reference: `json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")`.
This is compatible with RFC 8785 (JCS) for objects that contain no floats.

## 3. Signatures

The **signing input** is the canonical JSON of the 5 base fields:
`{decision_id, subject_id, values_hash, context_hash, timestamp}`.

A signature object is:

```json
{
  "role": "issuer",
  "signer_id": "default-node-issuer",
  "alg": "Ed25519",
  "public_key": "<base64url, no padding, raw 32 bytes>",
  "signature":  "<base64url, no padding, raw 64 bytes>"
}
```

Roles in use: `issuer` (the node that created the record), `subject` (the
decider countersigns), `witness` and `tsa` (third parties, e.g. a timestamp
authority). Other signers append their object to the array; they sign the
same signing input.

`HMAC-SHA256` (v1.0) is deprecated: it can only be checked by whoever holds
the secret, so it MUST NOT be used for new records.

## 4. Verification

A verifier MUST:

1. check that all 6 fields are present;
2. verify **every** signature over the signing input; one invalid signature makes the record invalid;
3. check that at least one valid signature comes from a public key it **trusts**
   (obtained out of band, e.g. from `GET /.well-known/default-node.json` over
   HTTPS, a DNS record, or a published registry). A valid signature from an
   unknown key only proves that *someone* signed it.

If the originals are available, it MUST also recompute `values_hash` and
`context_hash` and compare them.

`verify_record.py` is a standalone reference verifier.

## 5. Node HTTP API (reference)

| Method | Path | Description |
|--------|------|-------------|
| GET  | `/status` | Node id, version, public key, record count. |
| GET  | `/pubkey`, `/.well-known/default-node.json` | Node public key. |
| POST | `/record` | Body `{subject_id, values, context}` → 201 `{record}`. |
| GET  | `/record?id=` | One stored record. |
| GET  | `/records` | All stored records. |
| GET  | `/verify?id=` | Verify a stored record against this node's key. |
| POST | `/verify` | Body `{record, values?, context?}`: verify any record. |
