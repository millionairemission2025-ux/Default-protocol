import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp()
os.environ["DEFAULT_DB"] = os.path.join(TMP, "ledger.db")
os.environ["DEFAULT_KEY_PATH"] = os.path.join(TMP, "key.pem")

import default_node as node  # noqa: E402
import verify_record  # noqa: E402

node.init_db()


class RecordTests(unittest.TestCase):

    def setUp(self):
        self.values = {"terms": "v2", "accept": True}
        self.context = {"ui": "checkout", "lang": "it"}
        self.record = node.create_default_record("user-1", self.values, self.context)

    def test_record_has_six_fields(self):
        self.assertEqual(set(self.record), set(node.BASE_FIELDS) | {"signatures"})
        self.assertEqual(self.record["signatures"][0]["alg"], "Ed25519")

    def test_valid_record_verifies(self):
        self.assertTrue(node.verify_record_integrity(self.record, node.node_trusted_keys()))
        self.assertEqual(verify_record.verify(self.record, self.values, self.context,
                                              trusted=node.node_trusted_keys()), [])

    def test_tampered_field_fails(self):
        bad = {**self.record, "values_hash": "0" * 64}
        self.assertFalse(node.verify_record_integrity(bad))
        self.assertTrue(verify_record.verify(bad))

    def test_wrong_values_fail(self):
        self.assertFalse(node.verify_values(self.record, {"terms": "v3", "accept": True}))
        self.assertTrue(verify_record.verify(self.record, values={"terms": "v3"}))

    def test_resigned_with_foreign_key_is_untrusted(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        forger = Ed25519PrivateKey.generate()
        forged = {k: self.record[k] for k in node.BASE_FIELDS}
        forged["subject_id"] = "someone-else"
        sig = forger.sign(node.canonical_json(forged).encode())
        forged["signatures"] = [{"role": "issuer", "alg": "Ed25519",
                                 "public_key": node.public_key_b64(forger),
                                 "signature": node.b64url(sig)}]
        # cryptographically valid, but not from the trusted node
        self.assertTrue(node.verify_record_integrity(forged))
        self.assertFalse(node.verify_record_integrity(forged, node.node_trusted_keys()))
        self.assertTrue(verify_record.verify(forged, trusted=node.node_trusted_keys()))

    def test_decision_ids_unique(self):
        ids = {node.create_default_record("same", {}, {})["decision_id"] for _ in range(50)}
        self.assertEqual(len(ids), 50)


class ApiTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), node.DefaultHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def call(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_create_and_verify_roundtrip(self):
        status, res = self.call("/record", {"subject_id": "u", "values": {"a": 1}, "context": {}})
        self.assertEqual(status, 201)
        rec = res["record"]
        status, res = self.call(f"/verify?id={rec['decision_id']}")
        self.assertTrue(res["valid"])
        status, res = self.call("/verify", {"record": rec, "values": {"a": 1}})
        self.assertTrue(res["valid"])
        self.assertTrue(res["signed_by_this_node"])
        status, res = self.call("/verify", {"record": rec, "values": {"a": 2}})
        self.assertFalse(res["valid"])

    def test_pubkey(self):
        status, res = self.call("/pubkey")
        self.assertEqual(res["public_key"], node.public_key_b64(node.signing_key()))

    def test_rejects_bad_input(self):
        self.assertEqual(self.call("/record", {"values": "not-an-object"})[0], 400)
        self.assertEqual(self.call("/record", {"subject_id": 123})[0], 400)
        self.assertEqual(self.call("/record", [1, 2])[0], 400)


if __name__ == "__main__":
    unittest.main()
