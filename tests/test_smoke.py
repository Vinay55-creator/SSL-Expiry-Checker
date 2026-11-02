"""Offline smoke tests: a local TLS server stands in for a real website, certificate-log lookups are mocked."""
import datetime as dt
import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["ALLOW_PRIVATE_TARGETS"] = "1"   # test server lives on 127.0.0.1

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import scanner
from exporters import build_pdf, build_xlsx


def make_cert(days_valid, cn="localhost"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=30))
            .not_valid_after(now + dt.timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def serve(days_valid, tmp):
    key, cert = make_cert(days_valid)
    cp, kp = os.path.join(tmp, f"c{days_valid}.pem"), os.path.join(tmp, f"k{days_valid}.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                continue
            try:
                ctx.wrap_socket(c, server_side=True).close()
            except Exception:
                pass
    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1], stop


class Tests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(scanner.normalize_domain("https://www.Example.com/path?x=1"), "example.com")
        self.assertEqual(scanner.normalize_domain("example.com:8443"), "example.com")
        for bad in ["", "localhost", "10.0.0.1", "not a domain", "http://"]:
            with self.assertRaises(ValueError):
                scanner.normalize_domain(bad)

    def test_clean_names(self):
        got = scanner._clean_names(["*.a.example.com", "B.example.com", "x@example.com", "evil.com", "example.com.evil.com"], "example.com")
        self.assertEqual(got, {"a.example.com", "b.example.com"})

    def test_live_check_and_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = []
            for days in (5, 200):
                port, stop = serve(days, tmp)
                scanner.SCAN_PORT = port
                r = scanner.check_host("localhost"); r["sources"] = ["test"]
                stop.set()
                self.assertIn(r["days_left"], (days - 1, days))
                self.assertEqual(r["status"], "critical" if days == 5 else "ok")
                self.assertFalse(r["trusted"])          # self-signed
                r["host"] = f"h{days}.example.com"
                rows.append(r)
            scanner.SCAN_PORT = 1                        # closed port
            dead = scanner.check_host("localhost"); dead["host"] = "dead.example.com"; dead["sources"] = []
            self.assertEqual(dead["status"], "error")
            rows.append(dead)

            rows = scanner.sort_results(rows)
            self.assertEqual([r["host"] for r in rows], ["h5.example.com", "h200.example.com", "dead.example.com"])
            snap = {"domain": "example.com", "results": rows, "summary": scanner.summarize(rows),
                    "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()}
            self.assertTrue(build_xlsx(snap).startswith(b"PK"))
            self.assertTrue(build_pdf(snap).startswith(b"%PDF"))

    def test_private_targets_blocked(self):
        scanner.ALLOW_PRIVATE_TARGETS = False
        try:
            r = scanner.check_host("localhost")
            self.assertEqual(r["status"], "error")
            self.assertIn("private", r["error"].lower())
        finally:
            scanner.ALLOW_PRIVATE_TARGETS = True

    def test_api_flow(self):
        import time
        from unittest import mock
        import app as webapp
        fake = lambda h: {"host": h, "status": "ok", "days_left": 40, "expires_at": "2030-01-01T00:00:00+00:00",
                                        "issued_at": "2029-01-01T00:00:00+00:00", "issuer": "Test CA", "common_name": h,
                                        "ip": "203.0.113.5", "trusted": True, "trust_error": "", "error": ""}
        with mock.patch.object(scanner, "discover", lambda d, deep=False: ({d: {"entered"}}, ["demo warning"])), \
             mock.patch.object(scanner, "check_host", fake):
            self._api_flow(webapp, time)

    def _api_flow(self, webapp, time):
        c = webapp.app.test_client()
        self.assertEqual(c.post("/api/scan", json={"domain": "nope"}).status_code, 400)
        r = c.post("/api/scan", json={"domain": "https://www.example.com/"})
        self.assertEqual(r.status_code, 202)
        jid = r.get_json()["id"]
        for _ in range(50):
            snap = c.get(f"/api/scan/{jid}").get_json()
            if snap["phase"] == "done":
                break
            time.sleep(0.1)
        self.assertEqual(snap["phase"], "done")
        self.assertEqual(snap["results"][0]["host"], "example.com")
        self.assertEqual(c.get(f"/api/scan/{jid}/export.xlsx").status_code, 200)
        self.assertEqual(c.get(f"/api/scan/{jid}/export.pdf").mimetype, "application/pdf")
        self.assertEqual(c.get("/api/scan/missing").status_code, 404)
        self.assertEqual(c.get("/").status_code, 200)


if __name__ == "__main__":
    unittest.main()
