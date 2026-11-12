"""Real HTTPS listener regressions. No root, live apply, or TLS bypass required.

SENTINEL_BIN=/path/to/sentinel python3 tests/management_tls.py -v
Uses only the Python standard library, OpenSSL and the actual appliance binary.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest


class ManagementTls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-https-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "appliance.toml"
        self.token = self.root / "api-token"
        self.cert = self.root / "web-tls/cert.pem"
        self.key = self.root / "web-tls/key.pem"
        self.config.write_text('[system]\nhostname="tls-fixture"\n[services.web]\ntls=true\n')
        self.binary = os.environ.get("SENTINEL_BIN")
        self.assertTrue(self.binary, "Set SENTINEL_BIN to the actual binary under test")

    @contextmanager
    def listener(self, address):
        with socket.socket() as probe:
            probe.bind((address, 0))
            port = probe.getsockname()[1]
        env = os.environ.copy()
        env.pop("SENTINEL_API_LISTENER_CONFIG", None)
        env["SENTINEL_API_TOKEN"] = "disposable-local-tls-regression-token"
        # API output can contain a generated token; keep it in a private fixture,
        # not an assertion message or CI log.
        with (self.root / "private-api.log").open("wb") as log:
            proc = subprocess.Popen(
                [self.binary, "api", "--no-apply", "--config", str(self.config),
                 "--token-file", str(self.token), "--listen", f"{address}:{port}"],
                env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            )
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    self.assertIsNone(proc.poll(), "HTTPS listener exited before readiness; private log retained until fixture cleanup")
                    try:
                        with socket.create_connection((address, port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    self.fail("HTTPS listener was not ready within 15 seconds")
                yield port
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

    def https(self, address, port, ca, name=None):
        context = ssl.create_default_context(cafile=str(ca))
        with socket.create_connection((address, port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=name or address) as tls:
                tls.sendall(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                response = b""
                while True:
                    part = tls.recv(65536)
                    if not part:
                        break
                    response += part
                    self.assertLess(len(response), 1048576)
        self.assertIn(b"200 OK", response.split(b"\r\n", 1)[0])
        self.assertIn(b"ok", response)

    def identity(self):
        public_pem = subprocess.run(
            ["openssl", "x509", "-in", str(self.cert), "-pubkey", "-noout"],
            capture_output=True, check=True,
        ).stdout
        public_der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_pem,
            capture_output=True, check=True,
        ).stdout
        return self.key.read_bytes(), hashlib.sha256(public_der).digest()

    def test_rebind_renews_real_https_identity_without_rotating_the_pin(self):
        with self.listener("127.0.0.1") as port:
            self.https("127.0.0.1", port, self.cert)
        identity = self.identity()
        original_cert = self.cert.read_bytes()
        with self.listener("127.0.0.2") as port:
            self.https("127.0.0.2", port, self.cert)
            self.https("127.0.0.2", port, self.cert, "localhost")
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.https("127.0.0.2", port, self.cert, "127.0.0.3")
            self.assertEqual(self.identity(), identity)
            self.assertNotEqual(self.cert.read_bytes(), original_cert)
        renewed = self.cert.read_bytes()
        with self.listener("127.0.0.2") as port:
            self.https("127.0.0.2", port, self.cert)
            self.assertEqual(self.cert.read_bytes(), renewed)
            self.assertEqual(self.identity(), identity)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_explicit_operator_certificate_is_never_renewed_or_replaced(self):
        # Create the automatic identity first, then explicitly select a separate
        # operator certificate which does NOT cover the next bind address.
        with self.listener("127.0.0.1") as port:
            self.https("127.0.0.1", port, self.cert)
        auto = (self.cert.read_bytes(), self.key.read_bytes())
        cert, key = self.root / "operator.pem", self.root / "operator-key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=operator", "-addext", "subjectAltName=IP:127.0.0.1",
             "-out", str(cert), "-keyout", str(key)],
            capture_output=True, check=True,
        )
        operator = (cert.read_bytes(), key.read_bytes())
        self.config.write_text('[system]\nhostname="tls-fixture"\n[services.web]\ntls=true\n'
                               f'tls-cert="{cert}"\ntls-key="{key}"\n')
        with self.listener("127.0.0.1") as port:
            self.https("127.0.0.1", port, cert)
        with self.listener("127.0.0.2") as port:
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.https("127.0.0.2", port, cert)
            # Verify trust AND the declared operator name on the same listener.
            self.https("127.0.0.2", port, cert, "127.0.0.1")
        self.assertEqual((cert.read_bytes(), key.read_bytes()), operator)
        self.assertEqual((self.cert.read_bytes(), self.key.read_bytes()), auto)


if __name__ == "__main__":
    unittest.main()
