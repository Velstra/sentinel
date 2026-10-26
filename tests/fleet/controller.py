"""Test-only Fleet protocol peer. Certificates/signing keys are disposable fixtures."""
import base64
import json
import pathlib
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT = pathlib.Path('/var/lib/fleet-test')
ROOT.mkdir(exist_ok=True)
KEY = load_pem_private_key((ROOT / 'signing.key').read_bytes(), password=None)
DOMAIN = b'Velstra Sentinel Fleet command v1\0'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Tokens and proposed documents never enter a log.

    def do_POST(self):
        if self.path != '/api/v1/sentinel/check-in':
            self.send_error(404)
            return
        subject = dict(item for group in self.connection.getpeercert()['subject'] for item in group)
        if subject.get('commonName') != 'edge-a' or self.headers.get('Authorization') != 'Bearer fleet-test-enrollment-credential':
            self.send_error(403)
            return
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 4 * 1024 * 1024:
            self.send_error(413)
            return
        request = json.loads(self.rfile.read(length))
        assert request['node'] == 'edge-a' and request['protocol'] == 1
        with (ROOT / 'requests.jsonl').open('a') as log:
            log.write(json.dumps(request) + '\n')
        path = ROOT / 'command.json'
        command = json.loads(path.read_text()) if path.exists() else None
        reply = {'command': None}
        if command:
            operation = command['operation']
            mode = command.get('mode', '')
            pending = request['transaction']['pending']
            ready = True
            if operation['action'] == 'apply-hostname':
                document = (ROOT / 'candidate.toml').read_text()
                operation = {'action': 'apply', 'toml': document, 'expected_revision': request['revision']}
            elif operation['action'] == 'confirm-current':
                ready = bool(pending and pending['ready'])
                if ready:
                    operation = {'action': 'confirm', 'id': pending['id'], 'revision': pending['revision']}
            if ready:
                path.unlink()
                payload = json.dumps({'sequence': command['sequence'], 'operation': operation}, separators=(',', ':')).encode()
                node = 'edge-b' if mode == 'wrong-node' else request['node']
                nonce = 'wrong-challenge' if mode == 'wrong-challenge' else request['nonce']
                signature = KEY.sign(DOMAIN + node.encode() + b'\0' + nonce.encode() + b'\0' + payload)
                if mode == 'wrong-signature':
                    signature = bytes([signature[0] ^ 1]) + signature[1:]
                reply['command'] = {'payload': base64.b64encode(payload).decode(), 'signature': base64.b64encode(signature).decode()}
        body = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(str(ROOT / 'server.pem'), str(ROOT / 'server.key'))
context.load_verify_locations(str(ROOT / 'ca.pem'))
context.verify_mode = ssl.CERT_REQUIRED
server = HTTPServer(('0.0.0.0', 9443), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
