"""Independent isolated QA target, no actual customer data or credentials."""
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import sys


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        data=json.dumps({'peer':self.client_address[0],'marker':'sentinel-ipsec-failclosed-target'}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers()
        self.wfile.write(data)


address=sys.argv[1] if len(sys.argv)>1 else '198.19.210.9'
port=int(sys.argv[2]) if len(sys.argv)>2 else 9102
HTTPServer((address,port),Target).serve_forever()
