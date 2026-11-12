"""Independent ephemeral QA TCP peer: report the wire peer, then echo frames."""
import json
import socketserver
import threading


class Peer(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(60)
        self.wfile.write((json.dumps({'peer':self.client_address})+'\n').encode())
        self.wfile.flush()
        while True:
            frame=self.rfile.readline(32768)
            if not frame:
                return
            assert len(frame)<=16384 and frame.endswith(b'\n')
            self.wfile.write(frame)
            self.wfile.flush()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


servers=[Server(('198.18.10.254',port),Peer) for port in (9101,10920)]
for server in servers[:-1]:
    threading.Thread(target=server.serve_forever,daemon=True).start()
servers[-1].serve_forever()
