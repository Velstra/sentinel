"""Client and server for checks.nat-port-reopen.

serve: on 198.18.10.254:9300, read one line, answer with the wire peer it saw,
then close first, so this end keeps the 4-tuple in TIME_WAIT (60 s on Linux).

open: one connection from a fixed source port. --abort ends it with a reset
(SO_LINGER 0) after the answer; otherwise it reads to EOF and closes cleanly.
Prints one JSON line: the outcome and the public port the server saw.
"""
import argparse
import json
import socket
import struct
import sys

SERVER = ("198.18.10.254", 9300)


def serve():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(SERVER)
    listener.listen(16)
    while True:
        conn, peer = listener.accept()
        with conn:
            conn.settimeout(5)
            try:
                conn.recv(64)
                conn.sendall((json.dumps({"peer": list(peer)}) + "\n").encode())
            except OSError:
                pass


def open_one(source, port, abort, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((source, port))
    sock.settimeout(timeout)
    try:
        sock.connect(SERVER)
        sock.sendall(b"reopen\n")
        answer = b""
        while not answer.endswith(b"\n"):
            chunk = sock.recv(256)
            if not chunk:
                break
            answer += chunk
        peer = json.loads(answer)["peer"]
        if abort:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        else:
            while sock.recv(256):
                pass
        return {"outcome": "ok", "public": peer}
    except socket.timeout:
        return {"outcome": "timeout"}
    except (OSError, ValueError, KeyError) as error:
        return {"outcome": type(error).__name__}
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("serve")
    one = sub.add_parser("open")
    one.add_argument("--source", required=True)
    one.add_argument("--port", type=int, required=True)
    one.add_argument("--abort", action="store_true")
    one.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    if args.verb == "serve":
        serve()
        return 0
    print(json.dumps(open_one(args.source, args.port, args.abort, args.timeout)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
