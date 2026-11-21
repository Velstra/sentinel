# A protocol whose server speaks first (SMTP, FTP, POP, IMAP, SSH), for the
# SYN-proxy checks. `serve PORT...` greets every connection with a banner and
# answers one line; `probe HOST PORT` connects, waits for the banner WITHOUT
# sending anything, then exchanges one line. A proxy that only lets the
# server's segments through once the client has spoken hangs the probe.
import socket
import sys
import threading

BANNER = b"220 synproxy-banner ready\r\n"
REPLY = b"221 bye\r\n"


def handle(connection):
    with connection:
        connection.sendall(BANNER)
        connection.settimeout(30)
        try:
            if connection.recv(1024):
                connection.sendall(REPLY)
        except OSError:
            pass


def serve(port):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(64)
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=handle, args=(connection,), daemon=True).start()


def read_line(connection):
    data = b""
    while not data.endswith(b"\n"):
        part = connection.recv(1024)
        if not part:
            break
        data += part
    return data


def probe(host, port):
    with socket.create_connection((host, port), timeout=8) as connection:
        connection.settimeout(8)
        banner = read_line(connection)
        assert banner == BANNER, f"banner {banner!r}"
        connection.sendall(b"QUIT\r\n")
        reply = read_line(connection)
        assert reply == REPLY, f"reply {reply!r}"
    print(f"server-first exchange with {host}:{port} completed")


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        threads = [
            threading.Thread(target=serve, args=(int(p),), daemon=True) for p in sys.argv[2:]
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    elif sys.argv[1] == "probe":
        probe(sys.argv[2], int(sys.argv[3]))
    else:
        sys.exit(f"usage: {sys.argv[0]} serve PORT... | probe HOST PORT")
