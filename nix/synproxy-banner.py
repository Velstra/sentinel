# A protocol whose server speaks first (SMTP, FTP, POP, IMAP, SSH), for the
# SYN-proxy checks. `serve PORT...` greets every connection with a banner and
# answers one line; `probe HOST PORT` connects, waits for the banner WITHOUT
# sending anything, then exchanges one line; `reuse HOST PORT LPORT PAUSE` makes
# two connections from one source port. A proxy that only lets the
# server's segments through once the client has spoken hangs the probe.
import socket
import struct
import sys
import threading

BANNER = b"220 synproxy-banner ready\r\n"
REPLY = b"221 bye\r\n"


def handle(connection):
    with connection:
        connection.sendall(BANNER)
        # Long enough for the idle connections the splice-lifetime check
        # holds open across its whole churn.
        connection.settimeout(600)
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


def reuse(host, port, local_port, pause):
    """Two connections from ONE source port, the first aborted with a reset,
    `pause` seconds apart.

    A client that reuses a source port toward a protected service is
    ordinary (an exhausted or sequential port range, a NAT in front of many
    clients). Once the proxy's record of the first connection is gone, the
    second must complete through the proxy like any other."""
    import time

    for attempt in ("first", "second"):
        if attempt == "second":
            time.sleep(pause)
        connection = socket.socket()
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        connection.bind(("0.0.0.0", local_port))
        connection.settimeout(8)
        connection.connect((host, port))
        banner = read_line(connection)
        assert banner == BANNER, f"{attempt} connection from :{local_port}: banner {banner!r}"
        # Abort with a reset, so neither end keeps the tuple in TIME_WAIT
        # and the next connect may reuse it at once.
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        connection.close()
    print(f"two connections from source port {local_port} to {host}:{port} completed")


def hold(host, port, marker):
    """Open one connection and keep it idle until `marker`.go exists, then use it.

    Writes `marker`.ready once the banner arrived, and `marker`.ok when the
    exchange after the idle period completed, or `marker`.fail with the error."""
    import os
    import time

    connection = socket.create_connection((host, port), timeout=8)
    banner = read_line(connection)
    assert banner == BANNER, f"banner {banner!r}"
    with open(marker + ".port", "w") as port_file:
        port_file.write(str(connection.getsockname()[1]))
    open(marker + ".ready", "w").close()
    while not os.path.exists(marker + ".go"):
        time.sleep(0.2)
    try:
        connection.settimeout(8)
        connection.sendall(b"QUIT\r\n")
        reply = read_line(connection)
        assert reply == REPLY, f"reply {reply!r}"
        open(marker + ".ok", "w").close()
    except Exception as error:
        with open(marker + ".fail", "w") as failed:
            failed.write(repr(error))
        raise


def churn(host, port, count, per_second, first_port):
    """`count` short connections at about `per_second`, from source ports
    `first_port` upward, each used once: every other one ends normally (QUIT,
    the server closes, FIN both ways), the rest with a reset."""
    import time

    for n in range(count):
        started = time.monotonic()
        connection = socket.socket()
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        connection.bind(("0.0.0.0", first_port + n))
        connection.settimeout(8)
        connection.connect((host, port))
        with connection:
            connection.settimeout(8)
            banner = read_line(connection)
            assert banner == BANNER, f"connection {n}: banner {banner!r}"
            if n % 2 == 0:
                connection.sendall(b"QUIT\r\n")
                assert read_line(connection) == REPLY, f"connection {n}: no reply"
            else:
                connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
        time.sleep(max(0.0, 1.0 / per_second - (time.monotonic() - started)))
    print(f"{count} short connections to {host}:{port} completed")


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
    elif sys.argv[1] == "hold":
        hold(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == "churn":
        churn(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), int(sys.argv[6]))
    elif sys.argv[1] == "reuse":
        reuse(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]))
    else:
        sys.exit(f"usage: {sys.argv[0]} serve PORT... | probe HOST PORT | reuse HOST PORT LPORT PAUSE | hold HOST PORT MARKER | churn HOST PORT N RATE FIRST_PORT")
