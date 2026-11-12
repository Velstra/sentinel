"""Independent UDP request/response proof; connected sockets enforce reply tuples."""
import argparse
import hashlib
import json
import socket

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=("server", "probe"))
parser.add_argument("--address", required=True)
parser.add_argument("--port", type=int, default=9105)
parser.add_argument("--source")
parser.add_argument("--expected-peer")
args = parser.parse_args()
if args.mode == "server":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((args.address, args.port))
        while True:
            data, peer = server.recvfrom(65535)
            server.sendto(json.dumps({
                "marker": "sentinel-independent-routed-UDP",
                "peer": peer[0],
                "request_SHA256": hashlib.sha256(data).hexdigest(),
            }).encode(), peer)
else:
    assert args.source and args.expected_peer
    responses = []
    for number in range(16):
        payload = bytes(range(256)) + ("-routed-UDP-" + str(number)).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.bind((args.source, 0))
            client.connect((args.address, args.port))
            client.send(payload)
            response = json.loads(client.recv(4096))
            assert response == {
                "marker": "sentinel-independent-routed-UDP",
                "peer": args.expected_peer,
                "request_SHA256": hashlib.sha256(payload).hexdigest(),
            }, response
            responses.append({"connected_reply_tuple": client.getpeername(), "observed_peer": response["peer"]})
    print(json.dumps({"datagrams": len(responses), "observations": responses}))
