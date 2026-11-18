"""Independent RFC 2865/3579 UDP peer for the Rust RADIUS wire regression.

Only Python's hashlib/hmac/socket are used: no Sentinel codec or digest helper.
The caller supplies a test-only scenario, never a real directory credential.
"""

import hashlib
import hmac
import socket
import struct
import sys


def attributes(packet):
    offset = 20
    result = []
    while offset < len(packet):
        kind, length = packet[offset : offset + 2]
        assert kind and length >= 2 and offset + length <= len(packet)
        result.append((kind, offset + 2, packet[offset + 2 : offset + length]))
        offset += length
    assert offset == len(packet)
    return result


mode = sys.argv[1]
secret = b"independent-radius-fixture-secret"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)
    print(server.getsockname()[1], flush=True)
    request, address = server.recvfrom(8192)
    assert request[0] == 1
    assert len(request) == struct.unpack("!H", request[2:4])[0]
    attrs = attributes(request)
    signatures = [(offset, value) for kind, offset, value in attrs if kind == 80]
    assert len(signatures) == 1 and len(signatures[0][1]) == 16
    offset, supplied = signatures[0]
    check = bytearray(request)
    check[offset : offset + 16] = bytes(16)
    assert hmac.compare_digest(supplied, hmac.new(secret, check, hashlib.md5).digest())
    values = {kind: value for kind, _, value in attrs}
    assert values[1] == b"alice" and values[32] == b"sentinel-test"
    hidden = values[2]
    assert 16 <= len(hidden) <= 128 and len(hidden) % 16 == 0
    plaintext = bytearray()
    previous = request[4:20]
    for start in range(0, len(hidden), 16):
        block = hidden[start : start + 16]
        mask = hashlib.md5(secret + previous).digest()
        plaintext.extend(a ^ b for a, b in zip(block, mask))
        previous = block
    assert plaintext.rstrip(b"\0") == b"radius-fixture-password"

    code = 3 if mode == "reject" else 2
    reply_attrs = bytearray([18, 4]) + b"OK"  # Independent optional Reply-Message.
    if mode != "missing":
        reply_attrs.extend(bytes([80, 18]) + bytes(16))
    if mode == "duplicate":
        reply_attrs.extend(bytes([80, 18]) + bytes(16))
    if mode == "short-attribute":
        reply_attrs.extend(bytes([18, 1]))
    if mode == "truncated-attribute":
        reply_attrs.extend(bytes([18, 12, 0]))
    if mode == "zero-type":
        reply_attrs.extend(bytes([0, 2]))
    if mode == "trailing-byte":
        reply_attrs.append(18)
    length = 20 + len(reply_attrs)
    declared = length - 1 if mode == "wrong-length" else length
    reply = bytearray([code, request[1]]) + struct.pack("!H", declared)
    reply.extend(request[4:20])
    reply.extend(reply_attrs)
    # Message-Authenticator precedes Response Authenticator calculation.
    if mode != "missing":
        message_offset = 26
        signature = hmac.new(secret, reply, hashlib.md5).digest()
        if mode == "wrong-message-authenticator":
            signature = bytes(16)
        reply[message_offset : message_offset + 16] = signature
    reply[4:20] = hashlib.md5(reply + secret).digest()
    if mode == "wrong-response-authenticator":
        reply[4:20] = bytes(16)
    if mode == "padded-accept":
        # RFC 2865: octets outside Length are padding, not authenticated TLVs.
        reply.extend(b"padding-outside-logical-packet\x00\xff")
    server.sendto(reply, address)
    print("independent request authenticator and PAP checks passed", flush=True)
