"""Independent Ethernet DHCP-shaped probes; never configure the DUT or a lease.

These deliberately use an unknown transaction ID. A packet reaching the local
capture proves the firewall path only, not acceptance by the real DHCP client.
"""
import argparse
from pathlib import Path
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def frame(source_mac, client_mac, case, xid):
    hardware = bytes.fromhex(client_mac.replace(':', ''))
    bootp = bytearray(240)
    bootp[:3] = bytes([2, 1, 6])
    bootp[4:8] = struct.pack('!I', xid)
    bootp[16:20] = socket.inet_aton('198.18.88.100')
    bootp[28:34] = hardware
    bootp[236:240] = bytes([99, 130, 83, 99])
    sport, dport = 67, 68
    destination = '255.255.255.255'
    source = '198.18.88.1'
    fragment = 0
    if case == 'unicast':
        destination = '198.18.88.100'
    elif case == 'foreign-destination':
        destination = '198.18.88.200'
    elif case == 'foreign-client':
        bootp[33] ^= 1
    elif case == 'wrong-cookie':
        bootp[239] ^= 1
    elif case == 'request-not-reply':
        bootp[0] = 1
    elif case == 'wrong-hardware':
        bootp[1] = 2
    elif case == 'wrong-hardware-length':
        bootp[2] = 5
    elif case == 'wrong-source-port':
        sport = 66
    elif case == 'wrong-destination-port':
        dport = 69
    elif case == 'fragment':
        fragment = 0x2000
    elif case == 'later-fragment':
        fragment = 1
    elif case == 'reserved-fragment-bit':
        fragment = 0x8000
    elif case == 'invalid-source':
        source = '127.0.0.1'
    elif case == 'short-bootp':
        bootp = bootp[:239]
    elif case not in ('broadcast', 'bad-udp-length', 'short-ip-length', 'truncated-ip', 'ipv4-options'):
        raise ValueError('Unknown bounded probe case')
    # A syntactically plausible OFFER, but not the DHCP client's transaction.
    payload = bootp + bytes([53, 1, 2, 255])
    length = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, length + (1 if case == 'bad-udp-length' else 0), 0) + payload
    total = 20 + len(udp)
    options = bytes([1, 1, 1, 0]) if case == 'ipv4-options' else b''
    total += len(options)
    if case == 'short-ip-length':
        total = 28
    elif case == 'truncated-ip':
        total += 100
    ip = struct.pack('!BBHHHBBH4s4s', 0x46 if options else 0x45, 0, total, xid & 65535, fragment, 64, 17, 0,
                     socket.inet_aton(source), socket.inet_aton(destination)) + options
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    ethernet = hardware + bytes.fromhex(source_mac.replace(':', '')) + b'\x08\x00'
    return ethernet + ip + udp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    parser.add_argument('client_mac')
    parser.add_argument('case')
    parser.add_argument('xid', type=lambda value: int(value, 0))
    args = parser.parse_args()
    source_mac = Path('/sys/class/net', args.interface, 'address').read_text().strip()
    packet = frame(source_mac, args.client_mac, args.case, args.xid)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sender:
        sender.bind((args.interface, 0))
        for _ in range(3):
            assert sender.send(packet) == len(packet)
            time.sleep(0.05)
    print(f'Sent three independent {args.case} probes xid={args.xid:#x}')


if __name__ == '__main__':
    main()
