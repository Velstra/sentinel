#!/usr/bin/env python3
"""Normalize Rust BTF identifiers without changing types or string offsets.

LLVM can emit names such as MaybeUninit<u8>, which the kernel's BTF name
validator rejects. Only identifier references are normalized; section names,
source paths, line records, member layouts and relocations are unchanged.
"""
import struct
import sys
from pathlib import Path


def sanitize(raw: bytes) -> bytes:
    if len(raw) < 24:
        raise ValueError("truncated BTF header")
    magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        "<HBBIIIII", raw
    )
    if magic != 0xEB9F or version != 1 or flags or hdr_len < 24:
        raise ValueError("unsupported BTF header")
    start, end = hdr_len + type_off, hdr_len + type_off + type_len
    strings = hdr_len + str_off
    if start < hdr_len or end > len(raw) or strings < end or strings + str_len > len(raw):
        raise ValueError("invalid BTF bounds")
    result = bytearray(raw)

    def identifier(offset: int) -> None:
        if offset == 0:
            return
        if offset >= str_len:
            raise ValueError("invalid BTF name offset")
        pos = strings + offset
        finish = raw.find(b"\0", pos, strings + str_len)
        if finish < 0:
            raise ValueError("unterminated BTF name")
        for i in range(pos, finish):
            char = result[i]
            if not (65 <= char <= 90 or 97 <= char <= 122 or char == 95 or (i > pos and 48 <= char <= 57)):
                result[i] = 95

    pos = start
    while pos < end:
        if pos + 12 > end:
            raise ValueError("truncated BTF type")
        name, info, _ = struct.unpack_from("<III", raw, pos)
        kind, count = (info >> 24) & 31, info & 0xFFFF
        sizes = {1: 4, 2: 0, 3: 12, 4: count * 12, 5: count * 12,
                 6: count * 8, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
                 12: 0, 13: count * 8, 14: 4, 15: count * 12,
                 16: 0, 17: 4, 18: 0, 19: count * 12}
        if kind not in sizes or pos + 12 + sizes[kind] > end:
            raise ValueError("invalid BTF kind or payload")
        if kind != 15:  # DATASEC names are section names, not identifiers.
            identifier(name)
        if kind in (4, 5, 6, 13, 19):
            stride = 12 if kind in (4, 5, 19) else 8
            for i in range(count):
                identifier(struct.unpack_from("<I", raw, pos + 12 + i * stride)[0])
        pos += 12 + sizes[kind]
    return bytes(result)


def self_test() -> None:
    strings = b"\0MaybeUninit<u8>\0.data\0member::value\0"
    section = strings.index(b".data")
    member = strings.index(b"member::")
    types = struct.pack("<III", 1, (5 << 24) | 1, 1)
    types += struct.pack("<III", member, 1, 0)
    types += struct.pack("<III", section, 15 << 24, 0)
    header = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(strings))
    raw = header + types + strings
    fixed = sanitize(raw)
    assert fixed[:24 + len(types)] == raw[:24 + len(types)]
    assert len(fixed) == len(raw)
    assert b"MaybeUninit_u8_\0" in fixed
    assert b"member__value\0" in fixed
    assert b".data\0" in fixed
    assert sanitize(fixed) == fixed
    for invalid in (b"", raw[:-1], header + types[:-1]):
        try:
            sanitize(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed BTF accepted")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        path = Path(sys.argv[1])
        path.write_bytes(sanitize(path.read_bytes()))
