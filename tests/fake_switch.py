#!/usr/bin/env python3
"""Minimal NSDP switch simulator for smoke tests.

usage: fake_switch.py IP [unicast|broadcast] [ENCTYPE]

Answers queries for a few fields and acknowledges every set request,
printing what it received on stdout.  IP is the address it reports
for itself (use the address of the host it runs on).
"""
import socket
import struct
import sys

IP = sys.argv[1]
MODE = sys.argv[2] if len(sys.argv) > 2 else "unicast"
ENC = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
MAC = bytes.fromhex("b0b98a57f656")
VALUES = {
    0x0001: b"GS108Ev3",
    0x0003: b"fakeswitch\0\0",
    0x0004: MAC,
    0x0006: socket.inet_aton(IP),
    0x000b: b"\x01",
    0x000d: b"V2.06.24EN",
    0x0014: struct.pack(">I", ENC),
    0x0017: bytes.fromhex("01020304"),
    0x6000: b"\x08",
    0x7800: b"\x01" + b"4XB12345A0001" + b"\x00" * 7,
}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(("", 63322))
while True:
    pkt, addr = sock.recvfrom(8192)
    ctype = struct.unpack(">H", pkt[0:2])[0]
    if pkt[14:20] not in (MAC, b"\0" * 6):
        continue
    pos, tlvs, seen = 32, b"", []
    while pos + 4 <= len(pkt):
        cid, length = struct.unpack(">HH", pkt[pos:pos + 4])
        seen.append("%04x=%s" % (cid, pkt[pos + 4:pos + 4 + length].hex()))
        pos += 4 + length
        if cid == 0xffff:
            break
        if ctype == 0x0101 and cid in VALUES:
            tlvs += struct.pack(">HH", cid, len(VALUES[cid])) + VALUES[cid]
    print("%04x %s" % (ctype, " ".join(seen)), flush=True)
    header = (struct.pack(">H", ctype + 1) + b"\0" * 6 + pkt[8:14] + MAC +
              pkt[20:32])
    if MODE == "unicast":
        target = (addr[0], 63321)
    else:
        target = ("255.255.255.255", 63321)
    sock.sendto(header + tlvs + b"\xff\xff\x00\x00", target)
