#!/usr/bin/env python3
"""Generate capture files covering the variants the parser must handle.

Written by hand rather than captured, so every field is known and a wrong
answer is unambiguous.
"""
import struct, pathlib

OUT = pathlib.Path(__file__).parent / "fixtures"
OUT.mkdir(exist_ok=True)

def eth_ipv4_tcp(src, dst, sport, dport, flags=0x02):
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                     bytes(int(x) for x in src.split(".")),
                     bytes(int(x) for x in dst.split(".")))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0)
    return eth + ip + tcp

def eth_ipv6_udp(sport, dport):
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x86\xdd"
    src = bytes.fromhex("fe800000000000000000000000000001")
    dst = bytes.fromhex("fe800000000000000000000000000002")
    ip6 = struct.pack("!IHBB", 0x60000000, 8, 17, 64) + src + dst
    udp = struct.pack("!HHHH", sport, dport, 8, 0)
    return eth + ip6 + udp

def loopback_ipv4_tcp():
    # LINKTYPE_NULL: 4-byte host-order address family, AF_INET = 2
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                     bytes([127,0,0,1]), bytes([127,0,0,1]))
    tcp = struct.pack("!HHIIBBHHH", 5000, 6000, 0, 0, 0x50, 0x10, 8192, 0, 0)
    return struct.pack("<I", 2) + ip + tcp

def write_pcap(path, packets, magic, linktype, endian):
    e = "<" if endian == "little" else ">"
    out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    # Every fixture encodes the same instant, 1700000000.123456, so the
    # expected value is identical across variants. The *field* differs: a
    # nanosecond-resolution file stores 123456000 where a microsecond one
    # stores 123456, which is exactly what makes reading the magic number
    # necessary rather than optional.
    nanos = magic in (0xA1B23C4D, 0x4D3CB2A1)
    frac = 123456000 if nanos else 123456
    for i, p in enumerate(packets):
        out += struct.pack(e + "IIII", 1700000000 + i, frac, len(p), len(p)) + p
    path.write_bytes(out)

def write_pcapng(path, packets, linktype=1, tsresol=6):
    def block(btype, body):
        total = 12 + len(body) + (-len(body) % 4)
        return (struct.pack("<II", btype, total) + body
                + b"\x00" * (-len(body) % 4) + struct.pack("<I", total))
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    # Interface description, with if_tsresol (option 9) set explicitly.
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    idb_body += struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
    idb_body += struct.pack("<HH", 0, 0)
    idb = block(0x00000001, idb_body)
    out = shb + idb
    for i, p in enumerate(packets):
        ticks = (1700000000 + i) * (10 ** tsresol) + 123456 * (10 ** (tsresol - 6))
        body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(p), len(p))
        body += p + b"\x00" * (-len(p) % 4) + struct.pack("<HH", 0, 0)
        out += block(0x00000006, body)
    path.write_bytes(out)

pkts = [
    eth_ipv4_tcp("192.168.12.122", "192.168.12.1", 52341, 443),
    eth_ipv4_tcp("192.168.12.1", "192.168.12.122", 443, 52341, flags=0x12),
    eth_ipv6_udp(5353, 5353),
]

write_pcap(OUT / "classic-le-micro.pcap", pkts, 0xA1B2C3D4, 1, "little")
write_pcap(OUT / "classic-be-micro.pcap", pkts, 0xA1B2C3D4, 1, "big")
write_pcap(OUT / "classic-le-nano.pcap",  pkts, 0xA1B23C4D, 1, "little")
write_pcap(OUT / "loopback.pcap", [loopback_ipv4_tcp()], 0xA1B2C3D4, 0, "little")
write_pcapng(OUT / "modern.pcapng", pkts, linktype=1, tsresol=6)
write_pcapng(OUT / "modern-nano.pcapng", pkts, linktype=1, tsresol=9)

for f in sorted(OUT.iterdir()):
    print("  %-24s %5d bytes" % (f.name, f.stat().st_size))
