#!/usr/bin/env python3
"""Generate capture files covering the variants the parser and analyser must handle.

Written by hand rather than captured, so every field is known and a wrong
answer is unambiguous. A capture recorded off a real network would be a worse
test: you cannot assert "this segment is a fast retransmission" against traffic
whose intent you are inferring from the same packets you are checking.
"""
import struct, pathlib

OUT = pathlib.Path(__file__).parent / "fixtures"
OUT.mkdir(exist_ok=True)

ETH_SRC = bytes.fromhex("aabbccddeeff")
ETH_DST = bytes.fromhex("112233445566")


def eth_ipv4_tcp(src, dst, sport, dport, flags=0x02):
    eth = ETH_SRC + ETH_DST + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                     bytes(int(x) for x in src.split(".")),
                     bytes(int(x) for x in dst.split(".")))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0)
    return eth + ip + tcp


def eth_ipv6_udp(sport, dport):
    eth = ETH_SRC + ETH_DST + b"\x86\xdd"
    src = bytes.fromhex("fe800000000000000000000000000001")
    dst = bytes.fromhex("fe800000000000000000000000000002")
    ip6 = struct.pack("!IHBB", 0x60000000, 8, 17, 64) + src + dst
    udp = struct.pack("!HHHH", sport, dport, 8, 0)
    return eth + ip6 + udp


def loopback_ipv4_tcp():
    # LINKTYPE_NULL: 4-byte host-order address family, AF_INET = 2
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                     bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1]))
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


def write_pcap_timed(path, records, linktype=1, snaplen=65535):
    """records: (timestamp_seconds_float, frame_bytes, original_length)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)
    for ts, frame, orig in records:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        out += struct.pack("<IIII", sec, usec, len(frame), orig) + frame
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


# ---------------------------------------------------------------------------
# Frame construction for the analysis fixtures
# ---------------------------------------------------------------------------

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def ip4(addr):
    return bytes(int(x) for x in addr.split("."))


def ipv4_frame(src, dst, proto, payload, ident=1):
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64,
                         proto, 0, ip4(src), ip4(dst))
    return ETH_SRC + ETH_DST + b"\x08\x00" + header + payload


def tcp_segment(sport, dport, seq, ack, flags, window=8192, options=b"", payload=b""):
    offset = 20 + len(options)
    assert offset % 4 == 0, "TCP options must be padded to a 4-byte boundary"
    return (struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                        (offset // 4) << 4, flags, window, 0, 0)
            + options + payload)


def pad_to_minimum(frame):
    """Ethernet pads short frames to 60 bytes.

    Included deliberately: a bare ACK is 54 bytes and arrives on the wire with
    6 bytes of padding, so anything that measures payload from the frame rather
    than from the IP header reports 6 bytes of data on an empty segment.
    """
    return frame + b"\x00" * max(0, 60 - len(frame))


# MSS 1460, window scale 7, SACK permitted — padded to 12 bytes with NOPs.
SYN_OPTIONS = (struct.pack("!BBH", 2, 4, 1460)
               + b"\x01" + struct.pack("!BBB", 3, 3, 7)
               + b"\x01\x01" + struct.pack("!BB", 4, 2))

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"

HTTP_REQUEST = (b"GET /index.html HTTP/1.1\r\n"
                b"Host: example.test\r\n"
                b"User-Agent: fixture\r\n\r\n")
HTTP_RESPONSE_HEAD = (b"HTTP/1.1 200 OK\r\n"
                      b"Content-Type: text/plain\r\n"
                      b"Content-Length: 60\r\n\r\n")


def client_hello(server_name):
    """A minimal but structurally valid TLS 1.2 ClientHello carrying an SNI."""
    name = server_name.encode()
    sni_entry = b"\x00" + struct.pack("!H", len(name)) + name
    sni_ext_body = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0, len(sni_ext_body)) + sni_ext_body

    alpn_list = b"\x08http/1.1"
    alpn_body = struct.pack("!H", len(alpn_list)) + alpn_list
    alpn_ext = struct.pack("!HH", 16, len(alpn_body)) + alpn_body

    extensions = sni_ext + alpn_ext
    body = (b"\x03\x03"                       # client_version TLS 1.2
            + bytes(range(32))                # random
            + b"\x00"                         # session id length
            + struct.pack("!H", 2) + b"\x00\x2f"   # one cipher suite
            + b"\x01\x00"                     # one compression method: null
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def dns_query(name, qtype=1, qid=0x1234, response=False, answers=0):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    flags = 0x8180 if response else 0x0100
    header = struct.pack("!HHHHHH", qid, flags, 1, answers, 0, 0)
    question = labels + struct.pack("!HH", qtype, 1)
    body = header + question
    if response:
        # One A record pointing back at the question via a compression pointer.
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip4("93.184.216.34")
    return body


def udp_datagram(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def build_tcp_session():
    """A connection that exercises every TCP condition the analyser reports.

    Laid out so each event has exactly one cause:

      handshake            packets 0-2
      HTTP request         3
      capture gap          6      (server jumps over 20 bytes)
      3 duplicate ACKs     8-10
      fast retransmission  11     (fills the gap, after those duplicates)
      plain retransmission 14     (exact repeat, no duplicates outstanding)
      zero window          15
      window update        16
      out-of-order         19     (arrives 1 ms after a later segment)
      graceful close       20-23
      refused connection   24-25
      unanswered SYN       26
      TLS ClientHello      27-29
      DNS query & reply    30-31
    """
    recs = []
    t = [1700000100.0]

    def add(frame, orig=None, step=0.001):
        recs.append((t[0], frame, orig if orig is not None else len(frame)))
        t[0] += step

    def c2s(seq, ack, flags, payload=b"", window=1024, options=b"", pad=False):
        seg = tcp_segment(40000, 80, seq, ack, flags, window, options, payload)
        frame = ipv4_frame(CLIENT, SERVER, 6, seg)
        add(pad_to_minimum(frame) if pad else frame)

    def s2c(seq, ack, flags, payload=b"", window=8192, options=b"", pad=False):
        seg = tcp_segment(80, 40000, seq, ack, flags, window, options, payload)
        frame = ipv4_frame(SERVER, CLIENT, 6, seg)
        add(pad_to_minimum(frame) if pad else frame)

    ci, si = 1000, 5000  # initial sequence numbers

    c2s(ci, 0, SYN, options=SYN_OPTIONS)                       # 0
    s2c(si, ci + 1, SYN | ACK, options=SYN_OPTIONS)            # 1
    c2s(ci + 1, si + 1, ACK, pad=True)                         # 2

    req = HTTP_REQUEST
    c2s(ci + 1, si + 1, PSH | ACK, req)                        # 3
    cnext = ci + 1 + len(req)
    s2c(si + 1, cnext, ACK, pad=True)                          # 4

    s2c(si + 1, cnext, ACK, HTTP_RESPONSE_HEAD)                # 5
    after_head = si + 1 + len(HTTP_RESPONSE_HEAD)

    # 6: skips 20 bytes — from the capture's point of view a segment is missing.
    s2c(after_head + 20, cnext, ACK, b"B" * 20)                # 6
    c2s(cnext, after_head, ACK, pad=True)                      # 7  (baseline ACK)
    c2s(cnext, after_head, ACK, pad=True)                      # 8  dup #1
    c2s(cnext, after_head, ACK, pad=True)                      # 9  dup #2
    c2s(cnext, after_head, ACK, pad=True)                      # 10 dup #3

    # 11: the missing bytes, sent after three duplicate ACKs — a fast retransmit.
    s2c(after_head, cnext, ACK, b"A" * 20)                     # 11

    c2s(cnext, after_head + 40, ACK, pad=True)                 # 12 ACK advances
    s2c(after_head + 40, cnext, ACK, b"C" * 20)                # 13 new data
    # 14: byte-for-byte repeat with nothing outstanding — a plain retransmission.
    s2c(after_head + 40, cnext, ACK, b"C" * 20)                # 14

    c2s(cnext, after_head + 60, ACK, window=0, pad=True)       # 15 zero window
    c2s(cnext, after_head + 60, ACK, window=2048, pad=True)    # 16 window update

    s2c(after_head + 60, cnext, ACK, b"D" * 20)                # 17
    s2c(after_head + 100, cnext, ACK, b"F" * 20)               # 18 jumps ahead
    # 19: the segment 18 skipped, arriving 1 ms later — reordering, not loss.
    s2c(after_head + 80, cnext, ACK, b"E" * 20)                # 19

    send_end = after_head + 120
    s2c(send_end, cnext, FIN | ACK, pad=True)                  # 20
    c2s(cnext, send_end + 1, ACK, pad=True)                    # 21
    c2s(cnext, send_end + 1, FIN | ACK, pad=True)              # 22
    s2c(send_end + 1, cnext + 1, ACK, pad=True)                # 23

    # A refused connection: the SYN is answered with a RST.
    add(pad_to_minimum(ipv4_frame(CLIENT, SERVER, 6,
        tcp_segment(40001, 81, 2000, 0, SYN, options=SYN_OPTIONS))))          # 24
    add(pad_to_minimum(ipv4_frame(SERVER, CLIENT, 6,
        tcp_segment(81, 40001, 0, 2001, RST | ACK))))                          # 25

    # A SYN nothing ever answers.
    add(pad_to_minimum(ipv4_frame(CLIENT, SERVER, 6,
        tcp_segment(40002, 82, 3000, 0, SYN, options=SYN_OPTIONS))))          # 26

    # A TLS connection, opened far enough to carry the ClientHello.
    hello = client_hello("api.example.test")
    add(pad_to_minimum(ipv4_frame(CLIENT, SERVER, 6,
        tcp_segment(40003, 443, 7000, 0, SYN, options=SYN_OPTIONS))))         # 27
    add(pad_to_minimum(ipv4_frame(SERVER, CLIENT, 6,
        tcp_segment(443, 40003, 9000, 7001, SYN | ACK, options=SYN_OPTIONS))))# 28
    add(ipv4_frame(CLIENT, SERVER, 6,
        tcp_segment(40003, 443, 7001, 9001, PSH | ACK, payload=hello)))       # 29

    # DNS, where the question is the only part worth reading.
    add(ipv4_frame(CLIENT, SERVER, 17,
        udp_datagram(51000, 53, dns_query("api.example.test"))))              # 30
    add(ipv4_frame(SERVER, CLIENT, 17,
        udp_datagram(53, 51000, dns_query("api.example.test",
                                          response=True, answers=1))))        # 31

    return recs


def build_snaplen_capture():
    """The same exchange captured with `-s 96`: headers kept, payload cut off."""
    recs = []
    t = 1700000200.0
    body = b"X" * 400
    frames = [
        ipv4_frame(CLIENT, SERVER, 6, tcp_segment(40100, 80, 100, 0, SYN, options=SYN_OPTIONS)),
        ipv4_frame(SERVER, CLIENT, 6, tcp_segment(80, 40100, 900, 101, SYN | ACK, options=SYN_OPTIONS)),
        ipv4_frame(CLIENT, SERVER, 6, tcp_segment(40100, 80, 101, 901, PSH | ACK, payload=body)),
    ]
    for i, frame in enumerate(frames):
        kept = frame[:96]
        recs.append((t + i * 0.001, kept, len(frame)))
    return recs


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
write_pcap_timed(OUT / "tcp-session.pcap", build_tcp_session())
write_pcap_timed(OUT / "snaplen-96.pcap", build_snaplen_capture(), snaplen=96)

for f in sorted(OUT.iterdir()):
    print("  %-24s %5d bytes" % (f.name, f.stat().st_size))
