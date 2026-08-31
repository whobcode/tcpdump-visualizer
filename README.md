# tcpdump-visualizer

Open a packet capture and get the conversations, the TCP connections, what was
exchanged inside them, and a ranked list of what went wrong.

**Capture files are parsed entirely in the browser and never uploaded.** A pcap
contains every address, port and payload byte the machine saw; keeping it local
is the point, not an optimisation. The Worker only serves the page.

```bash
npm install
npm run build        # -> public/
npm test             # parser and analyser checks against generated fixtures
npm run fixtures     # regenerate test/fixtures/ (needs python3)
npm run dev          # wrangler dev
npm run deploy       # production build + deploy
```

## What it tells you

A packet list says what crossed the wire. Most of the time the question is *why
was this slow* or *why did this fail*, and answering that means reading packets
against the connection they belong to — which needs state carried from one
packet to the next.

**Connections.** Every TCP stream is tracked through its handshake, its data
transfer and its close. Each one reports its state (open, closed, reset,
refused, never answered), the handshake round trip, time to first byte, median
round trip from data/ACK pairs, per-direction payload totals, and the window
scale factor both ends negotiated.

**Follow the stream.** Click a connection to read what was actually exchanged,
as text or as a hex dump, coloured by direction. The transcript is cut from the
reassembled byte stream rather than from the packets, so a retransmission does
not print twice and a reordered segment appears where its sequence number says
it belongs. Bytes the capture never held are shown as holes, not closed up.

**What went wrong.** Retransmissions (plain, fast, and spurious), duplicate
ACKs, out-of-order delivery, zero-window stalls, a filled send window,
keep-alives, resets, refused and unanswered connections, gaps where a segment
was never captured, ACKs for data that was not, port reuse, ICMP errors, port
scans, and cleartext protocols. Each finding says what it means and names the
packets behind it, so it can be checked rather than believed.

**Conversations and endpoints.** Both directions of an exchange on one row —
40 KB up and 12 MB down is the shape that tells you what a connection was
doing, and counting `src → dst` pairs separately hides it. Endpoints show peer
and port counts, which is what a scanner looks like from the outside.

**Application protocols, read from the payload rather than the port.** HTTP
request lines and Host headers, TLS ClientHello with its SNI and ALPN, DNS
questions and response codes, SSH banners. On an encrypted capture the SNI is
usually the only useful thing in the stream, and it is in the clear.

Filtering is a *display* filter: it changes which rows are listed, never what
was analysed. A retransmission is only a retransmission relative to the packets
before it, so filtering the input and re-analysing would describe a capture
that never existed.

## Layout

```
src/
  worker.js          Worker entry — serves the built assets
  index.html         the page
  styles.css
  app.js             client entry: tabs, tables, charts, stream viewer
  format.js          byte/rate/duration/hex formatting
  parse/             decoding only — no state carried between packets
    index.js         picks a parser from the file's magic, not its extension
    pcap.js          classic libpcap
    pcapng.js        pcapng — what tcpdump and Wireshark write by default
    linktype.js      link layers, and where the network header starts
    packet.js        IPv4/IPv6/TCP/UDP/ICMP/ARP, options, payload slices
  analyze/           everything that needs to remember an earlier packet
    index.js         one pass, producing what the page shows
    tcp.js           connection tracking, event detection, reassembly
    flows.js         conversations, endpoints, throughput buckets
    appproto.js      HTTP, TLS/SNI, DNS, SSH from the payload
    expert.js        findings, ranked by severity
    services.js      port names, and which are cleartext
test/
  make_fixtures.py   generates captures with known contents
  parse.test.mjs     parser checks
  analyze.test.mjs   analyser checks
```

## Supported formats

| | |
|---|---|
| pcap | little- and big-endian, microsecond and nanosecond |
| pcapng | section/interface/packet blocks, per-interface timestamp resolution |
| Link types | Ethernet (incl. VLAN tags), loopback NULL/LOOP, raw IP, Linux cooked v1/v2 |
| Network | IPv4 (incl. fragments), IPv6 (with extension headers), ARP |
| Transport | TCP (all 8 flags, options, SACK), UDP, ICMP, ICMPv6 |

## Testing

`test/make_fixtures.py` builds captures by hand, so every assertion is about a
fact of the file rather than a judgement about a network. `tcp-session.pcap`
contains exactly one of each condition the analyser reports — the missing
segment, the three duplicate ACKs, the fast retransmission that fills the gap,
the byte-for-byte repeat, the zero window, the segment that arrives late — each
placed deliberately, so "packet 11 is a fast retransmission" is checkable
rather than inferred from the same packets being graded.

A few of the fixtures exist to catch mistakes that produce confidently wrong
output rather than errors:

- **Ethernet padding.** A bare ACK is 54 bytes and goes out padded to 60.
  Measuring payload from the frame instead of the IP header reports 6 bytes of
  data on an empty segment.
- **A snaplen capture.** `snaplen-96.pcap` keeps headers and cuts payload, so
  reassembly has to leave a hole rather than produce a short, plausible body.
- **Byte order, timestamp scale and link type**, each of which silently
  corrupted output in an earlier version of the parser: a big-endian capture
  read as little-endian yielded zero packets, nanosecond timestamps divided by
  10⁶ were ~1000× out, and assuming Ethernet on a loopback capture read every
  field at the wrong offset.

Chart.js is vendored at build time. It used to load from a CDN, which meant the
page rendered the whole dashboard minus every chart, silently, whenever that
host was unreachable.
