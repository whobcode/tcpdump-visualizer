# tcpdump-visualizer

Upload a packet capture, get statistics, charts, a flow diagram and a filterable
packet table.

**Capture files are parsed entirely in the browser and never uploaded.** A pcap
contains every address, port and payload byte the machine saw; keeping it local
is the point, not an optimisation. The Worker only serves the page.

```bash
npm install
npm run build        # -> public/
npm test             # parser checks against generated fixtures
npm run dev          # wrangler dev
npm run deploy       # production build + deploy
```

## Layout

```
src/
  worker.js          Worker entry — serves the built assets
  index.html         the page
  styles.css
  app.js             client entry: UI, charts, filters
  parse/
    index.js         picks a parser from the file's magic, not its extension
    pcap.js          classic libpcap
    pcapng.js        pcapng — what tcpdump and Wireshark write by default
    linktype.js      link layers, and where the network header starts
    packet.js        IPv4/IPv6/TCP/UDP/ICMP/ARP decoding
test/
  make_fixtures.py   generates captures with known contents
  parse.test.mjs     asserts against them
```

## Supported formats

| | |
|---|---|
| pcap | little- and big-endian, microsecond and nanosecond |
| pcapng | section/interface/packet blocks, per-interface timestamp resolution |
| Link types | Ethernet (incl. VLAN tags), loopback NULL/LOOP, raw IP, Linux cooked v1/v2 |
| Network | IPv4, IPv6 (with extension headers), ARP |
| Transport | TCP (all 8 flags), UDP, ICMP, ICMPv6 |

## What was wrong before

The original parser was reconstructed from a deployed bundle and had four bugs
that produced confidently wrong output rather than errors:

- **pcapng was accepted but not parsed.** The file picker offered `.pcapng`
  while the parser assumed classic pcap's fixed-record layout, so the default
  output of both tcpdump and Wireshark yielded garbage.
- **The magic number was read and discarded.** Byte order was hardcoded
  little-endian, so a big-endian capture produced zero packets.
- **Nanosecond timestamps were divided by 10⁶.** Every time was ~1000× out.
- **Ethernet was assumed unconditionally.** A loopback or `-i any` capture had
  every field read at the wrong offset.

`npm test` covers each case; `test/make_fixtures.py` builds captures by hand so
a wrong answer is unambiguous rather than a judgement call.

Chart.js is vendored at build time. It used to load from a CDN, which meant the
page rendered the whole dashboard minus every chart, silently, whenever that
host was unreachable.
