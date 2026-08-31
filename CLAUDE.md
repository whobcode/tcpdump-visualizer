# tcpdump-visualizer — working notes

A Cloudflare Worker that serves a static page; **all parsing and analysis run
in the browser**. The Worker never sees a capture. Do not add an upload
endpoint, a server-side parser, or telemetry that carries capture content — the
privacy claim on the page is the product, not a footnote.

## Layer rule

`src/parse/` **decodes**. It reads one packet and carries no state between
packets. `src/analyze/` **interprets**, and is the only place allowed to
remember an earlier packet.

If you find yourself wanting a previous packet inside `src/parse/`, the code
belongs in `src/analyze/`. If you find yourself re-reading bytes inside
`src/analyze/`, the field belongs on the packet object in `src/parse/packet.js`.

## Things that are the way they are on purpose

- **Payload length comes from the IP header, never the frame.** Ethernet pads
  frames to 60 bytes, so a bare ACK measured from the frame appears to carry 6
  bytes of data. `snaplen-96.pcap` and the padded ACKs in `tcp-session.pcap`
  exist to catch a regression here.
- **`length` is the wire length; `capturedLength` is what the file holds.**
  When they differ the capture was cut by a snaplen and payload analysis is
  working from a fragment — `snaplenTruncated` says so.
- **Window values are scaled** by the factor both ends negotiated in the
  handshake, and never on the SYN that offered it. Raw window values make every
  fast connection look like it is stalling.
- **Sequence comparison is `((a - b) | 0) < 0`**, not `<`. Sequence numbers wrap
  at 2^32.
- **The UI filter is a display filter.** Analysis always runs over the whole
  capture. A retransmission is only a retransmission relative to the packets
  before it, so filtering the input and re-analysing describes a capture that
  never existed. Do not wire the filter into `analyze()`.
- **Reassembly is lazy.** `analyze()` records segments; `followStream()` joins
  the bytes when a stream is actually opened. Joining every stream up front
  costs the size of the capture in memory for a result nobody asked to see.
- **Gaps stay gaps.** A byte range the capture never held is reported, not
  closed up. A spliced-shut hole produces a plausible and wrong transcript.
- **First copy of a byte range wins** in reassembly, so recording every copy of
  a payload (retransmissions included) cannot double-count — and a segment that
  was only ever captured on its retransmission is still recovered.
- **Charts follow the palette in `src/styles.css`.** The `--series-N` slots are
  a validated colour-vision-safe set and are assigned **in order, never
  cycled**; past eight categories, fold the tail into "Other". One series gets
  one colour — never a value-ramp across nominal categories. No dual-axis
  charts.

## Tests

`test/make_fixtures.py` builds captures by hand, so an assertion is a fact
about the file rather than a judgement about a network. `tcp-session.pcap`
contains exactly one of each condition, at known packet numbers:

| packet | condition |
|---|---|
| 0-2 | handshake, with MSS / window scale 7 / SACK-permitted |
| 3 | HTTP request (also the padded-ACK and payload-length check) |
| 6, 18 | a segment the capture never held |
| 8-10 | three duplicate ACKs |
| 11 | fast retransmission filling the gap |
| 14 | plain retransmission (byte-for-byte repeat) |
| 15-16 | zero window, then the window update |
| 19 | out-of-order delivery (arrives 1 ms after a later segment) |
| 20-23 | graceful FIN/ACK close |
| 24-25 | connection refused (SYN → RST) |
| 26 | SYN nothing answers |
| 27-29 | TLS ClientHello with SNI + ALPN |
| 30-31 | DNS query and response |

Changing the fixture generator renumbers these, and `test/analyze.test.mjs`
asserts against the numbers. If you add packets, add them at the end.

```bash
npm test        # parse.test.mjs then analyze.test.mjs
npm run fixtures  # regenerate test/fixtures (python3)
npm run build   # -> public/
```

Never run `npm run deploy` without being asked.
