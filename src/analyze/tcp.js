/**
 * TCP connection tracking.
 *
 * A packet list tells you what crossed the wire. What people open a capture to
 * find out is why something was slow or why it failed, and that only shows up
 * when packets are read against the connection they belong to: this segment is
 * a retransmission because we already sent those bytes, this ACK is the fourth
 * copy of the same number, this receiver has been advertising a zero window for
 * two seconds. All of that needs state carried from one packet to the next, so
 * it lives here rather than in the decoder.
 *
 * Reassembly is deliberately lazy. Stitching every stream's payload back
 * together up front costs the size of the capture in extra memory for a result
 * nobody has asked to look at yet; the segments are recorded and the bytes are
 * only joined when a stream is opened.
 */
import { TCP_FLAG } from "../parse/packet.js";
import { serviceName, likelyServerPort } from "./services.js";

/**
 * Sequence numbers are 32-bit and wrap. Truncating the difference to a signed
 * 32-bit integer compares them correctly across the wrap, which a plain `<`
 * does not: after a wrap, 10 is "after" 4294967290.
 */
const seqLt = (a, b) => ((a - b) | 0) < 0;
const seqGt = (a, b) => ((a - b) | 0) > 0;
const seqLte = (a, b) => ((a - b) | 0) <= 0;
const seqGte = (a, b) => ((a - b) | 0) >= 0;
const seqAdd = (a, n) => (a + n) >>> 0;
const seqDiff = (a, b) => (a - b) | 0;

export const EVENT = {
  RETRANSMISSION: "retransmission",
  FAST_RETRANSMISSION: "fast-retransmission",
  SPURIOUS_RETRANSMISSION: "spurious-retransmission",
  OUT_OF_ORDER: "out-of-order",
  DUP_ACK: "duplicate-ack",
  ZERO_WINDOW: "zero-window",
  WINDOW_UPDATE: "window-update",
  WINDOW_FULL: "window-full",
  KEEP_ALIVE: "keep-alive",
  RESET: "reset",
  LOST_SEGMENT: "previous-segment-not-captured",
  ACK_UNSEEN: "ack-for-unseen-segment",
  PORT_REUSE: "port-reuse",
  SYN_UNANSWERED: "syn-unanswered",
};

/**
 * A segment that repeats bytes we have already seen is a retransmission if the
 * sender gave up waiting, and a reordering if the network simply delivered it
 * late. The two look identical in isolation; the usual tiebreak is elapsed
 * time, since reordering happens within a round of transmission and a
 * retransmission timeout does not fire that fast.
 */
const OUT_OF_ORDER_WINDOW = 0.004; // seconds

/** Per-direction reassembly ceiling, so one enormous stream cannot exhaust memory. */
export const MAX_REASSEMBLY_BYTES = 4 * 1024 * 1024;

function newDirection(ip, port) {
  return {
    ip, port,
    isn: null,
    nextSeq: null,          // highest seq+len this direction has sent
    windowScale: null,
    mss: null,
    sackPermitted: false,
    sawSyn: false,
    sawFin: false,
    sawRst: false,
    finSeq: null,
    prevAck: null,
    prevWindow: null,
    lastAck: null,          // highest ack this direction has sent
    dupAckRun: 0,
    inZeroWindow: false,
    lastWindowScaled: null,
    maxWindowScaled: 0,
    packets: 0,
    bytes: 0,
    payloadBytes: 0,
    retransmittedBytes: 0,
    lastDataTime: null,
    sent: new Set(),        // "seq:len" already transmitted, for exact-repeat detection
    segments: [],           // first-transmission payload, for reassembly
    pendingRtt: [],         // { endSeq, time } awaiting an ACK
    retransmittedEnds: new Set(),
    rttSamples: [],
    counts: {
      retransmission: 0, fastRetransmission: 0, spuriousRetransmission: 0,
      outOfOrder: 0, dupAck: 0, zeroWindow: 0, windowFull: 0,
      keepAlive: 0, lostSegment: 0, ackUnseen: 0,
    },
  };
}

function newStream(id, key, a, b, p) {
  return {
    id,
    key,
    a, b,
    dirs: [newDirection(a.ip, a.port), newDirection(b.ip, b.port)],
    packetNums: [],
    events: [],
    first: p.timestamp,
    last: p.timestamp,
    syn: null, synAck: null, handshakeAck: null,
    handshakeRtt: null,
    firstDataTime: null,
    windowScalingInUse: false,
    state: "in progress",
    serverPort: likelyServerPort(a.port, b.port),
    service: serviceName(likelyServerPort(a.port, b.port)),
  };
}

const tupleKey = (p) => {
  const x = `${p.src}|${p.srcPort}`;
  const y = `${p.dst}|${p.dstPort}`;
  return x <= y ? `${x}|${y}` : `${y}|${x}`;
};

/**
 * Walk the capture once, in order, maintaining per-connection state.
 *
 * Returns the streams. Each packet also gains a `tcp` field describing its
 * place in its stream (relative sequence numbers, the scaled window, and any
 * events it triggered), which is what the packet list renders.
 */
export function analyzeTcpStreams(packets) {
  const streams = [];
  const active = new Map();

  for (const p of packets) {
    if (p.protocol !== "TCP" || !p.src) continue;

    const flags = p.flags | 0;
    const isSyn = Boolean(flags & TCP_FLAG.SYN);
    const isAck = Boolean(flags & TCP_FLAG.ACK);
    const isFin = Boolean(flags & TCP_FLAG.FIN);
    const isRst = Boolean(flags & TCP_FLAG.RST);

    const key = tupleKey(p);
    let stream = active.get(key);

    // A fresh SYN on a tuple whose connection already completed or ended is a
    // new connection reusing the port, not a retransmission on the old one.
    // Folding them together produces one connection that appears to restart
    // its sequence numbers halfway through.
    let reused = false;
    if (stream && isSyn && !isAck) {
      const finished = stream.synAck !== null ||
                       stream.dirs.some((dir) => dir.sawRst || dir.sawFin);
      if (finished) {
        active.delete(key);
        stream = null;
        reused = true;
      }
    }

    if (!stream) {
      // The client is whoever sent the opening SYN; failing that, whoever we
      // saw first. Getting this backwards mislabels every column downstream.
      const a = { ip: p.src, port: p.srcPort };
      const b = { ip: p.dst, port: p.dstPort };
      stream = newStream(streams.length, key, a, b, p);
      streams.push(stream);
      active.set(key, stream);
      if (reused) {
        stream.events.push({
          num: p.num, dir: 0, type: EVENT.PORT_REUSE,
          detail: `${p.src}:${p.srcPort} reused for a new connection`,
        });
      }
    }

    const i = (p.src === stream.a.ip && p.srcPort === stream.a.port) ? 0 : 1;
    const d = stream.dirs[i];
    const peer = stream.dirs[1 - i];
    const events = [];

    if (isSyn && !isAck && stream.syn === null) { stream.syn = p.num; stream.synSeq = p.seq; }
    if (isSyn && isAck && stream.synAck === null) {
      stream.synAck = p.num;
      if (stream.syn !== null) {
        const synPacket = packets[stream.syn];
        if (synPacket) stream.handshakeRtt = p.timestamp - synPacket.timestamp;
      }
    }
    if (!isSyn && isAck && stream.synAck !== null && stream.handshakeAck === null) {
      stream.handshakeAck = p.num;
    }

    if (d.isn === null) d.isn = p.seq;
    if (isSyn) {
      d.sawSyn = true;
      d.isn = p.seq;
      if (p.tcpOptions) {
        d.windowScale = p.tcpOptions.windowScale;
        d.mss = p.tcpOptions.mss;
        d.sackPermitted = p.tcpOptions.sackPermitted;
      }
    }

    // Window scaling only applies if both ends offered it, and never to the
    // SYN that offered it.
    const bothScaled = stream.dirs[0].windowScale != null && stream.dirs[1].windowScale != null;
    stream.windowScalingInUse = bothScaled;
    const scale = bothScaled && !isSyn ? (d.windowScale || 0) : 0;
    const scaledWindow = (p.window ?? 0) * Math.pow(2, scale);
    d.lastWindowScaled = scaledWindow;
    if (scaledWindow > d.maxWindowScaled) d.maxWindowScaled = scaledWindow;

    const payloadLen = p.payloadLength || 0;
    // SYN and FIN each occupy one sequence number even with no payload.
    const segLen = payloadLen + (isSyn ? 1 : 0) + (isFin ? 1 : 0);

    // ---- keep-alive, before retransmission: a keep-alive deliberately
    // resends the last byte, and would otherwise be reported as a retransmit.
    const isKeepAlive =
      !isSyn && !isFin && !isRst && isAck && payloadLen <= 1 &&
      d.nextSeq !== null && seqLt(p.seq, d.nextSeq) &&
      seqGte(p.seq, seqAdd(d.nextSeq, -1));

    let firstTransmission = false;

    if (isKeepAlive) {
      events.push({ type: EVENT.KEEP_ALIVE });
      d.counts.keepAlive++;
    } else if (segLen > 0) {
      const endSeq = seqAdd(p.seq, segLen);
      const exact = `${p.seq}:${segLen}`;

      if (d.nextSeq === null) {
        firstTransmission = true;
        d.nextSeq = endSeq;
      } else if (p.seq === d.nextSeq) {
        // The ordinary case: this segment continues exactly where the last one
        // ended. Checked first so a clean transfer never reaches the overlap
        // branch below and gets reported as retransmitting itself.
        firstTransmission = true;
        d.nextSeq = endSeq;
      } else if (seqGt(p.seq, d.nextSeq)) {
        // Bytes between nextSeq and this segment never appeared in the capture.
        events.push({
          type: EVENT.LOST_SEGMENT,
          detail: `${seqDiff(p.seq, d.nextSeq)} bytes missing`,
        });
        d.counts.lostSegment++;
        firstTransmission = true;
        d.nextSeq = endSeq;
      } else if (seqLte(endSeq, d.nextSeq)) {
        // Every byte here sits at or below what this direction has already
        // sent, so it is either a resend or a segment the network reordered.
        let resent = true;
        if (peer.lastAck !== null && seqGte(peer.lastAck, endSeq)) {
          events.push({ type: EVENT.SPURIOUS_RETRANSMISSION });
          d.counts.spuriousRetransmission++;
        } else if (peer.dupAckRun >= 3) {
          events.push({ type: EVENT.FAST_RETRANSMISSION, detail: `after ${peer.dupAckRun} duplicate ACKs` });
          d.counts.fastRetransmission++;
        } else if (
          !d.sent.has(exact) && d.lastDataTime !== null &&
          p.timestamp - d.lastDataTime < OUT_OF_ORDER_WINDOW
        ) {
          // Delivered late, not sent twice — so it does not count as bytes
          // spent retransmitting.
          events.push({ type: EVENT.OUT_OF_ORDER });
          d.counts.outOfOrder++;
          resent = false;
        } else {
          events.push({ type: EVENT.RETRANSMISSION });
          d.counts.retransmission++;
        }
        if (resent) d.retransmittedBytes += payloadLen;
        d.retransmittedEnds.add(endSeq);
      } else {
        // Partly old, partly new — a resend that got merged with fresh data.
        events.push({ type: EVENT.RETRANSMISSION, detail: "overlapping" });
        d.counts.retransmission++;
        d.retransmittedEnds.add(endSeq);
        d.nextSeq = endSeq;
      }

      d.sent.add(exact);
      d.lastDataTime = p.timestamp;

      // Every copy of a payload is recorded, retransmissions included: where a
      // segment was missed on its first pass, the retransmission is the only
      // copy the capture holds, and a receiving stack would accept it. The
      // reassembler resolves duplicates by taking the earliest copy of each
      // byte range, so recording all of them cannot double-count.
      if (payloadLen > 0 && p.payload) {
        d.segments.push({
          seq: p.seq,
          rel: seqDiff(p.seq, d.isn),
          len: payloadLen,
          payload: p.payload,
          num: p.num,
          time: p.timestamp,
          truncated: Boolean(p.payloadTruncated),
        });
      }

      if (firstTransmission) {
        // Only clean transmissions make usable round-trip samples; timing a
        // retransmitted segment cannot tell you which copy the ACK answered.
        d.pendingRtt.push({ endSeq, time: p.timestamp });
        if (d.pendingRtt.length > 4096) d.pendingRtt.shift();
      }

      if (payloadLen > 0) {
        d.payloadBytes += payloadLen;
        if (stream.firstDataTime === null) stream.firstDataTime = p.timestamp;
      }

      // Sending fills the receiver's advertised window: the sender is now
      // blocked until an ACK, which is what a stalled transfer looks like.
      if (peer.lastWindowScaled != null && peer.lastWindowScaled > 0 && peer.lastAck != null) {
        const inFlight = seqDiff(d.nextSeq, peer.lastAck);
        if (inFlight >= peer.lastWindowScaled) {
          events.push({ type: EVENT.WINDOW_FULL, detail: `${inFlight} bytes in flight` });
          d.counts.windowFull++;
        }
      }
    }

    // ---- acknowledgement handling
    if (isAck) {
      if (peer.nextSeq !== null && seqGt(p.ack, peer.nextSeq)) {
        events.push({ type: EVENT.ACK_UNSEEN });
        d.counts.ackUnseen++;
      }

      const pureAck = segLen === 0 && !isSyn && !isFin && !isRst;
      const sameAck = d.prevAck !== null && p.ack === d.prevAck;
      if (
        pureAck && sameAck && p.window === d.prevWindow &&
        peer.nextSeq !== null && seqLt(p.ack, peer.nextSeq)
      ) {
        d.dupAckRun++;
        d.counts.dupAck++;
        events.push({ type: EVENT.DUP_ACK, detail: `#${d.dupAckRun}` });
      } else if (!sameAck) {
        d.dupAckRun = 0;
      }
      d.prevAck = p.ack;
      d.prevWindow = p.window;
      if (d.lastAck === null || seqGt(p.ack, d.lastAck)) d.lastAck = p.ack;

      // Round-trip samples: this ACK covers data the peer sent at a known time.
      while (peer.pendingRtt.length && seqGte(p.ack, peer.pendingRtt[0].endSeq)) {
        const s = peer.pendingRtt.shift();
        if (!peer.retransmittedEnds.has(s.endSeq)) {
          peer.rttSamples.push({ time: p.timestamp, rtt: p.timestamp - s.time });
        }
      }
    }

    // ---- window state
    if (!isRst && !isSyn) {
      if (p.window === 0) {
        if (!d.inZeroWindow) {
          events.push({ type: EVENT.ZERO_WINDOW });
          d.counts.zeroWindow++;
        }
        d.inZeroWindow = true;
      } else if (d.inZeroWindow) {
        events.push({ type: EVENT.WINDOW_UPDATE });
        d.inZeroWindow = false;
      }
    }

    if (isRst) {
      d.sawRst = true;
      events.push({ type: EVENT.RESET });
      stream.state = "reset";
    }
    if (isFin) { d.sawFin = true; d.finSeq = p.seq; }

    d.packets++;
    d.bytes += p.length;
    stream.packetNums.push(p.num);
    if (p.timestamp < stream.first) stream.first = p.timestamp;
    if (p.timestamp > stream.last) stream.last = p.timestamp;

    for (const e of events) stream.events.push({ ...e, num: p.num, dir: i });

    p.tcp = {
      streamId: stream.id,
      dir: i,
      relSeq: seqDiff(p.seq, d.isn) >>> 0,
      relAck: isAck && peer.isn !== null ? (seqDiff(p.ack, peer.isn) >>> 0) : null,
      segLen: payloadLen,
      scaledWindow,
      scaled: scale > 0,
      events: events.map((e) => e.type),
      eventDetails: events,
    };
  }

  for (const s of streams) finalizeStream(s, packets);
  return streams;
}

function finalizeStream(stream, packets) {
  const [a, b] = stream.dirs;
  stream.duration = stream.last - stream.first;
  stream.packets = a.packets + b.packets;
  stream.bytes = a.bytes + b.bytes;
  stream.payloadBytes = a.payloadBytes + b.payloadBytes;

  if (a.sawRst || b.sawRst) stream.state = "reset";
  else if (a.sawFin && b.sawFin) stream.state = "closed";
  else if (a.sawFin || b.sawFin) stream.state = "closing";
  else if (stream.synAck !== null) stream.state = "open";
  else if (stream.syn !== null) stream.state = "unanswered";
  else stream.state = "mid-stream";

  // A SYN that never drew a SYN-ACK is a connection that did not happen. Which
  // kind of failure it was matters: refused is a host saying no, unanswered is
  // usually a firewall or a host that is not there.
  if (stream.syn !== null && stream.synAck === null) {
    stream.failed = b.sawRst ? "refused" : "no response";
  } else {
    stream.failed = null;
  }

  stream.counts = {};
  for (const k of Object.keys(a.counts)) stream.counts[k] = a.counts[k] + b.counts[k];

  const samples = [...a.rttSamples, ...b.rttSamples];
  if (samples.length) {
    const values = samples.map((s) => s.rtt).sort((x, y) => x - y);
    stream.rtt = {
      samples: samples.length,
      min: values[0],
      max: values[values.length - 1],
      median: values[Math.floor(values.length / 2)],
      mean: values.reduce((t, v) => t + v, 0) / values.length,
    };
  } else {
    stream.rtt = null;
  }

  stream.throughput = stream.duration > 0
    ? { aToB: (a.payloadBytes * 8) / stream.duration, bToA: (b.payloadBytes * 8) / stream.duration }
    : null;

  // Time from the client's first SYN to the first byte of application data —
  // the number a user would recognise as "how long before anything happened".
  if (stream.syn !== null && stream.firstDataTime !== null) {
    const syn = packets[stream.syn];
    if (syn) stream.timeToFirstByte = stream.firstDataTime - syn.timestamp;
  }

  stream.retransmittedBytes = a.retransmittedBytes + b.retransmittedBytes;
  stream.retransmissionRate = stream.payloadBytes > 0
    ? stream.retransmittedBytes / (stream.payloadBytes + stream.retransmittedBytes)
    : 0;
}

/**
 * Join one direction's segments into the byte stream the application saw.
 *
 * Where a byte range appears more than once the first copy wins, which is what
 * a receiving TCP stack does. Ranges that never appeared in the capture are
 * reported as gaps rather than quietly closed up: a hole shown as a hole is
 * debuggable, a hole spliced shut produces a plausible and wrong transcript.
 */
export function reassemble(segments, limit = MAX_REASSEMBLY_BYTES) {
  if (!segments.length) {
    return { bytes: new Uint8Array(0), length: 0, gaps: [], truncated: false, base: 0 };
  }
  const sorted = [...segments].sort((x, y) => x.rel - y.rel || x.num - y.num);

  // Offset zero is the first byte of payload, not the connection's initial
  // sequence number: the SYN consumes a sequence number without carrying data,
  // and a capture that started mid-connection has no ISN at all. Measuring
  // from the lowest payload offset avoids opening every stream with a phantom
  // one-byte hole.
  const base = sorted[0].rel;

  let maxEnd = 0;
  for (const s of sorted) maxEnd = Math.max(maxEnd, s.rel - base + s.len);
  const truncated = maxEnd > limit;
  const size = Math.min(maxEnd, limit);
  const bytes = new Uint8Array(size);
  const gaps = [];

  let covered = 0; // every byte below this offset has been written
  for (const s of sorted) {
    const start = s.rel - base;
    const end = start + s.len;
    if (end <= covered) continue;
    if (start > covered) gaps.push([covered, start]);

    const from = Math.max(covered, start);
    const skip = from - start;
    const avail = s.payload ? s.payload.length : 0;
    if (skip < avail && from < size) {
      const n = Math.min(avail - skip, size - from);
      bytes.set(s.payload.subarray(skip, skip + n), from);
    }
    // A segment cut short by the capture snaplen leaves a hole of its own.
    if (avail < s.len) gaps.push([start + avail, end]);

    covered = Math.min(Math.max(covered, end), size);
    if (covered >= size) break;
  }

  return { bytes, length: size, gaps, truncated, base };
}

/**
 * Both directions of a stream, and the exchange split into turns.
 *
 * The chunks are cut from the *reassembled* buffers rather than taken straight
 * off the packets, which is what makes the transcript readable: a
 * retransmission does not print its bytes a second time, and a segment the
 * network reordered appears where its sequence number says it belongs rather
 * than where it happened to arrive.
 */
export function followStream(stream, limit = MAX_REASSEMBLY_BYTES) {
  const [a, b] = stream.dirs;
  const data = [reassemble(a.segments, limit), reassemble(b.segments, limit)];

  const all = [
    ...a.segments.map((s) => ({ num: s.num, time: s.time, rel: s.rel, len: s.len, dir: 0 })),
    ...b.segments.map((s) => ({ num: s.num, time: s.time, rel: s.rel, len: s.len, dir: 1 })),
  ].sort((x, y) => x.num - y.num);

  const emittedTo = [0, 0];
  const chunks = [];
  let total = 0;

  for (const s of all) {
    const side = data[s.dir];
    const end = Math.min(side.length, s.rel - side.base + s.len);
    if (end <= emittedTo[s.dir]) continue; // already shown, or a pure repeat
    const from = emittedTo[s.dir];
    chunks.push({
      dir: s.dir, num: s.num, time: s.time,
      bytes: side.bytes.subarray(from, end),
    });
    total += end - from;
    emittedTo[s.dir] = end;
  }

  return {
    aToB: data[0], bToA: data[1], chunks, bytes: total,
    capped: data[0].truncated || data[1].truncated,
  };
}
