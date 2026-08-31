/**
 * Conversations and endpoints.
 *
 * A conversation is bidirectional. The previous version of this tool counted
 * `src → dst` pairs, which splits every exchange into two unrelated rows and
 * makes it impossible to see that a host sent 40 KB and got 12 MB back — the
 * shape that actually tells you what a connection was doing. Here the two
 * directions are folded into one row with per-direction counters, and A is
 * whichever end was seen first.
 */
import { serviceName, likelyServerPort } from "./services.js";

/** Order two endpoints so both directions hash to the same conversation. */
function orderKey(aIp, aPort, bIp, bPort) {
  const a = `${aIp}|${aPort}`;
  const b = `${bIp}|${bPort}`;
  return a <= b ? `${a}|${b}` : `${b}|${a}`;
}

export function buildConversations(packets) {
  const map = new Map();

  for (const p of packets) {
    if (!p.src || !p.dst) continue;
    const sPort = p.srcPort === "" ? null : p.srcPort;
    const dPort = p.dstPort === "" ? null : p.dstPort;
    const key = `${p.protocol}|${orderKey(p.src, sPort, p.dst, dPort)}`;

    let c = map.get(key);
    if (!c) {
      c = {
        key,
        protocol: p.protocol,
        a: p.src, aPort: sPort,
        b: p.dst, bPort: dPort,
        packetsAB: 0, packetsBA: 0,
        bytesAB: 0, bytesBA: 0,
        first: p.timestamp, last: p.timestamp,
        packetNums: [],
      };
      map.set(key, c);
    }

    const forward = p.src === c.a && (sPort === c.aPort);
    if (forward) { c.packetsAB++; c.bytesAB += p.length; }
    else { c.packetsBA++; c.bytesBA += p.length; }

    if (p.timestamp < c.first) c.first = p.timestamp;
    if (p.timestamp > c.last) c.last = p.timestamp;
    c.packetNums.push(p.num);
  }

  const conversations = [...map.values()];
  for (const c of conversations) {
    c.packets = c.packetsAB + c.packetsBA;
    c.bytes = c.bytesAB + c.bytesBA;
    c.duration = c.last - c.first;
    // Bits per second over the conversation's own lifetime. A single-packet
    // conversation has no duration, so it gets no rate rather than Infinity.
    c.bitrate = c.duration > 0 ? (c.bytes * 8) / c.duration : null;
    if (c.aPort != null && c.bPort != null) {
      const server = likelyServerPort(c.aPort, c.bPort);
      c.service = serviceName(server);
      c.serverPort = server;
    } else {
      c.service = null;
      c.serverPort = null;
    }
  }

  conversations.sort((x, y) => y.bytes - x.bytes);
  return conversations;
}

/** Per-host totals, split by direction so a talker is distinguishable from a listener. */
export function buildEndpoints(packets) {
  const map = new Map();
  const touch = (ip) => {
    let e = map.get(ip);
    if (!e) {
      e = {
        ip, packetsSent: 0, packetsReceived: 0,
        bytesSent: 0, bytesReceived: 0,
        peers: new Set(), ports: new Set(), ttls: new Set(),
      };
      map.set(ip, e);
    }
    return e;
  };

  for (const p of packets) {
    if (!p.src || !p.dst) continue;
    const s = touch(p.src);
    const d = touch(p.dst);
    s.packetsSent++; s.bytesSent += p.length;
    d.packetsReceived++; d.bytesReceived += p.length;
    s.peers.add(p.dst); d.peers.add(p.src);
    if (p.dstPort !== "" && p.dstPort != null) d.ports.add(p.dstPort);
    if (p.ttl != null) s.ttls.add(p.ttl);
  }

  const endpoints = [...map.values()].map((e) => ({
    ...e,
    packets: e.packetsSent + e.packetsReceived,
    bytes: e.bytesSent + e.bytesReceived,
    peerCount: e.peers.size,
    portCount: e.ports.size,
    // Distinct TTLs from one address usually means either a router in the
    // path rewriting, or two hosts sharing an address (NAT, or a conflict).
    ttlValues: [...e.ttls].sort((a, b) => a - b),
  }));

  endpoints.sort((a, b) => b.bytes - a.bytes);
  return endpoints;
}

/** Traffic over time, in fixed buckets, for the throughput chart. */
export function buildTimeline(packets, targetBuckets = 120) {
  const timed = packets.filter((p) => p.timestamp > 0);
  if (!timed.length) return { buckets: [], interval: 0, start: 0 };

  let start = Infinity, end = -Infinity;
  for (const p of timed) {
    if (p.timestamp < start) start = p.timestamp;
    if (p.timestamp > end) end = p.timestamp;
  }
  const span = end - start;
  // A capture spanning a fraction of a second still needs a positive interval.
  const interval = span > 0 ? span / targetBuckets : 0.001;

  const buckets = [];
  for (const p of timed) {
    const i = span > 0 ? Math.min(targetBuckets - 1, Math.floor((p.timestamp - start) / interval)) : 0;
    let b = buckets[i];
    if (!b) b = buckets[i] = { t: start + i * interval, packets: 0, bytes: 0 };
    b.packets++;
    b.bytes += p.length;
  }
  for (let i = 0; i < buckets.length; i++) {
    if (!buckets[i]) buckets[i] = { t: start + i * interval, packets: 0, bytes: 0 };
    buckets[i].bitsPerSecond = (buckets[i].bytes * 8) / interval;
  }

  return { buckets, interval, start, end };
}
