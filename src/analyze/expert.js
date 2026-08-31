/**
 * Findings — the things in a capture worth someone's attention.
 *
 * A capture rarely fails to answer a question because the data was missing; it
 * fails because the answer was one row in fifty thousand. Everything here is
 * something that would be tedious to notice by scrolling and obvious once
 * named, ranked so the connection that was reset comes above the connection
 * that merely reordered a packet.
 *
 * Each finding carries the packet numbers behind it, so a claim can always be
 * checked against the packets that produced it rather than taken on trust.
 */
import { EVENT } from "./tcp.js";
import { CLEARTEXT_PORTS } from "./services.js";

const SEVERITY_ORDER = { error: 0, warning: 1, note: 2 };
const MAX_PACKET_REFS = 200;

function finding(list, spec) {
  if (!spec.count) return;
  const refs = spec.packets || [];
  list.push({
    severity: "note",
    ...spec,
    // Keeping every packet number for a finding that covers half the capture
    // costs more than it explains; the first few are enough to go and look.
    packets: refs.slice(0, MAX_PACKET_REFS),
    totalPackets: refs.length,
  });
}

const pct = (n, total) => (total > 0 ? `${((n / total) * 100).toFixed(1)}%` : "0%");

/** Titles are read as sentences, so they have to agree with their own count. */
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

export function buildFindings(capture, packets, streams, conversations) {
  const findings = [];
  const tcpPackets = packets.filter((p) => p.protocol === "TCP");

  // ---- capture integrity -------------------------------------------------
  if (capture.truncated) {
    finding(findings, {
      severity: "error",
      category: "capture",
      title: "Capture file is truncated",
      detail: "The file ends mid-record. Packets after that point are missing, " +
              "so any count or total below is a floor, not a total.",
      count: 1,
    });
  }

  const snapped = packets.filter((p) => p.snaplenTruncated);
  if (snapped.length) {
    const worst = snapped.reduce((m, p) => Math.max(m, p.capturedLength), 0);
    finding(findings, {
      severity: "warning",
      category: "capture",
      title: "Packets cut short by the capture snaplen",
      detail: `${plural(snapped.length, "packet was", "packets were")} stored only in part (largest kept: ` +
              `${worst} bytes). Headers are intact but payload is incomplete, so ` +
              `reassembled streams have holes. Re-capture with -s 0 to keep whole packets.`,
      count: snapped.length,
      packets: snapped.map((p) => p.num),
    });
  }

  // ---- TCP health --------------------------------------------------------
  const byEvent = new Map();
  for (const s of streams) {
    for (const e of s.events) {
      if (!byEvent.has(e.type)) byEvent.set(e.type, []);
      byEvent.get(e.type).push(e.num);
    }
  }
  const nums = (t) => byEvent.get(t) || [];

  const retrans = [
    ...nums(EVENT.RETRANSMISSION),
    ...nums(EVENT.FAST_RETRANSMISSION),
    ...nums(EVENT.SPURIOUS_RETRANSMISSION),
  ];
  if (retrans.length) {
    const rate = retrans.length / Math.max(1, tcpPackets.length);
    finding(findings, {
      // Background loss is normal; a few percent is a network with a problem.
      severity: rate > 0.02 ? "error" : "warning",
      category: "tcp",
      title: `${plural(retrans.length, "retransmission", "retransmissions")} (${pct(retrans.length, tcpPackets.length)} of TCP packets)`,
      detail: rate > 0.02
        ? "Sustained loss at this rate throttles every transfer on the path: TCP " +
          "reads loss as congestion and backs off, so throughput collapses well " +
          "before the link is full."
        : "Occasional retransmission is normal. Check whether they cluster on one " +
          "connection or one peer before treating it as a network fault.",
      count: retrans.length,
      packets: retrans.sort((a, b) => a - b),
    });
  }

  finding(findings, {
    severity: "warning",
    category: "tcp",
    title: plural(nums(EVENT.FAST_RETRANSMISSION).length, "fast retransmission", "fast retransmissions"),
    detail: "The sender saw three duplicate ACKs and resent without waiting for a " +
            "timeout. This is loss being recovered quickly rather than a stall, but " +
            "it is still loss.",
    count: nums(EVENT.FAST_RETRANSMISSION).length,
    packets: nums(EVENT.FAST_RETRANSMISSION),
  });

  finding(findings, {
    severity: "warning",
    category: "tcp",
    title: plural(nums(EVENT.DUP_ACK).length, "duplicate ACK", "duplicate ACKs"),
    detail: "A receiver repeating an ACK is saying it has a hole: the segment it " +
            "wants has not arrived while later ones have.",
    count: nums(EVENT.DUP_ACK).length,
    packets: nums(EVENT.DUP_ACK),
  });

  finding(findings, {
    severity: "note",
    category: "tcp",
    title: plural(nums(EVENT.OUT_OF_ORDER).length, "out-of-order segment", "out-of-order segments"),
    detail: "Delivered late rather than lost — usually multipath or a device " +
            "reordering. Harmless in small numbers; in large ones it makes " +
            "receivers emit duplicate ACKs and triggers needless retransmission.",
    count: nums(EVENT.OUT_OF_ORDER).length,
    packets: nums(EVENT.OUT_OF_ORDER),
  });

  finding(findings, {
    severity: "error",
    category: "tcp",
    title: plural(nums(EVENT.ZERO_WINDOW).length, "zero-window advertisement", "zero-window advertisements"),
    detail: "A receiver said it had no buffer space left. The sender must stop " +
            "until a window update arrives, so this is the application at the " +
            "receiving end failing to read fast enough — not a network fault.",
    count: nums(EVENT.ZERO_WINDOW).length,
    packets: nums(EVENT.ZERO_WINDOW),
  });

  finding(findings, {
    severity: "warning",
    category: "tcp",
    title: `The send window filled ${nums(EVENT.WINDOW_FULL).length === 1 ? "once" : `${nums(EVENT.WINDOW_FULL).length} times`}`,
    detail: "The sender had as much data in flight as the receiver allowed and had " +
            "to wait. If throughput is short of the link's capacity, this is where " +
            "it is being lost.",
    count: nums(EVENT.WINDOW_FULL).length,
    packets: nums(EVENT.WINDOW_FULL),
  });

  finding(findings, {
    severity: "warning",
    category: "capture",
    title: plural(nums(EVENT.LOST_SEGMENT).length, "gap where a segment was never captured", "gaps where a segment was never captured"),
    detail: "Sequence numbers jump forward with nothing in between. Either the " +
            "segment was lost on the wire, or the capture itself dropped it — check " +
            "the interface's drop counter before blaming the network.",
    count: nums(EVENT.LOST_SEGMENT).length,
    packets: nums(EVENT.LOST_SEGMENT),
  });

  finding(findings, {
    severity: "note",
    category: "capture",
    title: plural(nums(EVENT.ACK_UNSEEN).length, "ACK for data that was never captured", "ACKs for data that was never captured"),
    detail: "Something acknowledged bytes this capture never saw sent, so the " +
            "capture is missing one direction or started mid-connection.",
    count: nums(EVENT.ACK_UNSEEN).length,
    packets: nums(EVENT.ACK_UNSEEN),
  });

  finding(findings, {
    severity: "note",
    category: "tcp",
    title: plural(nums(EVENT.KEEP_ALIVE).length, "keep-alive", "keep-alives"),
    detail: "An idle connection being held open. Normal, unless the interval is " +
            "shorter than the idle timeout of something in the path.",
    count: nums(EVENT.KEEP_ALIVE).length,
    packets: nums(EVENT.KEEP_ALIVE),
  });

  // ---- connection outcomes ----------------------------------------------
  const resets = streams.filter((s) => s.state === "reset");
  if (resets.length) {
    finding(findings, {
      severity: "warning",
      category: "tcp",
      title: `${plural(resets.length, "connection", "connections")} ended in RST`,
      detail: "An abrupt close. Sometimes an application simply closing without " +
              "draining, often a rejected connection, a timeout in a proxy, or a " +
              "firewall cutting the session.",
      count: resets.length,
      packets: resets.map((s) => s.events.find((e) => e.type === EVENT.RESET)?.num).filter((n) => n != null),
    });
  }

  const refused = streams.filter((s) => s.failed === "refused");
  finding(findings, {
    severity: "error",
    category: "tcp",
    title: `${plural(refused.length, "connection", "connections")} refused`,
    detail: "The SYN was answered with a RST: the host is reachable and nothing is " +
            "listening on that port.",
    count: refused.length,
    packets: refused.map((s) => s.syn).filter((n) => n != null),
  });

  const unanswered = streams.filter((s) => s.failed === "no response");
  finding(findings, {
    severity: "error",
    category: "tcp",
    title: `${plural(unanswered.length, "connection attempt", "connection attempts")} got no reply`,
    detail: "SYNs with no SYN-ACK and no RST. A silent drop is what a firewall does; " +
            "a host that is simply down usually answers with an ICMP error instead.",
    count: unanswered.length,
    packets: unanswered.map((s) => s.syn).filter((n) => n != null),
  });

  // ---- latency ----------------------------------------------------------
  const slow = streams.filter((s) => s.handshakeRtt != null && s.handshakeRtt > 0.2);
  if (slow.length) {
    const worst = Math.max(...slow.map((s) => s.handshakeRtt));
    finding(findings, {
      severity: "warning",
      category: "performance",
      title: `${plural(slow.length, "connection", "connections")} took over 200 ms to complete the handshake`,
      detail: `Slowest was ${(worst * 1000).toFixed(0)} ms. Handshake time is one ` +
              `round trip with no application logic in it, so it is the cleanest ` +
              `measure of the path itself.`,
      count: slow.length,
      packets: slow.map((s) => s.syn).filter((n) => n != null),
    });
  }

  // ---- ICMP -------------------------------------------------------------
  const unreachable = packets.filter(
    (p) => (p.protocol === "ICMP" && p.icmpType === 3) ||
           (p.protocol === "ICMPv6" && p.icmpType === 1),
  );
  finding(findings, {
    severity: "error",
    category: "network",
    title: `${plural(unreachable.length, "ICMP destination-unreachable message", "ICMP destination-unreachable messages")}`,
    detail: "Something in the path said it could not deliver. The code says why — " +
            "port unreachable is a closed UDP port, fragmentation needed is a path " +
            "MTU problem that will look like a hung transfer.",
    count: unreachable.length,
    packets: unreachable.map((p) => p.num),
  });

  const ttlExceeded = packets.filter(
    (p) => (p.protocol === "ICMP" && p.icmpType === 11) ||
           (p.protocol === "ICMPv6" && p.icmpType === 3),
  );
  finding(findings, {
    severity: "warning",
    category: "network",
    title: `${plural(ttlExceeded.length, "ICMP time-exceeded message", "ICMP time-exceeded messages")}`,
    detail: "A packet ran out of hops. Expected during a traceroute; otherwise a " +
            "routing loop.",
    count: ttlExceeded.length,
    packets: ttlExceeded.map((p) => p.num),
  });

  // ---- scan heuristic ---------------------------------------------------
  // One source touching many ports on one host, with almost nothing coming
  // back, is the shape of a port scan whatever tool produced it.
  const probes = new Map();
  for (const s of streams) {
    if (s.syn === null) continue;
    const k = `${s.a.ip}→${s.b.ip}`;
    let e = probes.get(k);
    if (!e) e = probes.set(k, { ports: new Set(), answered: 0, syns: [] }).get(k);
    e.ports.add(s.b.port);
    if (s.synAck !== null) e.answered++;
    e.syns.push(s.syn);
  }
  for (const [pair, e] of probes) {
    if (e.ports.size >= 15 && e.answered / e.ports.size < 0.2) {
      const [src, dst] = pair.split("→");
      finding(findings, {
        severity: "warning",
        category: "security",
        title: `${src} probed ${e.ports.size} ports on ${dst}`,
        detail: `${e.answered} of those attempts were answered. A sweep across many ` +
                `ports with few replies is a port scan; if it is yours, it is fine, ` +
                `and if it is not, it is reconnaissance.`,
        count: e.ports.size,
        packets: e.syns.filter((n) => n != null),
      });
    }
  }

  // ---- cleartext --------------------------------------------------------
  const cleartext = new Map();
  for (const c of conversations) {
    if (c.protocol !== "TCP" || c.serverPort == null) continue;
    const name = CLEARTEXT_PORTS[c.serverPort];
    if (!name) continue;
    let e = cleartext.get(name);
    if (!e) e = cleartext.set(name, { bytes: 0, convs: 0, packets: [] }).get(name);
    e.bytes += c.bytes;
    e.convs++;
    e.packets.push(...c.packetNums.slice(0, 20));
  }
  for (const [name, e] of cleartext) {
    finding(findings, {
      severity: name === "Telnet" || name === "FTP" ? "error" : "note",
      category: "security",
      title: `${name} in use, unencrypted (${e.convs} conversation${e.convs === 1 ? "" : "s"})`,
      detail: "Everything in these conversations — credentials included — was " +
              "readable to anyone on the path, and is readable in this capture.",
      count: e.convs,
      packets: e.packets,
    });
  }

  findings.sort((a, b) =>
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.count - a.count);
  return findings;
}
