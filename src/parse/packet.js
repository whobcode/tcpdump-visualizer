/**
 * Network and transport layer decoding.
 *
 * Offsets are computed from the link layer rather than assumed, and IPv6 is
 * handled — the previous version dropped every v6 packet into "Unknown", which
 * on a network where devices talk over link-local addresses silently discards
 * a large share of the traffic.
 */
import { decodeLink } from "./linktype.js";

const IPPROTO = { ICMP: 1, TCP: 6, UDP: 17, ICMPV6: 58 };

const TCP_FLAGS = [
  [0x01, "FIN"], [0x02, "SYN"], [0x04, "RST"],
  [0x08, "PSH"], [0x10, "ACK"], [0x20, "URG"],
  [0x40, "ECE"], [0x80, "CWR"],
];

const v4 = (d, o) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;

function v6(d, o) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push((((d[o + i] << 8) | d[o + i + 1]) >>> 0).toString(16));
  }
  // Collapse the longest run of zero groups, per RFC 5952.
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  parts.forEach((p, i) => {
    if (p === "0") {
      if (curStart < 0) { curStart = i; curLen = 0; }
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  });
  if (bestLen > 1) {
    return parts.slice(0, bestStart).join(":") + "::" +
           parts.slice(bestStart + bestLen).join(":");
  }
  return parts.join(":");
}

function decodeTransport(packet, data, start, protocol) {
  if (protocol === IPPROTO.TCP && data.length >= start + 14) {
    packet.protocol = "TCP";
    packet.srcPort = (data[start] << 8) | data[start + 1];
    packet.dstPort = (data[start + 2] << 8) | data[start + 3];
    const flags = data[start + 13];
    packet.info = TCP_FLAGS.filter(([bit]) => flags & bit).map(([, n]) => n).join(", ");
  } else if (protocol === IPPROTO.UDP && data.length >= start + 6) {
    packet.protocol = "UDP";
    packet.srcPort = (data[start] << 8) | data[start + 1];
    packet.dstPort = (data[start + 2] << 8) | data[start + 3];
    packet.info = `Len=${(data[start + 4] << 8) | data[start + 5]}`;
  } else if (protocol === IPPROTO.ICMP && data.length >= start + 2) {
    packet.protocol = "ICMP";
    packet.info = `Type=${data[start]} Code=${data[start + 1]}`;
  } else if (protocol === IPPROTO.ICMPV6 && data.length >= start + 2) {
    packet.protocol = "ICMPv6";
    packet.info = `Type=${data[start]} Code=${data[start + 1]}`;
  }
}

/** IPv6 extension headers sit between the fixed header and the transport one. */
const EXT_HEADERS = new Set([0, 43, 44, 50, 51, 60, 135]);

function skipExtensionHeaders(data, offset, nextHeader) {
  let guard = 0;
  while (EXT_HEADERS.has(nextHeader) && data.length >= offset + 2 && guard++ < 8) {
    const len = (data[offset + 1] + 1) * 8;
    nextHeader = data[offset];
    offset += len;
  }
  return { offset, protocol: nextHeader };
}

export function parsePacket(data, seconds, fraction, num, linktype, littleEndian) {
  const packet = {
    num,
    timestamp: seconds + fraction,
    time: new Date((seconds + fraction) * 1000).toLocaleTimeString(),
    length: data.length,
    protocol: "Unknown",
    src: "", dst: "", srcPort: "", dstPort: "", info: "",
  };

  const link = decodeLink(data, linktype, littleEndian);
  if (!link) return packet;
  const { offset: netStart, ethertype } = link;

  if (ethertype === 0x0800 && data.length >= netStart + 20) {
    const ihl = (data[netStart] & 0x0f) * 4;
    packet.src = v4(data, netStart + 12);
    packet.dst = v4(data, netStart + 16);
    decodeTransport(packet, data, netStart + ihl, data[netStart + 9]);
  } else if (ethertype === 0x86dd && data.length >= netStart + 40) {
    packet.src = v6(data, netStart + 8);
    packet.dst = v6(data, netStart + 24);
    const { offset, protocol } =
      skipExtensionHeaders(data, netStart + 40, data[netStart + 6]);
    decodeTransport(packet, data, offset, protocol);
  } else if (ethertype === 0x0806) {
    packet.protocol = "ARP";
    if (data.length >= netStart + 28) {
      packet.src = v4(data, netStart + 14);
      packet.dst = v4(data, netStart + 24);
      packet.info = (data[netStart + 7] === 1) ? "Request" : "Reply";
    }
  }

  return packet;
}
