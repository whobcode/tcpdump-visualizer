/**
 * Network and transport layer decoding.
 *
 * Offsets are computed from the link layer rather than assumed, and IPv6 is
 * handled — an earlier version dropped every v6 packet into "Unknown", which
 * on a network where devices talk over link-local addresses silently discards
 * a large share of the traffic.
 *
 * This layer decodes; it does not interpret. Sequence numbers, window sizes,
 * options and payload slices are recorded as they appear on the wire, and
 * everything that requires remembering an earlier packet — retransmissions,
 * duplicate ACKs, stream reassembly — lives in src/analyze/.
 */
import { decodeLink } from "./linktype.js";

const IPPROTO = { ICMP: 1, TCP: 6, UDP: 17, ICMPV6: 58 };

export const TCP_FLAG = {
  FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08,
  ACK: 0x10, URG: 0x20, ECE: 0x40, CWR: 0x80,
};

const TCP_FLAG_NAMES = [
  [TCP_FLAG.FIN, "FIN"], [TCP_FLAG.SYN, "SYN"], [TCP_FLAG.RST, "RST"],
  [TCP_FLAG.PSH, "PSH"], [TCP_FLAG.ACK, "ACK"], [TCP_FLAG.URG, "URG"],
  [TCP_FLAG.ECE, "ECE"], [TCP_FLAG.CWR, "CWR"],
];

export function tcpFlagNames(flags) {
  return TCP_FLAG_NAMES.filter(([bit]) => flags & bit).map(([, n]) => n);
}

/** ICMPv4 types worth naming; the rest are shown numerically. */
const ICMP_TYPES = {
  0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
  5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
  12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply",
};

const ICMP6_TYPES = {
  1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
  4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
  133: "Router Solicitation", 134: "Router Advertisement",
  135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
};

const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const u32 = (d, o) => (((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0);

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

/**
 * TCP options.
 *
 * The window field is meaningless without the window scale negotiated in the
 * handshake — a receiver advertising 64 KB with a scale of 7 actually has 8 MB
 * of room, and reading the raw field makes every fast connection look as
 * though it is about to stall.
 */
function parseTcpOptions(data, start, end) {
  const opts = {
    mss: null, windowScale: null, sackPermitted: false,
    sack: [], tsval: null, tsecr: null,
  };
  let o = start;
  let guard = 0;
  while (o < end && guard++ < 40) {
    const kind = data[o];
    if (kind === 0) break;                // End of option list
    if (kind === 1) { o += 1; continue; } // No-op padding
    if (o + 1 >= end) break;
    const len = data[o + 1];
    if (len < 2 || o + len > end) break;
    switch (kind) {
      case 2: if (len === 4) opts.mss = u16(data, o + 2); break;
      case 3: if (len === 3) opts.windowScale = data[o + 2]; break;
      case 4: opts.sackPermitted = true; break;
      case 5:
        for (let i = o + 2; i + 8 <= o + len; i += 8) {
          opts.sack.push([u32(data, i), u32(data, i + 4)]);
        }
        break;
      case 8:
        if (len === 10) { opts.tsval = u32(data, o + 2); opts.tsecr = u32(data, o + 6); }
        break;
    }
    o += len;
  }
  return opts;
}

/**
 * @param transportLen bytes of transport header + payload according to the IP
 *   header, or null when the IP header did not say (some offload paths write
 *   zero). It is the IP header and not the frame length that determines where
 *   the payload ends: Ethernet pads frames up to 60 bytes, so a bare ACK looks
 *   as though it carries 6 bytes of data if you measure from the frame.
 */
function decodeTransport(packet, data, start, protocol, transportLen) {
  const available = Math.max(0, data.length - start);
  const declared = transportLen == null ? available : Math.min(transportLen, 65535);

  if (protocol === IPPROTO.TCP && available >= 20) {
    packet.protocol = "TCP";
    packet.srcPort = u16(data, start);
    packet.dstPort = u16(data, start + 2);
    packet.seq = u32(data, start + 4);
    packet.ack = u32(data, start + 8);
    const dataOffset = Math.max((data[start + 12] >> 4) * 4, 20);
    packet.flags = data[start + 13];
    packet.flagNames = tcpFlagNames(packet.flags);
    packet.window = u16(data, start + 14);
    packet.urgentPointer = u16(data, start + 18);
    packet.tcpHeaderLength = dataOffset;

    packet.tcpOptions = start + dataOffset <= data.length
      ? parseTcpOptions(data, start + 20, start + dataOffset)
      : null;

    // What the sender says it sent, versus what the capture actually holds.
    const payloadStart = start + dataOffset;
    packet.payloadLength = Math.max(0, declared - dataOffset);
    const have = Math.max(0, Math.min(packet.payloadLength, data.length - payloadStart));
    packet.payload = have > 0 ? data.subarray(payloadStart, payloadStart + have) : null;
    packet.payloadTruncated = have < packet.payloadLength;
    packet.info = packet.flagNames.join(", ");
  } else if (protocol === IPPROTO.UDP && available >= 8) {
    packet.protocol = "UDP";
    packet.srcPort = u16(data, start);
    packet.dstPort = u16(data, start + 2);
    // The UDP length field covers the 8-byte header too.
    const udpLen = u16(data, start + 4);
    packet.payloadLength = Math.max(0, (udpLen >= 8 ? udpLen : declared) - 8);
    const have = Math.max(0, Math.min(packet.payloadLength, data.length - (start + 8)));
    packet.payload = have > 0 ? data.subarray(start + 8, start + 8 + have) : null;
    packet.payloadTruncated = have < packet.payloadLength;
    packet.info = `Len=${packet.payloadLength}`;
  } else if (protocol === IPPROTO.ICMP && available >= 2) {
    packet.protocol = "ICMP";
    packet.icmpType = data[start];
    packet.icmpCode = data[start + 1];
    const name = ICMP_TYPES[packet.icmpType];
    packet.info = name
      ? `${name}${packet.icmpCode ? ` (code ${packet.icmpCode})` : ""}`
      : `Type=${packet.icmpType} Code=${packet.icmpCode}`;
  } else if (protocol === IPPROTO.ICMPV6 && available >= 2) {
    packet.protocol = "ICMPv6";
    packet.icmpType = data[start];
    packet.icmpCode = data[start + 1];
    const name = ICMP6_TYPES[packet.icmpType];
    packet.info = name
      ? `${name}${packet.icmpCode ? ` (code ${packet.icmpCode})` : ""}`
      : `Type=${packet.icmpType} Code=${packet.icmpCode}`;
  }
}

/** IPv6 extension headers sit between the fixed header and the transport one. */
const EXT_HEADERS = new Set([0, 43, 44, 50, 51, 60, 135]);

function skipExtensionHeaders(data, offset, nextHeader) {
  const start = offset;
  let guard = 0;
  while (EXT_HEADERS.has(nextHeader) && data.length >= offset + 2 && guard++ < 8) {
    const len = (data[offset + 1] + 1) * 8;
    nextHeader = data[offset];
    offset += len;
  }
  return { offset, protocol: nextHeader, consumed: offset - start };
}

export function parsePacket(
  data, seconds, fraction, num, linktype, littleEndian, originalLength,
) {
  const timestamp = seconds + fraction;
  const packet = {
    num,
    timestamp,
    time: new Date(timestamp * 1000).toLocaleTimeString(),
    // Wire length. Where the capture holds fewer bytes than this, the capture
    // was cut short by the snaplen and any payload analysis is working from a
    // fragment — worth saying rather than silently analysing the fragment.
    length: originalLength == null ? data.length : originalLength,
    capturedLength: data.length,
    linktype,
    protocol: "Unknown",
    src: "", dst: "", srcPort: "", dstPort: "", info: "",
    payload: null, payloadLength: 0,
  };
  packet.snaplenTruncated = packet.capturedLength < packet.length;

  const link = decodeLink(data, linktype, littleEndian);
  if (!link) return packet;
  const { offset: netStart, ethertype } = link;

  if (ethertype === 0x0800 && data.length >= netStart + 20) {
    const ihl = (data[netStart] & 0x0f) * 4;
    const totalLength = u16(data, netStart + 2);
    packet.ipVersion = 4;
    packet.ttl = data[netStart + 8];
    packet.ipId = u16(data, netStart + 4);
    const fragField = u16(data, netStart + 6);
    packet.fragmentOffset = (fragField & 0x1fff) * 8;
    packet.moreFragments = Boolean(fragField & 0x2000);
    packet.dontFragment = Boolean(fragField & 0x4000);
    packet.src = v4(data, netStart + 12);
    packet.dst = v4(data, netStart + 16);
    // totalLength of 0 means segmentation offload wrote the frame; fall back
    // to what is actually present rather than computing a negative length.
    const transportLen = totalLength > ihl ? totalLength - ihl : null;
    if (packet.fragmentOffset === 0) {
      decodeTransport(packet, data, netStart + ihl, data[netStart + 9], transportLen);
    } else {
      // A non-first fragment carries no transport header to read.
      packet.protocol = "IPv4 fragment";
      packet.info = `offset ${packet.fragmentOffset}`;
    }
  } else if (ethertype === 0x86dd && data.length >= netStart + 40) {
    packet.ipVersion = 6;
    packet.ttl = data[netStart + 7]; // hop limit
    const payloadLength = u16(data, netStart + 4);
    packet.src = v6(data, netStart + 8);
    packet.dst = v6(data, netStart + 24);
    const { offset, protocol, consumed } =
      skipExtensionHeaders(data, netStart + 40, data[netStart + 6]);
    const transportLen = payloadLength > consumed ? payloadLength - consumed : null;
    decodeTransport(packet, data, offset, protocol, transportLen);
  } else if (ethertype === 0x0806) {
    packet.protocol = "ARP";
    if (data.length >= netStart + 28) {
      packet.src = v4(data, netStart + 14);
      packet.dst = v4(data, netStart + 24);
      packet.arpOpcode = u16(data, netStart + 6);
      packet.info = packet.arpOpcode === 1 ? "Request" : "Reply";
    }
  }

  return packet;
}
