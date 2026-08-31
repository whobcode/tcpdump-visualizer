/**
 * pcapng files.
 *
 * This is the format tcpdump and Wireshark write by default, so a tool that
 * only reads classic pcap fails on most captures people actually have.
 *
 * The structure is a stream of type-length-value blocks rather than a header
 * followed by fixed records:
 *
 *   Section Header Block      declares byte order and starts a section
 *   Interface Description     one per capture interface: link type, timestamp
 *                             resolution. Packets reference these by index.
 *   Enhanced Packet Block     a captured packet, tied to an interface
 *
 * Timestamps are a 64-bit count of units whose size is declared per interface
 * (option 9, if_tsresol), defaulting to microseconds. Assuming microseconds
 * would misread any capture made with nanosecond resolution.
 */
import { parsePacket } from "./packet.js";

const BLOCK = {
  SECTION_HEADER: 0x0a0d0d0a,
  INTERFACE_DESCRIPTION: 0x00000001,
  SIMPLE_PACKET: 0x00000003,
  ENHANCED_PACKET: 0x00000006,
};

const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

export function isPcapng(view) {
  return view.byteLength >= 12 && view.getUint32(0, true) === BLOCK.SECTION_HEADER;
}

/** Options are id/length pairs padded to 4 bytes, terminated by id 0. */
function readOptions(view, start, end, littleEndian) {
  const options = {};
  let offset = start;
  while (offset + 4 <= end) {
    const code = view.getUint16(offset, littleEndian);
    const length = view.getUint16(offset + 2, littleEndian);
    offset += 4;
    if (code === 0) break;
    if (offset + length > end) break;
    options[code] = new Uint8Array(view.buffer, view.byteOffset + offset, length);
    offset += length + ((4 - (length % 4)) % 4);
  }
  return options;
}

/**
 * if_tsresol: high bit clear means 10^value, set means 2^(value & 0x7f).
 * Absent means microseconds.
 */
function timestampDivisor(options) {
  const raw = options[9];
  if (!raw || raw.length < 1) return 1e6;
  const v = raw[0];
  return (v & 0x80) ? Math.pow(2, v & 0x7f) : Math.pow(10, v);
}

export function parsePcapng(buffer) {
  const view = new DataView(buffer);
  if (!isPcapng(view)) throw new Error("not a pcapng file");

  const packets = [];
  const interfaces = [];
  let littleEndian = true;
  let offset = 0;
  let num = 0;
  let truncated = false;

  while (offset + 12 <= buffer.byteLength) {
    const type = view.getUint32(offset, littleEndian);

    // A section header re-declares byte order, so it is read before trusting
    // the length field that follows it.
    if (type === BLOCK.SECTION_HEADER) {
      const bom = view.getUint32(offset + 8, true);
      littleEndian = bom === BYTE_ORDER_MAGIC;
    }

    const length = view.getUint32(offset + 4, littleEndian);
    // A zero or unaligned length would loop forever or walk off the end.
    if (length < 12 || offset + length > buffer.byteLength) { truncated = true; break; }
    const bodyEnd = offset + length - 4;

    if (type === BLOCK.INTERFACE_DESCRIPTION) {
      const linktype = view.getUint16(offset + 8, littleEndian);
      const options = readOptions(view, offset + 16, bodyEnd, littleEndian);
      interfaces.push({ linktype, divisor: timestampDivisor(options) });
    } else if (type === BLOCK.ENHANCED_PACKET) {
      const ifaceId = view.getUint32(offset + 8, littleEndian);
      const tsHigh = view.getUint32(offset + 12, littleEndian);
      const tsLow = view.getUint32(offset + 16, littleEndian);
      const capturedLen = view.getUint32(offset + 20, littleEndian);
      // Wire length; larger than capturedLen when a snaplen cut the packet.
      const originalLen = view.getUint32(offset + 24, littleEndian);
      const iface = interfaces[ifaceId] || { linktype: 1, divisor: 1e6 };

      // 64-bit count assembled in floating point: exact to 2^53, which is
      // ~285 years of microseconds, so precision is not a practical concern.
      const ticks = tsHigh * 4294967296 + tsLow;
      const seconds = Math.floor(ticks / iface.divisor);
      const fraction = (ticks % iface.divisor) / iface.divisor;

      const dataStart = offset + 28;
      if (dataStart + capturedLen <= bodyEnd) {
        packets.push(parsePacket(
          new Uint8Array(buffer, dataStart, capturedLen),
          seconds, fraction, num++, iface.linktype, littleEndian, originalLen,
        ));
      }
    } else if (type === BLOCK.SIMPLE_PACKET) {
      const iface = interfaces[0] || { linktype: 1, divisor: 1e6 };
      const dataStart = offset + 12;
      // A simple packet block records only the original length; how much of it
      // is present is whatever fits in the block.
      const originalLen = view.getUint32(offset + 8, littleEndian);
      const capturedLen = Math.min(originalLen, bodyEnd - dataStart);
      if (capturedLen > 0) {
        // Simple packet blocks carry no timestamp at all.
        packets.push(parsePacket(
          new Uint8Array(buffer, dataStart, capturedLen),
          0, 0, num++, iface.linktype, littleEndian, originalLen,
        ));
      }
    }

    offset += length;
  }

  return {
    format: "pcapng",
    linktype: interfaces.length ? interfaces[0].linktype : null,
    interfaces,
    packets,
    truncated,
  };
}
