/**
 * Classic pcap (libpcap) files.
 *
 * The global header is honoured rather than skipped. It carries three things
 * the previous parser ignored, each of which silently corrupted output:
 *
 *   byte order      — read as little-endian regardless, so a big-endian
 *                     capture parsed as nonsense
 *   timestamp scale — 0xa1b23c4d means nanoseconds, not microseconds, and
 *                     dividing by 1e6 put every timestamp ~1000x out
 *   link type       — Ethernet was assumed, so loopback and Linux "any"
 *                     captures were decoded at the wrong offsets
 */
import { parsePacket } from "./packet.js";

const MAGIC_MICRO_LE = 0xa1b2c3d4;
const MAGIC_MICRO_BE = 0xd4c3b2a1;
const MAGIC_NANO_LE = 0xa1b23c4d;
const MAGIC_NANO_BE = 0x4d3cb2a1;

export function isPcap(view) {
  if (view.byteLength < 24) return false;
  const m = view.getUint32(0, true);
  return m === MAGIC_MICRO_LE || m === MAGIC_MICRO_BE ||
         m === MAGIC_NANO_LE || m === MAGIC_NANO_BE;
}

export function readGlobalHeader(view) {
  const magic = view.getUint32(0, true);
  let littleEndian, nanos;

  if (magic === MAGIC_MICRO_LE) { littleEndian = true; nanos = false; }
  else if (magic === MAGIC_NANO_LE) { littleEndian = true; nanos = true; }
  else if (magic === MAGIC_MICRO_BE) { littleEndian = false; nanos = false; }
  else if (magic === MAGIC_NANO_BE) { littleEndian = false; nanos = true; }
  else throw new Error(`not a pcap file (magic 0x${magic.toString(16)})`);

  return {
    littleEndian,
    nanos,
    versionMajor: view.getUint16(4, littleEndian),
    versionMinor: view.getUint16(6, littleEndian),
    snaplen: view.getUint32(16, littleEndian),
    linktype: view.getUint32(20, littleEndian),
  };
}

export function parsePcap(buffer) {
  const view = new DataView(buffer);
  const header = readGlobalHeader(view);
  const { littleEndian, nanos, linktype } = header;
  const divisor = nanos ? 1e9 : 1e6;

  const packets = [];
  let offset = 24;
  let num = 0;
  let truncated = false;

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = view.getUint32(offset, littleEndian);
    const tsFrac = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    offset += 16;

    if (inclLen > buffer.byteLength - offset) { truncated = true; break; }

    packets.push(parsePacket(
      new Uint8Array(buffer, offset, inclLen),
      tsSec, tsFrac / divisor, num++, linktype, littleEndian,
    ));
    offset += inclLen;
  }

  return { format: "pcap", header, linktype, packets, truncated };
}
