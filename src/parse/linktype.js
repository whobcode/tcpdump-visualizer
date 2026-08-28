/**
 * Link-layer types, and how many bytes precede the network-layer header.
 *
 * The previous parser assumed Ethernet unconditionally. A loopback capture
 * (`tcpdump -i lo0`) or a Linux `-i any` capture has a different header length,
 * so every subsequent field was read at the wrong offset and produced
 * confident nonsense rather than an error.
 *
 * Values are from the pcap LINKTYPE registry.
 */
export const LINKTYPE = {
  NULL: 0,          // BSD loopback: 4-byte host-endian address family
  ETHERNET: 1,
  RAW: 101,         // raw IP, no link header
  LOOP: 108,        // OpenBSD loopback: 4-byte network-endian AF
  LINUX_SLL: 113,   // Linux "any" device: 16-byte cooked header
  LINUX_SLL2: 276,  // 20-byte cooked header v2
};

export const LINKTYPE_NAMES = {
  0: "Loopback (NULL)",
  1: "Ethernet",
  101: "Raw IP",
  108: "Loopback (LOOP)",
  113: "Linux cooked v1",
  276: "Linux cooked v2",
};

/**
 * Decode the link layer.
 *
 * Returns { offset, ethertype } where offset is where the network-layer header
 * begins, or null when the link type is not one we can walk.
 */
export function decodeLink(data, linktype, littleEndian = true) {
  switch (linktype) {
    case LINKTYPE.ETHERNET: {
      if (data.length < 14) return null;
      let offset = 14;
      let ethertype = (data[12] << 8) | data[13];
      // 802.1Q and QinQ carry the real ethertype after the VLAN tag.
      while ((ethertype === 0x8100 || ethertype === 0x88a8) && data.length >= offset + 4) {
        ethertype = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
      }
      return { offset, ethertype };
    }

    case LINKTYPE.NULL:
    case LINKTYPE.LOOP: {
      if (data.length < 4) return null;
      // NULL is host byte order, LOOP is always network order.
      const af = linktype === LINKTYPE.NULL && littleEndian
        ? data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
        : (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
      // AF_INET is 2 everywhere; AF_INET6 is 30 on macOS/BSD, 10 on Linux,
      // 24 on some others, and all three appear in captures in the wild.
      const ethertype = af === 2 ? 0x0800
        : (af === 30 || af === 28 || af === 24 || af === 10) ? 0x86dd
        : 0;
      return { offset: 4, ethertype };
    }

    case LINKTYPE.RAW: {
      if (data.length < 1) return null;
      const version = data[0] >> 4;
      return { offset: 0, ethertype: version === 6 ? 0x86dd : 0x0800 };
    }

    case LINKTYPE.LINUX_SLL: {
      if (data.length < 16) return null;
      return { offset: 16, ethertype: (data[14] << 8) | data[15] };
    }

    case LINKTYPE.LINUX_SLL2: {
      if (data.length < 20) return null;
      return { offset: 20, ethertype: (data[0] << 8) | data[1] };
    }

    default:
      return null;
  }
}
