/**
 * Application-layer identification, from the payload rather than the port.
 *
 * The port is a hint, not an answer — plenty of real traffic runs HTTP on 8080
 * and plenty of tunnels run something else on 443. More to the point, a
 * conversation labelled "TCP 443" tells you nothing you did not already know,
 * while "TLS ClientHello, SNI=api.stripe.com" tells you what the machine was
 * actually talking to. That name is in the clear in every TLS handshake, and
 * on an encrypted capture it is usually the only useful thing in the stream.
 */

const ascii = (bytes, start, len) => {
  let out = "";
  for (let i = start; i < start + len && i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
};

const u16 = (b, o) => (b[o] << 8) | b[o + 1];

const HTTP_METHODS = [
  "GET ", "POST ", "PUT ", "HEAD ", "DELE", "OPTI", "PATC", "TRAC", "CONN",
];

const TLS_VERSIONS = {
  0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
};

/** DNS names are label-length-prefixed, and may jump backwards via a pointer. */
function dnsName(b, offset, end) {
  const labels = [];
  let o = offset;
  let jumps = 0;
  while (o < end && jumps < 8) {
    const len = b[o];
    if (len === 0) { o++; break; }
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= end) break;
      const target = ((len & 0x3f) << 8) | b[o + 1];
      o = target;
      jumps++;
      continue;
    }
    if (o + 1 + len > end) break;
    labels.push(ascii(b, o + 1, len));
    o += 1 + len;
  }
  return { name: labels.join(".") || ".", next: o };
}

const DNS_TYPES = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
  28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 65: "HTTPS",
  255: "ANY",
};

const DNS_RCODES = {
  0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
  4: "NOTIMP", 5: "REFUSED",
};

export function parseDns(b) {
  if (!b || b.length < 12) return null;
  const flags = u16(b, 2);
  const qdcount = u16(b, 4);
  const ancount = u16(b, 6);
  const isResponse = Boolean(flags & 0x8000);
  const rcode = flags & 0x0f;

  let question = null, qtype = null;
  if (qdcount > 0) {
    const { name, next } = dnsName(b, 12, b.length);
    question = name;
    if (next + 2 <= b.length) qtype = DNS_TYPES[u16(b, next)] || `TYPE${u16(b, next)}`;
  }

  return {
    id: u16(b, 0),
    isResponse,
    rcode,
    rcodeName: DNS_RCODES[rcode] || `RCODE${rcode}`,
    question,
    qtype,
    answers: ancount,
    summary: isResponse
      ? `Response ${question || "?"} ${qtype || ""} → ${DNS_RCODES[rcode] || rcode}, ${ancount} answer${ancount === 1 ? "" : "s"}`
      : `Query ${question || "?"} ${qtype || ""}`.trim(),
  };
}

/** ClientHello extensions: 0 is SNI, 16 is ALPN, 43 is supported_versions. */
function tlsHelloExtensions(b, o, end) {
  const out = { sni: null, alpn: [], versions: [] };
  while (o + 4 <= end) {
    const type = u16(b, o);
    const len = u16(b, o + 2);
    const body = o + 4;
    if (body + len > end) break;

    if (type === 0 && len >= 5) {
      // server_name: list length, then entries of type(1) + length(2) + host
      let p = body + 2;
      while (p + 3 <= body + len) {
        const nameType = b[p];
        const nameLen = u16(b, p + 1);
        if (nameType === 0 && p + 3 + nameLen <= body + len) {
          out.sni = ascii(b, p + 3, nameLen);
          break;
        }
        p += 3 + nameLen;
      }
    } else if (type === 16 && len >= 2) {
      let p = body + 2;
      while (p < body + len) {
        const n = b[p];
        if (p + 1 + n > body + len) break;
        out.alpn.push(ascii(b, p + 1, n));
        p += 1 + n;
      }
    } else if (type === 43 && len >= 1) {
      const listLen = b[body];
      for (let p = body + 1; p + 1 < body + 1 + listLen && p + 1 < end; p += 2) {
        const v = TLS_VERSIONS[u16(b, p)];
        if (v) out.versions.push(v);
      }
    }
    o = body + len;
  }
  return out;
}

export function parseTls(b) {
  if (!b || b.length < 5) return null;
  const type = b[0];
  if (b[1] !== 0x03) return null; // every real TLS/SSL3 record starts 0x03xx
  const recordVersion = u16(b, 1);
  const recordLen = u16(b, 3);

  if (type === 0x16 && b.length >= 6) {
    const hs = b[5];
    if (hs === 0x01) {
      // ClientHello: 4-byte handshake header, version, 32-byte random,
      // session id, cipher suites, compression, then extensions.
      let o = 5 + 4;
      const clientVersion = TLS_VERSIONS[u16(b, o)] || null;
      o += 2 + 32;
      if (o >= b.length) return { kind: "ClientHello", summary: "TLS ClientHello (truncated)" };
      o += 1 + b[o];                       // session id
      if (o + 2 > b.length) return { kind: "ClientHello", summary: "TLS ClientHello (truncated)" };
      o += 2 + u16(b, o);                  // cipher suites
      if (o >= b.length) return { kind: "ClientHello", summary: "TLS ClientHello (truncated)" };
      o += 1 + b[o];                       // compression methods
      let ext = { sni: null, alpn: [], versions: [] };
      if (o + 2 <= b.length) ext = tlsHelloExtensions(b, o + 2, Math.min(b.length, o + 2 + u16(b, o)));
      const version = ext.versions[0] || clientVersion;
      return {
        kind: "ClientHello", sni: ext.sni, alpn: ext.alpn, version,
        summary: `TLS ClientHello${ext.sni ? ` SNI=${ext.sni}` : ""}` +
                 `${ext.alpn.length ? ` ALPN=${ext.alpn.join(",")}` : ""}`,
      };
    }
    if (hs === 0x02) return { kind: "ServerHello", summary: "TLS ServerHello" };
    if (hs === 0x0b) return { kind: "Certificate", summary: "TLS Certificate" };
    return { kind: "Handshake", summary: "TLS handshake" };
  }
  if (type === 0x15) return { kind: "Alert", summary: "TLS Alert" };
  if (type === 0x17) {
    return {
      kind: "ApplicationData",
      summary: `TLS application data, ${recordLen} bytes` +
               `${TLS_VERSIONS[recordVersion] ? ` (${TLS_VERSIONS[recordVersion]})` : ""}`,
    };
  }
  return null;
}

export function parseHttp(b) {
  if (!b || b.length < 16) return null;
  const head = ascii(b, 0, Math.min(b.length, 2048));

  if (head.startsWith("HTTP/1.")) {
    const line = head.split("\r\n", 1)[0];
    return { kind: "response", status: Number(line.split(" ")[1]) || null, summary: line.slice(0, 120) };
  }
  if (!HTTP_METHODS.some((m) => head.startsWith(m))) return null;
  const lines = head.split("\r\n");
  if (!/ HTTP\/1\.[01]$/.test(lines[0])) return null;
  const host = lines.slice(1).find((l) => /^host:/i.test(l));
  const [method, path] = lines[0].split(" ");
  return {
    kind: "request", method, path,
    host: host ? host.slice(5).trim() : null,
    summary: `${method} ${host ? host.slice(5).trim() : ""}${path}`.slice(0, 160),
  };
}

/**
 * Identify a payload. `hint` carries the ports, used only to break ties —
 * never to decide on its own.
 */
export function identify(payload, { srcPort, dstPort } = {}) {
  if (!payload || !payload.length) return null;

  const tls = parseTls(payload);
  if (tls) return { protocol: "TLS", ...tls };

  const http = parseHttp(payload);
  if (http) return { protocol: "HTTP", ...http };

  if (payload.length >= 4 && ascii(payload, 0, 4) === "SSH-") {
    return { protocol: "SSH", summary: ascii(payload, 0, Math.min(payload.length, 60)).trim() };
  }

  if (srcPort === 53 || dstPort === 53 || srcPort === 5353 || dstPort === 5353) {
    const dns = parseDns(payload);
    if (dns) return { protocol: srcPort === 5353 || dstPort === 5353 ? "mDNS" : "DNS", ...dns };
  }

  return null;
}

/**
 * Annotate packets in place with whatever their payload identifies as, and
 * hand back the per-stream picture (a stream's protocol is whatever its first
 * identified packet said).
 */
export function annotateApplication(packets, streams) {
  const byStream = new Map();

  for (const p of packets) {
    if (!p.payload || !p.payload.length) continue;
    if (p.protocol !== "TCP" && p.protocol !== "UDP") continue;
    const app = identify(p.payload, { srcPort: p.srcPort, dstPort: p.dstPort });
    if (!app) continue;
    p.app = app;
    const id = p.tcp ? p.tcp.streamId : null;
    if (id != null && !byStream.has(id)) byStream.set(id, app);
  }

  for (const s of streams) {
    const app = byStream.get(s.id);
    if (app) {
      s.appProtocol = app.protocol;
      s.appSummary = app.summary;
      if (app.sni) s.sni = app.sni;
      if (app.host) s.host = app.host;
    }
  }
  return byStream;
}
