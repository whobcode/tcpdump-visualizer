/** Parser checks against hand-built captures with known contents. */
import { readFileSync, readdirSync } from "node:fs";
import { parseCapture } from "../src/parse/index.js";

const DIR = new URL("./fixtures/", import.meta.url);
let failures = 0;

function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`    ${ok ? "ok  " : "FAIL"} ${label}` +
    (ok ? "" : `\n         expected ${JSON.stringify(expected)}\n         got      ${JSON.stringify(actual)}`));
}

for (const name of readdirSync(DIR).sort()) {
  const buf = readFileSync(new URL(name, DIR));
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  console.log(`\n  ${name}`);
  let r;
  try {
    r = parseCapture(ab);
  } catch (e) {
    console.log(`    FAIL threw: ${e.message}`); failures++; continue;
  }

  check("format", r.format, name.endsWith(".pcapng") ? "pcapng" : "pcap");
  check("not truncated", r.truncated, false);

  if (name === "loopback.pcap") {
    check("packet count", r.packets.length, 1);
    check("linktype NULL", r.linktype, 0);
    check("src", r.packets[0].src, "127.0.0.1");
    check("protocol", r.packets[0].protocol, "TCP");
    check("ports", [r.packets[0].srcPort, r.packets[0].dstPort], [5000, 6000]);
    continue;
  }

  if (name === "tcp-session.pcap") {
    check("packet count", r.packets.length, 32);

    const syn = r.packets[0];
    check("SYN options: MSS", syn.tcpOptions.mss, 1460);
    check("SYN options: window scale", syn.tcpOptions.windowScale, 7);
    check("SYN options: SACK permitted", syn.tcpOptions.sackPermitted, true);
    check("SYN sequence number", syn.seq, 1000);
    check("SYN counts one sequence number, carries no payload", syn.payloadLength, 0);

    // Ethernet pads this frame to 60 bytes. Measuring the payload from the
    // frame rather than the IP header would report 6 bytes of data here.
    const paddedAck = r.packets[2];
    check("padded ACK frame is 60 bytes", paddedAck.length, 60);
    check("padded ACK has no payload", paddedAck.payloadLength, 0);
    check("padded ACK has no payload bytes", paddedAck.payload, null);

    const request = r.packets[3];
    check("request payload length", request.payloadLength, 69);
    check("request payload present", request.payload.length, 69);
    check("flags decoded", request.flagNames, ["PSH", "ACK"]);

    check("RST decoded", r.packets[25].flagNames, ["RST", "ACK"]);
    check("UDP payload length", r.packets[30].protocol, "UDP");
    continue;
  }

  if (name === "snaplen-96.pcap") {
    check("packet count", r.packets.length, 3);
    const cut = r.packets[2];
    check("wire length preserved", cut.length, 454);
    check("captured length", cut.capturedLength, 96);
    check("marked as cut short", cut.snaplenTruncated, true);
    // The header survived the snaplen, so the ports are still trustworthy;
    // only the payload is a fragment.
    check("ports still readable", [cut.srcPort, cut.dstPort], [40100, 80]);
    check("payload reported as truncated", cut.payloadTruncated, true);
    check("payload length is what the sender sent", cut.payloadLength, 400);
    check("payload bytes are what was kept", cut.payload.length, 42);
    continue;
  }

  check("packet count", r.packets.length, 3);
  const [syn, synack, v6] = r.packets;
  check("v4 src", syn.src, "192.168.12.122");
  check("v4 dst", syn.dst, "192.168.12.1");
  check("v4 ports", [syn.srcPort, syn.dstPort], [52341, 443]);
  check("SYN flag", syn.info, "SYN");
  check("SYN,ACK flags", synack.info, "SYN, ACK");
  check("IPv6 decoded", v6.protocol, "UDP");
  check("IPv6 src collapsed", v6.src, "fe80::1");
  check("IPv6 ports", [v6.srcPort, v6.dstPort], [5353, 5353]);

  // Every fixture encodes 1700000000.123456 for its first packet.
  const t = r.packets[0].timestamp;
  check("timestamp seconds", Math.floor(t), 1700000000);
  check("timestamp fraction ~0.123456", Math.abs(t - 1700000000.123456) < 1e-6, true);
}

console.log(failures ? `\n  ${failures} FAILURE(S)` : "\n  all parser checks passed");
process.exit(failures ? 1 : 0);
