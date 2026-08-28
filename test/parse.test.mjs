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

console.log(failures ? `\n  ${failures} FAILURE(S)` : "\n  all checks passed");
process.exit(failures ? 1 : 0);
