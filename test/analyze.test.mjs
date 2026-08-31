/**
 * Analyser checks against a capture built to contain exactly one of each
 * condition.
 *
 * The point of a hand-built fixture is that "packet 11 is a fast
 * retransmission" is a fact about the file rather than a judgement about the
 * network: the generator put the missing bytes there, after three duplicate
 * ACKs, on purpose. Asserting against a real capture would mean grading the
 * analyser against its own guesswork.
 */
import { readFileSync } from "node:fs";
import { parseCapture } from "../src/parse/index.js";
import { analyze, followStream, EVENT } from "../src/analyze/index.js";

let failures = 0;

function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`    ${ok ? "ok  " : "FAIL"} ${label}` +
    (ok ? "" : `\n         expected ${JSON.stringify(expected)}\n         got      ${JSON.stringify(actual)}`));
}

function load(name) {
  const buf = readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  return analyze(parseCapture(ab));
}

/* ---------------------------------------------------------------- streams */

console.log("\n  tcp-session.pcap — connections");
const r = load("tcp-session.pcap");

check("four connections found", r.streams.length, 4);

const [session, refused, unanswered, tls] = r.streams;

check("client is the side that sent the SYN", session.a.port, 40000);
check("server is the side that answered", session.b.port, 80);
check("connection closed cleanly", session.state, "closed");
check("no failure recorded", session.failed, null);
check("handshake completed", session.synAck !== null, true);
check("window scaling negotiated both ways", session.windowScalingInUse, true);
check("handshake RTT measured", Math.abs(session.handshakeRtt - 0.001) < 1e-6, true);

check("refused connection state", refused.state, "reset");
check("refused connection reason", refused.failed, "refused");
check("unanswered connection state", unanswered.state, "unanswered");
check("unanswered connection reason", unanswered.failed, "no response");

/* ----------------------------------------------------------------- events */

console.log("\n  tcp-session.pcap — what the analyser flagged");

const eventsFor = (type) =>
  r.streams.flatMap((s) => s.events.filter((e) => e.type === type).map((e) => e.num));

check("segment missing from the capture", eventsFor(EVENT.LOST_SEGMENT), [6, 18]);
check("three duplicate ACKs, in order", eventsFor(EVENT.DUP_ACK), [8, 9, 10]);
check("fast retransmission follows them", eventsFor(EVENT.FAST_RETRANSMISSION), [11]);
check("plain retransmission (exact repeat)", eventsFor(EVENT.RETRANSMISSION), [14]);
check("nothing called spurious", eventsFor(EVENT.SPURIOUS_RETRANSMISSION), []);
check("zero window", eventsFor(EVENT.ZERO_WINDOW), [15]);
check("window update follows it", eventsFor(EVENT.WINDOW_UPDATE), [16]);
check("late segment is reordering, not loss", eventsFor(EVENT.OUT_OF_ORDER), [19]);
check("reset", eventsFor(EVENT.RESET), [25]);

// The duplicate ACKs are numbered from the first repeat, not the baseline ACK.
check("duplicate ACKs are numbered",
  session.events.filter((e) => e.type === EVENT.DUP_ACK).map((e) => e.detail),
  ["#1", "#2", "#3"]);

check("retransmitted bytes counted once", session.retransmittedBytes, 40);

/* ------------------------------------------------------ relative sequence */

console.log("\n  tcp-session.pcap — sequence numbers and windows");

const request = r.packets[3];
check("sequence shown relative to the ISN", request.tcp.relSeq, 1);
check("ack shown relative to the peer's ISN", request.tcp.relAck, 1);
check("payload length", request.tcp.segLen, 69);

// The client advertised 1024 with a scale factor of 7 negotiated in the
// handshake; the number that matters is 131072, not 1024.
check("window scaled by the negotiated factor", request.tcp.scaledWindow, 1024 * 128);
check("window marked as scaled", request.tcp.scaled, true);
// ...but never on the SYN that offered the scaling.
check("SYN window is not scaled", r.packets[0].tcp.scaled, false);

/* -------------------------------------------------- application protocols */

console.log("\n  tcp-session.pcap — application protocols");

check("HTTP request identified", r.packets[3].app.protocol, "HTTP");
check("HTTP method", r.packets[3].app.method, "GET");
check("Host header read", r.packets[3].app.host, "example.test");
check("HTTP response identified", r.packets[5].app.kind, "response");
check("HTTP status", r.packets[5].app.status, 200);

check("TLS ClientHello identified", r.packets[29].app.kind, "ClientHello");
check("SNI extracted", r.packets[29].app.sni, "api.example.test");
check("ALPN extracted", r.packets[29].app.alpn, ["http/1.1"]);
check("SNI attached to the stream", tls.sni, "api.example.test");

check("DNS query name", r.packets[30].app.question, "api.example.test");
check("DNS query type", r.packets[30].app.qtype, "A");
check("DNS response recognised", r.packets[31].app.isResponse, true);
check("DNS response code", r.packets[31].app.rcodeName, "NOERROR");

/* ------------------------------------------------------------ reassembly */

console.log("\n  tcp-session.pcap — stream reassembly");

const followed = followStream(session);
const text = new TextDecoder().decode(followed.aToB.bytes);
check("client bytes reassembled", text.startsWith("GET /index.html HTTP/1.1"), true);
check("client direction has no gaps", followed.aToB.gaps.length, 0);

const server = new TextDecoder().decode(followed.bToA.bytes);
check("server response head reassembled", server.startsWith("HTTP/1.1 200 OK"), true);
// The capture never held the 20 bytes that packet 6 skipped past, and the
// fast retransmission at packet 11 supplied them — so the stream is whole.
check("gap filled by the retransmission", followed.bToA.gaps.length, 0);
check("out-of-order segment placed by sequence, not arrival",
  server.includes("EEEEEEEEEEEEEEEEEEEE" + "FFFFFFFFFFFFFFFFFFFF"), true);
check("retransmitted bytes are not duplicated in the stream",
  (server.match(/C{20}/g) || []).length, 1);

/* -------------------------------------------------------- conversations */

console.log("\n  tcp-session.pcap — conversations and endpoints");

const http = r.conversations.find((c) => c.protocol === "TCP" && c.serverPort === 80);
check("conversation is bidirectional", http.packetsAB > 0 && http.packetsBA > 0, true);
check("conversation names the service", http.service, "http");
check("both directions counted separately",
  http.packets, http.packetsAB + http.packetsBA);

const client = r.endpoints.find((e) => e.ip === "10.0.0.1");
check("endpoint sees every peer", client.peerCount, 1);

/* ------------------------------------------------------------- findings */

console.log("\n  tcp-session.pcap — findings");

const titles = r.findings.map((f) => f.title);
const has = (fragment) => titles.some((t) => t.includes(fragment));
check("retransmissions reported", has("retransmissions"), true);
check("zero window reported", has("zero-window"), true);
check("refused connection reported", has("connection refused"), true);
check("unanswered connection reported", has("got no reply"), true);
check("cleartext HTTP reported", has("HTTP in use, unencrypted"), true);
check("findings are ranked, errors first", r.findings[0].severity, "error");
check("every finding names its packets",
  r.findings.every((f) => Array.isArray(f.packets)), true);

/* --------------------------------------------------------------- snaplen */

console.log("\n  snaplen-96.pcap");
const s = load("snaplen-96.pcap");
const snapFinding = s.findings.find((f) => f.title.includes("snaplen"));
check("snaplen truncation reported", Boolean(snapFinding), true);
check("reported as a warning, not an error", snapFinding.severity, "warning");
check("summary records it", s.summary.snaplenTruncated, true);

// A payload the capture only partly holds must leave a hole rather than a
// plausible-looking short body.
const snapped = followStream(s.streams[0]);
check("reassembly leaves the missing bytes as a gap", snapped.aToB.gaps.length, 1);
check("gap covers what the snaplen removed", snapped.aToB.gaps[0], [42, 400]);

/* ------------------------------------------------------- empty and edges */

// A handshake and nothing else is a perfectly healthy capture. An analyser
// that manufactures findings from it would make the Findings tab worthless on
// the captures where it matters.
console.log("\n  captures with nothing wrong in them");
const plain = load("classic-le-micro.pcap");
check("SYN and SYN-ACK are one connection, not two", plain.streams.length, 1);
check("handshake without data reads as open", plain.streams[0].state, "open");
check("nothing invented: no errors", plain.findings.filter((f) => f.severity === "error").length, 0);
// The fixture spaces its packets a second apart, so the one thing flagged is
// a real 1-second handshake — not a false positive.
check("the one warning is the handshake latency, which is real",
  plain.findings.map((f) => f.severity + ": " + f.title),
  ["warning: 1 connection took over 200 ms to complete the handshake"]);
check("the UDP packet still shows up as a conversation",
  plain.conversations.some((c) => c.protocol === "UDP"), true);
check("following an empty stream is safe", followStream(plain.streams[0]).chunks.length, 0);

console.log(failures ? `\n  ${failures} FAILURE(S)` : "\n  all analyser checks passed");
process.exit(failures ? 1 : 0);
