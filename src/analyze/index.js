/**
 * One pass over a parsed capture, producing everything the page shows.
 *
 * Order matters: TCP tracking has to run before application identification,
 * because a payload is attributed to a stream, and findings run last because
 * they read both.
 */
import { buildConversations, buildEndpoints, buildTimeline } from "./flows.js";
import { analyzeTcpStreams, followStream, reassemble, EVENT } from "./tcp.js";
import { annotateApplication } from "./appproto.js";
import { buildFindings } from "./expert.js";

export { followStream, reassemble, EVENT };
export { labelPort, serviceName } from "./services.js";

function buildSummary(capture, packets, conversations, streams, timeline) {
  const timed = packets.filter((p) => p.timestamp > 0);
  const start = timed.length ? Math.min(...timed.map((p) => p.timestamp)) : 0;
  const end = timed.length ? Math.max(...timed.map((p) => p.timestamp)) : 0;
  const bytes = packets.reduce((t, p) => t + p.length, 0);
  const duration = end - start;

  const protocols = {};
  for (const p of packets) {
    const e = protocols[p.protocol] || (protocols[p.protocol] = { packets: 0, bytes: 0 });
    e.packets++;
    e.bytes += p.length;
  }

  const hosts = new Set();
  for (const p of packets) {
    if (p.src) hosts.add(p.src);
    if (p.dst) hosts.add(p.dst);
  }

  const rtts = streams.map((s) => s.handshakeRtt).filter((v) => v != null).sort((a, b) => a - b);

  return {
    format: capture.format,
    linktype: capture.linktype,
    packets: packets.length,
    bytes,
    start, end, duration,
    // Average over the capture's own span, which is the only rate that means
    // anything when a capture covers a few seconds or several hours.
    averageBitrate: duration > 0 ? (bytes * 8) / duration : null,
    peakBitrate: timeline.buckets.length
      ? Math.max(...timeline.buckets.map((b) => b.bitsPerSecond))
      : null,
    protocols,
    hosts: hosts.size,
    conversations: conversations.length,
    tcpStreams: streams.length,
    completedStreams: streams.filter((s) => s.synAck !== null).length,
    failedStreams: streams.filter((s) => s.failed).length,
    resetStreams: streams.filter((s) => s.state === "reset").length,
    medianHandshakeRtt: rtts.length ? rtts[Math.floor(rtts.length / 2)] : null,
    truncated: Boolean(capture.truncated),
    snaplenTruncated: packets.some((p) => p.snaplenTruncated),
  };
}

export function analyze(capture) {
  const packets = capture.packets;
  const streams = analyzeTcpStreams(packets);
  annotateApplication(packets, streams);
  const conversations = buildConversations(packets);
  const endpoints = buildEndpoints(packets);
  const timeline = buildTimeline(packets);
  const findings = buildFindings(capture, packets, streams, conversations);
  const summary = buildSummary(capture, packets, conversations, streams, timeline);

  return { packets, streams, conversations, endpoints, timeline, findings, summary };
}
