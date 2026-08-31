/** Display helpers. Nothing here decides anything; it only renders. */

export function bytes(n) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function bits(n) {
  if (n == null) return "—";
  if (n < 1000) return `${Math.round(n)} bps`;
  const units = ["kbps", "Mbps", "Gbps"];
  let v = n / 1000, i = 0;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

/** Durations span microseconds to hours here, so the unit follows the value. */
export function duration(s) {
  if (s == null) return "—";
  if (s < 0.001) return `${(s * 1e6).toFixed(0)} µs`;
  if (s < 1) return `${(s * 1000).toFixed(s < 0.01 ? 2 : 1)} ms`;
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 1)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.round(s % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function ms(s) {
  return s == null ? "—" : `${(s * 1000).toFixed(s < 0.01 ? 2 : 1)} ms`;
}

export function count(n) {
  return n == null ? "—" : n.toLocaleString();
}

export function clockTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export function endpoint(ip, port) {
  if (port === "" || port == null) return ip;
  // Bracket v6 so the port is unmistakably a port and not another group.
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

const PRINTABLE = (b) => (b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x09;

/** Payload as text, with unprintable bytes shown as a dot rather than dropped. */
export function asText(bytesArray, limit = 65536) {
  const n = Math.min(bytesArray.length, limit);
  let out = "";
  for (let i = 0; i < n; i++) {
    const b = bytesArray[i];
    out += b === 0x0d ? "" : PRINTABLE(b) ? String.fromCharCode(b) : "·";
  }
  return out;
}

/** Classic hex + ASCII dump, 16 bytes to a line. */
export function asHex(bytesArray, limit = 16384, baseOffset = 0) {
  const n = Math.min(bytesArray.length, limit);
  const lines = [];
  for (let o = 0; o < n; o += 16) {
    const row = bytesArray.subarray(o, Math.min(o + 16, n));
    let hex = "";
    for (let i = 0; i < 16; i++) {
      hex += i < row.length ? row[i].toString(16).padStart(2, "0") : "  ";
      hex += i === 7 ? "  " : " ";
    }
    let text = "";
    for (const b of row) text += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ".";
    lines.push(`${(baseOffset + o).toString(16).padStart(8, "0")}  ${hex} |${text}|`);
  }
  return lines.join("\n");
}

/** A share, shown with enough precision to be actionable at small values. */
export function percent(part, whole) {
  if (!whole) return "0%";
  const v = (part / whole) * 100;
  if (v === 0) return "0%";
  if (v < 0.1) return "<0.1%";
  return `${v.toFixed(v < 10 ? 1 : 0)}%`;
}
