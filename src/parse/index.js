/** Pick a parser from the file's own magic rather than its extension. */
import { isPcap, parsePcap } from "./pcap.js";
import { isPcapng, parsePcapng } from "./pcapng.js";
import { LINKTYPE_NAMES } from "./linktype.js";

export { LINKTYPE_NAMES };

export function parseCapture(buffer) {
  const view = new DataView(buffer);
  if (isPcapng(view)) return parsePcapng(buffer);
  if (isPcap(view)) return parsePcap(buffer);
  throw new Error(
    "Unrecognised file. Expected pcap or pcapng — the first bytes match neither.",
  );
}
