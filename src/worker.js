/**
 * tcpdump-visualizer.
 *
 * The Worker only serves the page. Capture files are parsed entirely in the
 * browser and never uploaded — a pcap contains every address, port and payload
 * byte the machine saw, so keeping it on the machine is the point, not an
 * optimisation.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Static assets are bound by wrangler; anything it does not have is a 404.
    if (env.ASSETS) return env.ASSETS.fetch(request);

    return new Response("Not Found", { status: 404 });
  },
};
