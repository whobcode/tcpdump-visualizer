/**
 * Build the deployable site into public/.
 *
 * Bundles the client entry with its parser modules, copies the page and
 * stylesheet, and vendors Chart.js. Vendoring is deliberate: the page loaded
 * Chart.js from a CDN, so with no network to that host it rendered the whole
 * dashboard minus every chart, silently.
 */
import { build } from "esbuild";
import { mkdir, copyFile, rm, access } from "node:fs/promises";

const OUT = "public";
// The UMD build is not listed in chart.js's exports map, so require.resolve
// refuses it (ERR_PACKAGE_PATH_NOT_EXPORTED). The file is real; reach it by
// path and fail loudly if a future version moves it.
const CHART_UMD = "node_modules/chart.js/dist/chart.umd.min.js";

await rm(OUT, { recursive: true, force: true });
await mkdir(`${OUT}/vendor`, { recursive: true });

await build({
  entryPoints: ["src/app.js"],
  bundle: true,
  format: "esm",
  target: "es2022",
  outfile: `${OUT}/app.js`,
  minify: process.env.NODE_ENV === "production",
  sourcemap: process.env.NODE_ENV !== "production",
  logLevel: "info",
});

await copyFile("src/index.html", `${OUT}/index.html`);
await copyFile("src/styles.css", `${OUT}/styles.css`);

// Chart.js ships a prebuilt UMD file; copy it rather than bundling, since the
// page loads it as a classic script that defines a global.
try {
  await access(CHART_UMD);
} catch {
  throw new Error(`${CHART_UMD} not found — run npm install, or update the path ` +
                  "if chart.js moved its UMD build");
}
await copyFile(CHART_UMD, `${OUT}/vendor/chart.umd.min.js`);

await access(`${OUT}/index.html`);
console.log("built -> public/");
