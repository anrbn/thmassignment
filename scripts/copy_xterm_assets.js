const fs = require("node:fs");
const path = require("node:path");

const rootDir = path.resolve(__dirname, "..");
const vendorDir = path.join(rootDir, "vendor", "xterm");

const assets = [
  {
    source: path.join(rootDir, "node_modules", "@xterm", "xterm", "lib", "xterm.js"),
    target: path.join(vendorDir, "xterm.js")
  },
  {
    source: path.join(rootDir, "node_modules", "@xterm", "xterm", "css", "xterm.css"),
    target: path.join(vendorDir, "xterm.css")
  },
  {
    source: path.join(rootDir, "node_modules", "@xterm", "addon-fit", "lib", "addon-fit.js"),
    target: path.join(vendorDir, "addon-fit.js")
  }
];

fs.mkdirSync(vendorDir, { recursive: true });

for (const asset of assets) {
  if (!fs.existsSync(asset.source)) {
    throw new Error("Missing dependency asset: " + path.relative(rootDir, asset.source));
  }

  fs.copyFileSync(asset.source, asset.target);
}

console.log("Copied xterm browser assets to vendor/xterm.");
