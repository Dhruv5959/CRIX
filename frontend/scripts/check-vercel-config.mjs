import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const frontendDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const importConfig = "import('./vercel.mjs').then(({ config }) => process.stdout.write(JSON.stringify(config)))";

function loadConfig(backendUrl) {
  const env = { ...process.env };
  if (backendUrl === undefined) {
    delete env.CRIX_BACKEND_URL;
  } else {
    env.CRIX_BACKEND_URL = backendUrl;
  }
  return spawnSync(process.execPath, ["--input-type=module", "--eval", importConfig], {
    cwd: frontendDir,
    env,
    encoding: "utf8",
  });
}

const valid = loadConfig("https://api.example.invalid/");
assert.equal(valid.status, 0, valid.stderr);
const config = JSON.parse(valid.stdout);
assert.deepEqual(config.rewrites, [
  { source: "/api/:path*", destination: "https://api.example.invalid/api/:path*" },
  { source: "/(.*)", destination: "/index.html" },
]);

for (const invalid of [undefined, "http://api.example.invalid", "https://api.example.invalid/api"]) {
  const result = loadConfig(invalid);
  assert.notEqual(result.status, 0, `Expected ${String(invalid)} to fail configuration validation.`);
  assert.match(result.stderr, /CRIX_BACKEND_URL/);
}

console.log("Vercel rewrite configuration is valid and rejects unsafe backend URLs.");
