import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { routes, validateStaticFields } from "@vercel/config/v1";

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
validateStaticFields(config);
assert.deepEqual(config.rewrites, [
  routes.rewrite("/api/:path*", "https://api.example.invalid/api/:path*"),
  routes.rewrite("/(.*)", "/index.html"),
]);
for (const rewrite of config.rewrites) {
  assert.equal(typeof rewrite.source, "string");
  assert.equal(typeof rewrite.destination, "string");
  assert.notEqual(rewrite.destination.trim(), "");
}

for (const invalid of [
  undefined,
  "http://api.example.invalid",
  "https://api.example.invalid/api",
  "https://user:pass@api.example.invalid",
  "https://api.example.invalid?mode=test",
  "https://api.example.invalid#api",
]) {
  const result = loadConfig(invalid);
  assert.notEqual(result.status, 0, `Expected ${String(invalid)} to fail configuration validation.`);
  assert.match(result.stderr, /CRIX_BACKEND_URL/);
}

assert.match(loadConfig(undefined).stderr, /CRIX_BACKEND_URL is required/);
console.log("Vercel's exported config contains valid rewrite destinations and rejects unsafe backend URLs.");
