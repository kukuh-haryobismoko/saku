// Run: node tests/b64.test.mjs — b64 in assets/app.js must handle a large vault (sync broke at ~125 KB)
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const src = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
const line = src.split("\n").find(l => l.startsWith("const b64 ="));
const b64 = new Function(line + "return b64;")();

const bytes = new Uint8Array(2_000_000).map((_, i) => i * 7);
assert.equal(b64(bytes), Buffer.from(bytes).toString("base64"));
console.log("b64 ok");
