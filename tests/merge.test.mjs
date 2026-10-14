// Run: node tests/merge.test.mjs — checks the 3-way sync merge in assets/app.js
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const src = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
const fn = src.slice(src.indexOf("function mergeState("), src.indexOf("// Pull → merge → push."));
const mergeState = new Function(fn + "return mergeState;")();

const t = (id, amt) => ({ id, kind: "expense", date: "2026-10-01", amt });
const base   = { txns: [t("a", 1), t("b", 2), t("c", 3)], budgets: { Food: 100, Fun: 50 }, adjust: 0 };
const local  = { txns: [t("a", 1), t("b", 20), t("d", 4)], budgets: { Food: 100 }, adjust: 0 };          // edit b, delete c, add d, drop Fun budget
const remote = { txns: [t("a", 10), t("b", 2), t("c", 3), t("e", 5)], budgets: { Food: 200, Fun: 50 }, adjust: 7 }; // edit a, add e, Food budget, adjust

const m = mergeState(base, local, remote);
const byId = Object.fromEntries(m.txns.map(x => [x.id, x.amt]));
assert.deepEqual(byId, { a: 10, b: 20, d: 4, e: 5 }, "edits/adds from both sides kept, local delete applied");
assert.deepEqual(m.budgets, { Food: 200 }, "budgets merge per category");
assert.equal(m.adjust, 7);

// remote delete wins over an untouched local copy; local edit beats remote delete
const m2 = mergeState({ txns: [t("x", 1), t("y", 1)] }, { txns: [t("x", 1), t("y", 9)] }, { txns: [] });
assert.deepEqual(m2.txns.map(x => x.id), ["y"]);

// nothing changed locally → result is exactly the remote copy (so sync adopts it without a push)
assert.equal(JSON.stringify(mergeState(base, base, remote)), JSON.stringify(remote));

// first sync (no base): older copy acts as base → same as old last-write-wins
assert.deepEqual(mergeState(local, local, remote), remote);
assert.deepEqual(mergeState(remote, local, remote), local);

console.log("merge ok");
