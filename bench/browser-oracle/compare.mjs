#!/usr/bin/env node
// Compares oracle result files with crawlx `revalidate` verdicts.
// Refuses to merge files produced by different drivers.
//
// Usage: node compare.mjs --oracle results/g27.reference.json [--oracle more.json] --crawlx out/revalidate.g27.json
// crawlx file shape: { "verdicts": { "<control id>": "actionable" | "not_actionable" } }

import { readFileSync } from "node:fs";

function parseArgs(argv) {
  const out = { oracle: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--oracle") out.oracle.push(argv[++i]);
    else if (argv[i] === "--crawlx") out.crawlx = argv[++i];
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  return out;
}

export function merge(reports) {
  const drivers = new Set(reports.map((r) => `${r.driver}@${r.driver_version}`));
  if (drivers.size > 1) throw new Error(`refusing to merge results from different drivers: ${[...drivers].join(", ")}`);
  const byId = new Map();
  for (const r of reports) for (const x of r.results) byId.set(x.id, x);
  return { driver: reports[0]?.driver ?? null, driver_version: reports[0]?.driver_version ?? null, results: byId };
}

export function compare(oracle, crawlxVerdicts) {
  const falseActionable = [];
  const falseNonActionable = [];
  const gaps = [];
  for (const [id, o] of oracle.results) {
    const c = crawlxVerdicts[id];
    if (!c) continue;
    if (o.verdict === "oracle_gap") gaps.push(id);
    else if (c === "actionable" && o.verdict === "not_actionable") falseActionable.push({ id, reason: o.reason });
    else if (c === "not_actionable" && o.verdict === "actionable") falseNonActionable.push({ id });
  }
  const total = oracle.results.size || 1;
  return {
    driver: oracle.driver,
    false_actionable: falseActionable, // zero tolerated (blocking)
    false_non_actionable: falseNonActionable, // at most 2 percent, non-blocking
    false_non_actionable_rate: falseNonActionable.length / total,
    oracle_gaps: gaps,
    blocking: falseActionable.length > 0,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = parseArgs(process.argv.slice(2));
  const reports = args.oracle.map((p) => JSON.parse(readFileSync(p, "utf8")));
  const crawlx = JSON.parse(readFileSync(args.crawlx, "utf8")).verdicts;
  const result = compare(merge(reports), crawlx);
  console.log(JSON.stringify(result, null, 2));
  if (result.blocking) process.exit(2);
}
