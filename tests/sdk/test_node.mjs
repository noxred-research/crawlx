#!/usr/bin/env node
// Drives the official Firecrawl Node SDK (`firecrawl` 4.51.0) and the `firecrawl` CLI
// (`firecrawl-cli` 1.26.24, the tool the agent skills of `npx firecrawl-cli init` call) against a
// live crawlx facade. Run by crates/crawlx-cli/tests/sdk_python.rs after `npm ci` of package.json.
//
//   CRAWLX_SDK_FACADE_URL  http://127.0.0.1:P/compat/firecrawl   (the facade as mounted)
//   CRAWLX_SDK_API_KEY     fc-...
//   CRAWLX_SDK_SITE        http://site.example.test:PORT         (the fixture site)
//   CRAWLX_SDK_CLI         path of node_modules/firecrawl-cli/dist/index.js
//
// Unlike firecrawl-py, the Node SDK joins `/v2/...` onto `apiUrl` by string concatenation (axios
// `baseURL`), so the `/compat/firecrawl` prefix survives and no rewrite is needed.
//
// One JSON line per row on stdout: {"method", "ok", "detail", ...extra} (same shape as test_sdk.py).

import Firecrawl from "firecrawl";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const FACADE = process.env.CRAWLX_SDK_FACADE_URL;
const KEY = process.env.CRAWLX_SDK_API_KEY;
const SITE = process.env.CRAWLX_SDK_SITE.replace(/\/$/, "");
const CLI = process.env.CRAWLX_SDK_CLI;

const emit = (method, ok, detail, extra = {}) =>
  console.log(JSON.stringify({ method, ok, detail, ...extra }));

async function row(method, fn) {
  try {
    const [detail, extra] = await fn();
    emit(method, true, detail, extra);
  } catch (e) {
    emit(method, false, `${e?.name ?? "Error"}: ${e?.message ?? e}`, {
      error: e?.name ?? "Error",
      status: e?.statusCode ?? e?.status ?? e?.response?.status ?? null,
    });
  }
}

const bySource = (docs) =>
  Object.fromEntries(docs.map((d) => [d.metadata?.sourceURL ?? d.metadata?.url, d.markdown]));

const fc = new Firecrawl({ apiKey: KEY, apiUrl: FACADE });

await row("node.scrape", async () => {
  const doc = await fc.scrape(`${SITE}/`, { formats: ["markdown", "links"] });
  return [
    "scraped the home page",
    { markdown: doc.markdown, links: doc.links, title: doc.metadata?.title, source_url: doc.metadata?.sourceURL },
  ];
});

await row("node.startCrawl+getCrawlStatus", async () => {
  const started = await fc.startCrawl(`${SITE}/`, { limit: 3, scrapeOptions: { formats: ["markdown"] } });
  const deadline = Date.now() + 120_000;
  for (;;) {
    const job = await fc.getCrawlStatus(started.id);
    if (["completed", "failed", "cancelled"].includes(job.status)) {
      return [
        `crawl ${started.id} ${job.status}`,
        { status: job.status, total: job.total, completed: job.completed, markdown: bySource(job.data) },
      ];
    }
    if (Date.now() > deadline) throw new Error(`crawl ${started.id} still ${job.status}`);
    await new Promise((r) => setTimeout(r, 500));
  }
});

await row("node.crawl", async () => {
  const job = await fc.crawl(`${SITE}/`, {
    limit: 3,
    scrapeOptions: { formats: ["markdown"] },
    pollInterval: 1,
    timeout: 120,
  });
  return [`crawl ${job.status}`, { status: job.status, total: job.total, markdown: bySource(job.data) }];
});

await row("node.map", async () => {
  const res = await fc.map(`${SITE}/`);
  return ["mapped the site", { urls: res.links.map((l) => l.url) }];
});

await row("node.search", async () => {
  const res = await fc.search("fixture", { limit: 5 });
  return ["searched", { web: (res.web ?? []).map((h) => ({ url: h.url, title: h.title })) }];
});

await row("node.extract", async () => {
  const res = await fc.extract({
    urls: [`${SITE}/`],
    prompt: "Extract the headline and the answer",
    schema: {
      type: "object",
      properties: { headline: { type: "string" }, answer: { type: "integer" } },
      required: ["headline"],
    },
    pollInterval: 1,
    timeout: 120,
  });
  return [`extract ${res.status}`, { status: res.status, data: res.data }];
});

await row("node.batchScrape", async () => {
  const job = await fc.batchScrape([`${SITE}/a`, `${SITE}/b`], {
    options: { formats: ["markdown"] },
    pollInterval: 1,
    timeout: 120,
  });
  return [`batch ${job.status}`, { status: job.status, total: job.total, markdown: bySource(job.data) }];
});

// the `firecrawl` CLI: HOME and the current directory are throwaway (it keeps credentials in
// `~/.config` and writes results to `.firecrawl/`), no browser login is attempted because an
// explicit --api-key and --api-url are given
const cli = (args) =>
  run(process.execPath, [CLI, "--api-url", FACADE, "--api-key", KEY, ...args], {
    env: { ...process.env, FIRECRAWL_NO_UPDATE_CHECK: "1", NO_COLOR: "1" },
    timeout: 180_000,
    maxBuffer: 16 * 1024 * 1024,
  });

await row("cli.scrape", async () => {
  const { stdout } = await cli(["scrape", `${SITE}/`, "--format", "markdown,links", "--json"]);
  return ["firecrawl scrape", { stdout }];
});

await row("cli.map", async () => {
  const { stdout } = await cli(["map", `${SITE}/`, "--json"]);
  return ["firecrawl map", { stdout }];
});

await row("cli.search", async () => {
  const { stdout } = await cli(["search", "fixture", "--limit", "5", "--json"]);
  return ["firecrawl search", { stdout }];
});

await row("cli.crawl", async () => {
  const { stdout } = await cli([
    "crawl", `${SITE}/`, "--limit", "3", "--wait", "--poll-interval", "1", "--timeout", "120",
  ]);
  return ["firecrawl crawl --wait", { stdout }];
});

await row("cli.credit-usage", async () => {
  const { stdout } = await cli(["credit-usage", "--json"]);
  return ["firecrawl credit-usage", { stdout }];
});
