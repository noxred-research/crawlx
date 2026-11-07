#!/usr/bin/env node
// crawlx browser oracle.
//
// Runs an actionability matrix against a fixture page with either stock
// Playwright or the Patchright fork, selected by ORACLE_DRIVER, and writes a
// result file that records the driver and its package version. Result files
// from different drivers are never merged (see compare.mjs).
//
// Usage:
//   ORACLE_DRIVER=playwright node runner.mjs --manifest fixtures/g27.json --out results/g27.playwright.json
//   ORACLE_DRIVER=patchright node runner.mjs --manifest fixtures/g31.json --out results/g31.patchright.json
//   ORACLE_DRIVER=playwright node runner.mjs --discover out/job.json --proxy http://127.0.0.1:PROXY_PORT --out out/discovery.playwright.json
//   node runner.mjs --self-test
//
// Manifest shape: { "url": "http://127.0.0.1:PORT/g27/", "controls": [ { "id": "c1", "selector": "#c1", "expected": "actionable|not_actionable|oracle_gap" } ] }
//
// Discovery job shape ("AX recall" differential; written by
// `crawlx_bench::oracle::write_discovery_job`):
//   { "gym": "http://127.0.0.1:PORT", "fixtures": [ { "id": "g01", "url": "http://127.0.0.1:PORT/g01/", "settle_ms": 500 } ] }
// Discovery requires an already-running checked egress proxy (the Rust differential
// harness supplies its production EgressProxy with a retained FixtureEvaluationScope).
// Only the exact spelling http://127.0.0.1:PORT is accepted, with PORT in 1..65535
// and no credentials, path (including a trailing slash), query, or fragment.
// An arbitrary forwarding proxy is not containment: the proxy must deny destinations
// outside the fixture scope for HTTP, CONNECT, redirects, subresources, and WebSockets.
// Do not run adversarial fixtures such as G29 without that checked proxy.
// For every fixture page the runner enumerates the driver's role locators (every ARIA
// widget role crawlx's discovery ladder treats as a candidate), runs the actionability
// checks on each element (`click({ trial: true })`), and records one entry per element
// with a join key crawlx can recompute from its own ObservationBundle:
//   "<frame path>::#<dom id>"           when the element has an id attribute
//   "<frame path>::<role>|<name>"       otherwise (name = collapsed lowercase text)
// where the frame path is the chain of frame URL path+query values from the main frame
// (`/g05/ > /g05/frame1.html > about:srcdoc`), so it is independent of the gym port.

import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";

const require = createRequire(import.meta.url);

const DRIVERS = new Set(["playwright", "patchright"]);

// ARIA widget roles that make a node a crawlx candidate (crawlx-elements `WIDGET_ROLES`
// plus the `menuitem*` family), restricted to roles Playwright's `getByRole` accepts.
export const WIDGET_ROLES = [
  "button",
  "link",
  "textbox",
  "searchbox",
  "combobox",
  "listbox",
  "option",
  "checkbox",
  "radio",
  "switch",
  "slider",
  "spinbutton",
  "tab",
  "treeitem",
  "gridcell",
  "menuitem",
  "menuitemcheckbox",
  "menuitemradio",
];

function parseArgs(argv) {
  const out = { selfTest: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--self-test") out.selfTest = true;
    else if (a === "--manifest") out.manifest = argv[++i];
    else if (a === "--discover") out.discover = argv[++i];
    else if (a === "--proxy") out.proxy = argv[++i];
    else if (a === "--out") out.out = argv[++i];
    else if (a === "--chromium") out.chromium = argv[++i];
    else throw new Error(`unknown argument ${a}`);
  }
  return out;
}

function validateDiscoveryProxy(proxy) {
  // Match the raw input, not URL's normalized hostname/port: alternate IP spellings,
  // credentials, whitespace, and a missing explicit port must never become trusted.
  const match = typeof proxy === "string" && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(proxy);
  if (!match || match[0] !== proxy || Number(match[1]) > 65535) {
    throw new Error("--proxy must be an explicit checked proxy URL http://127.0.0.1:PORT (1..65535), without credentials, path, query, or fragment");
  }
  return proxy;
}

export function loadDriver(name) {
  if (!DRIVERS.has(name)) throw new Error(`ORACLE_DRIVER must be one of ${[...DRIVERS].join("|")}, got ${name}`);
  const mod = require(name);
  const version = require(`${name}/package.json`).version;
  return { name, version, chromium: mod.chromium };
}

function classify(trialResult) {
  // Playwright/Patchright `locator.click({ trial: true })` performs the
  // actionability checks (visible, stable, enabled, receives events) without
  // clicking; the thrown message names the failing check.
  if (trialResult.ok) return { verdict: "actionable", reason: null };
  const m = trialResult.error;
  if (/intercepts pointer events/i.test(m)) return { verdict: "not_actionable", reason: "obscured" };
  if (/not visible|hidden|zero size|outside of the viewport/i.test(m)) return { verdict: "not_actionable", reason: "not_visible" };
  if (/disabled/i.test(m)) return { verdict: "not_actionable", reason: "disabled" };
  if (/not stable/i.test(m)) return { verdict: "not_actionable", reason: "unstable" };
  if (/resolved to 0 elements|strict mode|not found|waiting for locator/i.test(m)) return { verdict: "oracle_gap", reason: "locator_unresolved" };
  return { verdict: "oracle_gap", reason: m.slice(0, 200) };
}

export async function runMatrix(driver, manifest, opts = {}) {
  const launch = { headless: true };
  if (opts.chromium) launch.executablePath = opts.chromium; // same pinned build as crawlx (chromium-pin.toml)
  const browser = await driver.chromium.launch(launch);
  const started = new Date().toISOString();
  const results = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const page = await context.newPage();
    await page.goto(manifest.url, { waitUntil: "networkidle" });
    for (const c of manifest.controls) {
      let trial;
      try {
        await page.locator(c.selector).click({ trial: true, timeout: opts.timeoutMs ?? 2000 });
        trial = { ok: true };
      } catch (e) {
        trial = { ok: false, error: String(e && e.message ? e.message : e) };
      }
      const { verdict, reason } = classify(trial);
      results.push({ id: c.id, selector: c.selector, expected: c.expected ?? null, verdict, reason });
    }
    await context.close();
  } finally {
    await browser.close();
  }
  return {
    driver: driver.name,
    driver_version: driver.version,
    console_capture: driver.name === "playwright", // Patchright disables the Console domain
    manifest_url: manifest.url,
    started,
    finished: new Date().toISOString(),
    results,
  };
}

/// Path+query of a frame URL without its origin (`about:srcdoc` stays as is).
export function framePathOf(url) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^/]*(\/.*)?$/i.exec(url);
  if (m) return (m[1] || "/").split("#")[0];
  return url.split("#")[0];
}

/// Frame path from the main frame down to `frame`, joined with " > ".
function framePath(frame) {
  const chain = [];
  for (let f = frame; f; f = f.parentFrame()) chain.push(framePathOf(f.url()));
  return chain.reverse().join(" > ");
}

/// Collapsed, lowercased, truncated text used in the id-less join key.
export function normalizeName(text) {
  return (text ?? "").replace(/\s+/g, " ").trim().toLowerCase().slice(0, 64);
}

/// The join key crawlx recomputes from its own observation (see the header comment).
export function elementKey(frame, domId, role, name) {
  return domId ? `${frame}::#${domId}` : `${frame}::${role}|${normalizeName(name)}`;
}

/// Enumerate the role locators of one page (every frame) and classify each element.
///
/// Enumeration is a snapshot taken before any actionability check: a trial click scrolls
/// its target into view, and on scroll-fed pages (G07) that appends content which must not
/// enter the set, because crawlx observed the page before any scrolling.
async function discoverPage(page, opts) {
  const found = [];
  for (const frame of page.frames()) {
    let path;
    try {
      path = framePath(frame);
    } catch {
      continue; // detached while enumerating
    }
    for (const role of WIDGET_ROLES) {
      let locators;
      try {
        locators = await frame.getByRole(role).all();
      } catch {
        continue;
      }
      for (const el of locators) {
        let info;
        try {
          info = await el.evaluate((e) => ({
            id: e.id || "",
            text: e.getAttribute("aria-label") || e.textContent || e.getAttribute("value") || "",
            tag: e.tagName.toLowerCase(),
          }));
        } catch {
          continue; // re-rendered away between enumeration and evaluation
        }
        found.push({ el, path, role, info });
      }
    }
  }
  const elements = [];
  const seen = new Set();
  for (const { el, path, role, info } of found) {
    const key = elementKey(path, info.id, role, info.text);
    if (seen.has(key)) continue;
    seen.add(key);
    let trial;
    try {
      if (!(await el.isVisible())) trial = { ok: false, error: "element is not visible" };
      else if (!(await el.isEnabled())) trial = { ok: false, error: "element is disabled" };
      else {
        await el.click({ trial: true, timeout: opts.timeoutMs ?? 1500 });
        trial = { ok: true };
      }
    } catch (e) {
      trial = { ok: false, error: String(e && e.message ? e.message : e) };
    }
    const { verdict, reason } = classify(trial);
    elements.push({
      key,
      frame: path,
      dom_id: info.id || null,
      role,
      name: normalizeName(info.text),
      tag: info.tag,
      actionable: verdict === "actionable",
      verdict,
      reason,
    });
  }
  return elements;
}

/// Run the discovery job: one page visit per fixture, elements keyed for the crawlx join.
/// opts.proxy must name an already-running checked egress proxy; validation precedes launch.
export async function runDiscovery(driver, job, opts = {}) {
  const proxy = { server: validateDiscoveryProxy(opts.proxy), bypass: "<-loopback>" };
  const launch = {
    headless: true,
    proxy,
    args: [
      "--proxy-bypass-list=<-loopback>",
      "--disable-quic",
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    ],
  };
  if (opts.chromium) launch.executablePath = opts.chromium;
  const browser = await driver.chromium.launch(launch);
  const started = new Date().toISOString();
  const fixtures = [];
  try {
    for (const fx of job.fixtures) {
      const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, proxy });
      const page = await context.newPage();
      let elements = [];
      let error = null;
      try {
        await page.goto(fx.url, { waitUntil: "networkidle", timeout: opts.navTimeoutMs ?? 30000 });
        await page.waitForTimeout(fx.settle_ms ?? 500);
        elements = await discoverPage(page, opts);
      } catch (e) {
        error = String(e && e.message ? e.message : e);
      }
      await context.close();
      fixtures.push({ id: fx.id, url: fx.url, settle_ms: fx.settle_ms ?? 500, error, elements });
      const n = elements.filter((e) => e.actionable).length;
      console.error(`${fx.id}: ${elements.length} role-locator elements, ${n} actionable${error ? ` (error: ${error})` : ""}`);
    }
  } finally {
    await browser.close();
  }
  return {
    driver: driver.name,
    driver_version: driver.version,
    mode: "discovery",
    gym: job.gym,
    started,
    finished: new Date().toISOString(),
    fixtures,
  };
}

async function selfTest() {
  // Verifies that both drivers load and that classification is stable, without a browser.
  for (const name of DRIVERS) {
    let d;
    try {
      d = loadDriver(name);
    } catch (e) {
      console.error(`driver ${name} not installed: ${e.message}`);
      process.exitCode = 1;
      continue;
    }
    console.log(`driver ${name} ${d.version} ok`);
  }
  const cases = [
    [{ ok: true }, "actionable"],
    [{ ok: false, error: "<div> intercepts pointer events" }, "not_actionable"],
    [{ ok: false, error: "element is not visible" }, "not_actionable"],
    [{ ok: false, error: "element is disabled" }, "not_actionable"],
    [{ ok: false, error: "waiting for locator('#x')" }, "oracle_gap"],
  ];
  for (const [input, want] of cases) {
    const got = classify(input).verdict;
    if (got !== want) {
      console.error(`classify(${JSON.stringify(input)}) = ${got}, want ${want}`);
      process.exitCode = 1;
    }
  }
  // Join keys must match what crawlx_bench::oracle computes from an ObservationBundle.
  const keys = [
    [framePathOf("http://127.0.0.1:4321/g05/frame1.html?x=1#top"), "/g05/frame1.html?x=1"],
    [framePathOf("about:srcdoc"), "about:srcdoc"],
    [elementKey("/g01/", "c1", "button", "ignored"), "/g01/::#c1"],
    [elementKey("/g01/", "", "link", "  Read\n More "), "/g01/::link|read more"],
  ];
  for (const [got, want] of keys) {
    if (got !== want) {
      console.error(`key ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
      process.exitCode = 1;
    }
  }
  // Reject proxy spellings that could normalize into wider or different authority.
  const invalid = [
    undefined, null, 3128, "", "http://127.0.0.1", "http://127.0.0.1:0",
    "http://127.0.0.1:65536", "http://127.0.0.1:03128", "http://127.0.0.1:3128/",
    "https://127.0.0.1:3128", "socks5://127.0.0.1:3128", "http://localhost:3128",
    "http://[::1]:3128", "http://127.1:3128", "http://2130706433:3128",
    "http://0x7f000001:3128", "http://127.0.0.2:3128", "http://example.com:3128",
    "http://user:pass@127.0.0.1:3128", "http://127.0.0.1:3128/path",
    "http://127.0.0.1:3128?x=1", "http://127.0.0.1:3128#fragment",
    " http://127.0.0.1:3128", "http://127.0.0.1:3128\n", "http://127.0.0.1:3128 ",
  ];
  for (const proxy of invalid) {
    assert.throws(() => validateDiscoveryProxy(proxy), Error);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.selfTest) return selfTest();
  if (!args.out || !(args.manifest || args.discover)) {
    throw new Error("--out and one of --manifest or --discover are required");
  }
  if (args.discover) validateDiscoveryProxy(args.proxy);
  const driver = loadDriver(process.env.ORACLE_DRIVER ?? "playwright");
  const chromium = args.chromium ?? process.env.CRAWLX_CHROMIUM_PATH;
  mkdirSync(dirname(args.out), { recursive: true });
  if (args.discover) {
    const job = JSON.parse(readFileSync(args.discover, "utf8"));
    const report = await runDiscovery(driver, job, { chromium, proxy: args.proxy });
    writeFileSync(args.out, JSON.stringify(report, null, 2));
    const total = report.fixtures.reduce((n, f) => n + f.elements.filter((e) => e.actionable).length, 0);
    console.log(`${driver.name} ${driver.version}: ${report.fixtures.length} fixtures, ${total} actionable elements`);
    return;
  }
  const manifest = JSON.parse(readFileSync(args.manifest, "utf8"));
  const report = await runMatrix(driver, manifest, { chromium });
  writeFileSync(args.out, JSON.stringify(report, null, 2));
  const mismatches = report.results.filter((r) => r.expected && r.expected !== r.verdict);
  console.log(`${driver.name} ${driver.version}: ${report.results.length} controls, ${mismatches.length} unexpected`);
  for (const m of mismatches) console.log(`  ${m.id}: expected ${m.expected}, got ${m.verdict} (${m.reason})`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
