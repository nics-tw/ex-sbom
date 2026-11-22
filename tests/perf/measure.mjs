// SPDX-License-Identifier: MIT
//
// Run from the repository root (macOS or Linux with ps):
//   npm ci --prefix tests/e2e
//   (cd tests/e2e && npx playwright install chromium)
//   run_dir=$(mktemp -d)
//   go test -tags e2e -c -o "$run_dir/server.test" .
//   go run ./tests/perf/cmd/seed -db "$run_dir/data.duckdb" > "$run_dir/fixture.json"
//   node tests/perf/measure.mjs "$run_dir/server.test" "$run_dir/data.duckdb" "$run_dir/fixture.json" 30
//
// Use the seeder flags to set populated projects, versions, components and fanout.
// The database migration also creates one empty default project.
// Compare first requests on fresh processes and repeated requests after startup.
// Browser times use test CSS, and RSS is sampled rather than an OS high-water mark.
// Microbenchmarks: go test -tags unit -run '^$' -bench 'BenchmarkSearchAndDiff|BenchmarkTopology' -benchmem ./internal/service/sbom ./internal/handler/topology

import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import os from "node:os";
import { performance } from "node:perf_hooks";
import { promisify } from "node:util";
import { chromium } from "../e2e/node_modules/playwright/index.mjs";
import { startServer, useLocalAssets } from "../e2e/server.mjs";

const execute = promisify(execFile);
const [binary, dbPath, manifestPath, count = "30"] = process.argv.slice(2);
const samples = Number(count);
assert(binary && dbPath && manifestPath && Number.isSafeInteger(samples) && samples > 0,
  "usage: node tests/perf/measure.mjs SERVER_BINARY DUCKDB MANIFEST_JSON [SAMPLES]");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const root = "/projects/" + manifest.target_project_id;
const search = root + "/search?" + new URLSearchParams({ q: manifest.search_term });
const diff = root + "/diff?" + new URLSearchParams({ a: manifest.first_version, b: manifest.second_version });
const topology = root + "/sboms/" + manifest.first_version + "/topology";

function summarize(values) {
  assert(values.length > 0 && values.every(Number.isFinite));
  const sorted = [...values].sort((a, b) => a - b);
  const percentile = p => sorted[Math.ceil(p * sorted.length) - 1];
  return {
    samples: sorted.length, min_ms: sorted[0], p50_ms: percentile(0.5),
    p95_ms: percentile(0.95), max_ms: sorted.at(-1),
  };
}

function sampleRSS(pid) {
  const scope = { peak_rss_kib: null, rss_samples: 0 };
  let reading = null;
  let failure;
  function read() {
    if (reading) return reading;
    reading = execute("ps", ["-o", "rss=", "-p", String(pid)]).then(({ stdout }) => {
      const kib = Number(stdout.trim());
      assert(Number.isFinite(kib) && kib > 0, "ps returned invalid RSS");
      scope.peak_rss_kib = Math.max(scope.peak_rss_kib ?? 0, kib);
      scope.rss_samples++;
    }).catch(err => { failure ??= err.message; }).finally(() => { reading = null; });
    return reading;
  }
  read();
  const timer = setInterval(read, 150);
  return async () => {
    clearInterval(timer);
    await read();
    if (failure) scope.rss_error = failure;
    return scope;
  };
}

async function withServer(action) {
  const start = performance.now();
  const service = await startServer(binary, dbPath);
  const startupToReady = performance.now() - start;
  const stopRSS = sampleRSS(service.pid);
  let result;
  let memory;
  try {
    result = await action(service.url);
  } finally {
    memory = await stopRSS();
    await service.stop();
  }
  return { ...result, startup_to_ready_ms: startupToReady, ...memory };
}

function operation(path, expected) {
  return async baseURL => {
    const start = performance.now();
    const response = await fetch(baseURL + path, { signal: AbortSignal.timeout(30_000) });
    const body = await response.arrayBuffer();
    const elapsed = performance.now() - start;
    assert.equal(response.status, 200, path);
    assert(expected(JSON.parse(Buffer.from(body)).data), "fixture result incorrect: " + path);
    return { elapsed, size: body.byteLength };
  };
}

async function measureAPI() {
  const operations = {
    search: operation(search, data => data.total ===
      Math.ceil(manifest.components_per_version / 10) * manifest.versions_per_project),
    diff: operation(diff, data => Object.values(data.by_level).reduce(
      (count, level) => count + (level.changed?.length ?? 0), 0) === Math.ceil(manifest.components_per_version / 5)),
    topology: operation(topology, data => data.reduce(
      (total, level) => total + level.total_components, 0) === manifest.components_per_version),
    topology_relations: operation(topology + "/relations", data => data.length === manifest.edges_in_first_version),
  };
  const results = {};
  for (const [name, execute] of Object.entries(operations)) {
    results[name] = await withServer(async baseURL => {
      const first = await execute(baseURL);
      const warm = [];
      for (let i = 0; i < samples; i++) warm.push((await execute(baseURL)).elapsed);
      return {
        first_request: summarize([first.elapsed]),
        warm_requests: summarize(warm), response_bytes: first.size,
      };
    });
  }
  return results;
}

async function measureBrowser() {
  return withServer(async baseURL => {
    const browser = await chromium.launch({ executablePath: process.env.PERF_CHROME_PATH });
    try {
      const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: "en-US" });
      await useLocalAssets(context);
      const page = await context.newPage();
      await page.goto(baseURL);
      const selected = page.locator("#project-select");
      await selected.selectOption({ label: manifest.target_project_name });
      await page.waitForFunction(version =>
        Array.from(document.querySelectorAll(".version-load-btn")).some(button => button.dataset.version === version),
      manifest.first_version);

      const operations = {
        search: {
          path: search,
          selector: '#search-results [data-action="show-component"]',
          expected: Math.ceil(manifest.components_per_version / 10) * manifest.versions_per_project,
          action: "#search-input",
          value: manifest.search_term,
        },
        diff: {
          path: diff,
          selector: "#diff-result tbody tr",
          expected: Math.ceil(manifest.components_per_version / 5),
          action: "#diff-compare-btn",
        },
        topology: {
          path: topology,
          selector: '#tab-content [data-is-expanded="true"] .truncate',
          expected: Array.from({ length: 8 }, (_, level) =>
            Math.min(10, Math.max(0, Math.ceil((manifest.components_per_version - level) / 8)))).reduce((a, b) => a + b, 0),
          action: `#file-tabs [data-version="${manifest.first_version}"] .sbom-tab-label`,
        },
      };
      const results = {};
      for (const [name, scenario] of Object.entries(operations)) {
        if (name === "diff") {
          await page.locator("#main-tab-diff").click();
          await page.locator("#diff-select-a").selectOption(manifest.first_version);
          await page.locator("#diff-select-b").selectOption(manifest.second_version);
        }
        if (name === "topology") {
          await page.locator("#main-tab-analysis").click();
          const button = page.locator(`.version-load-btn[data-version="${manifest.first_version}"]`);
          await button.click();
          await page.locator(scenario.selector).first().waitFor();
        }

        const durations = [];
        const presentations = [];
        for (let i = 0; i <= samples; i++) {
          const measured = await page.evaluate(({ path, selector, expected, action, value }) => {
            return new Promise((resolve, reject) => {
              performance.clearResourceTimings();
              const start = performance.now();
              let observer;
              const fail = setTimeout(() => {
                observer.disconnect();
                reject(new Error("Timed out waiting for real UI results: " + path));
              }, 30_000);
              observer = new MutationObserver(() => {
                if (document.querySelectorAll(selector).length !== expected) return;
                // The matching data must come from a request started by this interaction.
                const resource = performance.getEntriesByName(location.origin + path).find(
                  entry => entry.startTime >= start);
                if (!resource) return;
                observer.disconnect();
                requestAnimationFrame(() => requestAnimationFrame(() => {
                  clearTimeout(fail);
                  const ready = performance.now();
                  resolve({ elapsed: ready - start, presentation: ready - resource.responseEnd });
                }));
              });
              const container = document.querySelector(selector.split(" ")[0]);
              observer.observe(container, { childList: true, subtree: true });
              const control = document.querySelector(action);
              if (value === undefined) {
                control.click();
              } else {
                control.value = value;
                control.dispatchEvent(new Event("input", { bubbles: true }));
              }
            });
          }, scenario);
          durations.push(measured.elapsed);
          presentations.push(measured.presentation);
        }
        results[name] = {
          first_measured_interaction: summarize(durations.slice(0, 1)),
          warm_interactions: summarize(durations.slice(1)),
          first_response_end_to_presentation: summarize(presentations.slice(0, 1)),
          warm_response_end_to_presentation: summarize(presentations.slice(1)),
        };
      }
      return { browser: browser.version(), results };
    } finally {
      await browser.close();
    }
  });
}

const binaryHash = createHash("sha256");
for await (const chunk of createReadStream(binary)) binaryHash.update(chunk);

const output = {
  schema_version: 1,
  service_binary_sha256: binaryHash.digest("hex"),
  commit: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
  working_tree_dirty: !!execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim(),
  environment: {
    platform: process.platform, architecture: process.arch, os_release: os.release(),
    cpu: os.cpus()[0]?.model, processors: os.availableParallelism(), total_ram_bytes: os.totalmem(),
    node: process.version, go: execFileSync("go", ["version"], { encoding: "utf8" }).trim(),
    browser_viewport: "1280x900", browser_assets: "local-application-assets-with-test-CSS",
  },
  fixture: manifest,
  api: await measureAPI(),
  browser: await measureBrowser(),
};
console.log(JSON.stringify(output, null, 2));
