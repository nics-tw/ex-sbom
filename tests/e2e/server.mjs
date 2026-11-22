// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT

import { spawn } from "node:child_process";
import { once } from "node:events";

export async function startServer(binary, dbPath, { failScan = false } = {}) {
  const server = spawn(binary, ["-test.run", "^TestE2EServer$", "-test.v"], {
    env: { ...process.env, DB_PATH: dbPath, EX_SBOM_E2E_FAIL_SCAN: failScan ? "1" : "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  let ready;
  let rejectReady;
  const startup = new Promise((resolve, reject) => {
    ready = resolve;
    rejectReady = reject;
  });
  const exited = once(server, "exit");
  const read = chunk => {
    log = (log + chunk).slice(-16_384);
    const url = log.match(/^EX_SBOM_E2E_URL=(http:\/\/127\.0\.0\.1:\d+)\r?\n/m)?.[1];
    if (url) ready(url);
  };
  server.stdout.on("data", read);
  server.stderr.on("data", read);
  exited.then(
    ([code, signal]) => rejectReady(new Error(`Service exited (${code ?? signal})\n${log}`)),
    rejectReady,
  );
  const timeout = setTimeout(() => rejectReady(new Error(`Service startup timed out\n${log}`)), 15_000);
  try {
    const url = await startup;
    return {
      url,
      pid: server.pid,
      getLog: () => log,
      async stop() {
        if (server.exitCode === null && server.signalCode === null) {
          server.kill("SIGTERM");
        }
        const [code, signal] = await exited;
        if (code !== 0) throw new Error(`Service shutdown failed (${code ?? signal})\n${log}`);
      },
    };
  } catch (err) {
    server.kill("SIGTERM");
    await exited.catch(() => {});
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

// The suite verifies interactions, not visual styling. Keep the UI's hidden
// class behavior without relying on CDN availability during a test.
export async function useLocalAssets(context) {
  await context.route("**/*", route => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1") return route.continue();
    if (url.hostname === "cdn.tailwindcss.com") {
      return route.fulfill({
        contentType: "application/javascript",
        body: 'const css = document.createElement("style"); css.textContent = ".hidden{display:none!important}"; document.head.append(css);',
      });
    }
    return route.abort();
  });
}
