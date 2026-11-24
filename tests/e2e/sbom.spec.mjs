// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, test as base } from "@playwright/test";
import { startServer, useLocalAssets } from "./server.mjs";

const test = base.extend({
  service: async ({}, use, testInfo) => {
    const binary = process.env.EX_SBOM_E2E_BINARY;
    if (!binary) throw new Error("Set EX_SBOM_E2E_BINARY to the compiled Go browser test server.");
    const directory = await mkdtemp(join(tmpdir(), "ex-sbom-e2e-"));
    const dbPath = join(directory, "sbom.duckdb");
    let server;
    let hasBodyFailure = false;
    const service = {
      get url() { return server.url; },
      async restart(options) {
        await server.stop();
        server = await startServer(binary, dbPath, options);
      },
    };
    try {
      server = await startServer(binary, dbPath);
      await use(service);
      hasBodyFailure = testInfo.status !== testInfo.expectedStatus;
    } finally {
      try {
        if (server) {
          if (hasBodyFailure) await testInfo.attach("server.log", { body: server.getLog(), contentType: "text/plain" });
          await server.stop();
        }
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  },
  context: async ({ context }, use) => {
    await useLocalAssets(context);
    await use(context);
  },
});

function sbom(component, version, purl = `pkg:npm/${component}@${version}`) {
  return {
    name: `${component}.json`,
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: { component: { type: "application", name: "fixture", "bom-ref": "root" } },
      components: [{
        type: "library", name: component, version, "bom-ref": component,
        purl,
      }],
      dependencies: [{ ref: "root", dependsOn: [component] }, { ref: component, dependsOn: [] }],
    })),
  };
}

async function createProject(page, name) {
  await page.locator("#project-input").fill(name);
  await page.locator("#project-switch-btn").click();
  await expect(page.locator("#project-current")).toHaveText(`(${name})`);
  return page.locator("#project-select").inputValue();
}

async function selectProject(page, id, name) {
  const select = page.locator("#project-select");
  await select.selectOption(id);
  await expect(page.locator("#project-current")).toHaveText(`(${name})`);
}

async function upload(page, file, version) {
  await page.locator("#select-sbom-btn").click();
  await page.locator("#sbom-file-input").setInputFiles(file);
  await page.locator("#sbom-modal-preview-btn").click();
  const preview = page.locator("#sbom-preview-summary");
  await expect(preview).toContainText(/(?:元件數量|Components?)[:：]?\s*1\b/i);
  await page.locator("#sbom-version-input").fill(version);
  await page.locator("#sbom-modal-commit-btn").click();
  await expect(page.locator("#sbom-modal")).toBeHidden();
  await expect(versionRow(page, version)).toBeVisible();
}

function versionRow(page, version) {
  return page.locator("#version-history-list tr").filter({
    has: page.getByRole("cell", { name: version, exact: true }),
  });
}

test("upload dialog keeps keyboard focus and returns it when dismissed", async ({ page, service, browserName }) => {
  await page.goto(service.url);
  const trigger = page.locator("#select-sbom-btn");
  await trigger.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog).toHaveAccessibleName(/Select SBOM file|選擇 SBOM 檔案/);
  await expect(page.locator("#sbom-pick-file-btn")).toBeFocused();
  const tabKey = browserName === "webkit" && process.platform === "darwin" ? "Alt+Tab" : "Tab";
  await page.keyboard.press(tabKey);
  await expect(page.locator("#sbom-modal-cancel")).toBeFocused();
  await page.keyboard.press(`Shift+${tabKey}`);
  await expect(page.locator("#sbom-pick-file-btn")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();

  await page.keyboard.press("Enter");
  await page.locator("#sbom-file-input").setInputFiles(sbom("keyboard-fixture", "1.0.0"));
  await page.locator("#sbom-modal-preview-btn").focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#sbom-version-input")).toBeFocused();
  await expect(page.locator("#sbom-version-input")).toHaveAccessibleName("Version name");
  const previewComponent = page.locator("#sbom-preview-summary").getByRole("button", { name: /keyboard-fixture/ });
  await previewComponent.focus();
  await page.keyboard.press("Enter");
  const componentDialog = page.getByRole("dialog", { name: /Component details.*keyboard-fixture/i });
  await expect(componentDialog).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(componentDialog).toBeHidden();
  await expect(previewComponent).toBeFocused();
  await page.locator("#sbom-modal-back-btn").focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#sbom-pick-file-btn")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
});

test("keeps long upload filenames readable with enlarged text", async ({ page, service }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto(service.url);
  // Match the dialog's layout utilities without loading Tailwind from the CDN.
  await page.addStyleTag({ content: `
    #sbom-modal .flex { display: flex; }
    #sbom-modal .gap-3 { gap: .75rem; }
    #sbom-modal .p-6 { padding: 1.5rem; }
    #sbom-modal .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #sbom-filename-display { font-size: 28px; }
  ` });
  const payload = {
    ...sbom("fixture-library", "1.0.0"),
    name: "合成資料-sbom-components-2026-11-23-release.json",
  };
  const dialog = page.locator("#sbom-modal");
  const filename = dialog.locator("#sbom-filename-display");

  for (const language of ["en", "zh"]) {
    await page.locator("#lang-" + language).click();
    await page.locator("#select-sbom-btn").click();
    await page.locator("#sbom-file-input").setInputFiles(payload);
    await expect(filename).toBeVisible();
    await expect(filename).toHaveText(payload.name);
    const clipped = await filename.evaluate(el => el.scrollWidth > el.clientWidth);
    expect(clipped, language + " filename must fit across wrapped lines").toBe(false);
    await page.locator("#sbom-modal-preview-btn").focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#sbom-version-input")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
  }
});

test("@smoke creates a project, uploads and previews an SBOM, saves it and downloads it after reload", async ({ page, service }) => {
  await page.goto(service.url);
  const project = await createProject(page, "Browser fixture");
  await upload(page, sbom("fixture-library", "1.0.0"), "First release");
  await page.reload();
  await selectProject(page, project, "Browser fixture");
  const openVersion = versionRow(page, "First release").locator(".version-load-btn");
  await openVersion.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "First release", exact: true })).toBeFocused();
  const reportButton = page.getByRole("button", { name: "Download PDF Report" });
  const reportStatus = page.locator("#tab-content").getByRole("status");
  await page.route("**/report?*", route => route.fulfill({ status: 500 }), { times: 1 });
  await reportButton.focus();
  await page.keyboard.press("Enter");
  await expect(reportStatus).toHaveText(/Could not create (?:the )?PDF report/i);
  await expect(reportButton).toBeEnabled();
  await expect(reportButton).toBeFocused();
  await page.locator("#lang-zh").click();
  await expect(reportStatus).toHaveText("無法產製 PDF 報告，請再試一次。");
  await page.locator("#lang-en").click();
  await reportButton.focus();

  await page.route("**/report?*", route => route.fulfill({
    status: 500,
    json: { error: "failed to create PDF", code: "pdf_cache_unavailable" },
  }), { times: 1 });
  await page.keyboard.press("Enter");
  await expect(reportStatus).toContainText("Ask the administrator to check its permissions");
  await expect(reportButton).toBeEnabled();
  await page.locator("#lang-zh").click();
  await expect(reportStatus).toContainText("請管理者確認快取目錄的權限");
  await page.locator("#lang-en").click();
  await reportButton.focus();

  const downloadEvent = page.waitForEvent("download");
  await page.keyboard.press("Enter");
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toMatch(/^First release.*\.pdf$/i);
  await expect(reportStatus).toContainText(download.suggestedFilename());
  await expect(reportStatus).toContainText(/browser.*downloads/i);
  await page.locator("#search-input").fill("fixture-library");
  await expect(page.locator("#search-status")).toContainText(/Search results/);
  await page.locator("#lang-zh").click();
  await expect(page.locator("#search-status")).toContainText("搜尋結果");
  await expect(reportStatus).toContainText("請在瀏覽器的下載清單查找");
  await expect(reportStatus).toContainText(download.suggestedFilename());
  await expect(versionRow(page, "First release").locator(".version-load-btn")).toHaveAccessibleName(/開啟/);
  await page.locator("#search-clear-btn").focus();
  await page.keyboard.press("Space");
  await expect(page.locator("#search-input")).toBeFocused();
  const handle = await open(await download.path(), "r");
  try {
    const result = await handle.read(Buffer.alloc(5));
    expect(result.buffer.toString()).toBe("%PDF-");
  } finally {
    await handle.close();
  }
});

test("searches, compares, renames and deletes versions across windows and a service restart", async ({ page, context, service, browserName }) => {
  await page.goto(service.url);
  const project = await createProject(page, "Two releases");
  await upload(page, sbom("fixture-library", "1.0.0"), "Before");
  await upload(page, sbom("fixture-library", "2.0.0"), "After");

  await page.locator("#search-input").fill("fixture-library");
  const searchResult = page.locator("#search-results").getByRole("button", { name: /fixture-library.*After/ });
  await expect(searchResult).toBeVisible();
  await searchResult.focus();
  await page.keyboard.press("Enter");
  const componentDialog = page.getByRole("dialog", { name: /Component details.*fixture-library/i });
  await expect(componentDialog).toBeVisible();
  await expect(componentDialog.getByRole("button", { name: "Close" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(componentDialog).toBeHidden();
  await expect(searchResult).toBeFocused();
  await page.locator("#main-tab-diff").click();
  await page.locator("#diff-select-a").selectOption("Before");
  await page.locator("#diff-select-b").selectOption("After");
  await page.locator("#diff-compare-btn").click();
  await expect(page.locator("#diff-result")).toContainText("fixture-library");
  const comparison = page.getByRole("region", { name: /Version comparison at dependency level/ }).first();
  await expect(comparison.getByRole("columnheader", { name: "Before" })).toBeVisible();
  await expect(comparison.getByRole("columnheader", { name: "After" })).toBeVisible();
  const diffSummary = page.locator("#diff-result summary").first();
  await diffSummary.focus();
  await page.keyboard.press("Enter");
  await expect(comparison).toBeHidden();
  await expect(diffSummary).toBeFocused();
  await page.keyboard.press("Enter");
  const newVersion = comparison.getByRole("button", { name: /2\.0\.0.*fixture-library.*After/ });
  await newVersion.focus();
  await page.keyboard.press("Space");
  await expect(componentDialog).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(newVersion).toBeFocused();

  const second = await context.newPage();
  await second.goto(service.url);
  await selectProject(second, project, "Two releases");
  await second.route("**/sboms/After/topology", async route => {
    const response = await route.fetch();
    const json = await response.json();
    const level = json.data.find(entry => entry.components.some(component => component.includes("fixture-library")));
    for (let i = 1; i <= 10; i++) level.components.push(`extra-component-${i}`);
    await route.fulfill({ response, json });
  });
  await versionRow(second, "After").locator(".version-load-btn").click();
  await expect(second.locator("#tab-content")).toContainText("fixture-library");
  const topologyLevel = second.locator("#tab-content button[aria-controls^='topology-level-']").first();
  await expect(topologyLevel).toHaveAttribute("aria-expanded", "true");
  await topologyLevel.focus();
  await second.keyboard.press("Space");
  await expect(topologyLevel).toHaveAttribute("aria-expanded", "false");
  await second.keyboard.press("Enter");
  const showAll = second.locator("#tab-content").getByRole("button", { name: /Show all 11 components/ });
  const extraComponent = second.getByRole("button", { name: "extra-component-10", exact: true });
  await expect(showAll).toHaveAttribute("aria-expanded", "false");
  await expect(extraComponent).toBeHidden();
  await showAll.focus();
  await second.keyboard.press("Enter");
  const showLess = second.locator("#tab-content").getByRole("button", { name: /Show less/ });
  await expect(showLess).toHaveAttribute("aria-expanded", "true");
  await expect(showLess).toBeFocused();
  await second.keyboard.press(browserName === "webkit" && process.platform === "darwin" ? "Alt+Tab" : "Tab");
  await expect(extraComponent).toBeFocused();
  await showLess.focus();
  await second.keyboard.press("Space");
  await expect(extraComponent).toBeHidden();
  await expect(showAll).toBeFocused();
  const topologyComponent = second.locator("#tab-content").getByRole("button", { name: /fixture-library/ });
  await topologyComponent.focus();
  await second.keyboard.press("Enter");
  await expect(second.getByRole("dialog", { name: /Component details.*fixture-library/i })).toBeVisible();
  await second.keyboard.press("Escape");
  await expect(topologyComponent).toBeFocused();
  second.once("dialog", dialog => dialog.accept("Renamed"));
  await versionRow(second, "After").locator(".version-rename-btn").click();
  await expect(versionRow(second, "Renamed")).toBeVisible();
  await second.close();
  await page.reload();
  await selectProject(page, project, "Two releases");
  await expect(versionRow(page, "Renamed")).toBeVisible();
  await expect(versionRow(page, "After")).toHaveCount(0);

  await service.restart();
  await page.goto(service.url);
  await selectProject(page, project, "Two releases");
  await expect(versionRow(page, "Renamed")).toBeVisible();
  page.once("dialog", dialog => dialog.dismiss());
  await versionRow(page, "Renamed").locator(".version-delete-btn").click();
  await expect(versionRow(page, "Renamed")).toBeVisible();
  page.once("dialog", dialog => dialog.accept());
  await versionRow(page, "Renamed").locator(".version-delete-btn").click();
  await expect(versionRow(page, "Renamed")).toHaveCount(0);
  await page.reload();
  await selectProject(page, project, "Two releases");
  await expect(versionRow(page, "Before")).toBeVisible();
  await expect(versionRow(page, "Renamed")).toHaveCount(0);
  page.once("dialog", dialog => dialog.accept("Renamed project"));
  await page.locator("#project-rename-btn").click();
  await expect(page.locator("#project-current")).toHaveText("(Renamed project)");
  const deleteProject = page.locator("#project-delete-btn");
  let deletePrompt;
  page.once("dialog", async dialog => {
    deletePrompt = dialog.message();
    await dialog.dismiss();
  });
  await page.locator("#lang-zh").press("Enter");
  await deleteProject.press("Enter");
  expect(deletePrompt).toContain("Renamed project");
  expect(deletePrompt).toContain("SBOM 資料仍保留在資料庫。");
  await expect(deleteProject).toBeFocused();
  await expect(page.locator("#project-current")).toHaveText("(Renamed project)");
  await expect(versionRow(page, "Before")).toBeVisible();
  await page.locator("#lang-en").press("Enter");
  page.once("dialog", async dialog => {
    deletePrompt = dialog.message();
    await dialog.accept();
  });
  await deleteProject.press("Enter");
  expect(deletePrompt).toContain("Renamed project");
  expect(deletePrompt).toContain("SBOMs will remain in the database.");
  await expect(page.locator("#project-select option").filter({ hasText: "Renamed project" })).toHaveCount(0);
  await expect(page.locator("#project-current")).toHaveText("(default)");
  await page.close();
});

test("translates a search error and keeps topology controls when changing language", async ({ page, service }) => {
  await page.goto(service.url);
  const componentName = "language-fixture";
  await createProject(page, "Language fixtures");
  await upload(page, sbom(componentName, "1.0.0"), "First release");
  await versionRow(page, "First release").locator(".version-load-btn").click();
  const level = page.locator("#active-topology button[aria-controls^='topology-level-']").first();
  await expect(level).toBeVisible();
  const original = await level.elementHandle();
  await level.click();
  await expect(level).toHaveAttribute("aria-expanded", "false");

  await page.route("**/search?*", route => route.fulfill({ status: 500 }));
  await page.locator("#search-input").fill(componentName);
  const status = page.locator("#search-status");
  await expect(status).toHaveText("Could not complete the search. Please try again.");
  await page.locator("#lang-zh").click();
  await expect(status).toHaveText("無法完成搜尋，請再試一次。");
  await expect(level).toContainText("直接使用之元件");
  await expect(level).toHaveAttribute("aria-expanded", "false");
  expect(await original.evaluate(node => node.isConnected)).toBe(true);
  await page.locator("#search-clear-btn").click();
  await page.locator("#lang-en").click();
  await expect(status).toBeEmpty();
});

test("cancels the previous project request and keeps the latest project selected", async ({ page, service }) => {
  await page.goto(service.url);
  const first = await createProject(page, "First project");
  await upload(page, sbom("first-library", "1.0.0"), "First version");
  const second = await createProject(page, "Second project");
  await upload(page, sbom("second-library", "1.0.0"), "Second version");
  let releaseFirst;
  let holdFirst;
  const release = new Promise(resolve => { releaseFirst = resolve; });
  const held = new Promise(resolve => { holdFirst = resolve; });
  await page.route(`**/projects/${first}`, async route => {
    const original = await route.fetch();
    holdFirst();
    await release;
    await route.fulfill({ response: original });
  }, { times: 1 });
  try {
    await page.locator("#project-select").selectOption(first);
    await held;
    const cancelled = page.waitForEvent("requestfailed", {
      predicate: request => request.url().endsWith(`/projects/${first}`),
    });
    await page.locator("#project-select").selectOption(second);
    expect((await cancelled).failure()?.errorText).toMatch(/aborted|cancelled/i);
    releaseFirst();
    await expect(versionRow(page, "Second version")).toBeVisible();
    await expect(page.locator("#project-select")).toHaveValue(second);
    await expect(versionRow(page, "Second version")).toBeVisible();
    await expect(versionRow(page, "First version")).toHaveCount(0);
  } finally {
    releaseFirst();
  }
});

test("keeps the latest version visible during slow topology requests", async ({ page, service }) => {
  await page.goto(service.url);
  await createProject(page, "Version switching");
  await upload(page, sbom("earlier-library", "1.0.0"), "Earlier");
  await upload(page, sbom("later-library", "1.0.0"), "Later");
  const content = page.locator("#tab-content");
  await expect(content).toContainText("later-library");
  let allowEarlier;
  const blocked = new Promise(resolve => { allowEarlier = resolve; });
  let didStart;
  const requested = new Promise(resolve => { didStart = resolve; });
  let sentEarlier;
  const routeDone = new Promise(resolve => { sentEarlier = resolve; });
  const earlierResponse = page.waitForEvent("requestfailed", {
    predicate: request => new URL(request.url()).pathname.endsWith("/sboms/Earlier/topology"),
  });
  await page.route("**/sboms/Earlier/topology", async route => {
    didStart();
    try {
      await blocked;
      await route.continue();
    } finally {
      sentEarlier();
    }
  }, { times: 1 });
  try {
    await page.locator('#file-tabs [data-version="Earlier"] .sbom-tab-label').focus();
    await page.keyboard.press('Enter');
    await requested;
    await page.locator('#file-tabs [data-version="Later"] .sbom-tab-label').focus();
    await page.keyboard.press('Space');
    await expect(content).toContainText("later-library");
    expect((await earlierResponse).failure()?.errorText).toMatch(/aborted|cancelled/i);
    allowEarlier();
    await routeDone;
    await expect(page.locator("#file-tabs .tab-active")).toHaveText("Later");
    await expect(content).not.toContainText("earlier-library");
  } finally {
    allowEarlier();
  }
});

test("shows upload errors and rejects missing resources and oversized uploads without writing another version", async ({ page, request, service }) => {
  await page.goto(service.url);
  const project = await createProject(page, "Negative cases");
  await upload(page, sbom("fixture-library", "1.0.0"), "Preserved");

  await page.locator("#select-sbom-btn").click();
  await page.locator("#sbom-file-input").setInputFiles({
    name: "broken.json", mimeType: "application/json", buffer: Buffer.from("{"),
  });
  await page.locator("#sbom-modal-preview-btn").click();
  await expect(page.locator("#sbom-modal-step1-error")).toBeVisible();
  await page.locator("#sbom-modal-cancel").click();

  const preview = `${service.url}/projects/${project}/sboms/preview`;
  const large = await request.post(preview, {
    multipart: { file: { name: "large.json", mimeType: "application/json", buffer: Buffer.alloc(50 * 1024 * 1024 + 1, 32) } },
  });
  expect(large.status()).toBe(413);
  const missing = await request.get(`${service.url}/projects/${project}/sboms/absent/topology`);
  expect(missing.status()).toBe(404);
  await page.reload();
  await selectProject(page, project, "Negative cases");
  await expect(versionRow(page, "Preserved")).toBeVisible();
  await expect(page.locator("#version-history-list tbody tr")).toHaveCount(1);
});

test("binds preview to its project and leaves persisted versions intact on scan failure", async ({ request, service }) => {
  async function addProject(name) {
    const response = await request.post(`${service.url}/projects`, { data: { name } });
    expect(response.status()).toBe(201);
    return (await response.json()).data.project_id;
  }
  const source = await addProject("Source");
  const other = await addProject("Other");
  const table = id => `${service.url}/projects/${id}/sboms`;
  const file = sbom("fixture-library", "1.0.0");
  const accepted = await request.post(`${table(source)}/preview`, { multipart: { file } });
  expect(accepted.status()).toBe(200);
  const { data: parsed } = await accepted.json();
  const reportSource = parsed.bom_result.report_source;
  expect(reportSource).toMatchObject({
    filename: file.name,
    sha256: createHash("sha256").update(file.buffer).digest("hex"),
    query_status: "completed",
  });
  const record = { ...parsed, version: "Recorded" };
  const mismatched = await request.post(table(other), { data: record });
  expect(mismatched.status()).toBe(400);
  expect(await mismatched.text()).toContain("invalid preview token");
  const checksumMismatch = await request.post(table(source), {
    data: { ...record, bom_result: { ...record.bom_result, Components: ["different-component"] } },
  });
  expect(checksumMismatch.status()).toBe(400);
  const tamperedSource = await request.post(table(source), {
    data: {
      ...record,
      bom_result: { ...record.bom_result, report_source: { ...reportSource, sha256: "0".repeat(64) } },
    },
  });
  expect(tamperedSource.status()).toBe(400);
  expect(await tamperedSource.text()).toContain("invalid preview token");
  const saved = await request.post(table(source), { data: record });
  expect(saved.status()).toBe(200);
  const duplicate = await request.post(`${table(source)}/preview`, { multipart: { file } });
  expect(duplicate.status()).toBe(200);
  const { data: repeated } = await duplicate.json();
  expect(repeated.sha256).toBe(parsed.sha256);
  expect(repeated.existing_version).toBe("Recorded");

  await service.restart({ failScan: true });
  const failed = await request.post(`${table(source)}/preview`, {
    multipart: { file: sbom("fixture-library", "2.0.0") },
  });
  expect(failed.status()).toBe(502);
  const versions = await request.get(`${service.url}/projects/${source}/versions`);
  expect(versions.status()).toBe(200);
  expect((await versions.json()).data.map(version => version.version)).toEqual(["Recorded"]);
  const otherVersions = await request.get(`${service.url}/projects/${other}/versions`);
  expect(otherVersions.status()).toBe(200);
  expect((await otherVersions.json()).data ?? []).toEqual([]);
});

test("preserves a chosen interface language across navigation and reload", async ({ page, service }) => {
  await page.goto(service.url);
  const html = page.locator("html");
  await expect(html).toHaveAttribute("lang", "en");
  await page.locator("#lang-zh").click();
  await page.locator("#tutorial-btn").click();
  await expect(page).toHaveURL(/\/tutorial$/);
  await expect(html).toHaveAttribute("lang", "zh-Hant");
  await page.reload();
  await expect(html).toHaveAttribute("lang", "zh-Hant");
  await expect(page.locator("#lang-zh")).toHaveAttribute("aria-pressed", "true");
  await page.locator("#lang-en").click();
  await page.locator("#back-btn").click();
  await expect(page).toHaveURL(new URL("/", service.url).href);
  await expect(html).toHaveAttribute("lang", "en");
});

test("keeps control boundaries and selection visible in forced colors", async ({ page, service }) => {
  await page.emulateMedia({ forcedColors: "active" });
  if (!(await page.evaluate(() => matchMedia("(forced-colors: active)").matches))) {
    test.skip(true, "Browser does not support forced colors emulation");
  }
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto(service.url);
  await createProject(page, "Forced colors");
  await upload(page, sbom("forced-colors-fixture", "1.0.0"), "Before");
  await upload(page, sbom("forced-colors-fixture", "2.0.0"), "After");

  const english = page.locator("#lang-en");
  const chinese = page.locator("#lang-zh");
  const analysis = page.locator("#main-tab-analysis");
  const comparison = page.locator("#main-tab-diff");
  const download = page.getByRole("button", { name: "Download PDF Report" });
  await expect(english).toHaveAttribute("aria-pressed", "true");
  await expect(english).toHaveCSS("text-decoration-line", "underline");
  await expect(chinese).toHaveCSS("text-decoration-line", "none");
  await expect(analysis).toHaveCSS("text-decoration-line", "underline");
  await expect(comparison).toHaveCSS("text-decoration-line", "none");
  await expect(download).toHaveCSS("border-top-style", "solid");

  await page.getByRole("button", { name: "Before", exact: true }).press("Enter");
  await expect(page.getByRole("button", { name: "Before", exact: true })).toHaveCSS("text-decoration-line", "underline");
  await expect(page.getByRole("button", { name: "After", exact: true })).toHaveCSS("text-decoration-line", "none");

  await chinese.press("Enter");
  await expect(chinese).toHaveAttribute("aria-pressed", "true");
  await expect(chinese).toHaveCSS("text-decoration-line", "underline");
  await expect(english).toHaveCSS("text-decoration-line", "none");
  await comparison.press("Enter");
  await expect(comparison).toBeFocused();
  await expect(comparison).toHaveCSS("outline-width", "3px");
  await expect(comparison).toHaveCSS("text-decoration-line", "underline");
  await expect(analysis).toHaveCSS("text-decoration-line", "none");
});

test("provides bilingual landmarks, field names, and keyboard skip links", async ({ page, service, browserName }) => {
  await page.goto(service.url);
  const main = page.getByRole("main");
  const skipLink = page.getByRole("link", { name: "Skip to main content" });

  await expect(page.getByRole("navigation", { name: "Site navigation" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Project", exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "New project name" })).toBeVisible();
  await expect(page.getByRole("searchbox", { name: "Search components or CVEs" })).toBeVisible();

  await page.keyboard.press(browserName === "webkit" && process.platform === "darwin" ? "Alt+Tab" : "Tab");
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(main).toBeFocused();

  await page.getByRole("button", { name: "正體中文" }).click();
  await expect(page.getByRole("searchbox", { name: "搜尋元件或 CVE" })).toBeVisible();
  await page.getByRole("link", { name: "操作教學" }).click();
  await expect(page).toHaveTitle("ex-sbom · 操作教學");
  await expect(main.getByRole("heading", { level: 1, name: "ex-sbom 操作教學" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "網站導覽" })).toBeVisible();

  await page.keyboard.press(browserName === "webkit" && process.platform === "darwin" ? "Alt+Tab" : "Tab");
  await expect(page.getByRole("link", { name: "跳至主要內容" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(main).toBeFocused();
});

test("keeps selected version visible and Chinese open label in its accessible name", async ({ page, service }) => {
  await page.goto(service.url);
  await createProject(page, "Selected versions");
  await upload(page, sbom("selection-fixture", "1.0.0"), "Before");
  await upload(page, sbom("selection-fixture", "2.0.0"), "After");
  await versionRow(page, "Before").locator(".version-load-btn").click();
  await versionRow(page, "After").locator(".version-load-btn").click();
  const before = page.getByRole("button", { name: "Before", exact: true });
  const after = page.getByRole("button", { name: "After", exact: true });
  await expect(after).toHaveAttribute("aria-pressed", "true");
  await expect(after).toHaveCSS("text-decoration-line", "underline");
  await expect(before).toHaveCSS("text-decoration-line", "none");
  await page.locator("#lang-zh").click();
  const open = versionRow(page, "Before").locator(".version-load-btn");
  await expect(open).toHaveText("開啟分析");
  await expect(open).toHaveAccessibleName(/^開啟分析.*Before/);
});

test("keeps comparison controls in view with increased text spacing", async ({ page, service }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto(service.url);
  await page.locator("#main-tab-diff").click();
  await page.addStyleTag({ content: `
    * { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; }
    p { margin-block-end: 2em !important; }
  ` });

  for (const language of ["en", "zh"]) {
    await page.locator("#lang-" + language).click();
    const controls = page.locator("#diff-select-a, #diff-swap-btn, #diff-select-b, #diff-compare-btn");
    await expect(controls).toHaveCount(4);
    for (const control of await controls.all()) {
      await expect(control).toBeVisible();
      const bounds = await control.boundingBox();
      expect(bounds.x).toBeGreaterThanOrEqual(0);
      expect(bounds.x + bounds.width).toBeLessThanOrEqual(320);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);
  }
});

test("preserves comparison disclosures and horizontal scroll when translating", async ({ page, service }) => {
  await page.goto(service.url);
  await createProject(page, "Comparison state");
  await upload(page, sbom("diff-fixture", "1.0.0"), "Before");
  await upload(page, sbom("diff-fixture", "2.0.0"), "After");
  await page.locator("#main-tab-diff").click();
  await page.addStyleTag({ content: "#diff-result [role=region]{width:160px;overflow-x:auto} #diff-result table{min-width:600px}" });
  await page.locator("#diff-select-a").selectOption("Before");
  await page.locator("#diff-select-b").selectOption("After");
  await page.locator("#diff-compare-btn").click();
  const region = page.locator("#diff-result [role=region]").first();
  await expect(region).toBeVisible();
  const scroll = await region.evaluate(el => { el.scrollLeft = 90; return el.scrollLeft; });
  expect(scroll).toBeGreaterThan(0);
  await page.locator("#lang-zh").click();
  expect(await region.evaluate(el => el.scrollLeft)).toBe(scroll);
  await page.locator("#diff-result summary").first().click();
  await expect(region).toBeHidden();
  await page.locator("#lang-en").click();
  await expect(region).toBeHidden();
  await page.locator("#diff-result summary").first().click();
  await expect.poll(() => region.evaluate(el => el.scrollLeft)).toBe(scroll);
});

test("downloads verified remediation findings after storing and reopening an SBOM", async ({ page, service }, testInfo) => {
  await service.restart({ historicalLEV: true });
  await page.goto(service.url);
  const project = await createProject(page, "Remediation fixture");
  const [preview] = await Promise.all([
    page.waitForResponse(res => new URL(res.url()).pathname.endsWith("/sboms/preview")),
    upload(page, sbom("fixture-remediation", "1.0.0"), "Repair exercise"),
  ]);
  const previewBOM = (await preview.json()).data.bom_result;
  expect(previewBOM.report_source.lev_archive_status).toBe("configured");
  const findings = previewBOM.ComponentInfo["fixture-remediation"].vulns;
  const finding = findings.find(vuln => vuln.id === "CVE-2025-99999");
  expect(finding).toMatchObject({
    lev: "0.37",
    lev_method: "nist-cswp41-eq10-v1",
    lev_cve: "CVE-2025-99999",
    kev: "listed",
  });
  expect(findings.find(vuln => vuln.id === "CVE-2025-99998")).toMatchObject({ kev: "unlisted" });
  expect(finding.lev_first).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  expect(finding.lev_as_of).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  await service.restart();
  await page.goto(service.url);
  await selectProject(page, project, "Remediation fixture");
  await versionRow(page, "Repair exercise").locator(".version-load-btn").click();
  const component = await page.request.get(
    new URL(`/projects/${project}/sboms/Repair%20exercise/topology/component?component=fixture-remediation`, service.url).href,
  );
  expect(component.ok()).toBe(true);
  const saved = (await component.json()).data;
  expect(saved.lev_archive_status).toBe("configured");
  expect(saved.vulns.find(vuln => vuln.id === finding.id)).toMatchObject({
    lev: "0.37", lev_first: finding.lev_first, lev_as_of: finding.lev_as_of,
  });
  expect(saved.vulns.find(vuln => vuln.id === "CVE-2025-99998")).toMatchObject({ kev: "unlisted" });
  for (const [lang, button] of [["en", "Download PDF Report"], ["zh", "下載 PDF 報告"]]) {
    await page.locator("#lang-" + lang).click();
    const [download, response] = await Promise.all([
      page.waitForEvent("download"),
      page.waitForResponse(res => new URL(res.url()).pathname.endsWith("/report")),
      page.getByRole("button", { name: button, exact: true }).click(),
    ]);
    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("application/pdf");
    expect(download.suggestedFilename()).toMatch(/^Repair exercise.*\.pdf$/i);
    const output = testInfo.outputPath(`remediation-${lang}.pdf`);
    await download.saveAs(output);
    if (process.env.EX_SBOM_E2E_TAGGED_PDF === "1") {
      const { stdout } = await promisify(execFile)("pdfinfo", [output]);
      expect(stdout).toMatch(/^Tagged:\s+yes$/m);
    }
    const handle = await open(output, "r");
    try {
      expect((await handle.read(Buffer.alloc(5))).buffer.toString()).toBe("%PDF-");
    } finally {
      await handle.close();
    }
  }
});

test("formats Go advisory candidates in preview, saved details and PDF", async ({ page, service }, testInfo) => {
  await page.goto(service.url);
  const project = await createProject(page, "Go candidate fixture");
  const component = "example.com/widget";
  const file = { ...sbom(component, "v1.2.3", `pkg:golang/${component}@v1.2.3`), name: "go-candidate.json" };
  await page.locator("#select-sbom-btn").click();
  await page.locator("#sbom-file-input").setInputFiles(file);
  await page.locator("#sbom-modal-preview-btn").click();
  const previewComponent = page.locator("#sbom-preview-summary").getByRole("button", { name: /example\.com\/widget/ });
  await previewComponent.click();
  const details = page.locator("#component-modal-content");
  await expect(details).toContainText("v1.2.4");
  await page.keyboard.press("Escape");
  await page.locator("#sbom-version-input").fill("Go release");
  await page.locator("#sbom-modal-commit-btn").click();
  await expect(page.locator("#sbom-modal")).toBeHidden();

  await service.restart();
  await page.goto(service.url);
  await selectProject(page, project, "Go candidate fixture");
  await versionRow(page, "Go release").locator(".version-load-btn").click();
  await page.locator("#active-topology").getByRole("button", { name: /example\.com\/widget/ }).click();
  await expect(details).toContainText("v1.2.4");
  await page.keyboard.press("Escape");
  const response = await page.request.get(new URL(`/projects/${project}/sboms/Go%20release/topology/component?component=${encodeURIComponent(component)}`, service.url).href);
  expect(response.ok()).toBe(true);
  const { data } = await response.json();
  expect(data.suggested_fix_version).toBe("v1.2.4");
  expect(data.vulns[0].suggest_fix_version).toBe("v1.2.4");
  expect(data.vulns[0].fix_versions).toEqual(["1.2.4"]);

  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download PDF Report" }).click();
  const output = testInfo.outputPath("go-candidate.pdf");
  await (await download).saveAs(output);
  let content;
  try {
    ({ stdout: content } = await promisify(execFile)("pdftotext", ["-raw", output, "-"]));
  } catch (error) {
    if (error.code !== "ENOENT" || process.env.CI) throw error;
    testInfo.annotations.push({ type: "PDF text check", description: "Install Poppler to verify candidate versions" });
    return;
  }
  expect(content.replaceAll("\u200b", "")).toMatch(/Advisory candidates for this finding\s+v1\.2\.4/);
});

test("keeps remediation findings and PDF download available when risk feeds fail", async ({ page, service }, testInfo) => {
  await service.restart({ failRiskFeeds: true });
  await page.goto(service.url);
  const project = await createProject(page, "Unavailable risk feeds");
  const [preview] = await Promise.all([
    page.waitForResponse(res => new URL(res.url()).pathname.endsWith("/sboms/preview")),
    upload(page, sbom("fixture-remediation", "1.0.0"), "Offline risk evidence"),
  ]);
  const previewBOM = (await preview.json()).data.bom_result;
  expect(previewBOM.report_source.lev_archive_status).toBe("disabled");
  const finding = previewBOM.ComponentInfo["fixture-remediation"].vulns.find(vuln => vuln.id === "CVE-2025-99999");
  expect(finding).toMatchObject({ id: "CVE-2025-99999", cvss_score: "9.8" });
  expect(finding.epss).toBeUndefined();
  expect(finding.lev).toBeUndefined();
  expect(finding.kev).toBeUndefined();
  const response = await page.request.get(new URL(
    `/projects/${project}/sboms/Offline%20risk%20evidence/report?lang=zh-TW`, service.url,
  ).href);
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("application/pdf");
  const body = await response.body();
  expect(body.subarray(0, 5).toString()).toBe("%PDF-");
  const output = testInfo.outputPath("missing-risk-feeds-zh.pdf");
  await testInfo.attach("missing-risk-feeds-zh", { body, contentType: "application/pdf" });
  await writeFile(output, body);
  let text;
  try {
    ({ stdout: text } = await promisify(execFile)("pdftotext", ["-raw", output, "-"]));
  } catch (error) {
    if (error.code !== "ENOENT" || process.env.CI) throw error;
    testInfo.annotations.push({ type: "PDF text check", description: "Install Poppler to verify report wording" });
    return;
  }
  text = text.replaceAll("\u200b", "");
  expect(text).toMatch(/安排評估\s*\|\s*fixture-remediation/);
  expect(text).toMatch(/KEV\s*(?:\|\s*)?尚未查核/);
  expect(text).toMatch(/EPSS\s*(?:\|\s*)?未記錄/);
  expect(text).toMatch(/綜合利用指標\s*(?:\|\s*)?資料不足/);
  expect(text).toMatch(/LEV\s*(?:\|\s*)?掃描時未啟用/);
  expect(text).toContain("CVE-2025-99999");
});

test("explains a blank project name and lets the user correct it", async ({ page, service }) => {
  await page.goto(service.url);
  const name = page.locator("#project-input");
  await name.fill("   ");
  await page.locator("#project-switch-btn").click();
  await expect(name).toBeFocused();
  await expect(name).toHaveAttribute("aria-invalid", "true");
  await expect(name).toHaveAccessibleDescription("Enter a new project name.");

  await page.locator("#lang-zh").click();
  await expect(name).toHaveAccessibleDescription("請輸入新專案名稱。");
  await name.fill("驗收專案");
  await expect(name).not.toHaveAttribute("aria-invalid");
  await expect(page.locator("#project-name-error")).toBeHidden();
  await page.locator("#project-switch-btn").click();
  await expect(page.locator("#project-current")).toHaveText("(驗收專案)");
});

test("clears comparison status on reopening", async ({ page, service }) => {
  await page.goto(service.url);
  await createProject(page, "History and comparison");
  await upload(page, sbom("history-fixture", "1.0.0"), "Before");
  await upload(page, sbom("history-fixture", "2.0.0"), "After");
  await page.locator("#main-tab-diff").click();
  await page.locator("#diff-select-a").selectOption("Before");
  await page.locator("#diff-select-b").selectOption("After");
  const { promise: pending, resolve: release } = Promise.withResolvers();
  await page.route("**/projects/*/diff?*", async route => {
    await pending;
    await route.continue();
  });
  const compare = page.locator("#diff-compare-btn");
  const status = page.locator("#diff-status");
  const loading = page.locator("#diff-result [data-i18n='loading']");
  try {
    await compare.click();
    await expect(status).toHaveText("Loading...");
    await expect(loading).toHaveText("Loading...");
    await expect(loading).toHaveCSS("animation-name", "none");
    await compare.click();
    await expect(status).toHaveText("Loading...");
    await page.locator("#lang-zh").click();
    await expect(status).toHaveText("載入中...");
    await expect(loading).toHaveText("載入中...");
    await page.locator("#lang-en").click();
  } finally {
    release();
  }
  await expect(loading).toHaveCount(0);
  await expect(status).not.toBeEmpty();
  await page.locator("#main-tab-analysis").click();
  await page.locator("#main-tab-diff").click();
  await expect(page.locator("#diff-result")).toBeEmpty();
  await expect(page.locator("#diff-status")).toBeEmpty();
});

test("announces comparison errors and clears them before retry", async ({ page, service }) => {
  await page.goto(service.url);
  await createProject(page, "Comparison status");
  await upload(page, sbom("status-fixture", "1.0.0"), "Before");
  await upload(page, sbom("status-fixture", "2.0.0"), "After");
  await page.locator("#main-tab-diff").click();

  const compare = page.locator("#diff-compare-btn");
  const panel = page.locator("#panel-diff");
  const error = panel.getByRole("status").filter({ hasText: /select two different|請選擇兩個不同/ });
  await page.locator("#diff-select-a").selectOption("Before");
  await page.locator("#diff-select-b").selectOption("Before");
  await compare.press("Enter");
  await expect(error).toHaveText("Please select two different SBOMs");
  await expect(compare).toBeFocused();
  await page.locator("#lang-zh").click();
  await expect(error).toHaveText("請選擇兩個不同的 SBOM");

  await page.locator("#diff-select-b").selectOption("After");
  await expect(error).toHaveCount(0);
  await compare.press("Enter");
  await expect(panel.getByRole("status")).toContainText(/共 .*項新增/);
  await expect(compare).toBeFocused();
  await expect(error).toHaveCount(0);

  await page.locator("#main-tab-analysis").click();
  await page.route("**/projects/*/versions", route => route.fulfill({ status: 503 }), { times: 1 });
  const comparisonTab = page.locator("#main-tab-diff");
  await comparisonTab.press("Enter");
  await expect(panel.getByRole("status")).toContainText("無法載入版本");
  await expect(comparisonTab).toBeFocused();
  await page.locator("#lang-en").click();
  await expect(panel.getByRole("status")).toContainText("Could not load versions.");
  await comparisonTab.press("Enter");
  await expect(compare).toBeEnabled();
  await expect(panel.getByRole("status")).toBeEmpty();
});

test("provides a labelled and keyboard-scrollable version history region", async ({ page, service }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto(service.url);
  await createProject(page, "Version history region");
  await upload(page, sbom("history-fixture", "1.0.0"), "First release");
  await page.addStyleTag({ content: "#version-history-list table { min-width: 600px; }" });
  const tableRegion = page.getByRole("region", { name: "Version History", exact: true });
  await expect(tableRegion.getByRole("table")).toBeVisible();
  const actions = tableRegion.getByRole("button");
  await expect(actions).toHaveCount(3);
  for (const action of await actions.all()) {
    const { width, height } = await action.boundingBox();
    expect(width).toBeGreaterThanOrEqual(24);
    expect(height).toBeGreaterThanOrEqual(24);
  }
  await expect(tableRegion).toHaveAttribute("tabindex", "0");
  await tableRegion.focus();
  await page.keyboard.press("ArrowRight");
  await expect.poll(() => tableRegion.evaluate(el => el.scrollLeft)).toBeGreaterThan(0);
  await page.keyboard.press("ArrowLeft");
  await expect.poll(() => tableRegion.evaluate(el => el.scrollLeft)).toBe(0);
  await page.keyboard.press("ArrowRight");
  await expect.poll(() => tableRegion.evaluate(el => el.scrollLeft)).toBeGreaterThan(0);
  const position = await tableRegion.evaluate(el => el.scrollLeft);
  await page.locator("#lang-zh").click();
  const translatedRegion = page.getByRole("region", { name: "版本歷程", exact: true });
  await expect(translatedRegion.getByRole("table")).toBeVisible();
  await expect.poll(() => translatedRegion.evaluate(el => el.scrollLeft)).toBe(position);
  await page.locator("#lang-en").click();
  await expect.poll(() => tableRegion.evaluate(el => el.scrollLeft)).toBe(position);
});

test("translates pending and failed version history without interpreting error text", async ({ page, service }) => {
  let finish;
  const pending = new Promise(resolve => { finish = resolve; });
  await page.route("**/projects/*/versions", async route => {
    await pending;
    await route.fulfill({ status: 500, json: { error: 'Failure <b>quoted</b> "&"' } });
  });
  await page.goto(service.url);
  const history = page.locator("#version-history-list");
  try {
    await expect(history).toHaveText("Loading versions…");
    await page.locator("#lang-zh").click();
    await expect(history).toHaveText("正在載入版本…");
  } finally {
    finish();
  }
  await expect(history).toContainText('無法載入版本：Failure <b>quoted</b> "&"');
  await page.locator("#lang-en").click();
  await expect(history).toContainText('Could not load versions: Failure <b>quoted</b> "&"');
  await expect(history.locator("b")).toHaveCount(0);
});
