// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

// Regression tests for the project-selection race: when the user switches
// A -> B quickly and A's response arrives last, the stale response must not
// overwrite State.projectID. Run with `node --test "tests/js/*.test.mjs"`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";

const appJs = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "../../static/js/app.js"),
  "utf8",
);

function makeApp() {
  // Minimal DOM stub: one memoized element object per id
  const elements = new Map();
  const makeEl = () => ({
    innerHTML: "", textContent: "", value: "", style: {}, dataset: {},
    options: [], selectedIndex: -1,
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {},
    querySelector: () => null, querySelectorAll: () => [],
  });
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, makeEl());
    return elements.get(id);
  };

  const sandbox = {
    document: { addEventListener() {}, getElementById, createElement: makeEl, body: makeEl() },
    navigator: { language: "en" },
    window: {},
    console,
    AbortController,
  };
  vm.createContext(sandbox);
  // Expose script-scope state and actions for the test.
  vm.runInContext(appJs + "\n;globalThis.__test = { Project, State, Api, Diff };", sandbox);

  const { Project, State, Api, Diff } = sandbox.__test;
  // Triggered indirectly via _apply -> MainTab.show("analysis")
  Api.listVersions = () => Promise.resolve({ data: [] });
  return { Project, State, Api, Diff, getElementById };
}

function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

test("stale A response does not override newer B selection", async () => {
  const { Project, State, Api, getElementById } = makeApp();

  const pending = new Map();
  Api.getProject = id => {
    const d = deferred();
    pending.set(id, d);
    return d.promise;
  };

  const sel = getElementById("project-select");

  // User selects A, then quickly selects B
  sel.value = "A";
  const getA = Project.get("A");
  sel.value = "B";
  const getB = Project.get("B");

  // B responds first and is applied
  pending.get("B").resolve({ data: { project_id: "B" } });
  await getB;
  assert.equal(State.projectID, "B");

  // A responds last: stale, must be ignored
  pending.get("A").resolve({ data: { project_id: "A" } });
  await getA;
  assert.equal(State.projectID, "B");
});

test("response is ignored when selector moved before it arrived", async () => {
  const { Project, State, Api, getElementById } = makeApp();

  const d = deferred();
  Api.getProject = () => d.promise;

  const sel = getElementById("project-select");
  sel.value = "A";
  const getA = Project.get("A");

  // Selector moved on (e.g. options rebuilt after create/delete)
  sel.value = "B";
  d.resolve({ data: { project_id: "A" } });
  await getA;

  assert.notEqual(State.projectID, "A");
});

test("matching response for the current selection still applies", async () => {
  const { Project, State, Api, getElementById } = makeApp();

  Api.getProject = id => Promise.resolve({ data: { project_id: id } });

  const sel = getElementById("project-select");
  sel.value = "A";
  await Project.get("A");

  assert.equal(State.projectID, "A");
});

test("stale diff version response does not replace current project options", async () => {
  const { Diff, State, Api, getElementById } = makeApp();
  const pending = new Map();
  Api.listVersions = projectID => {
    const request = deferred();
    pending.set(projectID, request);
    return request.promise;
  };

  State.projectID = "A";
  const oldLoad = Diff.openInPanel();
  State.projectID = "B";
  const currentLoad = Diff.openInPanel();
  pending.get("B").resolve({ data: [{ version: "B1" }, { version: "B2" }] });
  await currentLoad;
  pending.get("A").resolve({ data: [{ version: "A1" }] });
  await oldLoad;

  assert.match(getElementById("diff-select-a").innerHTML, /B1/);
  assert.doesNotMatch(getElementById("diff-select-a").innerHTML, /A1/);
});

test("duplicate in-flight diff comparison makes one request", async () => {
  const { Diff, State, Api, getElementById } = makeApp();
  State.projectID = "A";
  getElementById("diff-select-a").value = "v1";
  getElementById("diff-select-b").value = "v2";
  const pending = deferred();
  let calls = 0;
  Api.diff = () => {
    calls++;
    return pending.promise;
  };

  const first = Diff._run();
  const second = Diff._run();
  assert.equal(calls, 1);
  pending.resolve({ data: { by_level: {} } });
  await Promise.all([first, second]);
});

test("diff shows vulnerability totals for a destination level without duplicate rows", () => {
  const { Diff, getElementById } = makeApp();
  Diff._diffRow = row => `<tr><td>${row.name}</td></tr>`;
  Diff._renderResult({ by_level: {
    0: { changed: [{ name: "moved-package" }], total_vulns_a: 6, total_vulns_b: 5 },
    1: { total_vulns_a: 0, total_vulns_b: 2 },
  } }, "v1", "v2");

  const html = getElementById("diff-result").innerHTML;
  assert.match(html, /Level 1[\s\S]*?>0<\/span> → 2/);
  assert.equal((html.match(/moved-package/g) || []).length, 1);
  assert.equal((html.match(/<table/g) || []).length, 1);
});
