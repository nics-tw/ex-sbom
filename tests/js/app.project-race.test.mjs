// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

// Regression tests for the project-selection race: when the user switches
// A -> B quickly and A's response arrives last, the stale response must not
// overwrite State.projectID. Run with `node --test "tests/js/*.test.mjs"`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const appJs = ["api.js", "request-slot.js", "result-view.js", "app.js"]
  .map(file => readFileSync(new URL(`../../static/js/${file}`, import.meta.url), "utf8"))
  .join("\n");

function makeApp() {
  // Minimal DOM stub: one memoized element object per id
  const elements = new Map();
  const makeEl = () => ({
    listeners: new Map(),
    innerHTML: "", textContent: "", value: "", style: {}, dataset: {},
    options: [], selectedIndex: -1, disabled: false,
    open: false,
    showModal() { this.open = true; },
    close() { this.open = false; },
    focus() {},
    setAttribute() {},
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener(type, listener) { this.listeners.set(type, listener); }, appendChild() {},
    querySelector: () => null, querySelectorAll: () => [],
  });
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, makeEl());
    return elements.get(id);
  };

  let start;
  const pendingTimers = new Set();
  const sandbox = {
    document: {
      addEventListener(type, listener) {
        if (type === "DOMContentLoaded") start = listener;
      },
      getElementById, createElement: makeEl, body: makeEl(),
      querySelector: () => null,
    },
    bindLanguageSwitcher() {},
    setTimeout(callback) { pendingTimers.add(callback); return callback; },
    clearTimeout(callback) { pendingTimers.delete(callback); },
    navigator: { language: "en" },
    window: {},
    console,
    AbortController,
  };
  vm.createContext(sandbox);
  // Expose script-scope state and actions for the test.
  vm.runInContext(appJs + "\n;globalThis.__test = { Project, State, Api, Diff, ComponentModal, Sbom, ResultView };", sandbox);

  const { Project, State, Api, Diff, ComponentModal, Sbom, ResultView } = sandbox.__test;
  // Triggered indirectly via _apply -> MainTab.show("analysis")
  Api.listVersions = () => Promise.resolve({ data: [] });
  return { Project, State, Api, Diff, ComponentModal, Sbom, ResultView, getElementById, start, pendingTimers };
}

function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

test("stale A response does not override newer B selection", async () => {
  const { Project, State, Api, getElementById } = makeApp();

  const pending = new Map();
  Api.getProject = (id, signal) => {
    const d = deferred();
    pending.set(id, { ...d, signal });
    return d.promise;
  };

  const sel = getElementById("project-select");

  // User selects A, then quickly selects B
  sel.value = "A";
  const getA = Project.get("A");
  sel.value = "B";
  const getB = Project.get("B");
  assert.equal(pending.get("A").signal?.aborted, true);

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
  assert.equal(getElementById("diff-compare-btn").disabled, true);
  pending.get("B").resolve({ data: [{ version: "B1" }, { version: "B2" }] });
  await currentLoad;
  pending.get("A").resolve({ data: [{ version: "A1" }] });
  await oldLoad;

  assert.match(getElementById("diff-select-a").innerHTML, /B1/);
  assert.doesNotMatch(getElementById("diff-select-a").innerHTML, /A1/);
  assert.equal(getElementById("diff-compare-btn").disabled, false);
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
  const { ResultView, getElementById } = makeApp();
  ResultView._diffRow = row => `<tr><td>${row.name}</td></tr>`;
  ResultView.diff(getElementById("diff-result"), { by_level: {
    0: { changed: [{ name: "moved-package" }], total_vulns_a: 6, total_vulns_b: 5 },
    1: { total_vulns_a: 0, total_vulns_b: 2 },
  } }, "v1", "v2");

  const html = getElementById("diff-result").innerHTML;
  assert.match(html, /Level 1[\s\S]*?>0<\/span> → 2/);
  assert.equal((html.match(/moved-package/g) || []).length, 1);
  assert.equal((html.match(/<table/g) || []).length, 1);
});

test("leaving a project cancels its pending component details even when returning to it", async () => {
  const { Project, State, Api, ComponentModal, getElementById } = makeApp();
  const old = deferred();
  let signal;
  let rendered = false;
  Api.getProject = async id => ({ data: { project_id: id } });
  Api.getComponent = (_project, _version, _component, activeSignal) => {
    signal = activeSignal;
    return old.promise;
  };
  Api.getVulnDep = async () => ({ data: [] });
  ComponentModal._renderDetails = () => { rendered = true; };
  State.projectID = "A";
  const request = ComponentModal.show("v1", "old component");
  const select = getElementById("project-select");
  select.value = "B";
  await Project.get("B");
  select.value = "A";
  await Project.get("A");
  old.resolve({ data: { name: "old component" } });
  await request;

  assert.equal(signal.aborted, true);
  assert.equal(rendered, false);
});

test("late topology does not render for a replaced tab of the same version", async () => {
  const { State, Api, Sbom } = makeApp();
  const request = deferred();
  Api.getTopology = () => request.promise;
  let rendered = false;
  Sbom._renderTopology = () => { rendered = true; };
  State.projectID = "A";
  State.activeTab = { dataset: { version: "shared" } };
  const response = Sbom.fetchTopology("shared");
  State.activeTab = { dataset: { version: "shared" } };
  request.resolve({ data: [] });
  await response;

  assert.equal(rendered, false);
});

test("changing the diff selection cancels pending results, even if switched back", async () => {
  const { Diff, State, Api, ResultView, getElementById } = makeApp();
  State.projectID = "A";
  const first = getElementById("diff-select-a");
  const second = getElementById("diff-select-b");
  first.value = "v1";
  second.value = "v2";
  const pending = deferred();
  let signal;
  let rendered = false;
  Api.diff = (_project, _a, _b, activeSignal) => {
    signal = activeSignal;
    return pending.promise;
  };
  ResultView.diff = () => { rendered = true; };
  const request = Diff._run();
  Diff._swap();
  Diff._swap();
  pending.resolve({ data: { by_level: {} } });
  await request;

  assert.equal(signal.aborted, true);
  assert.equal(rendered, false);
});


test("search input drops the old project's queued query after switching projects", async () => {
  const { Project, State, Api, getElementById, start, pendingTimers } = makeApp();
  Project.load = () => {};
  Api.getProject = async id => ({ data: { project_id: id } });
  const queries = [];
  Api.search = async (project, query) => { queries.push([project, query]); return { data: { total: 0 } }; };
  start();

  State.projectID = "A";
  const input = getElementById("search-input");
  input.value = "only in A";
  input.listeners.get("input")({ target: input });
  assert.equal(pendingTimers.size, 1);

  const selector = getElementById("project-select");
  selector.value = "B";
  await selector.listeners.get("change")({ target: selector });
  for (const callback of pendingTimers) callback();
  assert.equal(State.projectID, "B");
  assert.deepEqual(queries, []);
});

test("diff clears older project options immediately and keeps controls disabled on a load error", async () => {
  const { Diff, State, Api, getElementById } = makeApp();
  let reject;
  const unavailable = new Promise((_resolve, fail) => { reject = fail; });
  Api.listVersions = projectID => projectID === "A"
    ? Promise.resolve({ data: [{ version: "A1" }, { version: "A2" }] })
    : unavailable;
  State.projectID = "A";
  await Diff.openInPanel();
  const option = getElementById("diff-select-a");
  const compare = getElementById("diff-compare-btn");
  assert.match(option.innerHTML, /A1/);
  assert.equal(compare.disabled, false);

  State.projectID = "B";
  State.language = "zh";
  const load = Diff.openInPanel();
  assert.equal(option.innerHTML, "");
  assert.equal(option.disabled, true);
  assert.equal(compare.disabled, true);
  reject(new Error("internal data"));
  await load;
  assert.equal(option.disabled, true);
  assert.equal(compare.disabled, true);
  const result = getElementById("diff-result").textContent;
  assert.match(result, /無法載入版本/);
  assert.doesNotMatch(result, /internal data/);
});
