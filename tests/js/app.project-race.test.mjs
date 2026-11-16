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
  };
  vm.createContext(sandbox);
  // Project/State/Api are consts in script scope; expose them for the test
  vm.runInContext(appJs + "\n;globalThis.__test = { Project, State, Api };", sandbox);

  const { Project, State, Api } = sandbox.__test;
  // Triggered indirectly via _apply -> MainTab.show("analysis")
  Api.listVersions = () => Promise.resolve({ data: [] });
  return { Project, State, Api, getElementById };
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
