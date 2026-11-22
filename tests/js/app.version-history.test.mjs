// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const appJs = ["api.js", "request-slot.js", "result-view.js", "app.js"]
  .map(file => readFileSync(new URL(`../../static/js/${file}`, import.meta.url), "utf8"))
  .join("\n");

function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

function makeElement(tag = "div") {
  const listeners = new Map();
  const classes = new Set();
  let html = "";
  const el = {
    tagName: tag.toUpperCase(), dataset: {}, style: {}, value: "", textContent: "",
    className: "", children: [], parentNode: null, options: [], selectedIndex: -1,
    buttons: new Map(),
    classList: {
      add(...names) { names.forEach(name => classes.add(name)); },
      remove(...names) { names.forEach(name => classes.delete(name)); },
      contains(name) { return classes.has(name); },
      toggle(name, force) {
        const on = force ?? !classes.has(name);
        if (on) classes.add(name); else classes.delete(name);
        return on;
      },
    },
    get innerHTML() { return html; },
    set innerHTML(value) {
      html = String(value);
      this.children = [];
      if (tag === "select") {
        const options = [...html.matchAll(/<option value="([^"]*)"([^>]*)>(.*?)<\/option>/g)];
        this.options = options.map(([, value, , text]) => ({ value, text }));
        this.selectedIndex = options.length ? Math.max(0, options.findIndex(([, , attrs]) => attrs.includes("selected"))) : -1;
        this.value = this.options[this.selectedIndex]?.value ?? "";
      }
    },
    appendChild(child) { child.parentNode = this; this.children.push(child); return child; },
    removeChild(child) { this.children.splice(this.children.indexOf(child), 1); child.parentNode = null; },
    remove() { this.parentNode?.removeChild(this); },
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(listener);
    },
    async fire(type, event = {}) {
      for (const listener of listeners.get(type) ?? []) await listener(event);
    },
    querySelector(selector) {
      if (selector === ".sbom-tab-label") return this.children.find(child => child.className === "sbom-tab-label") ?? null;
      if (selector === "div") return this.children.find(child => child.tagName === "DIV") ?? null;
      return null;
    },
    querySelectorAll(selector) {
      if (!selector.startsWith(".version-")) return [];
      const buttons = [...html.matchAll(/<button\b([^>]*)>/g)]
        .filter(([, attrs]) => attrs.includes(selector.slice(1)))
        .map(([, attrs]) => {
          const button = makeElement("button");
          button.dataset.version = attrs.match(/data-version="([^"]*)"/)?.[1] ?? "";
          return button;
        });
      this.buttons.set(selector, buttons);
      return buttons;
    },
  };
  return el;
}

function makeApp() {
  const elements = new Map();
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, makeElement(id === "project-select" ? "select" : "div"));
    return elements.get(id);
  };
  const sandbox = {
    document: { addEventListener() {}, getElementById, createElement: makeElement, body: makeElement() },
    navigator: { language: "en" }, window: {}, console, AbortController,
    prompt: () => "renamed", confirm: () => true, alert() {},
  };
  vm.createContext(sandbox);
  vm.runInContext(appJs + "\n;globalThis.__test = { Project, State, Api, VersionHistory, Sbom, SbomModal, MainTab };", sandbox);
  return { ...sandbox.__test, getElementById };
}

const version = name => ({ version: name, created_at: "2026-01-01T00:00:00Z" });
const flush = () => new Promise(resolve => setImmediate(resolve));

test("save sends the preview token and ignores completion after switching projects", async () => {
  const { State, Api, Sbom, SbomModal, VersionHistory, getElementById } = makeApp();
  const pending = deferred();
  const calls = [];
  const rendered = [];
  Api.commitSBOM = (...args) => { calls.push(args); return pending.promise; };
  Sbom.addTab = name => rendered.push(name);
  VersionHistory.load = () => rendered.push("history");
  State.projectID = "A";
  Object.assign(SbomModal, { _projectID: "A", _bomResult: {}, _sha256: "hash", _previewToken: "token" });
  getElementById("sbom-version-input").value = "shared";
  const commit = SbomModal.commit();
  assert.equal(calls[0][0], "A");
  assert.equal(calls[0][5], "token");
  State.projectID = "B";
  SbomModal.open();
  const button = getElementById("sbom-modal-commit-btn");
  button.disabled = true;
  button.textContent = "B save pending";
  pending.resolve({ ok: true, json: async () => ({}) });
  await commit;
  assert.deepEqual(rendered, []);
  assert.equal(button.disabled, true);
  assert.equal(button.textContent, "B save pending");
});

for (const action of ["rename", "delete"]) {
  test(`late project ${action} preserves the currently selected project`, async () => {
    const { Project, State, Api, getElementById } = makeApp();
    const pending = deferred();
    const select = getElementById("project-select");
    const projects = [{ ID: "A", Name: "renamed" }, { ID: "B", Name: "Project B" }];
    Api.getProjects = async () => ({
      data: { current: "renamed", projects: action === "delete" ? projects.slice(1) : projects },
    });
    Api.getProject = async id => ({ data: { project_id: id } });
    Api.listVersions = async () => ({ data: [] });
    Api.renameProject = Api.deleteProject = () => pending.promise;
    select.value = State.projectID = "A";
    const mutation = Project[action]("A", "renamed");
    select.value = "B";
    await Project.get("B");
    pending.resolve({});
    await mutation;
    assert.equal(select.value, "B");
    assert.equal(State.projectID, "B");
  });
}

test("switch clears A's actions while B is still loading", async () => {
  const { Project, State, Api, Sbom, getElementById } = makeApp();
  const pendingB = deferred();
  Api.getProject = id => id === "A"
    ? Promise.resolve({ data: { project_id: id } }) : pendingB.promise;
  Api.listVersions = () => Promise.resolve({ data: [version("shared")] });
  const select = getElementById("project-select");
  select.value = "A";
  await Project.get("A");
  await flush();
  Sbom.addTab("shared", false);

  select.value = "B";
  const loadingB = Project.get("B");
  assert.equal(State.projectID, null);
  assert.equal(State.uploadedFiles.size, 0);
  assert.equal(getElementById("file-tabs").children.length, 0);
  assert.match(getElementById("version-history-list").innerHTML, /尚未選擇專案/);

  pendingB.resolve({ data: { project_id: "B" } });
  await loadingB;
  assert.equal(State.projectID, "B");
});

test("delayed A history cannot replace B's same-named versions", async () => {
  const { Project, State, Api, VersionHistory, getElementById } = makeApp();
  const pending = { A: deferred(), B: deferred() };
  Api.getProject = id => Promise.resolve({ data: { project_id: id } });
  Api.listVersions = id => pending[id].promise;
  const select = getElementById("project-select");

  select.value = "A";
  await Project.get("A");
  select.value = "B";
  await Project.get("B");
  pending.B.resolve({ data: [version("shared"), version("only-B")] });
  await flush();
  pending.A.resolve({ data: [version("shared"), version("only-A")] });
  await flush();

  assert.equal(State.projectID, "B");
  assert.equal(VersionHistory._projectID, "B");
  assert.deepEqual(Array.from(VersionHistory._versions, v => v.version), ["shared", "only-B"]);
  const history = getElementById("version-history-list");
  assert.match(history.innerHTML, /only-B/);
  assert.doesNotMatch(history.innerHTML, /only-A/);
});

for (const action of ["rename", "delete"]) {
  test(`late A ${action} completion cannot mutate B's same-named history`, async () => {
    const { Project, Api, VersionHistory, Sbom, getElementById } = makeApp();
    Api.getProject = id => Promise.resolve({ data: { project_id: id } });
    Api.listVersions = id => Promise.resolve({ data: [version("shared"), version(`only-${id}`)] });
    const select = getElementById("project-select");
    const history = getElementById("version-history-list");
    select.value = "A";
    await Project.get("A");
    await flush();

    const button = history.buttons.get(`.version-${action}-btn`)[0];
    const pending = deferred();
    const calls = [];
    const apiMethod = action === "rename" ? "renameSBOM" : "deleteSBOM";
    Api[apiMethod] = (...args) => { calls.push(args); return pending.promise; };
    let tabChanges = 0;
    Sbom.renameTab = () => { tabChanges++; };
    Sbom.removeTab = () => { tabChanges++; };

    const mutation = button.fire("click");
    select.value = "B";
    await Project.get("B");
    await flush();
    await button.fire("click"); // A's detached row must no longer start another mutation.
    pending.resolve(action === "rename" ? { data: { version: "renamed" } } : { data: {} });
    await mutation;

    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], "A");
    assert.equal(calls[0][1], "shared");
    assert.equal(tabChanges, 0);
    assert.equal(VersionHistory._projectID, "B");
    assert.deepEqual(Array.from(VersionHistory._versions, v => v.version), ["shared", "only-B"]);
    assert.match(history.innerHTML, /only-B/);
  });
}

test("rename completion refreshes a newer load of the same project", async () => {
  const { Project, Api, VersionHistory, getElementById } = makeApp();
  Api.getProject = id => Promise.resolve({ data: { project_id: id } });
  const names = ["shared", "shared", "renamed"];
  Api.listVersions = () => Promise.resolve({ data: [version(names.shift())] });
  const select = getElementById("project-select");
  const history = getElementById("version-history-list");
  select.value = "A";
  await Project.get("A");
  await flush();

  const button = history.buttons.get(".version-rename-btn")[0];
  const pending = deferred();
  Api.renameSBOM = () => pending.promise;
  const mutation = button.fire("click");
  await VersionHistory.load(); // This response still predates the rename.
  pending.resolve({ data: { version: "renamed" } });
  await mutation;
  await flush();

  assert.deepEqual(Array.from(VersionHistory._versions, v => v.version), ["renamed"]);
  assert.match(history.innerHTML, /renamed/);
});

test("renamed tab keeps its icon and can be closed and reopened", async () => {
  const { Sbom, State, getElementById } = makeApp();
  Sbom.addTab("old", false);
  const tabs = getElementById("file-tabs");
  const tab = tabs.children[0];
  const [icon, label, close] = tab.children;
  const svg = icon.innerHTML;

  Sbom.renameTab("old", "new");
  assert.equal(tab.dataset.version, "new");
  assert.equal(label.textContent, "new");
  assert.equal(icon.innerHTML, svg);
  assert.equal(State.uploadedFiles.has("old"), false);
  await close.fire("click", { stopPropagation() {} });
  assert.equal(State.uploadedFiles.has("new"), false);
  assert.equal(tabs.children.length, 0);

  Sbom.addTab("new", false);
  assert.equal(tabs.children[0].dataset.version, "new");
});

test("deleting the last project clears its tabs and version history", async () => {
  const { Project, State, Api, Sbom, getElementById } = makeApp();
  State.projectID = "A";
  getElementById("project-select").value = "A";
  Sbom.addTab("shared", false);
  Api.deleteProject = () => Promise.resolve({ data: {} });
  Api.getProjects = () => Promise.resolve({ data: { projects: [] } });

  await Project.delete("A");

  assert.equal(State.projectID, null);
  assert.equal(getElementById("project-select").value, "");
  assert.equal(State.uploadedFiles.size, 0);
  assert.equal(getElementById("file-tabs").children.length, 0);
  assert.match(getElementById("version-history-list").innerHTML, /尚未選擇專案/);
  assert.equal(getElementById("project-current").textContent, "");
});

test("changing the selected file cancels an in-flight preview and ignores its result", async () => {
  const { State, Api, SbomModal, getElementById } = makeApp();
  const pending = deferred();
  const old = { name: "old.json" };
  const next = { name: "next.json" };
  let signal;
  let rendered = false;

  State.projectID = "A";
  SbomModal.open();
  const fileInput = getElementById("sbom-file-input");
  fileInput.files = [old];
  Api.previewSBOM = (_project, _file, activeSignal) => {
    signal = activeSignal;
    return pending.promise;
  };
  SbomModal._renderPreviewTopology = () => { rendered = true; };
  const response = SbomModal.preview();
  fileInput.files = [next];
  SbomModal._onFileSelected(fileInput.files);
  pending.resolve({ ok: true, json: async () => ({ data: {
    bom_result: {}, preview_token: "old-token", summary: { component_count: 1, vuln_count: 0 },
  } }) });
  await response;

  assert.equal(signal?.aborted, true);
  assert.equal(rendered, false);
  assert.equal(getElementById("sbom-modal-preview-btn").disabled, false);
  assert.equal(getElementById("sbom-modal-step1-error").classList.contains("hidden"), true);
});

test("Enter while saving does not start a second version creation", async () => {
  const { State, Api, SbomModal, getElementById } = makeApp();
  const pending = deferred();
  let calls = 0;
  Api.commitSBOM = () => {
    calls++;
    return pending.promise;
  };
  State.projectID = "A";
  Object.assign(SbomModal, { _projectID: "A", _bomResult: {}, _sha256: "hash", _previewToken: "token" });
  getElementById("sbom-version-input").value = "version";
  const first = SbomModal.commit();
  const second = SbomModal.commit();
  pending.resolve({ ok: false, json: async () => ({ error: "failure" }) });
  await Promise.all([first, second]);
  assert.equal(calls, 1);
});


test("closing the upload dialog cancels the request and drops a late preview failure", async () => {
  const { State, Api, SbomModal, getElementById } = makeApp();
  let reject;
  const pending = new Promise((_resolve, rejectPromise) => { reject = rejectPromise; });
  let signal;
  Api.previewSBOM = (_project, _file, activeSignal) => {
    signal = activeSignal;
    return pending;
  };
  State.projectID = "A";
  SbomModal.open();
  getElementById("sbom-file-input").files = [{ name: "example.json" }];
  const response = SbomModal.preview();
  SbomModal.close();
  reject(new Error("Late failure"));
  await response;

  assert.equal(signal.aborted, true);
  assert.equal(getElementById("sbom-modal").classList.contains("hidden"), true);
  assert.equal(getElementById("sbom-modal-step1-error").classList.contains("hidden"), true);
});

for (const action of ["rename", "delete"]) {
  test(`version ${action} updates an open analysis tab after switching to diff`, async () => {
    const { Project, Api, MainTab, Sbom, getElementById } = makeApp();
    Api.getProject = async id => ({ data: { project_id: id } });
    Api.listVersions = async () => ({ data: [version("old")] });
    getElementById("project-select").value = "A";
    await Project.get("A");
    await flush();
    Sbom.addTab("old", false);

    const mutation = deferred();
    Api[action === "rename" ? "renameSBOM" : "deleteSBOM"] = () => mutation.promise;
    const history = getElementById("version-history-list");
    const changed = history.buttons.get(`.version-${action}-btn`)[0].fire("click");
    MainTab.show("diff");
    mutation.resolve(action === "rename" ? { data: { version: "renamed" } } : {});
    await changed;

    assert.deepEqual(
      getElementById("file-tabs").children.map(tab => tab.dataset.version),
      action === "rename" ? ["renamed"] : [],
    );
  });
}
