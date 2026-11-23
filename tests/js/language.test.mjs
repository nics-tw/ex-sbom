// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const script = readFileSync(new URL("../../static/js/language.js", import.meta.url), "utf8");

function openPage(browserLanguage, storage) {
  const clicks = new Map();
  const skipLink = { dataset: { shellI18n: "skipToMain" } };
  const document = {
    body: { dataset: {} },
    documentElement: {},
    querySelectorAll: selector => selector === "[data-shell-i18n]" ? [skipLink] : [],
    getElementById: id => ({
      classList: { toggle() {} },
      setAttribute() {},
      addEventListener: (_, fn) => clicks.set(id, fn),
    }),
  };
  const rendered = [];
  const events = new Map();
  vm.runInNewContext(script + "\nbindLanguageSwitcher(lang => rendered.push(lang));", {
    navigator: { language: browserLanguage }, window: { localStorage: storage, addEventListener: (name, fn) => events.set(name, fn) }, document, rendered,
  });
  return { rendered, restore: () => events.get("pageshow")({ persisted: true }), select: lang => clicks.get("lang-" + lang)(), html: document.documentElement, skipLink };
}

test("only explicit choices persist and either language survives a new page", () => {
  const entries = new Map();
  const storage = { getItem: key => entries.get(key), setItem: (key, val) => entries.set(key, val) };
  const first = openPage("en-US", storage);
  assert.deepEqual(first.rendered, ["en"]);
  assert.equal(entries.size, 0);
  first.select("zh");
  const next = openPage("en-US", storage);
  assert.equal(next.html.lang, "zh-Hant");
  assert.equal(next.skipLink.textContent, "跳至主要內容");
  next.select("en");
  assert.deepEqual(openPage("zh-TW", storage).rendered, ["en"]);
});

test("invalid or inaccessible storage preserves browser fallback and manual switching", () => {
  const blocked = () => { throw new Error("Storage unavailable"); };
  for (const getItem of [blocked, () => "invalid"]) {
    const page = openPage("zh-TW", { getItem, setItem: blocked });
    page.select("en");
    assert.deepEqual(page.rendered, ["zh", "en"]);
    assert.equal(page.html.lang, "en");
  }
});

test("restoring a cached page picks up a later selection only when it changed", () => {
  const entries = new Map();
  const storage = { getItem: key => entries.get(key), setItem: (key, val) => entries.set(key, val) };
  const home = openPage("en-US", storage);
  openPage("en-US", storage).select("zh");
  home.restore();
  home.restore();
  assert.deepEqual(home.rendered, ["en", "zh"]);
  assert.equal(home.html.lang, "zh-Hant");
});
