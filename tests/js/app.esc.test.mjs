// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

// DOM XSS regression tests for the safe-output helpers in app.js.
// Zero-dependency: run with `node --test "tests/js/*.test.mjs"`.
//
// app.js is a plain browser script, so we evaluate it in a vm sandbox with a
// stub document/navigator and pull out the top-level function declarations.

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

const sandbox = {
  document: { addEventListener() {}, getElementById: () => null },
  navigator: { language: "en" },
  window: {},
  console,
};
vm.createContext(sandbox);
vm.runInContext(appJs, sandbox);

const { esc, _renderMarkdown } = sandbox;

test("esc and _renderMarkdown are exposed by app.js", () => {
  assert.equal(typeof esc, "function");
  assert.equal(typeof _renderMarkdown, "function");
});

test("esc neutralizes HTML element payloads", () => {
  const out = esc('<img src=x onerror=alert(1)><script>alert(2)</script>');
  assert.ok(!out.includes("<"), out);
  assert.ok(!out.includes(">"), out);
  assert.equal(
    out,
    "&lt;img src=x onerror=alert(1)&gt;&lt;script&gt;alert(2)&lt;/script&gt;",
  );
});

test("esc neutralizes attribute-breaking payloads", () => {
  // e.g. value interpolated into data-sbom="..." or <option value="...">
  const out = esc('" onmouseover="alert(1)');
  assert.ok(!out.includes('"'), out);
  assert.equal(out, "&quot; onmouseover=&quot;alert(1)");

  const single = esc("' autofocus onfocus='alert(1)");
  assert.ok(!single.includes("'"), single);
});

test("esc handles non-string and nullish values", () => {
  assert.equal(esc(null), "");
  assert.equal(esc(undefined), "");
  assert.equal(esc(123), "123");
  assert.equal(esc({ toString: () => "<x>" }), "&lt;x&gt;");
});

test("_renderMarkdown escapes before adding markup", () => {
  const out = _renderMarkdown('<script>alert(1)</script> **bold**');
  assert.ok(!out.includes("<script>"), out);
  assert.ok(out.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), out);
  assert.ok(out.includes("<strong>bold</strong>"), out);
});

test("_renderMarkdown blocks javascript: and data: link schemes", () => {
  const js = _renderMarkdown("[click](javascript:alert(1))");
  assert.ok(!js.includes("javascript:"), js);
  assert.ok(!js.includes("<a "), js);

  const data = _renderMarkdown("[click](data:text/html,<script>alert(1)</script>)");
  assert.ok(!data.includes("<a "), data);

  const https = _renderMarkdown("[ok](https://example.com/x)");
  assert.ok(https.includes('<a href="https://example.com/x"'), https);
});

test("_renderMarkdown link text/href cannot break out of the attribute", () => {
  const out = _renderMarkdown('[x" onmouseover="alert(1)](https://e.com/"onload="x)');
  // esc() runs before link markup is generated, so quotes are already entities
  assert.ok(!out.includes('" onmouseover="'), out);
  assert.ok(!out.includes('"onload="'), out);
});
