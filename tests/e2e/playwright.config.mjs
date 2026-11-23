// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT

// 從儲存庫根目錄安裝依賴及建置測試服務。
// npm --prefix tests/e2e ci
// (cd tests/e2e && npx playwright install chromium)
// go test -tags e2e -c -o /tmp/ex-sbom-browser.test .
// EX_SBOM_E2E_BINARY=/tmp/ex-sbom-browser.test npm --prefix tests/e2e test
// 將 test 換成 run test:smoke 可只執行基本煙霧測試。
// 測試使用暫存 DuckDB、正式 HTTP 路由、固定的 OSV 回應及測試用樣式。

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  forbidOnly: Boolean(process.env.CI),
  workers: 1,
  reporter: "list",
  use: {
    channel: process.env.EX_SBOM_E2E_CHROME_CHANNEL || undefined,
    locale: "en-US",
    acceptDownloads: true,
    trace: "retain-on-failure",
  },
});
