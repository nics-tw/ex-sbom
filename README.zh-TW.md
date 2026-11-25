# ex-sbom

ex-sbom，簡稱 Explorer of SBOM，是一個用於 SBOM 掃描結果視覺化、分析與版本控管的本地網頁工具。

![GitHub license](https://img.shields.io/github/license/nics-tw/ex-sbom)

[![Go Reference](https://pkg.go.dev/badge/github.com/nics-tw/ex-sbom.svg)](https://pkg.go.dev/github.com/nics-tw/ex-sbom)

ex-sbom 封裝為單一執行檔，內嵌應用程式頁面、本地 JavaScript 與靜態資源；使用者無需架設伺服器即可直接執行，啟動後會自動於瀏覽器開啟本地網頁介面。弱點資料來源採用 OSV（Open Source Vulnerabilities）生態系，透過 osv-scanner 函式庫取得，無需額外的 API 訂閱。

> 注意：由於 osv-scanner 需連線至 OSV API 取得弱點資料，因此在啟動時以及上傳 SBOM 時皆需要可用的網際網路連線。

若環境限制對外連線，請允許工具透過 HTTPS 連線至下列主機。

- `api.osv.dev` 用於啟動時的連線檢查與 OSV 弱點查詢。
- `api.first.org` 用於從 `/data/v1/epss` 取得最新 EPSS 分數。
- `www.cisa.gov` 用於從 `/sites/default/files/feeds/known_exploited_vulnerabilities.json` 取得 KEV 清單。

## 我該怎麼使用它

1. 從 [Releases](https://github.com/nics-tw/ex-sbom/releases) 下載對應平台的執行檔。Windows x64 直接下載 `ex-sbom.exe`。
2. 執行它，瀏覽器會自動開啟本地網頁介面 `http://localhost:8080`。
3. 建立或選擇一個專案。專案可用來彙整同一產品或系統的多個 SBOM 版本。
4. 在 **SBOM 分析** 分頁新增版本，上傳 CycloneDX JSON 或 SPDX JSON 檔案。
5. 預覽解析結果，輸入版本名稱並儲存。
6. 探索相依性圖、跨版本搜尋，或在 **Diff 比對** 分頁比較兩個版本。要匯出報告，選好已儲存的版本後點 **下載 PDF 報告**。由下方發布流程建置的執行檔已內含產生器與字型，會直接產出標籤式 PDF。

## 功能特色

- **多專案管理**：將 SBOM 組織到具名專案，可依軟體產品或系統分類管理。
- **雙格式匯入**：支援解析並正規化 CycloneDX JSON 與 SPDX JSON，轉換為統一的內部表示。
  CycloneDX JSON 可直接讀取至 1.7。檔案宣告較新版本時，ex-sbom 會以 1.7 相容模式嘗試匯入，可能略過 1.7 之後新增的欄位。
- **相依性圖形視覺化**：逐層展示完整相依樹，直觀呈現不同元件之間的關係。
- **弱點影響鏈**：透過反向相依遍歷，呈現有弱點的元件如何沿著供應鏈影響系統中的其他元件。
- **版本控制**：每次掃描結果以版本為單位持久化儲存，保留歷史紀錄以供追溯與比對。
- **跨版本差異比對（diff）**：比較同一專案內的兩份 SBOM，依相依層級列出新增、移除、變更的元件，並附帶弱點彙總指標。
- **跨版本搜尋**：可在專案內所有 SBOM 版本中，以元件名稱、CVE ID 或弱點摘要搜尋，並定位其出現於哪些版本。
- **豐富的弱點指標**：檢視元件的 CVE、CVSS、EPSS 及 LEV（在野遭利用可能性）等資訊。
- **元件與授權資訊**：查看每個元件的詳細資訊與授權（License）資料，協助規劃弱點修復。
- **PDF 報告輸出**：針對任一 SBOM 的弱點發現，產出可攜帶的 PDF 快照。
- **本地資料持久化**：已處理的結果儲存於內嵌的 DuckDB 資料庫，啟動時自動載回記憶體。

## 用途

- 工具的首頁提供將 SBOM 檔案進行視覺化的介面
- 透過依賴關係圖，您可以查看不同元件之間的關係
- 此外，系統中漏洞於外部依賴性的供應鏈將透過視覺化的方式呈現和分析，幫助您了解系統中的潛在風險
- 除了視覺化之外，還可以查看每個組件的詳細資訊，這可能有助於您計劃漏洞的修復工作

## 這個工具適合誰使用
此工具旨在為開發人員、安全工程師以及任何希望分析其軟體專案 SBOM 的人員提供幫助。它可以幫助您：
- 將您的軟體專案的 SBOM 進行視覺化
- 了解軟體中不同組件之間的關係
- 分析軟體中的漏洞及其對軟體外部依賴性供應鏈的影響
- 追蹤元件與弱點在各版本間的變化
- 計劃修復軟體中的漏洞

## 為什麼我們要做這個專案

最初，我們在尋找一個可以把 SBOM 和其中的漏洞進行視覺化的工具（事實上，市面上無論是開源或者是商用軟體，提供的功能其實都並未完全滿足我們的需求。但這不代表其他工具就是不好的，其中也有許多是讓人驚艷的整合軟體，有興趣的話建議可以稍微查詢一下）。經過一番思考，我們認為如果能夠將 SBOM 資料與漏洞的影響鏈進行視覺化，或許可以幫助使用者從不同面向了解到供應鏈攻擊是如何影響到系統本身。此外，現有工具也缺乏以時間點為維度對掃描結果進行版本控制、以及跨版本視覺化差異比對的能力，因此我們決定自己動手做這個工具，將 SBOM 匯入、弱點掃描、版本控制與圖形化分析整合於同一工具中。

在從外部來源檢索 SBOM 資料的部分，我們認為 [osv-scanner](https://github.com/google/osv-scanner) 與 [osv-scalibr](https://github.com/google/osv-scalibr) 提供了相當完整的功能，因此我們決定採用這兩個專案的部分工具來撈取 SBOM 中元件的資料，特別是與 CVE 漏洞相關的資訊。因此，我們要對這兩個專案的作者們、以及開源軟體社群的每一位成員表達最誠摯的感謝。

## 安裝
0. 安裝 Golang，版本 1.25 或更高版本。

   對於 MacOS，您可以使用 Homebrew 來安裝 Golang。如果您尚未安裝 Homebrew，可以在 [這裡](https://brew.sh/) 找到安裝說明。
   ```bash
   brew install go
   ```
1. 複製此 repo 至您要執行的電腦：
   ```bash
   git clone git@github.com:nics-tw/ex-sbom.git
   ```
2. 執行以下命令以安裝所需的依賴項：
   ```bash
   go mod tidy
   ```
3. 編譯專案：
   ```bash
   go build -o ex-sbom
   ```
4. 執行專案：
   ```bash
   ./ex-sbom
   ```
5. 您的瀏覽器應該會自動打開一個新標籤頁，網址為 `http://localhost:8080`。如果沒有自動打開，您可以手動在瀏覽器中輸入此網址。
本機開發時，可執行 `go run .` 啟動服務。

從原始碼執行上述 `go build`，可使用開發用 PDF 產生器。正式發布版的 Windows x64、macOS ARM64、Linux ARM64 與 Linux x64 執行檔由 [GitHub Actions 建置與驗證](.github/workflows/ci.yml)，並內嵌產生器與字型。

## 環境設定

您可以透過以下環境變數來設定此工具：

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `PORT` | `8080` | 本地網頁伺服器監聽的連接埠。 |
| `BIND_ADDR` | `127.0.0.1` | 僅接受本機 loopback IP，例如 `127.0.0.1` 或 `::1`。其他位址會被拒絕。 |
| `AUTO_OPEN_BROWSER` | `true` | 設為 `false` 可在啟動時不自動開啟瀏覽器。 |
| `DB_PATH` | 依作業系統而定（見下方） | DuckDB 資料庫檔案的路徑。 |
| `EX_SBOM_PDF_TIMEOUT` | `30s` | 選填。標籤式 PDF 匯出時間上限，包含等待產生器的時間。可設為 `60s` 等時長。 |
| `EX_SBOM_PDF_CACHE_DIR` | 作業系統使用者快取目錄下的 `ex-sbom/typst` | 選填。可執行內嵌產生器的絕對路徑。請指定由程式執行帳號擁有、僅限該帳號與系統管理者存取的目錄。 |
| `EPSS_ARCHIVE_DIR` | — | 選填。存放官方每日 `epss_scores-YYYY-MM-DD.csv.gz` 的目錄。請保留自 2021-04-14 起至前一個 UTC 日的封存。每次匯入最多花 3 秒查詢封存，檔案未變更時可重用記憶體中的查詢結果。若已驗證首次評分日期，報告可用查得的 30 天視窗分數計算 LEV 下界。若無法驗證該日期，報告會標示 LEV 未取得。 |
| `CVE_RESERVATIONS_FILE` | — | 選填。指定本機 JSON 檔，內容為 CVE 識別碼對應官方保留日期（`YYYY-MM-DD`）。CVE 保留日前的歷史封存缺檔不影響該 CVE。請使用 CVE Program 整批封存的日期。 |

### 歷史 EPSS 與 LEV

可選的封存索引適合匯入時需要查詢多年歷史 LEV 的情境。維運人員可在離線環境用同一個執行檔預先建立索引。

```bash
./ex-sbom lev-index build --archive /path/to/epss --as-of 2026-11-22 --output /private/ex-sbom/epss-2026-11-22 --reservations /path/to/reservations.json
```

輸出路徑須尚未使用，且位於服務帳號可控的目錄。指令會複製來源資料，完整建置後發布為唯讀快照。沒有可信的保留日期檔時省略 `--reservations`。將 `EPSS_ARCHIVE_DIR` 指向新快照。有保留日期時，另將 `CVE_RESERVATIONS_FILE` 指向快照內的 `cve-reservations.json`。匯入以掃描時間的前一個 UTC 日為截日。索引不符或無法使用時，可在三秒預算剩餘時間內查詢原始封存。LEV 分為完整值、下界與未取得。

截日更新、日檔補齊或來源修正時先建立新快照，再一起切換兩個設定並重啟程式。需要回復時，以相同步驟指回先前驗證過的快照。已儲存的報告使用該次掃描留下的 LEV 證據。

46 個 CVE 的選用驗收可執行 `go test -v -count=1 -tags unit -run '^TestHistoricalLEVOfficialArchiveAcceptance$' ./internal/service/sbom`。將 `EX_SBOM_LEV_ACCEPT_SNAPSHOT`、`EX_SBOM_LEV_ACCEPT_SOURCE`、`EX_SBOM_LEV_ACCEPT_CUTOFF`、`EX_SBOM_LEV_ACCEPT_CVES` 分別設為快照、原始封存、UTC 截日及包含 46 個不同 CVE 的文字檔。使用保留日期檔時設定 `EX_SBOM_LEV_ACCEPT_RESERVATIONS`。若要保存逐筆結果，將 `EX_SBOM_LEV_ACCEPT_REPORT` 指向新的私有檔案路徑。

預設情況下，資料庫檔案會儲存於各平台原生的設定目錄：
- macOS：`~/Library/Application Support/ex-sbom/data.duckdb`
- Linux：`~/.config/ex-sbom/data.duckdb`
- Windows：`%AppData%\ex-sbom\data.duckdb`

刪除專案後，應用程式會隱藏該專案及其 SBOM；資料列仍保留在 DuckDB 檔案中，但應用程式沒有還原功能。

## API 文件
我們使用 Postman 來記錄 API 文件。您可以在根目錄中找到名為 `ex-sbom.postman_collection.json` 的文件。您可以將此文件匯入 Postman 以查看 API 文件。

### 從舊版 API 遷移

HTTP API 已改以「專案 / 版本」為核心重新設計。由於唯一支援的 client 是與後端包在同一個執行檔內的網頁介面，舊的路由已直接移除，沒有過渡期。若您有針對舊 API 撰寫的腳本，請依下表調整：

| 舊路由 | 新路由 |
|--------|--------|
| `POST /sbom/upload` | 先 `POST /projects/:id/sboms/preview`（解析與掃描），再 `POST /projects/:id/sboms`（存成版本） |
| `DELETE /sbom/delete` | `DELETE /projects/:id/sboms/:name` |
| `GET /sbom/report/:name` | `GET /projects/:id/sboms/:name/report` |
| `GET /topology/get_list_by_level` | `GET /projects/:id/sboms/:name/topology` |
| `GET /topology/relations` | `GET /projects/:id/sboms/:name/topology/relations` |
| `GET /topology/component` | `GET /projects/:id/sboms/:name/topology/component` |
| `GET /topology/get_component_vuln_dep` | `GET /projects/:id/sboms/:name/topology/component/vuln-dep` |

所有 SBOM 現在都隸屬於某個專案：請先以 `GET /projects` 取得專案清單（首次啟動時會自動建立一個 `default` 專案），或以 `POST /projects` 建立新專案，再將其 `id` 帶入上述路由。`:name` 為儲存時指定的版本名稱。若專案 id 不存在，會回傳 `404`。

## 測試

所有 Go 測試檔都帶有 build tag，直接執行 `go test ./...` 不會跑到任何測試，請明確指定 tag：

```bash
go build ./...
go test -tags "unit integration" ./...
node --test "tests/js/*.test.mjs"   # 前端測試，需 Node.js 22 以上，無額外相依套件
```

CI（`.github/workflows/ci.yml`）會在每個 pull request 執行相同的指令。

## 貢獻
如果您想要對此專案提出任何形式的貢獻（例如：錯誤回報、提出 PR 等等），請參考 [CONTRIBUTING.md](CONTRIBUTING.md) 文件以了解如何開始。

順帶一提，當你在使用此工具時，請務必遵守我們的 [Code of Conduct](CODE_OF_CONDUCT.md) 並確保符合 [License](LICENSE)的授權內容。
