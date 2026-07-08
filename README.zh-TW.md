# ex-sbom

ex-sbom，簡稱 Explorer of SBOM，是一個用於 SBOM 掃描結果視覺化、分析與版本控管的本地網頁工具。

![GitHub license](https://img.shields.io/github/license/nics-tw/ex-sbom)

[![Go Reference](https://pkg.go.dev/badge/github.com/nics-tw/ex-sbom.svg)](https://pkg.go.dev/github.com/nics-tw/ex-sbom)

ex-sbom 封裝為單一執行檔，內嵌應用程式頁面、本地 JavaScript 與靜態資源；使用者無需架設伺服器即可直接執行，啟動後會自動於瀏覽器開啟本地網頁介面。弱點資料來源採用 OSV（Open Source Vulnerabilities）生態系，透過 osv-scanner 函式庫取得，無需額外的 API 訂閱。

> 注意：由於 osv-scanner 需連線至 OSV API 取得弱點資料，因此在啟動時以及上傳 SBOM 時皆需要可用的網際網路連線。

## 我該怎麼使用它

1. 下載 Release 中的執行檔（推薦），或是自行編譯此專案。
2. 執行它，瀏覽器會自動開啟本地網頁介面 `http://localhost:8080`。
3. 建立或選擇一個專案。專案可用來彙整同一產品或系統的多個 SBOM 版本。
4. 在 **SBOM 分析** 分頁新增版本，上傳 CycloneDX JSON 或 SPDX JSON 檔案。
5. 預覽解析結果，輸入版本名稱並儲存。
6. 探索相依性圖、跨版本搜尋、在 **Diff 比對** 分頁比較兩個版本，或匯出 PDF 報告。

## 功能特色

- **多專案管理**：將 SBOM 組織到具名專案，可依軟體產品或系統分類管理。
- **雙格式匯入**：支援解析並正規化 CycloneDX JSON 與 SPDX JSON，轉換為統一的內部表示。
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
   （如果是本地開發，您可以直接執行 `go run main.go` 來啟動它。）

## 環境設定

您可以透過以下環境變數來設定此工具：

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `PORT` | `8080` | 本地網頁伺服器監聽的連接埠。 |
| `AUTO_OPEN_BROWSER` | `true` | 設為 `false` 可在啟動時不自動開啟瀏覽器。 |
| `DB_PATH` | 依作業系統而定（見下方） | DuckDB 資料庫檔案的路徑。 |

預設情況下，資料庫檔案會儲存於各平台原生的設定目錄：
- macOS：`~/Library/Application Support/ex-sbom/data.duckdb`
- Linux：`~/.config/ex-sbom/data.duckdb`
- Windows：`%AppData%\ex-sbom\data.duckdb`

## API 文件
我們使用 Postman 來記錄 API 文件。您可以在根目錄中找到名為 `ex-sbom.postman_collection.json` 的文件。您可以將此文件匯入 Postman 以查看 API 文件。

## 貢獻
如果您想要對此專案提出任何形式的貢獻（例如：錯誤回報、提出 PR 等等），請參考 [CONTRIBUTING.md](CONTRIBUTING.md) 文件以了解如何開始。

順帶一提，當你在使用此工具時，請務必遵守我們的 [Code of Conduct](CODE_OF_CONDUCT.md) 並確保符合 [License](LICENSE)的授權內容。
