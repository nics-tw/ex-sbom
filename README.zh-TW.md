# ex-sbom

ex-sbom, 簡稱 Explorer of SBOM，是一個實驗性的 SBOM 分析可視化工具。
目前仍處於開發的早期階段，有部分功能並沒有相當穩定。（我們認為目前的狀態處於 pre-alpha 階段）歡迎任何建議與改善方向。

![GitHub license](https://img.shields.io/github/license/nics-tw/ex-sbom)

[![Go Reference](https://pkg.go.dev/badge/github.com/nics-tw/ex-sbom.svg)](https://pkg.go.dev/github.com/nics-tw/ex-sbom)

## 我該怎麼使用它

1. 下載 Release 中的執行檔(推薦)，或是自行編譯此專案
2. 執行它，就可以開始使用了。

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
- 計劃修復軟體中的漏洞

## 為什麼我們要做這個專案

最初，我們在尋找一個可以把 SBOM 和其中的漏洞進行視覺化的工具（事實上，市面上無論是開源或者是商用軟體，提供的功能其實都並未完全滿足我們的需求。但這不代表其他工具就是不好的，其中也有許多是讓人驚艷的整合軟體，有興趣的話建議可以稍微查詢一下）。經過一番思考，我們認為如果能夠將 SBOM 資料與漏洞的影響鏈進行視覺化，或許可以幫助使用者從不同面向了解到供應鏈攻擊是如何影響到系統本身。因此，我們決定自己動手做這個工具。

在從外部來源檢索 SBOM 資料的部分，我們認為 [osv-scanner](https://github.com/google/osv-scanner) 與 [osv-scalibr](https://github.com/google/osv-scalibr) 提供了相當完整的功能，因此我們決定採用這兩個專案的部分工具來撈取 SBOM 中元件的資料，特別是與 CVE 漏洞相關的資訊。因此，我們要對這兩個專案的作者們、以及開源軟體社群的每一位成員表達最誠摯的感謝。

## 安裝
0. 安裝 Golang，版本 1.24 或更高版本。

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

## API 文件
我們使用 Postman 來記錄 API 文件。您可以在根目錄中找到名為 `ex-sbom.postman_collection.json` 的文件。您可以將此文件匯入 Postman 以查看 API 文件。

## 貢獻
如果您想要對此專案提出任何形式的貢獻（例如：錯誤回報、提出 PR 等等），請參考 [CONTRIBUTING.md](CONTRIBUTING.md) 文件以了解如何開始。

順帶一提，當你在使用此工具時，請務必遵守我們的 [Code of Conduct](CODE_OF_CONDUCT.md) 並確保符合 [License](LICENSE)的授權內容。
   