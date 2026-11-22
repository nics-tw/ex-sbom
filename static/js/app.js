    // ═══════════════════════════════════════════════════════════════════════════
    // Project owns projectID, Sbom owns the open and active tabs, and i18n owns language.
    // Request ownership stays with each feature, alongside its render and reset logic.
    // ═══════════════════════════════════════════════════════════════════════════
    const State = {
      projectID: null,
      uploadedFiles: new Set(),
      activeTab: null,
      language: "en",
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // i18n — translations and language switching
    // ═══════════════════════════════════════════════════════════════════════════
    const i18n = {
      data: {
        en: {
          appTitle: "ex-sbom",
          appDescription: "SBOM Explorer, designed by NICS-ra",
          selectFiles: "Select SBOM Files",
          selectedFiles: "Selected files:",
          uploadedFiles: "Selected SBOM Versions",
          noFilesUploaded: "No files selected yet",
          uploading: "Processing {0}...",
          uploadedSuccessfully: "{0} processed successfully",
          uploadFailed: "{0}: {1}",
          errorReadingFile: "Error reading file",
          warningOverwrite: "Warning: the previous <strong>{0}</strong> will be overwritten since the file names are same.",
          downloadReport: "Download PDF Report",
          reportPreparing: "Preparing the PDF report…",
          reportDownloadStarted: "Download requested for {0}. You can find it in your browser’s downloads.",
          reportDownloadError: "Could not create the PDF report. Please try again.",
          delete: "Delete",
          deletedSuccessfully: "{0} deleted successfully",
          errorDeleting: "Error deleting file: {0}",
          failedToDelete: "Failed to delete file: {0}",
          loadingTopology: "Loading topology data...",
          failedToLoadTopology: "Failed to load topology data",
          noTopologyData: "No topology data available for this SBOM",
          rootLevel: "Root Level",
          level: "Level {0}",
          topLevelDependencies: "(Top-level dependencies, which is directly import as package/component)",
          componentsCount: "({0} components)",
          vulnerabilities: "{0} vulnerabilities",
          noVulnerabilities: "No vulnerabilities",
          noComponents: "No components at this level",
          showAll: "Show all {0} components",
          showLess: "Show less",
          unknownError: "Unknown error occurred",
          componentDetails: "Component Details",
          componentName: "Component Name",
          componentVersion: "Version",
          componentLicense: "License",
          vulnerabilityCount: "Vulnerabilities of this component",
          noVulnerabilitiesFound: "No vulnerabilities found for this component",
          vulnerabilityId: "Vulnerability ID",
          cvssScore: "CVSS Score",
          severity: "Severity",
          summary: "Summary",
          details: "Details",
          fixVersion: "Suggest Fix Version",
          otherFixVersions: "Other Available Fix Versions",
          close: "Close",
          loading: "Loading...",
          tutorialBtn: "Tutorial",
          backToMain: "Back to Main",
          dependencyVulnPaths: "Dependency Vulnerability Paths",
          vulnerablePath: "Vulnerability Path {0}",
          vulnerableComponent: "(Vulnerable)",
          suggestUpgradeTo: "Suggest upgrade to version {0}",
          breakingChangeWarning: "Warning: Updating to version {0} includes breaking changes that may require code modifications.",
          severeVulnWarning: "This component contains security vulnerabilities with a CVSS score of 7.0 or higher. The suggested fix version is based on these vulnerabilities.",
          project: "Project",
          newProject: "New project name",
          projectSwitch: "Switch",
          projectRename: "Rename",
          projectDelete: "Delete",
          projectRenamePrompt: "Enter new project name:",
          projectDeleteConfirm: "Delete this project from the app? Its SBOMs will remain in the database.",
          diffFiles: "Diff Files",
          diffSbomTitle: "Compare SBOMs",
          diffSbomA: "SBOM A (before)",
          diffSbomB: "SBOM B (after)",
          diffCompare: "Compare",
          diffSwap: "Swap A ↔ B",
          diffAdded: "Added",
          diffRemoved: "Removed",
          diffChanged: "Changed",
          diffComponent: "Component",
          diffVersionA: "Version (A)",
          diffVersionB: "Version (B)",
          diffVulnsA: "Vulns (A)",
          diffVulnsB: "Vulns (B)",
          diffLevel: "Level",
          diffTotalVulnsA: "Total Vulns (A)",
          diffTotalVulnsB: "Total Vulns (B)",
          diffSevere: "Severe",
          diffNoChanges: "No differences found",
          diffSelectBoth: "Please select two different SBOMs",
          diffVersionsFailed: "Could not load versions. Open the comparison tab again to retry.",
          diffSummary: "Showing {0} additions, {1} removals, {2} changes",
          diffVulns: "Vulns",
        },
        zh: {
          appTitle: "ex-sbom",
          appDescription: "SBOM explorer，由 NICS-ra 設計",
          selectFiles: "選擇 SBOM 檔案",
          selectedFiles: "已選擇的檔案：",
          uploadedFiles: "選擇的 SBOM 版本",
          noFilesUploaded: "尚未上傳檔案",
          uploading: "正在處理 {0}...",
          uploadedSuccessfully: "{0} 的資料彙整完畢",
          uploadFailed: "{0}: {1}",
          errorReadingFile: "讀取檔案錯誤",
          warningOverwrite: "警告：由於檔案名稱相同，之前的 <strong>{0}</strong> 將被覆蓋。",
          downloadReport: "下載 PDF 報告",
          reportPreparing: "正在產製 PDF 報告…",
          reportDownloadStarted: "已交由瀏覽器下載 {0}，請在瀏覽器的下載清單查找。",
          reportDownloadError: "無法產製 PDF 報告，請再試一次。",
          delete: "刪除",
          deletedSuccessfully: "{0} 刪除成功",
          errorDeleting: "刪除檔案錯誤: {0}",
          failedToDelete: "刪除檔案失敗: {0}",
          loadingTopology: "正在處理...",
          failedToLoadTopology: "資料處理失敗",
          noTopologyData: "此 SBOM 沒有足夠的相關資料",
          rootLevel: "直接使用之元件",
          level: "第 {0} 級",
          topLevelDependencies: "（被直接使用於應用程式之元件、工具、或者套件）",
          componentsCount: "（{0} 個元件）",
          vulnerabilities: "{0} 個漏洞",
          noVulnerabilities: "沒有漏洞",
          noComponents: "此層沒有任何元件",
          showAll: "顯示所有 {0} 個元件",
          showLess: "顯示較少",
          unknownError: "發生錯誤",
          componentDetails: "元件詳細資訊",
          componentName: "元件名稱",
          componentVersion: "版本",
          componentLicense: "授權條款",
          vulnerabilityCount: "此元件漏洞數量",
          noVulnerabilitiesFound: "此元件無已知漏洞",
          vulnerabilityId: "漏洞 ID",
          cvssScore: "CVSS 評分",
          severity: "嚴重程度",
          summary: "摘要",
          details: "詳細資訊",
          fixVersion: "建議修復版本",
          otherFixVersions: "其他可用修復版本",
          close: "關閉",
          loading: "載入中...",
          tutorialBtn: "使用教學",
          backToMain: "返回主頁",
          dependencyVulnPaths: "相依性漏洞路徑",
          vulnerablePath: "漏洞路徑 {0}",
          vulnerableComponent: "(有漏洞)",
          suggestUpgradeTo: "建議升級到版本 {0}",
          breakingChangeWarning: "警告：升級到版本 {0} 包含破壞性改動，請依個別情況判斷是否需調整相關程式碼。",
          severeVulnWarning: "此元件內包含 CVSS 評分為 7.0 或以上之資安漏洞，建議修正版本為基於此漏洞計算而來",
          project: "專案",
          newProject: "輸入新專案名稱",
          projectSwitch: "切換",
          projectRename: "重新命名",
          projectDelete: "刪除",
          projectRenamePrompt: "輸入新的專案名稱：",
          projectDeleteConfirm: "確定從應用程式刪除此專案？SBOM 資料仍保留在資料庫。",
          diffFiles: "Diff 檔案",
          diffSbomTitle: "比較 SBOM",
          diffSbomA: "SBOM A（舊版）",
          diffSbomB: "SBOM B（新版）",
          diffCompare: "比較",
          diffSwap: "A ↔ B 交換",
          diffAdded: "新增",
          diffRemoved: "移除",
          diffChanged: "變更",
          diffComponent: "元件",
          diffVersionA: "版本 (A)",
          diffVersionB: "版本 (B)",
          diffVulnsA: "漏洞數 (A)",
          diffVulnsB: "漏洞數 (B)",
          diffLevel: "層級",
          diffTotalVulnsA: "總漏洞數 (A)",
          diffTotalVulnsB: "總漏洞數 (B)",
          diffSevere: "嚴重",
          diffNoChanges: "無差異",
          diffSelectBoth: "請選擇兩個不同的 SBOM",
          diffVersionsFailed: "無法載入版本。請重新開啟差異比對頁籤再試一次。",
          diffSummary: "共 {0} 項新增、{1} 項移除、{2} 項變更",
          diffVulns: "漏洞",
        },
      },

      t(key, ...args) {
        const str = this.data[State.language]?.[key] ?? this.data.en[key] ?? key;
        return str.replace(/{(\d+)}/g, (_, i) => args[i] ?? _);
      },

      apply() {
        document.querySelectorAll("[data-i18n]").forEach(el => {
          const args = el.dataset.i18nArgs ? JSON.parse(el.dataset.i18nArgs) : [];
          el.innerHTML = this.t(el.dataset.i18n, ...args);
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
          el.placeholder = this.t(el.dataset.i18nPlaceholder);
        });
      },

      change(lang) {
        State.language = lang;
        this.apply();
        if (State.activeTab) Sbom.fetchTopology(State.activeTab.dataset.version);
      },
    };

    // Convenience shorthand
    function t(key, ...args) { return i18n.t(key, ...args); }

    // esc HTML-escapes a value before it is interpolated into innerHTML.
    // Every dynamic value coming from SBOM content, filenames, versions,
    // vulnerability data or API errors must go through this.
    function esc(v) {
      return String(v ?? "").replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      }[c]));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PROJECT — project CRUD + UI state sync
    // ═══════════════════════════════════════════════════════════════════════════
    const Project = {
      _list: new RequestSlot(),
      _selection: new RequestSlot(),
      _selectionGen: 0,

      async load(autoLoad = true, selectID = null) {
        const request = this._list.begin();
        const selection = this._selectionGen;
        try {
          const json = await Api.getProjects(request.controller.signal);
          if (!this._list.owns(request)) return;
          const { projects, current } = json.data;
          const sel = document.getElementById("project-select");
          const preferred = selection === this._selectionGen && selectID !== null
            ? String(selectID) : sel.value;
          const selected = (projects || []).some(w => String(w.ID) === preferred)
            ? preferred : String((projects || []).find(w => w.Name === current)?.ID ?? projects?.[0]?.ID ?? "");
          sel.innerHTML = (projects || [])
            .map(w => `<option value="${esc(w.ID)}"${String(w.ID) === selected ? " selected" : ""}>${esc(w.Name)}</option>`)
            .join("");
          const name = (projects || []).find(w => String(w.ID) === String(State.projectID))?.Name;
          document.getElementById("project-current").textContent = name ? `(${name})` : "";
          if (autoLoad && selection === this._selectionGen) {
            if (sel.value) await this.get(sel.value);
            else this._apply({ data: { project_id: null } });
          }
        } catch (e) {
          if (this._list.owns(request)) console.error("Failed to load projects:", e);
        } finally {
          this._list.finish(request);
        }
      },

      _apply(json) {
        State.projectID = json.data?.project_id ?? null;
        ComponentModal.close();
        SbomModal.close();
        Sbom.reset();
        document.getElementById("upload-status").innerHTML = "";
        Search.clear();

        // Default to SBOM 分析 tab on project load
        MainTab.show("analysis");

        const sel = document.getElementById("project-select");
        const opt = sel.options[sel.selectedIndex];
        document.getElementById("project-current").textContent = State.projectID && opt ? `(${opt.text})` : "";
      },

      async get(id) {
        this._selectionGen++;
        const request = this._selection.begin({ id });
        this._apply({ data: { project_id: null } });
        try {
          const json = await Api.getProject(request.id, request.controller.signal);
          if (!this._selection.owns(request)) return;
          const sel = document.getElementById("project-select");
          if (sel && sel.value !== String(id)) return;
          this._apply(json);
        } catch (e) {
          if (this._selection.owns(request)) console.error("Failed to get project:", e);
        } finally {
          this._selection.finish(request);
        }
      },

      async create(name) {
        const selection = this._selectionGen;
        try {
          const json = await Api.createProject(name);
          const stillSelected = selection === this._selectionGen;
          await this.load(stillSelected, stillSelected ? json.data.project_id : null);
        } catch (e) {
          console.error("Failed to create project:", e);
          if (selection === this._selectionGen) alert(e.message || "Failed to create project");
        }
      },

      async rename(id, name) {
        const selection = this._selectionGen;
        try {
          await Api.renameProject(id, name);
          await this.load(false);
        } catch (e) {
          console.error("Failed to rename project:", e);
          if (selection === this._selectionGen) alert(e.message || "Failed to rename project");
        }
      },

      async delete(id) {
        const selection = this._selectionGen;
        try {
          await Api.deleteProject(id);
          const sel = document.getElementById("project-select");
          const deletedSelection = String(sel.value || State.projectID) === String(id);
          if (deletedSelection) {
            this._selectionGen++;
            this._selection.cancel();
            this._apply({ data: { project_id: null } });
          }
          await this.load(deletedSelection);
        } catch (e) {
          console.error("Failed to delete project:", e);
          if (selection === this._selectionGen) alert(e.message || "Failed to delete project");
        }
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // SBOM — file upload, tabs, topology rendering, delete, report download
    // ═══════════════════════════════════════════════════════════════════════════
    const Sbom = {
      _topology: new RequestSlot(),

      reset() {
        document.getElementById("file-tabs").innerHTML = "";
        State.uploadedFiles.clear();
        this._clearActiveTab();
      },

      _clearActiveTab() {
        this._topology.cancel();
        State.activeTab = null;
        document.getElementById("tab-content").innerHTML =
          `<div id="no-tabs-message" class="text-gray-500 italic" data-i18n="noFilesUploaded">${t("noFilesUploaded")}</div>`;
      },

      // autoSelect=true: also select+fetch the tab (default for user-uploaded files).
      // autoSelect=false: only create the tab element (used on project load to avoid N fetches).
      addTab(fileName, autoSelect = true) {
        const tabsContainer = document.getElementById("file-tabs");
        const noMsg = document.getElementById("no-tabs-message");
        if (noMsg) noMsg.style.display = "none";

        if (State.uploadedFiles.has(fileName)) {
          const existing = Array.from(tabsContainer.children).find(el => el.dataset.version === fileName);
          if (existing) this.selectTab(existing);
          return;
        }

        State.uploadedFiles.add(fileName);
        const tab = document.createElement("div");
        tab.className = "px-4 py-2 border border-gray-300 rounded-t-md mr-2 mb-2 cursor-pointer hover:bg-gray-50 flex items-center gap-2";
        tab.dataset.version = fileName;

        const fileIcon = document.createElement("span");
        fileIcon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-[#009999]" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
        </svg>`;

        const label = document.createElement("span");
        label.className = "sbom-tab-label";
        label.textContent = fileName;

        const closeBtn = document.createElement("span");
        closeBtn.className = "ml-1 text-gray-400 hover:text-gray-700 leading-none";
        closeBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
        </svg>`;
        closeBtn.addEventListener("click", e => {
          e.stopPropagation();
          this.removeTab(tab.dataset.version);
        });

        tab.appendChild(fileIcon);
        tab.appendChild(label);
        tab.appendChild(closeBtn);
        tab.addEventListener("click", () => this.selectTab(tab));
        tabsContainer.appendChild(tab);
        if (autoSelect) this.selectTab(tab);
      },

      selectTab(tabEl) {
        document.getElementById("file-tabs").querySelectorAll("div").forEach(el => el.classList.remove("tab-active"));
        tabEl.classList.add("tab-active");
        State.activeTab = tabEl;

        const fileName = tabEl.dataset.version;
        const content = document.getElementById("tab-content");

        // Build header with buttons programmatically (no inline onclick)
        const header = document.createElement("div");
        header.className = "flex items-center justify-between mb-4";

        const title = document.createElement("div");
        title.className = "text-lg font-medium";
        title.textContent = fileName;

        const btnGroup = document.createElement("div");
        btnGroup.className = "flex gap-2";

        const downloadBtn = document.createElement("button");
        downloadBtn.className = "bg-[#009999] hover:bg-[#19a3a3] text-white py-1 px-3 rounded text-sm flex items-center";
        downloadBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd" />
        </svg><span data-i18n="downloadReport">${t("downloadReport")}</span>`;
        const status = document.createElement("span");
        status.className = "max-w-xs text-sm break-all";
        status.setAttribute("role", "status");
        downloadBtn.addEventListener("click", () => this.downloadReport(fileName, downloadBtn, status));
        btnGroup.appendChild(status);

        btnGroup.appendChild(downloadBtn);
        header.appendChild(title);
        header.appendChild(btnGroup);

        const spinner = document.createElement("div");
        spinner.className = "mt-4 text-gray-600 flex items-center";
        spinner.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="animate-spin h-5 w-5 mr-3 text-[#009999]" viewBox="0 0 24 24" fill="none">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>${t("loadingTopology")}`;

        content.innerHTML = "";
        content.appendChild(header);
        content.appendChild(spinner);

        this.fetchTopology(fileName);
      },

      async downloadReport(version, button, status) {
        const projectID = State.projectID;
        const isCurrent = () => State.projectID === projectID && State.activeTab?.dataset.version === version && button.isConnected;
        button.disabled = true;
        status.textContent = t("reportPreparing");
        try {
          const response = await Api.getReport(projectID, version, State.language);
          if (!response.ok || response.headers.get("Content-Type")?.split(";")[0] !== "application/pdf") {
            throw new Error("PDF report unavailable");
          }
          const filename = this._reportFilename(response.headers.get("Content-Disposition"));
          const pdf = await response.blob();
          if (!isCurrent()) return;
          const url = URL.createObjectURL(pdf);
          try {
            const link = document.createElement("a");
            link.href = url;
            link.download = filename;
            link.click();
          } finally {
            // Give the browser time to start reading the download.
            setTimeout(() => URL.revokeObjectURL(url), 30_000);
          }
          status.textContent = t("reportDownloadStarted", filename);
        } catch {
          if (isCurrent()) status.textContent = t("reportDownloadError");
        } finally {
          button.disabled = false;
        }
      },

      _reportFilename(disposition) {
        if (!disposition) return "sbom_report.pdf";
        const encoded = disposition.match(/;\s*filename\*=UTF-8''([^;]+)/i);
        if (encoded) {
          try {
            return decodeURIComponent(encoded[1]);
          } catch {
            return "sbom_report.pdf";
          }
        }
        const filename = disposition.match(/;\s*filename=(?:"([^"]+)"|([^;]+))/i);
        return filename?.[1] || filename?.[2] || "sbom_report.pdf";
      },

      async fetchTopology(fileName) {
        const req = this._topology.begin({ projectID: State.projectID, tab: State.activeTab, fileName });
        const isCurrent = () => this._topology.owns(req) &&
          State.projectID === req.projectID &&
          State.activeTab === req.tab && req.tab?.dataset.version === req.fileName;

        const content = document.getElementById("tab-content");
        const header = content.querySelector("div:first-child");
        try {
          const json = await Api.getTopology(req.projectID, fileName, req.controller.signal);
          if (!isCurrent()) return;
          if (!json.data) throw new Error("No topology data");
          this._renderTopology(json.data, fileName, header);
        } catch (e) {
          if (e.name === "AbortError" || !isCurrent()) return;
          console.error("Topology error:", e);
          content.innerHTML = "";
          content.appendChild(header);
          const errEl = document.createElement("div");
          errEl.className = "mt-4 p-4 bg-red-50 text-red-600 rounded-md";
          errEl.innerHTML = `<div class="font-medium">${t("failedToLoadTopology")}</div>
            <div class="text-sm mt-1">${esc(e.message) || t("unknownError")}</div>`;
          content.appendChild(errEl);
        } finally {
          this._topology.finish(req);
        }
      },

      _renderTopology(data, fileName, header) {
        const content = document.getElementById("tab-content");
        content.innerHTML = "";
        content.appendChild(header);

        const container = document.createElement("div");
        container.className = "mt-6";

        const sorted = [...data].sort((a, b) => a.level - b.level);
        if (sorted.length === 0) {
          const empty = document.createElement("div");
          empty.className = "text-gray-500 italic";
          empty.textContent = t("noTopologyData");
          container.appendChild(empty);
        } else {
          sorted.forEach(level => container.appendChild(this._buildLevelPanel(level, fileName)));
        }
        content.appendChild(container);
      },

      _buildLevelPanel(level, fileName) {
        const panel = document.createElement("div");
        panel.className = "mb-6 border border-gray-200 rounded-md overflow-hidden";

        // Header row
        const header = document.createElement("div");
        header.className = "bg-gray-50 px-4 py-3 flex items-center justify-between cursor-pointer";

        const titleEl = document.createElement("div");
        titleEl.className = "font-medium";
        if (level.level === 0) {
          titleEl.innerHTML = `${t("rootLevel")} <span class="text-sm font-normal text-gray-500">${t("topLevelDependencies")}</span>`;
        } else {
          titleEl.innerHTML = `${t("level", level.level)} <span class="text-sm font-normal text-gray-500">${t("componentsCount", level.components.length)}</span>`;
        }

        const right = document.createElement("div");
        right.className = "flex items-center space-x-2";

        const badge = document.createElement("div");
        if (level.total_vulns > 0) {
          badge.className = "px-2 py-1 text-xs font-medium bg-[#D9936E] text-red-800 rounded-full";
          badge.textContent = t("vulnerabilities", level.total_vulns);
        } else {
          badge.className = "px-2 py-1 text-xs font-medium bg-[#95D0C0] text-[#231815] rounded-full";
          badge.textContent = t("noVulnerabilities");
        }

        const foldIcon = document.createElement("span");
        foldIcon.className = "text-gray-500";
        foldIcon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 transform transition-transform duration-200" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
        </svg>`;

        right.appendChild(badge);
        right.appendChild(foldIcon);
        header.appendChild(titleEl);
        header.appendChild(right);
        panel.appendChild(header);

        // Components list
        const list = document.createElement("div");
        list.className = "px-4 py-3";
        list.dataset.isExpanded = "true";

        if (level.components.length === 0) {
          const msg = document.createElement("div");
          msg.className = "text-gray-500 italic";
          msg.textContent = t("noComponents");
          list.appendChild(msg);
        } else {
          const grid = document.createElement("div");
          grid.className = "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2";
          const hasMany = level.components.length > 10;

          const render = (showAll) => {
            grid.innerHTML = "";
            const shown = showAll ? level.components : level.components.slice(0, 10);
            shown.forEach(comp => {
              const hasVuln    = Array.isArray(level.components_with_vuln)     && level.components_with_vuln.includes(comp);
              const hasVulnDep = Array.isArray(level.components_with_vuln_dep) && level.components_with_vuln_dep.includes(comp) && !hasVuln;

              const item = document.createElement("div");
              item.className = hasVuln
                ? "px-3 py-2 border border-red-200 bg-red-50 rounded flex items-center cursor-pointer"
                : hasVulnDep
                  ? "px-3 py-2 border border-yellow-200 bg-yellow-50 rounded flex items-center cursor-pointer"
                  : "px-3 py-2 border border-gray-200 bg-white rounded flex items-center cursor-pointer";

              const icon = hasVuln
                ? `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-red-500 mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>`
                : hasVulnDep
                  ? `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-yellow-500 mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>`
                  : `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-gray-400 mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a1 1 0 01-1 1h-2a1 1 0 01-1-1v-2a1 1 0 00-1-1H9a1 1 0 00-1 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V4zm3 1h2v2H7V5zm2 4H7v2h2V9zm2-4h2v2h-2V5zm2 4h-2v2h2V9z" clip-rule="evenodd" /></svg>`;

              item.innerHTML = `${icon}<span class="truncate">${esc(comp)}</span>`;
              item.addEventListener("click", e => { e.stopPropagation(); ComponentModal.show(fileName, comp); });
              grid.appendChild(item);
            });

            if (hasMany) {
              const btn = document.createElement("button");
              btn.className = "mt-4 text-sm text-[#009999] hover:text-[#CCCC00] font-medium flex items-center";
              if (showAll) {
                btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clip-rule="evenodd" /></svg>${t("showLess")}`;
                btn.addEventListener("click", () => render(false));
              } else {
                btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>${t("showAll", level.components.length)}`;
                btn.addEventListener("click", () => render(true));
              }
              grid.appendChild(btn);
            }
          };

          render(false);
          list.appendChild(grid);
        }

        header.addEventListener("click", () => {
          const expanded = list.dataset.isExpanded === "true";
          list.style.display = expanded ? "none" : "block";
          list.dataset.isExpanded = String(!expanded);
          foldIcon.querySelector("svg").classList.toggle("-rotate-90", expanded);
        });

        panel.appendChild(list);
        return panel;
      },

      renameTab(oldVersion, newVersion) {
        const tabsContainer = document.getElementById("file-tabs");
        const tabEl = Array.from(tabsContainer.children).find(el => el.dataset.version === oldVersion);
        if (!tabEl) return;
        tabEl.dataset.version = newVersion;
        const label = tabEl.querySelector(".sbom-tab-label");
        if (label) label.textContent = newVersion;
        if (State.uploadedFiles.has(oldVersion)) {
          State.uploadedFiles.delete(oldVersion);
          State.uploadedFiles.add(newVersion);
        }
        if (State.activeTab === tabEl) this.selectTab(tabEl);
      },

      removeTab(version) {
        const tabsContainer = document.getElementById("file-tabs");
        const tabEl = Array.from(tabsContainer.children).find(el => el.dataset.version === version);
        if (!tabEl) return;
        State.uploadedFiles.delete(version);
        const wasActive = State.activeTab === tabEl;
        tabsContainer.removeChild(tabEl);
        if (wasActive) {
          const next = tabsContainer.querySelector("div");
          if (next) {
            this.selectTab(next);
          } else {
            this._clearActiveTab();
          }
        }
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // COMPONENT MODAL — lazy-created, event delegation for vuln toggles
    // ═══════════════════════════════════════════════════════════════════════════
    const ComponentModal = {
      _details: new RequestSlot(),
      _ensureModal() {
        if (document.getElementById("component-modal")) return;
        const modal = document.createElement("div");
        modal.id = "component-modal";
        modal.className = "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden";
        modal.innerHTML = `
          <div class="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[85vh] flex flex-col">
            <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 class="text-xl font-medium text-gray-800" id="component-modal-title">${t("componentDetails")}</h2>
              <button id="component-modal-close" class="text-gray-500 hover:text-gray-700">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="overflow-y-auto flex-1 p-6" id="component-modal-content"></div>
          </div>`;
        document.body.appendChild(modal);

        document.getElementById("component-modal-close").addEventListener("click", () => this.close());

        // Event delegation for vuln accordion toggles
        document.getElementById("component-modal-content").addEventListener("click", e => {
          const header = e.target.closest("[data-vuln-id]");
          if (!header) return;
          const id = header.dataset.vulnId;
          const details = document.getElementById(`vuln-body-${id}`);
          const chevron = document.getElementById(`vuln-chevron-${id}`);
          if (!details) return;
          const hidden = details.classList.toggle("hidden");
          chevron?.classList.toggle("rotate-180", !hidden);
        });
      },

      close() {
        this._details.cancel();
        document.getElementById("component-modal")?.classList.add("hidden");
      },

      async show(sbomName, component) {
        this._ensureModal();
        const req = this._details.begin({ projectID: State.projectID, sbomName, component });
        const isCurrent = () => this._details.owns(req) &&
          State.projectID === req.projectID &&
          !document.getElementById("component-modal").classList.contains("hidden");
        document.getElementById("component-modal-title").textContent = component;
        document.getElementById("component-modal").classList.remove("hidden");
        document.getElementById("component-modal-content").innerHTML = `
          <div class="flex justify-center items-center py-8">
            <svg class="animate-spin -ml-1 mr-3 h-8 w-8 text-[#009999]" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>${t("loading")}</span>
          </div>`;

        try {
          const [compRes, vulnDepRes] = await Promise.all([
            Api.getComponent(req.projectID, sbomName, component, req.controller.signal).catch(() => null),
            Api.getVulnDep(req.projectID, sbomName, component, req.controller.signal).catch(() => null),
          ]);
          if (!isCurrent()) return;
          if (!compRes?.data) throw new Error("No component data");
          this._renderDetails(compRes.data, vulnDepRes?.data || []);
        } catch (e) {
          if (!isCurrent()) return;
          document.getElementById("component-modal-content").innerHTML = `
            <div class="bg-red-50 text-red-800 p-4 rounded-md">
              <p class="font-medium">Error loading component details</p>
              <p class="mt-2">${esc(e.message) || "Unknown error"}</p>
            </div>`;
        } finally {
          this._details.finish(req);
        }
      },

      showFromLocal(compKey, compInfo, bomResult) {
        this._ensureModal();
        // Local render must not be overwritten by a late in-flight response
        this._details.cancel();
        document.getElementById("component-modal-title").textContent = compInfo.name || compKey;
        document.getElementById("component-modal").classList.remove("hidden");

        // Compute suggested_fix_version from first vuln that has one
        const vulns = compInfo.vulns || [];
        const suggestedFix = vulns.find(v => v.suggest_fix_version)?.suggest_fix_version || "";
        const hasSevere = vulns.some(v => parseFloat(v.cvss_score) >= 7);

        // Compute vuln dep paths from local dependency map
        const vulnComps = Object.entries(bomResult.ComponentInfo || {})
          .filter(([, info]) => (info.vuln_number || 0) > 0)
          .map(([k]) => k);
        const paths = _getVulnDepPaths(compKey, vulnComps, bomResult.Dependency || {});

        this._renderDetails({
          name: compInfo.name || compKey,
          version: compInfo.version,
          vuln_number: compInfo.vuln_number || 0,
          vulns,
          licences: compInfo.licences,
          suggested_fix_version: suggestedFix,
          is_breaking_change: false,
          has_severe_vuln: hasSevere,
        }, paths);
      },

      _renderDetails(comp, vulnDepPaths = []) {
        const { name, version, vuln_number = 0, vulns: _vulns = [],
                suggested_fix_version, is_breaking_change, has_severe_vuln, licences } = comp;
        const vulns = _vulns ?? [];

        const warnIcon = (color) => _warnSVG(color, "", "h-5 w-5 mr-1 flex-shrink-0 mt-0.5");

        let html = `
          <div class="mb-6 pb-6 border-b border-gray-200">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
              <div>
                <h3 class="text-sm font-medium text-gray-500">${t("componentName")}</h3>
                <p class="mt-2 text-lg">${esc(name) || "—"}</p>
              </div>
              <div>
                <h3 class="text-sm font-medium text-gray-500">${t("componentLicense")}</h3>
                <p class="mt-2 text-lg">${esc(licences) || "—"}</p>
              </div>
            </div>
            <div>
              <h3 class="text-sm font-medium text-gray-500">${t("componentVersion")}</h3>
              <div class="mt-2 flex items-center flex-wrap">
                <span class="text-lg">${esc(version) || "—"}</span>
                ${suggested_fix_version ? `
                  <div class="ml-3 flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-[#009999] mr-1" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L9 9.414V13a1 1 0 102 0V9.414l1.293 1.293a1 1 0 001.414-1.414z" clip-rule="evenodd" />
                    </svg>
                    <span class="text-[#009999] font-medium">${t("suggestUpgradeTo", esc(suggested_fix_version))}</span>
                  </div>` : ""}
              </div>
              ${is_breaking_change && suggested_fix_version ? `
                <div class="mt-2 p-2 bg-yellow-50 border border-yellow-200 rounded text-sm flex items-start">
                  ${warnIcon("yellow")}<span class="text-yellow-700">${t("breakingChangeWarning", esc(suggested_fix_version))}</span>
                </div>` : ""}
              ${has_severe_vuln ? `
                <div class="mt-2 p-2 bg-red-50 border border-red-200 rounded text-sm flex items-start">
                  ${warnIcon("red")}<span class="text-red-700">${t("severeVulnWarning")}</span>
                </div>` : ""}
            </div>
          </div>`;

        if (vulnDepPaths.length > 0) {
          html += `<div class="mb-6 pb-6 border-b border-gray-200">
            <h3 class="text-md font-medium mb-3">${t("dependencyVulnPaths")}</h3>
            <div class="space-y-3">`;
          vulnDepPaths.forEach((path, i) => {
            html += `<div class="p-3 bg-yellow-50 border border-yellow-200 rounded-md">
              <div class="flex items-center mb-2">${warnIcon("yellow")}<span class="font-medium">${t("vulnerablePath", i + 1)}</span></div>
              <div class="flex items-center flex-wrap ml-2">
                ${path.path.map((p, j) => {
                  const arrow = j > 0 ? `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-gray-400 mx-1" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" /></svg>` : "";
                  const vuln = p === path.end;
                  return `${arrow}<span class="px-2 py-1 text-sm rounded ${vuln ? "bg-red-100 text-red-800 font-medium" : "bg-gray-100 text-gray-800"}">${esc(p)}</span>`;
                }).join("")}
              </div>
            </div>`;
          });
          html += `</div></div>`;
        }

        html += `<div>
          <div class="flex items-center justify-between">
            <h3 class="text-md font-medium">${t("vulnerabilityCount")}</h3>
            <span class="px-2.5 py-0.5 rounded-full text-sm font-medium ${vuln_number > 0 ? "bg-red-100 text-red-800" : "bg-green-100 text-green-800"}">${vuln_number}</span>
          </div>`;

        if (vulns.length > 0) {
          vulns.forEach((vuln, i) => {
            const severity  = _severityFromCvss(vuln.cvss_score);
            const sevClass  = _severityClass(severity);
            html += `
              <div class="mt-4 border border-gray-200 rounded-lg overflow-hidden">
                <div class="bg-gray-50 px-4 py-3 flex items-center justify-between cursor-pointer" data-vuln-id="${i}">
                  <div class="flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-red-500 mr-2" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                    <span class="font-medium">${esc(vuln.id) || "Unknown"}</span>
                  </div>
                  <div class="flex items-center">
                    ${vuln.cvss_score ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 mr-2">CVSS: ${esc(vuln.cvss_score)}</span>` : ""}
                    ${vuln.epss       ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 mr-2">EPSS: ${esc(vuln.epss)}</span>` : ""}
                    ${vuln.lev        ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 mr-2">LEV: ${esc(vuln.lev)}</span>` : ""}
                    <span class="px-2.5 py-0.5 rounded-full text-xs font-medium ${sevClass}">${severity}</span>
                    <svg id="vuln-chevron-${i}" xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 ml-2 transform transition-transform duration-200" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div id="vuln-body-${i}" class="px-4 py-3 border-t border-gray-200 hidden">
                  ${vuln.summary           ? `<div class="mb-4"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("summary")}</h4><p>${esc(vuln.summary)}</p></div>` : ""}
                  ${vuln.details           ? `<div class="mb-4"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("details")}</h4><div class="prose prose-sm max-w-none">${_renderMarkdown(vuln.details)}</div></div>` : ""}
                  ${vuln.suggest_fix_version  ? `<div class="mt-2"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("fixVersion")}</h4><p class="text-green-600 font-medium">${esc(vuln.suggest_fix_version)}</p></div>` : ""}
                  ${vuln.other_fix_versions   ? `<div class="mt-2"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("otherFixVersions")}</h4><p class="text-gray-800">${esc(vuln.other_fix_versions)}</p></div>` : ""}
                </div>
              </div>`;
          });
        } else {
          html += `<div class="mt-4 text-gray-500 italic">${t("noVulnerabilitiesFound")}</div>`;
        }

        html += "</div>";
        document.getElementById("component-modal-content").innerHTML = html;
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // SEARCH — debounced search with event delegation for result clicks
    // ═══════════════════════════════════════════════════════════════════════════
    const Search = {
      _results: new RequestSlot(),
      _timer: null,

      schedule(value) {
        const query = value.trim();
        if (!query) {
          this.clear();
          return;
        }
        this._cancel();
        const projectID = State.projectID;
        this._timer = setTimeout(() => {
          this._timer = null;
          if (State.projectID === projectID) this.run(query);
        }, 300);
      },

      _cancel() {
        if (this._timer !== null) clearTimeout(this._timer);
        this._timer = null;
        this._results.cancel();
      },

      async run(q) {
        if (!State.projectID) return;
        const req = this._results.begin({ projectID: State.projectID, q });
        // Only render if this is still the latest request and the project +
        // query are unchanged when the response arrives
        const isCurrent = () =>
          this._results.owns(req) &&
          State.projectID === req.projectID &&
          document.getElementById("search-input").value.trim() === req.q;
        try {
          const json = await Api.search(req.projectID, q, req.controller.signal);
          if (!isCurrent()) return;
          ResultView.search(
            document.getElementById("search-results"),
            document.getElementById("search-clear-btn"),
            json.data,
          );
        } catch (e) {
          if (e.name === "AbortError" || !isCurrent()) return;
          console.error("Search error:", e);
        } finally {
          this._results.finish(req);
        }
      },

      clear() {
        this._cancel();
        document.getElementById("search-input").value = "";
        const container = document.getElementById("search-results");
        container.classList.add("hidden");
        container.innerHTML = "";
        document.getElementById("search-clear-btn").classList.add("hidden");
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // DIFF — modal with lazy creation and event delegation
    // ═══════════════════════════════════════════════════════════════════════════
    const Diff = {
      _versions: new RequestSlot(),
      _comparison: new RequestSlot(),

      cancel() {
        this._versions.cancel();
        this._comparison.cancel();
      },

      _selectionChanged() {
        this._comparison.cancel();
        document.getElementById("diff-result").innerHTML = "";
      },

      _swap() {
        const a = document.getElementById("diff-select-a");
        const b = document.getElementById("diff-select-b");
        if (!a || !b) return;
        [a.value, b.value] = [b.value, a.value];
        this._selectionChanged();
      },

      async _run() {
        const a = document.getElementById("diff-select-a").value;
        const b = document.getElementById("diff-select-b").value;
        const resultEl = document.getElementById("diff-result");

        if (!a || !b || a === b) {
          this._comparison.cancel();
          resultEl.innerHTML = `<p class="text-red-500">${t("diffSelectBoth")}</p>`;
          return;
        }

        const pending = this._comparison.current;
        if (pending?.projectID === State.projectID && pending.a === a && pending.b === b) return;
        const req = this._comparison.begin({ projectID: State.projectID, a, b });
        const isCurrent = () =>
          this._comparison.owns(req) &&
          State.projectID === req.projectID &&
          document.getElementById("diff-select-a").value === req.a &&
          document.getElementById("diff-select-b").value === req.b;

        resultEl.innerHTML = `<div class="flex justify-center py-8">
          <svg class="animate-spin h-8 w-8 text-[#009999]" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg></div>`;

        try {
          const json = await Api.diff(req.projectID, a, b, req.controller.signal);
          if (!isCurrent()) return;
          ResultView.diff(resultEl, json.data, a, b);
        } catch (e) {
          if (e.name === "AbortError" || !isCurrent()) return;
          resultEl.innerHTML = `<p class="text-red-500">${esc(e.message)}</p>`;
        } finally {
          this._comparison.finish(req);
        }
      },

      async openInPanel() {
        const panel = document.getElementById("panel-diff");

        if (!panel.querySelector("#diff-select-a")) {
          panel.innerHTML = `
            <div class="flex items-end space-x-4 mb-6">
              <div class="flex-1">
                <label class="block text-sm font-medium text-gray-700 mb-1" id="diff-label-a"></label>
                <select id="diff-select-a" class="w-full border border-gray-300 rounded-md py-2 px-3 focus:outline-none focus:ring-2 focus:ring-[#009999]"></select>
              </div>
              <button id="diff-swap-btn" type="button" class="border border-gray-300 hover:bg-gray-100 text-gray-600 p-2 rounded-md transition duration-150" title="">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4M16 17H4m0 0l4 4m-4-4l4-4" />
                </svg>
              </button>
              <div class="flex-1">
                <label class="block text-sm font-medium text-gray-700 mb-1" id="diff-label-b"></label>
                <select id="diff-select-b" class="w-full border border-gray-300 rounded-md py-2 px-3 focus:outline-none focus:ring-2 focus:ring-[#009999]"></select>
              </div>
              <button id="diff-compare-btn" class="bg-[#009999] hover:bg-[#19a3a3] text-white font-medium py-2 px-4 rounded-md shadow"></button>
            </div>
            <div id="diff-result"></div>`;

          document.getElementById("diff-compare-btn").addEventListener("click", () => this._run());
          document.getElementById("diff-swap-btn").addEventListener("click", () => this._swap());
          for (const id of ["diff-select-a", "diff-select-b"]) {
            document.getElementById(id).addEventListener("change", () => this._selectionChanged());
          }
          document.getElementById("diff-result").addEventListener("click", e => {
            const el = e.target.closest("[data-action='show-component']");
            if (!el) return;
            ComponentModal.show(el.dataset.sbom, el.dataset.component);
          });
        }

        const selects = ["diff-select-a", "diff-select-b"].map(id => document.getElementById(id));
        const compare = document.getElementById("diff-compare-btn");
        const swap = document.getElementById("diff-swap-btn");
        const result = document.getElementById("diff-result");
        document.getElementById("diff-label-a").textContent = t("diffSbomA");
        document.getElementById("diff-label-b").textContent = t("diffSbomB");
        compare.textContent = t("diffCompare");
        swap.title = t("diffSwap");
        result.innerHTML = "";
        for (const select of selects) {
          select.innerHTML = "";
          select.disabled = true;
        }
        compare.disabled = true;
        swap.disabled = true;

        this._comparison.cancel();
        const request = this._versions.begin({ projectID: State.projectID });
        const isCurrent = () => this._versions.owns(request) && State.projectID === request.projectID;
        try {
          if (!request.projectID) return;
          const json = await Api.listVersions(request.projectID, request.controller.signal);
          if (!isCurrent()) return;
          const versions = (json.data ?? []).map(v => v.version);
          const options = versions.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
          selects.forEach((select, i) => {
            select.innerHTML = options;
            if (versions[i]) select.value = versions[i];
            select.disabled = versions.length === 0;
          });
          compare.disabled = versions.length < 2;
          swap.disabled = versions.length < 2;
        } catch {
          if (isCurrent()) result.textContent = t("diffVersionsFailed");
        } finally {
          this._versions.finish(request);
        }
      },

    };

    // ═══════════════════════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN TABS — SBOM 分析 / Diff 比對
    // ═══════════════════════════════════════════════════════════════════════════
    const MainTab = {
      _tabs: ["analysis", "diff"],

      show(tab) {
        this._tabs.forEach(id => {
          document.getElementById(`panel-${id}`).classList.toggle("hidden", id !== tab);
          const btn = document.getElementById(`main-tab-${id}`);
          btn.classList.toggle("text-[#009999]", id === tab);
          btn.classList.toggle("border-[#009999]", id === tab);
          btn.classList.toggle("text-gray-500", id !== tab);
          btn.classList.toggle("border-transparent", id !== tab);
        });
        if (tab === "analysis") {
          Diff.cancel();
          VersionHistory.load();
        } else {
          VersionHistory.invalidate();
          Diff.openInPanel();
        }
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // VERSION HISTORY — list all stored versions for current project
    // ═══════════════════════════════════════════════════════════════════════════
    const VersionHistory = {
      refreshIfVisible() {
        if (!document.getElementById("panel-analysis").classList.contains("hidden")) this.load();
      },

      _listing: new RequestSlot(),
      _page: 0,
      _versions: [],
      _projectID: null,
      _loadSeq: 0,
      PAGE_SIZE: 10,

      invalidate() {
        this._listing.cancel();
        this._loadSeq++;
        this._projectID = null;
        this._versions = [];
        document.getElementById("version-history-list").innerHTML =
          `<p class="text-gray-400 italic text-sm">載入中...</p>`;
      },

      async load() {
        const container = document.getElementById("version-history-list");
        const projectID = State.projectID;
        this.invalidate();
        if (!projectID) {
          container.innerHTML = `<p class="text-gray-400 italic text-sm">尚未選擇專案</p>`;
          return;
        }

        const request = this._listing.begin({ projectID });
        try {
          const json = await Api.listVersions(projectID, request.controller.signal);
          if (!this._listing.owns(request) || State.projectID !== projectID) return;
          this._projectID = projectID;
          this._versions = json.data ?? [];
          this._page = 0;
          this._render(container);
        } catch (e) {
          if (this._listing.owns(request) && State.projectID === projectID) {
            container.innerHTML = `<p class="text-red-500 text-sm">載入失敗：${esc(e.message)}</p>`;
          }
        } finally {
          this._listing.finish(request);
        }
      },

      _render(container) {
        const projectID = this._projectID;
        const seq = this._loadSeq;
        const selection = Project._selectionGen;
        const ownsSelection = () => State.projectID === projectID &&
          Project._selectionGen === selection;
        const isCurrent = () => this._loadSeq === seq &&
          this._projectID === projectID && ownsSelection();
        const refreshIfSelected = () => {
          if (State.projectID === projectID &&
              document.getElementById("project-select").value === String(projectID)) this.refreshIfVisible();
        };
        const versions = this._versions;
        if (versions.length === 0) {
          container.innerHTML = `<p class="text-gray-400 italic text-sm">尚無版本記錄，請至「SBOM 分析」上傳檔案。</p>`;
          return;
        }

        const totalPages = Math.ceil(versions.length / this.PAGE_SIZE);
        const page = Math.min(this._page, totalPages - 1);
        const pageVersions = versions.slice(page * this.PAGE_SIZE, (page + 1) * this.PAGE_SIZE);

        const rows = pageVersions.map(v => {
          const _d = new Date(v.created_at);
          const pad = n => String(n).padStart(2, "0");
          const date = `${_d.getFullYear()}/${pad(_d.getMonth()+1)}/${pad(_d.getDate())} ${pad(_d.getHours())}:${pad(_d.getMinutes())}:${pad(_d.getSeconds())}`;
          return `<tr class="hover:bg-gray-50">
            <td class="px-4 py-3 text-sm font-medium text-gray-800">${esc(v.version)}</td>
            <td class="px-4 py-3 text-sm text-gray-500">${date}</td>
            <td class="px-4 py-3 text-sm">
              <button class="text-[#009999] hover:underline text-xs mr-3 version-load-btn" data-version="${esc(v.version)}">載入分析</button>
              <button class="text-gray-500 hover:underline text-xs mr-3 version-rename-btn" data-version="${esc(v.version)}">重新命名</button>
              <button class="text-red-400 hover:underline text-xs version-delete-btn" data-version="${esc(v.version)}">刪除</button>
            </td>
          </tr>`;
        }).join("");

        const pager = totalPages > 1 ? `
          <div class="flex items-center justify-end gap-2 mt-2 text-sm text-gray-600">
            <button class="px-2 py-1 rounded border border-gray-300 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed pager-prev" ${page === 0 ? "disabled" : ""}>‹</button>
            <span>${page + 1} / ${totalPages}</span>
            <button class="px-2 py-1 rounded border border-gray-300 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed pager-next" ${page >= totalPages - 1 ? "disabled" : ""}>›</button>
          </div>` : "";

        container.innerHTML = `
          <table class="w-full border border-gray-200 rounded-lg overflow-hidden text-left">
            <thead class="bg-gray-50 text-xs text-gray-500 uppercase tracking-wider">
              <tr>
                <th class="px-4 py-3">版本名稱</th>
                <th class="px-4 py-3">建立時間</th>
                <th class="px-4 py-3">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">${rows}</tbody>
          </table>${pager}`;

        container.querySelectorAll(".version-load-btn").forEach(btn => {
          btn.addEventListener("click", () => {
            if (!isCurrent()) return;
            const version = btn.dataset.version;
            MainTab.show("analysis");
            Sbom.addTab(version, true);
          });
        });

        container.querySelectorAll(".version-rename-btn").forEach(btn => {
          btn.addEventListener("click", async () => {
            if (!isCurrent()) return;
            const oldName = btn.dataset.version;
            const newName = prompt("輸入新的版本名稱：", oldName);
            if (!newName || newName.trim() === oldName) return;
            try {
              const json = await Api.renameSBOM(projectID, oldName, newName.trim());
              const updatedName = json?.data?.version;
              if (!updatedName) return;
              if (ownsSelection()) Sbom.renameTab(oldName, updatedName);
              if (!isCurrent()) { refreshIfSelected(); return; }
              const entry = this._versions.find(v => v.version === oldName);
              if (entry) entry.version = updatedName;
              this._render(container);
            } catch (e) {
              if (isCurrent()) alert(`重新命名失敗：${e.message}`);
            }
          });
        });

        container.querySelectorAll(".version-delete-btn").forEach(btn => {
          btn.addEventListener("click", async () => {
            if (!isCurrent()) return;
            const version = btn.dataset.version;
            if (!confirm(`確定要刪除版本「${version}」？`)) return;
            try {
              await Api.deleteSBOM(projectID, version);
              if (ownsSelection()) Sbom.removeTab(version);
              if (!isCurrent()) { refreshIfSelected(); return; }
              // Remove from in-memory list and re-render without a network round-trip
              this._versions = this._versions.filter(v => v.version !== version);
              if (this._page >= Math.ceil(this._versions.length / this.PAGE_SIZE)) {
                this._page = Math.max(0, this._page - 1);
              }
              this._render(container);
            } catch (e) {
              if (isCurrent()) alert(`刪除失敗：${e.message}`);
            }
          });
        });

        container.querySelector(".pager-prev")?.addEventListener("click", () => {
          if (!isCurrent()) return;
          this._page--;
          this._render(container);
        });
        container.querySelector(".pager-next")?.addEventListener("click", () => {
          if (!isCurrent()) return;
          this._page++;
          this._render(container);
        });
      },
    };

    // SBOM MODAL — two-step: pick file → preview → create version
    // ═══════════════════════════════════════════════════════════════════════════
    const SbomModal = {
      _bomResult: null,
      _sha256: null,
      _bomTimestamp: null,
      _previewToken: null,
      _existingVersion: null,
      // Only this dialog's active project and file can submit its preview.
      _projectID: null,
      _preview: new RequestSlot(),
      _saving: null,

      _resetPreview() {
        this._preview.cancel();
        this._saving = null;
        this._bomResult = null;
        this._sha256 = null;
        this._bomTimestamp = null;
        this._previewToken = null;
        this._existingVersion = null;
        this._projectID = null;
      },

      open() {
        this._resetPreview();
        const previewBtn = document.getElementById("sbom-modal-preview-btn");
        previewBtn.disabled = false;
        previewBtn.textContent = "預覽";
        document.getElementById("sbom-modal-commit-btn").textContent = "建立版本";
        document.getElementById("sbom-modal-commit-btn").disabled = false;
        document.getElementById("sbom-file-input").value = "";
        document.getElementById("sbom-filename-display").textContent = "尚未選擇檔案";
        document.getElementById("sbom-modal-step1-error").classList.add("hidden");
        document.getElementById("sbom-modal-step1").classList.remove("hidden");
        document.getElementById("sbom-modal-step2").classList.add("hidden");
        document.getElementById("sbom-modal").classList.remove("hidden");
      },

      close() {
        document.getElementById("sbom-modal").classList.add("hidden");
        this._resetPreview();
        document.getElementById("sbom-file-input").value = "";
      },

      back() {
        this._resetPreview();
        const button = document.getElementById("sbom-modal-preview-btn");
        button.disabled = false;
        button.textContent = "預覽";
        document.getElementById("sbom-modal-step2").classList.add("hidden");
        document.getElementById("sbom-modal-step1").classList.remove("hidden");
      },

      _onFileSelected(files) {
        this._resetPreview();
        const button = document.getElementById("sbom-modal-preview-btn");
        button.disabled = false;
        button.textContent = "預覽";
        document.getElementById("sbom-filename-display").textContent = files[0]?.name ?? "尚未選擇檔案";
        document.getElementById("sbom-modal-step1-error").classList.add("hidden");
      },

      async preview() {
        const fileInput = document.getElementById("sbom-file-input");
        const errEl = document.getElementById("sbom-modal-step1-error");
        errEl.classList.add("hidden");

        if (!fileInput.files.length) {
          errEl.textContent = "請先選擇 SBOM 檔案";
          errEl.classList.remove("hidden");
          return;
        }

        const previewBtn = document.getElementById("sbom-modal-preview-btn");
        previewBtn.disabled = true;
        previewBtn.textContent = "解析中...";

        this._resetPreview();
        const req = this._preview.begin({ projectID: State.projectID, file: fileInput.files[0] });
        const isCurrent = () => this._preview.owns(req) &&
          State.projectID === req.projectID && fileInput.files[0] === req.file;
        try {
          const resp = await Api.previewSBOM(req.projectID, req.file, req.controller.signal);
          if (!isCurrent()) return;
          const json = await resp.json();
          if (!isCurrent()) return;
          if (!resp.ok) {
            errEl.textContent = json.error || "預覽失敗";
            errEl.classList.remove("hidden");
            return;
          }

          const data = json.data;
          this._bomResult = data.bom_result;
          this._sha256 = data.sha256;
          this._bomTimestamp = data.bom_timestamp;
          this._previewToken = data.preview_token;
          this._existingVersion = data.existing_version || "";
          this._projectID = req.projectID;

          const summary = document.getElementById("sbom-preview-summary");
          summary.innerHTML = `
            <div class="flex gap-6 mb-3 text-sm">
              <span class="text-gray-500">元件數量 <strong class="text-gray-800">${data.summary.component_count}</strong></span>
              <span class="text-gray-500">漏洞數量 <strong class="${data.summary.vuln_count > 0 ? 'text-red-600' : 'text-green-600'}">${data.summary.vuln_count}</strong></span>
            </div>`;
          this._renderPreviewTopology(summary, data.bom_result);

          const displayName = data.filename || req.file.name;
          document.getElementById("sbom-preview-title").innerHTML =
            `預覽結果 <span class="text-gray-400 font-normal text-base">— ${esc(displayName)}</span>`;
          document.getElementById("sbom-version-input").value = "";

          const commitBtn = document.getElementById("sbom-modal-commit-btn");
          if (this._existingVersion) {
            document.getElementById("sbom-version-hint").textContent =
              `此檔案已存在，版本：${this._existingVersion}`;
            document.getElementById("sbom-version-hint").classList.add("text-yellow-600");
            commitBtn.disabled = true;
          } else {
            document.getElementById("sbom-version-hint").textContent =
              "建議命名方式：{filename}_{version} / {filename}_{date} / {prefix}_{version} / {prefix}_{date}";
            document.getElementById("sbom-version-hint").classList.remove("text-yellow-600");
            commitBtn.disabled = false;
          }

          document.getElementById("sbom-modal-step2-error").classList.add("hidden");
          document.getElementById("sbom-modal-step1").classList.add("hidden");
          document.getElementById("sbom-modal-step2").classList.remove("hidden");
        } catch (e) {
          if (!isCurrent()) return;
          errEl.textContent = e.message || "預覽失敗";
          errEl.classList.remove("hidden");
        } finally {
          if (this._preview.owns(req)) {
            previewBtn.disabled = false;
            previewBtn.textContent = "預覽";
          }
          this._preview.finish(req);
        }
      },

      async commit() {
        if (this._saving) return;
        const version = document.getElementById("sbom-version-input").value.trim();
        const errEl = document.getElementById("sbom-modal-step2-error");
        errEl.classList.add("hidden");

        if (!version) {
          errEl.textContent = "請輸入版本名稱";
          errEl.classList.remove("hidden");
          return;
        }

        // the preview result is only valid for the project it was scanned
        // against; refuse to commit if the user switched project meanwhile
        if (!this._bomResult || !this._previewToken || this._projectID == null) {
          errEl.textContent = "預覽資料已失效，請重新預覽";
          errEl.classList.remove("hidden");
          return;
        }
        if (State.projectID !== this._projectID) {
          errEl.textContent = "專案已變更，請重新預覽後再建立版本";
          errEl.classList.remove("hidden");
          return;
        }

        const commitBtn = document.getElementById("sbom-modal-commit-btn");
        const projectID = this._projectID;
        const saving = { projectID };
        this._saving = saving;
        const isCurrent = () => this._saving === saving &&
          State.projectID === saving.projectID;
        commitBtn.disabled = true;
        commitBtn.textContent = "建立中...";

        try {
          const resp = await Api.commitSBOM(projectID, version, this._bomResult, this._sha256, this._bomTimestamp, this._previewToken);
          const json = await resp.json();
          if (!isCurrent()) {
            // The write may already have completed. Refresh only its project.
            if (resp.ok && State.projectID === projectID) VersionHistory.refreshIfVisible();
            return;
          }
          if (resp.status === 409 || !resp.ok) {
            errEl.textContent = json.error || "建立失敗";
            errEl.classList.remove("hidden");
            return;
          }

          this.close();
          Sbom.addTab(version);
          VersionHistory.load();
        } catch (e) {
          if (!isCurrent()) return;
          errEl.textContent = e.message || "建立失敗";
          errEl.classList.remove("hidden");
        } finally {
          if (this._saving === saving) {
            this._saving = null;
            commitBtn.disabled = false;
            commitBtn.textContent = "建立版本";
          }
        }
      },

      _renderPreviewTopology(container, bomResult) {
        const depLevel = bomResult?.DependencyLevel || {};
        const compInfo = bomResult?.ComponentInfo || {};
        const levels = Object.entries(depLevel).map(([lvlStr, components]) => {
          let totalVulns = 0;
          const withVuln = [], withVulnDep = [];
          components.forEach(comp => {
            const info = compInfo[comp] || {};
            totalVulns += info.vuln_number || 0;
            if ((info.vuln_number || 0) > 0) withVuln.push(comp);
            if (info.contains_vuln_dep && !(info.vuln_number > 0)) withVulnDep.push(comp);
          });
          return { level: parseInt(lvlStr), components, components_with_vuln: withVuln, components_with_vuln_dep: withVulnDep, total_vulns: totalVulns };
        }).sort((a, b) => a.level - b.level);

        const wrap = document.createElement("div");
        wrap.className = "mt-2 overflow-y-auto max-h-[55vh]";
        if (levels.length === 0) {
          wrap.innerHTML = `<div class="text-gray-400 italic text-sm">無元件資料</div>`;
        } else {
          levels.forEach(lvl => wrap.appendChild(this._buildPreviewLevelPanel(lvl, compInfo, bomResult)));
        }
        container.appendChild(wrap);
      },

      _buildPreviewLevelPanel(level, compInfo, bomResult) {
        const panel = document.createElement("div");
        panel.className = "mb-4 border border-gray-200 rounded-md overflow-hidden";

        const hdr = document.createElement("div");
        hdr.className = "bg-gray-50 px-4 py-3 flex items-center justify-between";
        const titleEl = document.createElement("div");
        titleEl.className = "font-medium";
        if (level.level === 0) {
          titleEl.innerHTML = `${t("rootLevel")} <span class="text-sm font-normal text-gray-500">${t("topLevelDependencies")}</span>`;
        } else {
          titleEl.innerHTML = `${t("level", level.level)} <span class="text-sm font-normal text-gray-500">${t("componentsCount", level.components.length)}</span>`;
        }
        const badge = document.createElement("div");
        if (level.total_vulns > 0) {
          badge.className = "px-2 py-1 text-xs font-medium bg-[#D9936E] text-red-800 rounded-full";
          badge.textContent = t("vulnerabilities", level.total_vulns);
        } else {
          badge.className = "px-2 py-1 text-xs font-medium bg-[#95D0C0] text-[#231815] rounded-full";
          badge.textContent = t("noVulnerabilities");
        }
        hdr.appendChild(titleEl);
        hdr.appendChild(badge);
        panel.appendChild(hdr);

        const body = document.createElement("div");
        body.className = "px-4 py-3";
        const grid = document.createElement("div");
        grid.className = "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2";

        const WARN_SVG = (color) => `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-${color}-500 mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>`;
        const FILE_SVG = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-gray-400 mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a1 1 0 01-1 1h-2a1 1 0 01-1-1v-2a1 1 0 00-1-1H9a1 1 0 00-1 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V4zm3 1h2v2H7V5zm2 4H7v2h2V9zm2-4h2v2h-2V5zm2 4h-2v2h2V9z" clip-rule="evenodd" /></svg>`;

        level.components.forEach(comp => {
          const hasVuln    = level.components_with_vuln.includes(comp);
          const hasVulnDep = level.components_with_vuln_dep.includes(comp);
          const item = document.createElement("div");
          item.className = hasVuln
            ? "px-3 py-2 border border-red-200 bg-red-50 rounded flex items-center cursor-pointer"
            : hasVulnDep
              ? "px-3 py-2 border border-yellow-200 bg-yellow-50 rounded flex items-center cursor-pointer"
              : "px-3 py-2 border border-gray-200 bg-white rounded flex items-center cursor-pointer";
          item.innerHTML = `${hasVuln ? WARN_SVG("red") : hasVulnDep ? WARN_SVG("yellow") : FILE_SVG}<span class="truncate">${esc(comp)}</span>`;
          item.addEventListener("click", e => {
            e.stopPropagation();
            ComponentModal.showFromLocal(comp, compInfo[comp] || {}, bomResult);
          });
          grid.appendChild(item);
        });

        body.appendChild(grid);
        panel.appendChild(body);
        return panel;
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // UTILITIES — pure helpers with no side effects
    // ═══════════════════════════════════════════════════════════════════════════
    // JS port of Go's GetVulnDepPaths — BFS from start to each end node.
    function _getVulnDepPaths(start, ends, depMap) {
      const paths = [];
      for (const end of ends) {
        if (start === end) continue;
        const visited = new Set();
        const path = [];
        function find(cur) {
          if (visited.has(cur)) return false;
          visited.add(cur);
          if (cur === end) { path.push(cur); return true; }
          for (const next of (depMap[cur] || [])) {
            if (find(next)) { path.unshift(cur); return true; }
          }
          return false;
        }
        if (find(start)) paths.push({ start, end, path });
      }
      return paths;
    }
    // Shared warning triangle SVG.
    // sizeClass controls display size/spacing; defaults to inline badge style used in lists.
    // Pass sizeClass="h-5 w-5 mr-1 flex-shrink-0 mt-0.5" for the larger modal inline variant.
    const WARN_PATH = `<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />`;
    function _warnSVG(color, title, sizeClass = "inline h-4 w-4 ml-1") {
      return `<svg xmlns="http://www.w3.org/2000/svg" class="${sizeClass} text-${color}-500" viewBox="0 0 20 20" fill="currentColor" title="${title}">${WARN_PATH}</svg>`;
    }

    function _severityFromCvss(score) {
      if (!score) return "Unknown";
      const n = parseFloat(score);
      if (isNaN(n))  return "Unknown";
      if (n >= 9.0)  return "Critical";
      if (n >= 7.0)  return "High";
      if (n >= 4.0)  return "Medium";
      if (n >= 0.1)  return "Low";
      return "None";
    }

    function _severityClass(severity) {
      switch (severity.toLowerCase()) {
        case "critical": return "bg-red-100 text-red-800";
        case "high":     return "bg-orange-100 text-orange-800";
        case "medium":   return "bg-yellow-100 text-yellow-800";
        case "low":      return "bg-blue-100 text-blue-800";
        default:         return "bg-gray-100 text-gray-800";
      }
    }

    function _renderMarkdown(md) {
      if (!md) return "";
      // escape first: vulnerability details are external input, only the
      // markup generated below is allowed to remain as HTML
      return esc(md)
        .replace(/^### (.*$)/gm, '<h3 class="text-lg font-medium mt-3 mb-2">$1</h3>')
        .replace(/^## (.*$)/gm,  '<h2 class="text-xl font-medium mt-4 mb-2">$1</h2>')
        .replace(/^# (.*$)/gm,   '<h1 class="text-2xl font-bold mt-4 mb-3">$1</h1>')
        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
        .replace(/\*(.*?)\*/g,     "<em>$1</em>")
        .replace(/```([\s\S]*?)```/g, '<pre class="bg-gray-100 p-2 rounded my-2 overflow-x-auto text-sm"><code>$1</code></pre>')
        .replace(/`(.*?)`/g, '<code class="bg-gray-100 px-1 rounded text-sm">$1</code>')
        .replace(/\[(.*?)\]\((.*?)\)/g, (m, text, href) =>
          /^https?:\/\//i.test(href)
            ? `<a href="${href}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline">${text}</a>`
            : text)
        .replace(/^\s*-\s(.*$)/gm, '<li class="ml-4">$1</li>')
        .replace(/^\s*(\n)?([^\n]+)/gm, m => /^<(\/)?(h1|h2|h3|pre|li)/i.test(m) ? m : `<p class="my-2">${m}</p>`)
        .replace(/<p><\/p>/g, "");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // APP INIT — wire up all event listeners, then load initial data
    // ═══════════════════════════════════════════════════════════════════════════
    document.addEventListener("DOMContentLoaded", () => {
      // Language
      bindLanguageSwitcher(lang => i18n.change(lang));

      // Main tab switching
      document.getElementById("main-tab-analysis").addEventListener("click", () => MainTab.show("analysis"));
      document.getElementById("main-tab-diff").addEventListener("click",     () => MainTab.show("diff"));

      // SBOM modal
      document.getElementById("select-sbom-btn").addEventListener("click", () => SbomModal.open());
      document.getElementById("sbom-pick-file-btn").addEventListener("click", () => document.getElementById("sbom-file-input").click());
      document.getElementById("sbom-file-input").addEventListener("change", e => SbomModal._onFileSelected(e.target.files));
      document.getElementById("sbom-modal-cancel").addEventListener("click", () => SbomModal.close());
      document.getElementById("sbom-modal-preview-btn").addEventListener("click", () => SbomModal.preview());
      document.getElementById("sbom-modal-back-btn").addEventListener("click", () => SbomModal.back());
      document.getElementById("sbom-modal-commit-btn").addEventListener("click", () => SbomModal.commit());
      document.getElementById("sbom-version-input").addEventListener("keydown", e => {
        if (e.key === "Enter" && !document.getElementById("sbom-modal-commit-btn").disabled) {
          SbomModal.commit();
        }
        if (e.key === "Escape") SbomModal.close();
      });

      // Tutorial
      document.getElementById("tutorial-btn").addEventListener("click", () => {
        window.location.href = "/tutorial";
      });

      // Search (debounced)
      document.getElementById("search-input").addEventListener("input", e => Search.schedule(e.target.value));
      document.getElementById("search-input").addEventListener("keydown", e => {
        if (e.key === "Escape") Search.clear();
      });
      document.getElementById("search-clear-btn").addEventListener("click", () => Search.clear());

      // Event delegation: search result rows → open component modal
      document.getElementById("search-results").addEventListener("click", e => {
        const row = e.target.closest("[data-action='show-component']");
        if (row) ComponentModal.show(row.dataset.sbom, row.dataset.component);
      });

      // Project controls
      document.getElementById("project-select").addEventListener("change", e => Project.get(e.target.value));
      document.getElementById("project-switch-btn").addEventListener("click", () => {
        const name = document.getElementById("project-input").value.trim();
        if (!name) return;
        document.getElementById("project-input").value = "";
        Project.create(name);
      });
      document.getElementById("project-rename-btn").addEventListener("click", () => {
        if (!State.projectID) return;
        const sel     = document.getElementById("project-select");
        const current = sel.options[sel.selectedIndex]?.text || "";
        const name    = prompt(t("projectRenamePrompt"), current);
        if (!name?.trim() || name.trim() === current) return;
        Project.rename(State.projectID, name.trim());
      });
      document.getElementById("project-delete-btn").addEventListener("click", () => {
        if (!State.projectID) return;
        if (!confirm(t("projectDeleteConfirm"))) return;
        Project.delete(State.projectID);
      });


      // Bootstrap
      Project.load();
    });
