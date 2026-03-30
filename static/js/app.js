    // ═══════════════════════════════════════════════════════════════════════════
    // STATE — single source of truth for mutable app state
    // ═══════════════════════════════════════════════════════════════════════════
    const State = {
      workspaceID: null,
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
          uploadedFiles: "Processed SBOM Files",
          noFilesUploaded: "No files selected yet",
          uploading: "Processing {0}...",
          uploadedSuccessfully: "{0} processed successfully",
          uploadFailed: "{0}: {1}",
          errorReadingFile: "Error reading file",
          warningOverwrite: "Warning: the previous <strong>{0}</strong> will be overwritten since the file names are same.",
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
          workspace: "Workspace",
          newWorkspace: "New workspace name",
          workspaceSwitch: "Switch",
          workspaceRename: "Rename",
          workspaceDelete: "Delete",
          workspaceRenamePrompt: "Enter new workspace name:",
          workspaceDeleteConfirm: "Delete this workspace and all its SBOMs? This cannot be undone.",
          diffFiles: "Diff Files",
          diffSbomTitle: "Compare SBOMs",
          diffSbomA: "SBOM A (before)",
          diffSbomB: "SBOM B (after)",
          diffCompare: "Compare",
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
        },
        zh: {
          appTitle: "ex-sbom",
          appDescription: "SBOM explorer，由 NICS-ra 設計",
          selectFiles: "選擇 SBOM 檔案",
          selectedFiles: "已選擇的檔案：",
          uploadedFiles: "已選擇的 SBOM 檔案",
          noFilesUploaded: "尚未上傳檔案",
          uploading: "正在處理 {0}...",
          uploadedSuccessfully: "{0} 的資料彙整完畢",
          uploadFailed: "{0}: {1}",
          errorReadingFile: "讀取檔案錯誤",
          warningOverwrite: "警告：由於檔案名稱相同，之前的 <strong>{0}</strong> 將被覆蓋。",
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
          workspace: "工作區",
          newWorkspace: "輸入新工作區名稱",
          workspaceSwitch: "切換",
          workspaceRename: "重新命名",
          workspaceDelete: "刪除",
          workspaceRenamePrompt: "輸入新的工作區名稱：",
          workspaceDeleteConfirm: "確定刪除此工作區及所有 SBOM？此操作無法復原。",
          diffFiles: "Diff 檔案",
          diffSbomTitle: "比較 SBOM",
          diffSbomA: "SBOM A（舊版）",
          diffSbomB: "SBOM B（新版）",
          diffCompare: "比較",
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
        document.getElementById("lang-en").classList.toggle("active-language", lang === "en");
        document.getElementById("lang-zh").classList.toggle("active-language", lang === "zh");
        this.apply();
        if (State.activeTab) Sbom.fetchTopology(State.activeTab.dataset.fileName);
      },
    };

    // Convenience shorthand
    function t(key, ...args) { return i18n.t(key, ...args); }

    // ═══════════════════════════════════════════════════════════════════════════
    // API — all HTTP calls in one place
    // ═══════════════════════════════════════════════════════════════════════════
    const Api = {
      async _json(url, opts = {}) {
        const resp = await fetch(url, opts);
        const json = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
        return json;
      },

      getWorkspaces()      { return this._json("/workspaces"); },
      getWorkspace(id)     { return this._json(`/workspaces/${encodeURIComponent(id)}`); },
      createWorkspace(name) {
        return this._json("/workspaces", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name }),
        });
      },
      renameWorkspace(id, name) {
        return this._json(`/workspaces/${encodeURIComponent(id)}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name }),
        });
      },
      deleteWorkspace(id)  { return this._json(`/workspaces/${encodeURIComponent(id)}`, { method: "DELETE" }); },

      uploadSBOM(workspaceID, file) {
        const fd = new FormData();
        fd.append("name", file.name);
        fd.append("file", file);
        return fetch(`/workspaces/${workspaceID}/sboms`, { method: "POST", body: fd });
      },
      deleteSBOM(workspaceID, name) {
        return this._json(`/workspaces/${workspaceID}/sboms/${encodeURIComponent(name)}`, { method: "DELETE" });
      },

      getTopology(workspaceID, name) {
        return this._json(`/workspaces/${workspaceID}/sboms/${encodeURIComponent(name)}/topology`);
      },
      getComponent(workspaceID, sbom, comp) {
        return this._json(`/workspaces/${workspaceID}/sboms/${encodeURIComponent(sbom)}/topology/component?component=${encodeURIComponent(comp)}`);
      },
      getVulnDep(workspaceID, sbom, comp) {
        return this._json(`/workspaces/${workspaceID}/sboms/${encodeURIComponent(sbom)}/topology/component/vuln-dep?component=${encodeURIComponent(comp)}`);
      },
      search(workspaceID, q) {
        return this._json(`/workspaces/${workspaceID}/search?q=${encodeURIComponent(q)}`);
      },
      diff(workspaceID, a, b) {
        return this._json(`/workspaces/${workspaceID}/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // WORKSPACE — workspace CRUD + UI state sync
    // ═══════════════════════════════════════════════════════════════════════════
    const Workspace = {
      async load(autoLoad = true) {
        try {
          const json = await Api.getWorkspaces();
          const { workspaces, current } = json.data;
          const sel = document.getElementById("workspace-select");
          sel.innerHTML = (workspaces || [])
            .map(w => `<option value="${w.ID}"${w.Name === current ? " selected" : ""}>${w.Name}</option>`)
            .join("");
          document.getElementById("workspace-current").textContent = current ? `(${current})` : "";
          if (autoLoad && sel.value) await this.get(sel.value);
        } catch (e) {
          console.error("Failed to load workspaces:", e);
        }
      },

      _apply(json) {
        State.workspaceID = json.data?.workspace_id ?? null;
        document.getElementById("upload-status").innerHTML = "";
        document.getElementById("selected-files").innerHTML = "";
        const selectBtn = document.getElementById("select-sbom-btn");
        selectBtn.disabled = false;
        selectBtn.classList.remove("opacity-50", "cursor-not-allowed");

        document.getElementById("file-tabs").innerHTML = "";
        document.getElementById("tab-content").innerHTML =
          `<div id="no-tabs-message" class="text-gray-500 italic" data-i18n="noFilesUploaded">${t("noFilesUploaded")}</div>`;
        State.uploadedFiles.clear();
        State.activeTab = null;

        // Create all tabs without triggering a topology fetch per tab,
        // then select only the first one (avoids N wasted network requests).
        const sboms = json.data.sboms || [];
        sboms.forEach(name => Sbom.addTab(name, false));
        if (sboms.length > 0) {
          const firstTab = document.getElementById("file-tabs").querySelector("div");
          if (firstTab) Sbom.selectTab(firstTab);
        }

        const sel = document.getElementById("workspace-select");
        const opt = sel.options[sel.selectedIndex];
        document.getElementById("workspace-current").textContent = opt ? `(${opt.text})` : "";
      },

      async get(id) {
        try { this._apply(await Api.getWorkspace(id)); }
        catch (e) { console.error("Failed to get workspace:", e); }
      },

      async create(name) {
        try {
          const json = await Api.createWorkspace(name);
          this._apply(json);
          await this.load(false);
          document.getElementById("workspace-select").value = json.data.workspace_id;
        } catch (e) { console.error("Failed to create workspace:", e); }
      },

      async rename(id, name) {
        try {
          await Api.renameWorkspace(id, name);
          await this.load(false);
          document.getElementById("workspace-select").value = id;
        } catch (e) {
          console.error("Failed to rename workspace:", e);
          alert(e.message || "Failed to rename workspace");
        }
      },

      async delete(id) {
        try {
          await Api.deleteWorkspace(id);
          State.workspaceID = null;
          await this.load(true);
        } catch (e) {
          console.error("Failed to delete workspace:", e);
          alert(e.message || "Failed to delete workspace");
        }
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // SBOM — file upload, tabs, topology rendering, delete, report download
    // ═══════════════════════════════════════════════════════════════════════════
    const Sbom = {
      async upload(files) {
        const statusContainer = document.getElementById("upload-status");
        const selectedContainer = document.getElementById("selected-files");
        statusContainer.innerHTML = "";
        selectedContainer.innerHTML = "";
        if (!files.length) return;

        const heading = document.createElement("div");
        heading.className = "font-medium mb-2";
        heading.textContent = t("selectedFiles");
        selectedContainer.appendChild(heading);

        const fileList = document.createElement("ul");
        fileList.className = "space-y-1";
        Array.from(files).forEach(file => {
          const li = document.createElement("li");
          li.className = "flex items-center";
          li.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-[#009999] mr-1" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
          </svg><span>${file.name}</span>`;
          fileList.appendChild(li);
        });
        selectedContainer.appendChild(fileList);

        const statusList = document.createElement("ul");
        statusList.className = "space-y-2 mt-4";
        statusContainer.appendChild(statusList);

        const selectBtn = document.getElementById("select-sbom-btn");
        selectBtn.disabled = true;
        selectBtn.classList.add("opacity-50", "cursor-not-allowed");

        for (const file of files) {
          const item = document.createElement("li");
          item.className = "flex items-center";
          item.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-yellow-500 mr-2" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
          </svg><span>${t("uploading", file.name)}</span>`;
          statusList.appendChild(item);

          if (State.uploadedFiles.has(file.name)) {
            const warning = document.createElement("li");
            warning.className = "flex items-center bg-yellow-50 px-4 py-2 rounded-md border border-yellow-200 mt-2";
            warning.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-yellow-600 mr-2" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
            </svg><span class="text-yellow-800">${t("warningOverwrite", file.name)}</span>`;
            statusList.appendChild(warning);
            setTimeout(() => {
              warning.classList.add("transition-opacity", "duration-500", "opacity-0");
              setTimeout(() => warning.remove(), 500);
            }, 15000);
          }

          try {
            const resp = await Api.uploadSBOM(State.workspaceID, file);
            if (resp.ok) {
              const data = await resp.json();
              const fileName = data.data?.name || file.name;
              item.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-600 mr-2" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
              </svg><span class="text-green-600">${t("uploadedSuccessfully", file.name)}</span>`;
              this.addTab(fileName);
              setTimeout(() => item.remove(), 3000);
            } else {
              const err = await resp.json().catch(() => ({}));
              item.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-red-500 mr-2" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
              </svg><span class="text-red-600">${t("uploadFailed", file.name, err.error || "Upload failed")}</span>`;
            }
          } catch (e) {
            item.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-red-500 mr-2" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
            </svg><span class="text-red-600">${t("uploadFailed", file.name, e.message || t("errorReadingFile"))}</span>`;
          }
        }

        selectBtn.disabled = false;
        selectBtn.classList.remove("opacity-50", "cursor-not-allowed");
      },

      // autoSelect=true: also select+fetch the tab (default for user-uploaded files).
      // autoSelect=false: only create the tab element (used on workspace load to avoid N fetches).
      addTab(fileName, autoSelect = true) {
        const tabsContainer = document.getElementById("file-tabs");
        const noMsg = document.getElementById("no-tabs-message");
        if (noMsg) noMsg.style.display = "none";

        if (State.uploadedFiles.has(fileName)) {
          const existing = Array.from(tabsContainer.children).find(el => el.dataset.fileName === fileName);
          if (existing) this.selectTab(existing);
          return;
        }

        State.uploadedFiles.add(fileName);
        const tab = document.createElement("div");
        tab.className = "px-4 py-2 border border-gray-300 rounded-t-md mr-2 mb-2 cursor-pointer hover:bg-gray-50 flex items-center";
        tab.dataset.fileName = fileName;
        tab.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-[#009999] mr-2" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
        </svg><span>${fileName}</span>`;
        tab.addEventListener("click", () => this.selectTab(tab));
        tabsContainer.appendChild(tab);
        if (autoSelect) this.selectTab(tab);
      },

      selectTab(tabEl) {
        document.getElementById("file-tabs").querySelectorAll("div").forEach(el => el.classList.remove("tab-active"));
        tabEl.classList.add("tab-active");
        State.activeTab = tabEl;

        const fileName = tabEl.dataset.fileName;
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
        </svg><span>Download PDF Report</span>`;
        downloadBtn.addEventListener("click", () => this.downloadReport(fileName));

        const deleteBtn = document.createElement("button");
        deleteBtn.className = "delete-btn bg-[#E46058] hover:bg-red-600 text-white py-1 px-3 rounded text-sm flex items-center";
        deleteBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
        </svg>${t("delete")}`;
        deleteBtn.addEventListener("click", () => this.delete(fileName));

        btnGroup.appendChild(downloadBtn);
        btnGroup.appendChild(deleteBtn);
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

      downloadReport(fileName) {
        // Server sends Content-Disposition: attachment — window.open triggers browser download
        window.open(`/workspaces/${State.workspaceID}/sboms/${encodeURIComponent(fileName)}/report`);
      },

      async fetchTopology(fileName) {
        const content = document.getElementById("tab-content");
        const header = content.querySelector("div:first-child");
        try {
          const json = await Api.getTopology(State.workspaceID, fileName);
          if (!json.data) throw new Error("No topology data");
          this._renderTopology(json.data, fileName, header);
        } catch (e) {
          console.error("Topology error:", e);
          content.innerHTML = "";
          content.appendChild(header);
          const errEl = document.createElement("div");
          errEl.className = "mt-4 p-4 bg-red-50 text-red-600 rounded-md";
          errEl.innerHTML = `<div class="font-medium">${t("failedToLoadTopology")}</div>
            <div class="text-sm mt-1">${e.message || t("unknownError")}</div>`;
          content.appendChild(errEl);
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

              item.innerHTML = `${icon}<span class="truncate">${comp}</span>`;
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

      async delete(fileName) {
        try {
          await Api.deleteSBOM(State.workspaceID, fileName);
          const tabsContainer = document.getElementById("file-tabs");
          const tabEl = Array.from(tabsContainer.children).find(el => el.dataset.fileName === fileName);
          State.uploadedFiles.delete(fileName); // always sync state, even if tab element is missing
          if (tabEl) {
            tabsContainer.removeChild(tabEl);
            if (State.activeTab === tabEl) {
              document.getElementById("tab-content").innerHTML = "";
              State.activeTab = null;
            }
          }
          if (State.uploadedFiles.size > 0) {
            const first = tabsContainer.querySelector("div");
            if (first) this.selectTab(first);
          } else {
            document.getElementById("tab-content").innerHTML =
              `<div id="no-tabs-message" class="text-gray-500 italic">${t("noFilesUploaded")}</div>`;
          }
          document.getElementById("sbom-file-input").value = "";

          const status = document.getElementById("upload-status");
          const msg = document.createElement("div");
          msg.className = "mt-2 text-green-600 flex items-center";
          msg.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
          </svg>${t("deletedSuccessfully", fileName)}`;
          status.innerHTML = "";
          status.appendChild(msg);
          setTimeout(() => msg.remove(), 3000);
        } catch (e) {
          console.error("Delete error:", e);
          alert(t("errorDeleting", e.message || t("unknownError")));
        }
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // COMPONENT MODAL — lazy-created, event delegation for vuln toggles
    // ═══════════════════════════════════════════════════════════════════════════
    const ComponentModal = {
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

        document.getElementById("component-modal-close").addEventListener("click", () =>
          document.getElementById("component-modal").classList.add("hidden")
        );

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

      async show(sbomName, component) {
        this._ensureModal();
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
            Api.getComponent(State.workspaceID, sbomName, component).catch(() => null),
            Api.getVulnDep(State.workspaceID, sbomName, component).catch(() => null),
          ]);
          if (!compRes?.data) throw new Error("No component data");
          this._renderDetails(compRes.data, vulnDepRes?.data || []);
        } catch (e) {
          document.getElementById("component-modal-content").innerHTML = `
            <div class="bg-red-50 text-red-800 p-4 rounded-md">
              <p class="font-medium">Error loading component details</p>
              <p class="mt-2">${e.message || "Unknown error"}</p>
            </div>`;
        }
      },

      _renderDetails(comp, vulnDepPaths = []) {
        const { name, version, vuln_number = 0, vulns = [],
                suggested_fix_version, is_breaking_change, has_severe_vuln, licences } = comp;

        const warnIcon = (color) => _warnSVG(color, "", "h-5 w-5 mr-1 flex-shrink-0 mt-0.5");

        let html = `
          <div class="mb-6 pb-6 border-b border-gray-200">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
              <div>
                <h3 class="text-sm font-medium text-gray-500">${t("componentName")}</h3>
                <p class="mt-2 text-lg">${name || "—"}</p>
              </div>
              <div>
                <h3 class="text-sm font-medium text-gray-500">${t("componentLicense")}</h3>
                <p class="mt-2 text-lg">${licences || "—"}</p>
              </div>
            </div>
            <div>
              <h3 class="text-sm font-medium text-gray-500">${t("componentVersion")}</h3>
              <div class="mt-2 flex items-center flex-wrap">
                <span class="text-lg">${version || "—"}</span>
                ${suggested_fix_version ? `
                  <div class="ml-3 flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-[#009999] mr-1" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L9 9.414V13a1 1 0 102 0V9.414l1.293 1.293a1 1 0 001.414-1.414z" clip-rule="evenodd" />
                    </svg>
                    <span class="text-[#009999] font-medium">${t("suggestUpgradeTo", suggested_fix_version)}</span>
                  </div>` : ""}
              </div>
              ${is_breaking_change && suggested_fix_version ? `
                <div class="mt-2 p-2 bg-yellow-50 border border-yellow-200 rounded text-sm flex items-start">
                  ${warnIcon("yellow")}<span class="text-yellow-700">${t("breakingChangeWarning", suggested_fix_version)}</span>
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
                  return `${arrow}<span class="px-2 py-1 text-sm rounded ${vuln ? "bg-red-100 text-red-800 font-medium" : "bg-gray-100 text-gray-800"}">${p}</span>`;
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
                    <span class="font-medium">${vuln.id || "Unknown"}</span>
                  </div>
                  <div class="flex items-center">
                    ${vuln.cvss_score ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 mr-2">CVSS: ${vuln.cvss_score}</span>` : ""}
                    ${vuln.epss       ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 mr-2">EPSS: ${vuln.epss}</span>` : ""}
                    ${vuln.lev        ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 mr-2">LEV: ${vuln.lev}</span>` : ""}
                    <span class="px-2.5 py-0.5 rounded-full text-xs font-medium ${sevClass}">${severity}</span>
                    <svg id="vuln-chevron-${i}" xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 ml-2 transform transition-transform duration-200" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div id="vuln-body-${i}" class="px-4 py-3 border-t border-gray-200 hidden">
                  ${vuln.summary           ? `<div class="mb-4"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("summary")}</h4><p>${vuln.summary}</p></div>` : ""}
                  ${vuln.details           ? `<div class="mb-4"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("details")}</h4><div class="prose prose-sm max-w-none">${_renderMarkdown(vuln.details)}</div></div>` : ""}
                  ${vuln.suggest_fix_version  ? `<div class="mt-2"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("fixVersion")}</h4><p class="text-green-600 font-medium">${vuln.suggest_fix_version}</p></div>` : ""}
                  ${vuln.other_fix_versions   ? `<div class="mt-2"><h4 class="text-sm font-medium text-gray-500 mb-1">${t("otherFixVersions")}</h4><p class="text-gray-800">${vuln.other_fix_versions}</p></div>` : ""}
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
      async run(q) {
        if (!State.workspaceID) return;
        try {
          const json = await Api.search(State.workspaceID, q);
          this._renderResults(json.data);
        } catch (e) {
          console.error("Search error:", e);
        }
      },

      _renderResults(data) {
        const container = document.getElementById("search-results");
        const clearBtn  = document.getElementById("search-clear-btn");

        if (!data || data.total === 0) {
          container.innerHTML = `<div class="px-4 py-3 text-sm text-gray-500">No results found</div>`;
          container.classList.remove("hidden");
          clearBtn.classList.remove("hidden");
          return;
        }

        const rows = data.results.map(r => {
          const typeBadge = r.match_type === "component"
            ? `<span class="inline-block text-xs bg-blue-100 text-blue-700 rounded px-1.5 py-0.5">component</span>`
            : `<span class="inline-block text-xs bg-red-100 text-red-700 rounded px-1.5 py-0.5">CVE</span>`;
          const levelLabel = r.level === 0 ? "直接使用之元件" : `第${r.level}級`;
          const levelBadge = `<span class="inline-block text-xs bg-gray-100 text-gray-500 rounded px-1.5 py-0.5 ml-1">${levelLabel}</span>`;
          const icons = (r.has_vuln     ? _warnSVG("red",    "alert")   : "")
                      + (r.has_vuln_dep ? _warnSVG("yellow", "warning") : "");
          const vulnInfo = r.match_type === "vuln"
            ? `<div class="text-xs text-red-600 mt-0.5">${r.vuln_id}${r.cvss_score ? " · CVSS " + r.cvss_score : ""}</div>
               <div class="text-xs text-gray-400 truncate">${r.vuln_summary || ""}</div>`
            : `<div class="text-xs text-gray-400">${r.vuln_count} vuln${r.vuln_count !== 1 ? "s" : ""}</div>`;
          // Use data attributes for event delegation (no inline onclick)
          const safeSbom = r.sbom.replace(/"/g, "&quot;");
          const safeComp = r.component.replace(/"/g, "&quot;");
          return `
            <div class="flex items-start gap-3 px-4 py-2.5 hover:bg-gray-50 border-b border-gray-100 last:border-0 cursor-pointer"
                 data-action="show-component" data-sbom="${safeSbom}" data-component="${safeComp}">
              <div class="mt-0.5 flex gap-1">${typeBadge}${levelBadge}</div>
              <div class="flex-1 min-w-0">
                <div class="text-sm font-medium text-gray-800">
                  ${r.component}${icons}
                  <span class="text-xs text-gray-400 font-normal ml-1">${r.version || ""}</span>
                </div>
                <div class="text-xs text-gray-500">${r.sbom}</div>
                ${vulnInfo}
              </div>
            </div>`;
        }).join("");

        container.innerHTML = rows;
        container.classList.remove("hidden");
        clearBtn.classList.remove("hidden");
      },

      clear() {
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
      openModal() {
        let modal = document.getElementById("diff-modal");
        if (!modal) {
          modal = document.createElement("div");
          modal.id = "diff-modal";
          modal.className = "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden";
          modal.innerHTML = `
            <div class="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] flex flex-col">
              <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
                <h2 class="text-xl font-medium text-gray-800" id="diff-modal-title"></h2>
                <button id="diff-modal-close" class="text-gray-500 hover:text-gray-700">
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <div class="p-6 border-b border-gray-200 flex items-end space-x-4">
                <div class="flex-1">
                  <label class="block text-sm font-medium text-gray-700 mb-1" id="diff-label-a"></label>
                  <select id="diff-select-a" class="w-full border border-gray-300 rounded-md py-2 px-3 focus:outline-none focus:ring-2 focus:ring-[#009999]"></select>
                </div>
                <div class="flex-1">
                  <label class="block text-sm font-medium text-gray-700 mb-1" id="diff-label-b"></label>
                  <select id="diff-select-b" class="w-full border border-gray-300 rounded-md py-2 px-3 focus:outline-none focus:ring-2 focus:ring-[#009999]"></select>
                </div>
                <button id="diff-compare-btn" class="bg-[#009999] hover:bg-[#19a3a3] text-white font-medium py-2 px-4 rounded-md shadow transition duration-200"></button>
              </div>
              <div class="overflow-y-auto flex-1 p-6" id="diff-result"></div>
            </div>`;
          document.body.appendChild(modal);
          const hideModal = () => modal.classList.add("hidden");
          document.getElementById("diff-modal-close").addEventListener("click", hideModal);
          modal.addEventListener("click", e => { if (e.target === modal) hideModal(); });
          document.getElementById("diff-compare-btn").addEventListener("click", () => this._run());
          // Event delegation for version-cell component clicks
          document.getElementById("diff-result").addEventListener("click", e => {
            const el = e.target.closest("[data-action='show-component']");
            if (!el) return;
            ComponentModal.show(el.dataset.sbom, el.dataset.component);
          });
        }

        modal.classList.remove("hidden");
        document.getElementById("diff-modal-title").textContent = t("diffSbomTitle");
        document.getElementById("diff-label-a").textContent     = t("diffSbomA");
        document.getElementById("diff-label-b").textContent     = t("diffSbomB");
        document.getElementById("diff-compare-btn").textContent = t("diffCompare");
        document.getElementById("diff-result").innerHTML = "";

        const names = Array.from(State.uploadedFiles);
        ["diff-select-a", "diff-select-b"].forEach((id, i) => {
          const sel = document.getElementById(id);
          sel.innerHTML = names.map(n => `<option value="${n}">${n}</option>`).join("");
          if (names[i]) sel.value = names[i];
        });
      },

      async _run() {
        const a = document.getElementById("diff-select-a").value;
        const b = document.getElementById("diff-select-b").value;
        const resultEl = document.getElementById("diff-result");

        if (!a || !b || a === b) {
          resultEl.innerHTML = `<p class="text-red-500">${t("diffSelectBoth")}</p>`;
          return;
        }

        resultEl.innerHTML = `<div class="flex justify-center py-8">
          <svg class="animate-spin h-8 w-8 text-[#009999]" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg></div>`;

        try {
          const json = await Api.diff(State.workspaceID, a, b);
          this._renderResult(json.data, a, b);
        } catch (e) {
          resultEl.innerHTML = `<p class="text-red-500">${e.message}</p>`;
        }
      },

      _versionCell(ver, sbomName, compName) {
        if (!ver || !sbomName) return `<td class="px-3 py-2 text-gray-400 align-top">-</td>`;
        const safeSbom = sbomName.replace(/"/g, "&quot;");
        const safeComp = compName.replace(/"/g, "&quot;");
        return `<td class="px-3 py-2 align-top">
          <span class="cursor-pointer hover:underline text-[#009999] font-mono text-xs"
                data-action="show-component" data-sbom="${safeSbom}" data-component="${safeComp}">${ver}</span>
        </td>`;
      },

      _section(rows, label, color, vA, vB, sbomA, sbomB) {
        if (!rows?.length) return "";
        return `
          <div class="mb-4">
            <h4 class="text-sm font-semibold text-${color}-700 mb-1">${label} (${rows.length})</h4>
            <table class="w-full text-sm border border-gray-200 rounded overflow-hidden">
              <thead class="bg-gray-50"><tr>
                <th class="text-left px-3 py-2 font-medium text-gray-600">${t("diffComponent")}</th>
                ${vA ? `<th class="text-left px-3 py-2 font-medium text-gray-600">${t("diffVersionA")}</th><th class="text-left px-3 py-2 font-medium text-gray-600 w-12">${t("diffVulnsA")}</th>` : ""}
                ${vB ? `<th class="text-left px-3 py-2 font-medium text-gray-600">${t("diffVersionB")}</th><th class="text-left px-3 py-2 font-medium text-gray-600 w-12">${t("diffVulnsB")}</th>` : ""}
              </tr></thead>
              <tbody>
                ${rows.map((r, i) => `
                  <tr class="${i % 2 === 0 ? "bg-white" : "bg-gray-50"}">
                    <td class="px-3 py-2 align-top">
                      <div class="flex items-center gap-1 font-mono text-xs">
                        <span>${r.name}</span>
                        ${r.has_vuln     ? _warnSVG("red",    "alert")   : ""}
                        ${r.has_vuln_dep ? _warnSVG("yellow", "warning") : ""}
                      </div>
                    </td>
                    ${vA ? `${this._versionCell(r.version_a, sbomA, r.name)}<td class="px-3 py-2 align-top text-center">${r.vulns_a ?? 0}</td>` : ""}
                    ${vB ? `${this._versionCell(r.version_b, sbomB, r.name)}<td class="px-3 py-2 align-top text-center">${r.vulns_b ?? 0}</td>` : ""}
                  </tr>`).join("")}
              </tbody>
            </table>
          </div>`;
      },

      _renderResult(data, sbomA, sbomB) {
        const resultEl = document.getElementById("diff-result");
        const byLevel  = data.by_level || {};
        const levels   = Object.keys(byLevel).map(Number).sort((a, b) => a - b);
        let html = "";
        let anyChanges = false;

        for (const level of levels) {
          const ld = byLevel[level];
          const total = (ld.added?.length || 0) + (ld.removed?.length || 0) + (ld.changed?.length || 0);
          if (!total) continue;
          anyChanges = true;
          const va = ld.total_vulns_a ?? 0, vb = ld.total_vulns_b ?? 0;
          const color = vb > va ? "text-red-600" : vb < va ? "text-green-600" : "text-gray-500";
          html += `
            <div class="mb-8 border border-gray-200 rounded-lg overflow-hidden">
              <div class="flex items-center justify-between bg-gray-100 px-4 py-2">
                <span class="font-semibold text-gray-700">${t("diffLevel")} ${level}</span>
                <span class="text-xs font-medium ${color}">Vulns: <span class="line-through text-gray-400">${va}</span> → ${vb}</span>
              </div>
              <div class="p-4">
                ${this._section(ld.added,   t("diffAdded"),   "green",  false, true,  "",     sbomB)}
                ${this._section(ld.removed, t("diffRemoved"), "red",    true,  false, sbomA, "")}
                ${this._section(ld.changed, t("diffChanged"), "yellow", true,  true,  sbomA, sbomB)}
              </div>
            </div>`;
        }

        resultEl.innerHTML = anyChanges
          ? html
          : `<p class="text-gray-500 text-center py-8">${t("diffNoChanges")}</p>`;
      },
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // UTILITIES — pure helpers with no side effects
    // ═══════════════════════════════════════════════════════════════════════════
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
      return md
        .replace(/^### (.*$)/gm, '<h3 class="text-lg font-medium mt-3 mb-2">$1</h3>')
        .replace(/^## (.*$)/gm,  '<h2 class="text-xl font-medium mt-4 mb-2">$1</h2>')
        .replace(/^# (.*$)/gm,   '<h1 class="text-2xl font-bold mt-4 mb-3">$1</h1>')
        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
        .replace(/\*(.*?)\*/g,     "<em>$1</em>")
        .replace(/```([\s\S]*?)```/g, '<pre class="bg-gray-100 p-2 rounded my-2 overflow-x-auto text-sm"><code>$1</code></pre>')
        .replace(/`(.*?)`/g, '<code class="bg-gray-100 px-1 rounded text-sm">$1</code>')
        .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" target="_blank" class="text-blue-600 hover:underline">$1</a>')
        .replace(/^\s*-\s(.*$)/gm, '<li class="ml-4">$1</li>')
        .replace(/^\s*(\n)?([^\n]+)/gm, m => /^<(\/)?(h1|h2|h3|pre|li)/i.test(m) ? m : `<p class="my-2">${m}</p>`)
        .replace(/<p><\/p>/g, "");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // APP INIT — wire up all event listeners, then load initial data
    // ═══════════════════════════════════════════════════════════════════════════
    document.addEventListener("DOMContentLoaded", () => {
      // Language
      const lang = (navigator.language || "en").startsWith("zh") ? "zh" : "en";
      i18n.change(lang);

      // File upload
      document.getElementById("sbom-file-input").addEventListener("change", e => {
        Sbom.upload(e.target.files);
      });
      document.getElementById("select-sbom-btn").addEventListener("click", () => {
        document.getElementById("sbom-file-input").click();
      });

      // Language switcher
      document.getElementById("lang-en").addEventListener("click", () => i18n.change("en"));
      document.getElementById("lang-zh").addEventListener("click", () => i18n.change("zh"));

      // Tutorial
      document.getElementById("tutorial-btn").addEventListener("click", () => {
        window.location.href = "/tutorial";
      });

      // Search (debounced)
      let searchTimer = null;
      document.getElementById("search-input").addEventListener("input", e => {
        clearTimeout(searchTimer);
        const q = e.target.value.trim();
        if (!q) { Search.clear(); return; }
        searchTimer = setTimeout(() => Search.run(q), 300);
      });
      document.getElementById("search-input").addEventListener("keydown", e => {
        if (e.key === "Escape") Search.clear();
      });
      document.getElementById("search-clear-btn").addEventListener("click", () => Search.clear());

      // Event delegation: search result rows → open component modal
      document.getElementById("search-results").addEventListener("click", e => {
        const row = e.target.closest("[data-action='show-component']");
        if (row) ComponentModal.show(row.dataset.sbom, row.dataset.component);
      });

      // Workspace controls
      document.getElementById("workspace-select").addEventListener("change", e => Workspace.get(e.target.value));
      document.getElementById("workspace-switch-btn").addEventListener("click", () => {
        const name = document.getElementById("workspace-input").value.trim();
        if (!name) return;
        document.getElementById("workspace-input").value = "";
        Workspace.create(name);
      });
      document.getElementById("workspace-rename-btn").addEventListener("click", () => {
        if (!State.workspaceID) return;
        const sel     = document.getElementById("workspace-select");
        const current = sel.options[sel.selectedIndex]?.text || "";
        const name    = prompt(t("workspaceRenamePrompt"), current);
        if (!name?.trim() || name.trim() === current) return;
        Workspace.rename(State.workspaceID, name.trim());
      });
      document.getElementById("workspace-delete-btn").addEventListener("click", () => {
        if (!State.workspaceID) return;
        if (!confirm(t("workspaceDeleteConfirm"))) return;
        Workspace.delete(State.workspaceID);
      });

      // Diff
      document.getElementById("diff-sbom-btn").addEventListener("click", () => Diff.openModal());

      // Bootstrap
      Workspace.load();
    });
