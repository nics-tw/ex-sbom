// SPDX-License-Identifier: MIT

// Both pages use the browser default until the user explicitly chooses a language.
function bindLanguageSwitcher(applyLanguage) {
  const key = "ex-sbom.language";
  const languages = ["en", "zh"];
  function storedLanguage() {
    try {
      const stored = window.localStorage.getItem(key);
      if (languages.includes(stored)) return stored;
    } catch {
      // Browser privacy settings can restrict access to storage.
    }
  }

  const shellText = {
    en: {
      skipToMain: "Skip to main content",
      siteNavigation: "Site navigation",
      displayLanguage: "Display language",
      appDescription: "SBOM Explorer, designed by NICS-ra",
      tutorialBtn: "Tutorial",
      backToMain: "Back to Explorer",
      tutorialHeading: "How to use ex-sbom",
      tutorialTitle: "ex-sbom · Tutorial",
      newProject: "New project name",
      analysisTab: "SBOM Analysis",
      diffTab: "Compare Versions",
      searchLabel: "Search components or CVEs",
      clearSearch: "Clear search",
      versionHistory: "Version History",
      loading: "Loading…",
    },
    zh: {
      skipToMain: "跳至主要內容",
      siteNavigation: "網站導覽",
      displayLanguage: "顯示語言",
      appDescription: "由 NICS-ra 設計的 SBOM 探索工具",
      tutorialBtn: "操作教學",
      backToMain: "返回主頁",
      tutorialHeading: "ex-sbom 操作教學",
      tutorialTitle: "ex-sbom · 操作教學",
      newProject: "新專案名稱",
      analysisTab: "SBOM 分析",
      diffTab: "版本比對",
      searchLabel: "搜尋元件或 CVE",
      clearSearch: "清除搜尋",
      versionHistory: "版本歷程",
      loading: "載入中…",
    },
  };

  let currentLanguage;
  function render(selected) {
    currentLanguage = selected;
    document.documentElement.lang = selected === "zh" ? "zh-Hant" : "en";
    for (const code of languages) {
      const button = document.getElementById("lang-" + code);
      button.classList.toggle("active-language", code === selected);
      button.setAttribute("aria-pressed", String(code === selected));
    }
    const labels = shellText[selected];
    for (const element of document.querySelectorAll("[data-shell-i18n]")) {
      element.textContent = labels[element.dataset.shellI18n];
    }
    for (const element of document.querySelectorAll("[data-shell-aria-label]")) {
      element.setAttribute("aria-label", labels[element.dataset.shellAriaLabel]);
    }
    for (const element of document.querySelectorAll("[data-shell-placeholder]")) {
      element.placeholder = labels[element.dataset.shellPlaceholder];
    }
    if (document.body.dataset.shellTitle) {
      document.title = labels[document.body.dataset.shellTitle];
    }
    applyLanguage(selected);
  }

  for (const code of languages) {
    document.getElementById("lang-" + code).addEventListener("click", () => {
      try {
        window.localStorage.setItem(key, code);
      } catch {
        // The choice still applies to this page when storage is unavailable.
      }
      render(code);
    });
  }
  window.addEventListener("pageshow", event => {
    if (!event.persisted) return;
    // A restored page keeps its DOM even if another page changed the preference.
    const stored = storedLanguage();
    if (stored && stored !== currentLanguage) render(stored);
  });
  const browserLanguage = (navigator.language || "en").toLowerCase().startsWith("zh") ? "zh" : "en";
  render(storedLanguage() || browserLanguage);
}
