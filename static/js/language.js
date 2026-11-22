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

  let currentLanguage;
  function render(selected) {
    currentLanguage = selected;
    document.documentElement.lang = selected === "zh" ? "zh-Hant" : "en";
    for (const code of languages) {
      const button = document.getElementById("lang-" + code);
      button.classList.toggle("active-language", code === selected);
      button.setAttribute("aria-pressed", String(code === selected));
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
