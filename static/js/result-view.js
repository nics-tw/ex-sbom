// SPDX-License-Identifier: MIT

// Render completed search and diff results. Request handlers own when to update the view.
const ResultView = {
  _diffScroll: new WeakMap(),
  search(container, clearBtn, data) {
    if (!data || data.total === 0) {
      container.innerHTML = `<p class="px-4 py-3 text-sm text-gray-600">${t("searchNoResults")}</p>`;
      container.classList.remove("hidden");
      clearBtn.classList.remove("hidden");
      return;
    }

    const rows = data.results.map(r => {
      const typeBadge = r.match_type === "component"
        ? `<span class="inline-block text-xs bg-blue-100 text-blue-700 rounded px-1.5 py-0.5">${t("searchComponentMatch")}</span>`
        : `<span class="inline-block text-xs bg-red-100 text-red-700 rounded px-1.5 py-0.5">CVE</span>`;
      const levelLabel = r.level === 0 ? t("rootLevel") : esc(t("level", r.level));
      const levelBadge = `<span class="inline-block text-xs bg-gray-100 text-gray-700 rounded px-1.5 py-0.5">${levelLabel}</span>`;
      const vulnInfo = r.match_type === "vuln"
        ? `<span class="block text-xs text-red-700 mt-0.5">${esc(r.vuln_id)}${r.cvss_score ? " · CVSS " + esc(r.cvss_score) : ""}</span>
           <span class="block text-xs text-gray-600 break-words">${esc(r.vuln_summary) || ""}</span>`
        : `<span class="block text-xs text-gray-600">${esc(t("vulnerabilities", r.vuln_count ?? 0))}</span>`;
      // Use data attributes for event delegation (no inline onclick)
      const safeSbom = esc(r.sbom);
      const safeComp = esc(r.component);
      return `
        <li class="border-b border-gray-100 last:border-0">
          <button type="button" class="w-full text-left px-4 py-2.5 hover:bg-gray-50"
                  aria-haspopup="dialog" data-action="show-component" data-sbom="${safeSbom}" data-component="${safeComp}">
            <span class="block min-w-0 break-words text-sm font-medium text-gray-800">
              ${safeComp}
              <span class="text-xs text-gray-600 font-normal ml-1">${esc(r.version) || ""}</span>
            </span>
            <span class="block break-words text-xs text-gray-600">${safeSbom}</span>
            <span class="mt-0.5 flex flex-wrap gap-1">${typeBadge}${levelBadge}</span>
            ${this._vulnerabilityStatus(r)}
            ${vulnInfo}
          </button>
        </li>`;
    }).join("");

    container.innerHTML = `<ul role="list">${rows}</ul>`;
    container.classList.remove("hidden");
    clearBtn.classList.remove("hidden");
  },

  _versionCell(ver, sbomName, compKey, compName) {
    if (!ver || !sbomName) return "";
    return `<button type="button" class="p-1 min-h-6 min-w-6 max-w-[8rem] underline text-[var(--site-accent)] font-mono text-xs break-all text-left"
                   aria-haspopup="dialog" aria-label="${esc(t("diffVersionDetails", ver, compName, sbomName))}"
                   data-action="show-component" data-sbom="${esc(sbomName)}" data-component="${esc(compKey)}">${esc(ver)}</button>`;
  },

  _vulnerabilityStatus(result) {
    return [
      result.has_vuln && t("topologyVulnerableComponent"),
      result.has_vuln_dep && t("topologyVulnerableDependency"),
    ].filter(Boolean).map(status => `<span class="block text-xs text-gray-700">${status}</span>`).join("");
  },

  _diffRow(r, type, sbomA, sbomB) {
    const name = `<span class="font-mono text-xs break-all">${esc(r.name)}</span>`;
    const component = name + this._vulnerabilityStatus(r);

    if (type === "added") {
      return `<tr>
        <td class="px-3 py-1.5 border-r border-gray-200 bg-white"></td>
        <td class="px-3 py-1.5 bg-green-50">
          <div class="flex items-center gap-2">
            <span class="text-green-800 font-bold w-4 text-center flex-shrink-0" aria-hidden="true">+</span>
            <div class="flex-1 min-w-0"><span class="sr-only">${t("diffAdded")} </span>${component}</div>
            <div class="flex items-center gap-2 flex-shrink-0">
              ${this._versionCell(r.version_b, sbomB, r.name, r.name)}
              <span class="text-xs text-gray-600 w-8 text-right">${esc(r.vulns_b ?? 0)}<span class="sr-only"> ${t("diffVulns")}</span></span>
            </div>
          </div>
        </td>
      </tr>`;
    }

    if (type === "removed") {
      return `<tr>
        <td class="px-3 py-1.5 border-r border-gray-200 bg-red-50">
          <div class="flex items-center gap-2">
            <span class="text-red-800 font-bold w-4 text-center flex-shrink-0" aria-hidden="true">−</span>
            <div class="flex-1 min-w-0"><span class="sr-only">${t("diffRemoved")} </span>${component}</div>
            <div class="flex items-center gap-2 flex-shrink-0">
              ${this._versionCell(r.version_a, sbomA, r.name, r.name)}
              <span class="text-xs text-gray-600 w-8 text-right">${esc(r.vulns_a ?? 0)}<span class="sr-only"> ${t("diffVulns")}</span></span>
            </div>
          </div>
        </td>
        <td class="px-3 py-1.5 bg-white"></td>
      </tr>`;
    }

    // changed
    return `<tr>
      <td class="px-3 py-1.5 border-r border-amber-200 bg-amber-50">
        <div class="flex items-center gap-2">
          <span class="text-amber-800 font-bold w-4 text-center flex-shrink-0" aria-hidden="true">~</span>
          <div class="flex-1 min-w-0"><span class="sr-only">${t("diffChanged")} </span>${component}</div>
          <div class="flex items-center gap-2 flex-shrink-0">
            ${this._versionCell(r.version_a, sbomA, r.name, r.name)}
            <span class="text-xs text-gray-600 w-8 text-right">${esc(r.vulns_a ?? 0)}<span class="sr-only"> ${t("diffVulns")}</span></span>
          </div>
        </div>
      </td>
      <td class="px-3 py-1.5 bg-amber-50">
        <div class="flex items-center gap-2">
          <span class="text-amber-800 font-bold w-4 text-center flex-shrink-0" aria-hidden="true">~</span>
          <div class="flex-1 min-w-0"><span class="sr-only">${t("diffChanged")} </span>${component}</div>
          <div class="flex items-center gap-2 flex-shrink-0">
            ${this._versionCell(r.version_b, sbomB, r.key_b ?? r.name, r.name)}
            <span class="text-xs text-gray-600 w-8 text-right">${esc(r.vulns_b ?? 0)}<span class="sr-only"> ${t("diffVulns")}</span></span>
          </div>
        </div>
      </td>
    </tr>`;
  },

  diff(resultEl, data, sbomA, sbomB, { preserveView = false } = {}) {
    const regions = () => resultEl.querySelectorAll("details > [role=region]");
    const state = new Map();
    if (preserveView) {
      for (const region of regions()) {
        state.set(region.getAttribute("aria-labelledby"), {
          open: region.parentElement.open,
          // A closed disclosure does not expose a usable scroll offset.
          scrollLeft: region.parentElement.open ? region.scrollLeft : this._diffScroll.get(region),
        });
      }
    }
    const byLevel  = data.by_level || {};
    const levels   = Object.keys(byLevel).map(Number).sort((a, b) => a - b);

    let totalAdded = 0, totalRemoved = 0, totalChanged = 0;
    for (const level of levels) {
      const ld = byLevel[level];
      totalAdded   += ld.added?.length   || 0;
      totalRemoved += ld.removed?.length || 0;
      totalChanged += ld.changed?.length || 0;
    }
    const anyChanges = totalAdded + totalRemoved + totalChanged > 0;

    if (!anyChanges) {
      resultEl.innerHTML = `<p class="text-gray-500 text-center py-8">${t("diffNoChanges")}</p>`;
      return;
    }

    // Summary bar
    let html = `<div class="flex flex-wrap items-center gap-4 mb-6 px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg text-sm">
      <span class="font-medium text-gray-700">${t("diffSummary", totalAdded, totalRemoved, totalChanged)}</span>
      <span class="flex items-center gap-3 ml-auto">
        ${totalAdded   ? `<span class="flex items-center gap-1"><span class="inline-block w-3 h-3 rounded-sm bg-green-200 border border-green-400"></span><span class="text-green-700 font-medium">+${totalAdded}</span></span>` : ""}
        ${totalRemoved ? `<span class="flex items-center gap-1"><span class="inline-block w-3 h-3 rounded-sm bg-red-200 border border-red-400"></span><span class="text-red-700 font-medium">−${totalRemoved}</span></span>` : ""}
        ${totalChanged ? `<span class="flex items-center gap-1"><span class="inline-block w-3 h-3 rounded-sm bg-yellow-200 border border-yellow-400"></span><span class="text-yellow-700 font-medium">~${totalChanged}</span></span>` : ""}
      </span>
    </div>`;

    for (const level of levels) {
      const ld = byLevel[level];
      const nA = ld.added?.length || 0, nR = ld.removed?.length || 0, nC = ld.changed?.length || 0;
      const total = nA + nR + nC;
      const va = ld.total_vulns_a ?? 0, vb = ld.total_vulns_b ?? 0;
      if (!total && va === vb) continue;
      const vulnColor = vb > va ? "text-red-800" : vb < va ? "text-green-800" : "text-gray-600";
      const captionId = `diff-level-caption-${level}`;

      // Merge all rows into a unified list: removed first, then changed, then added
      let rows = "";
      (ld.removed || []).forEach(r => { rows += this._diffRow(r, "removed", sbomA, sbomB); });
      (ld.changed || []).forEach(r => { rows += this._diffRow(r, "changed", sbomA, sbomB); });
      (ld.added   || []).forEach(r => { rows += this._diffRow(r, "added",   sbomA, sbomB); });

      // Badge counts
      const badges = [
        nA ? `<span class="bg-green-100 text-green-800 text-xs font-medium px-2 py-0.5 rounded">+${nA}</span>` : "",
        nR ? `<span class="bg-red-100 text-red-800 text-xs font-medium px-2 py-0.5 rounded">−${nR}</span>` : "",
        nC ? `<span class="bg-yellow-100 text-yellow-800 text-xs font-medium px-2 py-0.5 rounded">~${nC}</span>` : "",
      ].filter(Boolean).join(" ");

      const levelSummary = `<span class="font-semibold text-gray-700">${t("diffLevel")} ${level}</span>
        <span class="ml-2" aria-hidden="true">${badges}</span>
        ${total ? `<span class="sr-only">${t("diffSummary", nA, nR, nC)}</span>` : ""}
        <span class="ml-2 text-xs font-medium ${vulnColor}">${t("diffVulns")}: <span class="line-through text-gray-600">${va}</span> → ${vb}</span>`;
      html += total ? `
        <details class="mb-4 border border-gray-200 rounded-lg min-w-0" open>
          <summary class="bg-gray-100 px-4 py-2 cursor-pointer hover:bg-gray-200">${levelSummary}</summary>
          <div class="relative max-w-full overflow-x-auto" role="region" aria-labelledby="${captionId}" tabindex="0">
            <table class="w-full min-w-[36rem] table-fixed text-sm border-collapse">
              <caption id="${captionId}" class="sr-only">${t("diffTableCaption", level)}</caption>
              <thead>
                <tr class="bg-gray-50 border-b border-gray-200">
                  <th scope="col" class="text-left px-3 py-2 font-medium text-gray-700 w-1/2 break-words border-r border-gray-200">${esc(sbomA)}</th>
                  <th scope="col" class="text-left px-3 py-2 font-medium text-gray-700 w-1/2 break-words">${esc(sbomB)}</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100">${rows}</tbody>
            </table>
          </div>
        </details>` : `<div class="mb-4 border border-gray-200 rounded-lg bg-gray-100 px-4 py-2">${levelSummary}</div>`;
    }

    resultEl.innerHTML = html;
    for (const region of regions()) {
      const disclosure = region.parentElement;
      const previous = state.get(region.getAttribute("aria-labelledby"));
      if (previous) {
        disclosure.open = previous.open;
        if (previous.scrollLeft !== undefined) this._diffScroll.set(region, previous.scrollLeft);
        if (disclosure.open) region.scrollLeft = previous.scrollLeft ?? 0;
      }
      region.addEventListener("scroll", () => {
        if (disclosure.open) this._diffScroll.set(region, region.scrollLeft);
      });
      disclosure.addEventListener("toggle", () => {
        if (disclosure.open && this._diffScroll.has(region)) region.scrollLeft = this._diffScroll.get(region);
      });
    }
  },
};
