// SPDX-License-Identifier: MIT

// Render completed search and diff results. Request handlers own when to update the view.
const ResultView = {
  search(container, clearBtn, data) {
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
      const levelLabel = r.level === 0 ? "直接使用之元件" : `第${esc(r.level)}級`;
      const levelBadge = `<span class="inline-block text-xs bg-gray-100 text-gray-500 rounded px-1.5 py-0.5 ml-1">${levelLabel}</span>`;
      const icons = (r.has_vuln     ? _warnSVG("red",    "alert")   : "")
                  + (r.has_vuln_dep ? _warnSVG("yellow", "warning") : "");
      const vulnInfo = r.match_type === "vuln"
        ? `<div class="text-xs text-red-600 mt-0.5">${esc(r.vuln_id)}${r.cvss_score ? " · CVSS " + esc(r.cvss_score) : ""}</div>
           <div class="text-xs text-gray-400 truncate">${esc(r.vuln_summary) || ""}</div>`
        : `<div class="text-xs text-gray-400">${esc(r.vuln_count)} vuln${r.vuln_count !== 1 ? "s" : ""}</div>`;
      // Use data attributes for event delegation (no inline onclick)
      const safeSbom = esc(r.sbom);
      const safeComp = esc(r.component);
      return `
        <div class="flex items-start gap-3 px-4 py-2.5 hover:bg-gray-50 border-b border-gray-100 last:border-0 cursor-pointer"
             data-action="show-component" data-sbom="${safeSbom}" data-component="${safeComp}">
          <div class="mt-0.5 flex gap-1">${typeBadge}${levelBadge}</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-medium text-gray-800">
              ${safeComp}${icons}
              <span class="text-xs text-gray-400 font-normal ml-1">${esc(r.version) || ""}</span>
            </div>
            <div class="text-xs text-gray-500">${safeSbom}</div>
            ${vulnInfo}
          </div>
        </div>`;
    }).join("");

    container.innerHTML = rows;
    container.classList.remove("hidden");
    clearBtn.classList.remove("hidden");
  },

  _versionCell(ver, sbomName, compName) {
    if (!ver || !sbomName) return "";
    return `<span class="cursor-pointer hover:underline text-[#009999] font-mono text-xs"
                  data-action="show-component" data-sbom="${esc(sbomName)}" data-component="${esc(compName)}">${esc(ver)}</span>`;
  },

  _diffRow(r, type, sbomA, sbomB) {
    const icons = `${r.has_vuln ? _warnSVG("red", "alert") : ""}${r.has_vuln_dep ? _warnSVG("yellow", "warning") : ""}`;
    const name = `<span class="font-mono text-xs">${esc(r.name)}</span>`;

    if (type === "added") {
      return `<tr>
        <td class="px-3 py-1.5 border-r border-gray-200 bg-white"></td>
        <td class="px-3 py-1.5 bg-green-50">
          <div class="flex items-center gap-2">
            <span class="text-green-600 font-bold w-4 text-center flex-shrink-0">+</span>
            <div class="flex items-center gap-1 flex-1 min-w-0">${name}${icons}</div>
            <div class="flex items-center gap-2 flex-shrink-0">
              ${this._versionCell(r.version_b, sbomB, r.name)}
              <span class="text-xs text-gray-500 w-8 text-right">${r.vulns_b ?? 0}</span>
            </div>
          </div>
        </td>
      </tr>`;
    }

    if (type === "removed") {
      return `<tr>
        <td class="px-3 py-1.5 border-r border-gray-200 bg-red-50">
          <div class="flex items-center gap-2">
            <span class="text-red-600 font-bold w-4 text-center flex-shrink-0">−</span>
            <div class="flex items-center gap-1 flex-1 min-w-0">${name}${icons}</div>
            <div class="flex items-center gap-2 flex-shrink-0">
              ${this._versionCell(r.version_a, sbomA, r.name)}
              <span class="text-xs text-gray-500 w-8 text-right">${r.vulns_a ?? 0}</span>
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
          <span class="text-amber-600 font-bold w-4 text-center flex-shrink-0">~</span>
          <div class="flex items-center gap-1 flex-1 min-w-0">${name}${icons}</div>
          <div class="flex items-center gap-2 flex-shrink-0">
            ${this._versionCell(r.version_a, sbomA, r.name)}
            <span class="text-xs text-gray-500 w-8 text-right">${r.vulns_a ?? 0}</span>
          </div>
        </div>
      </td>
      <td class="px-3 py-1.5 bg-amber-50">
        <div class="flex items-center gap-2">
          <span class="text-amber-600 font-bold w-4 text-center flex-shrink-0">~</span>
          <div class="flex items-center gap-1 flex-1 min-w-0">${name}${icons}</div>
          <div class="flex items-center gap-2 flex-shrink-0">
            ${this._versionCell(r.version_b, sbomB, r.name)}
            <span class="text-xs text-gray-500 w-8 text-right">${r.vulns_b ?? 0}</span>
          </div>
        </div>
      </td>
    </tr>`;
  },

  diff(resultEl, data, sbomA, sbomB) {
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
    let html = `<div class="flex items-center gap-4 mb-6 px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg text-sm">
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
      const vulnColor = vb > va ? "text-red-600" : vb < va ? "text-green-600" : "text-gray-500";
      const levelId = `diff-level-${level}`;

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

      html += `
        <div class="mb-4 border border-gray-200 rounded-lg overflow-hidden">
          <div class="flex items-center justify-between bg-gray-100 px-4 py-2 ${total ? "cursor-pointer select-none hover:bg-gray-200 transition-colors" : ""}" ${total ? `onclick="(function(el){var b=document.getElementById('${levelId}');b.classList.toggle('hidden');el.querySelector('[data-chevron]').classList.toggle('rotate-90');})(this)"` : ""}>
            <div class="flex items-center gap-3">
              ${total ? `<svg data-chevron class="h-4 w-4 text-gray-500 transition-transform" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
              </svg>` : ""}
              <span class="font-semibold text-gray-700">${t("diffLevel")} ${level}</span>
              ${badges}
            </div>
            <span class="text-xs font-medium ${vulnColor}">${t("diffVulns")}: <span class="line-through text-gray-400">${va}</span> → ${vb}</span>
          </div>
          ${total ? `<div id="${levelId}">
            <table class="w-full text-sm border-collapse">
              <thead>
                <tr class="bg-gray-50 border-b border-gray-200">
                  <th class="text-left px-3 py-2 font-medium text-gray-600 w-1/2 border-r border-gray-200">${esc(sbomA)}</th>
                  <th class="text-left px-3 py-2 font-medium text-gray-600 w-1/2">${esc(sbomB)}</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100">${rows}</tbody>
            </table>
          </div>` : ""}
        </div>`;
    }

    resultEl.innerHTML = html;
  },
};
