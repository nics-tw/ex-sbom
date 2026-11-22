// SPDX-License-Identifier: MIT

const Api = {
  async _json(url, opts = {}) {
    const resp = await fetch(url, opts);
    const json = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
    return json;
  },

  getProjects(signal)    { return this._json("/projects", { signal }); },
  getProject(id, signal) { return this._json(`/projects/${encodeURIComponent(id)}`, { signal }); },
  createProject(name) {
    return this._json("/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
  },
  renameProject(id, name) {
    return this._json(`/projects/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
  },
  deleteProject(id)  { return this._json(`/projects/${encodeURIComponent(id)}`, { method: "DELETE" }); },

  previewSBOM(projectID, file, signal) {
    const form = new FormData();
    form.append("file", file);
    return fetch(`/projects/${projectID}/sboms/preview`, { method: "POST", body: form, signal });
  },

  commitSBOM(projectID, version, bomResult, sha256, bomTimestamp, previewToken) {
    return fetch(`/projects/${projectID}/sboms`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version, bom_result: bomResult, sha256, bom_timestamp: bomTimestamp, preview_token: previewToken }),
    });
  },
  getReport(projectID, version, language) {
    return fetch(`/projects/${encodeURIComponent(projectID)}/sboms/${encodeURIComponent(version)}/report?lang=${encodeURIComponent(language)}`, { redirect: "error" });
  },
  listVersions(projectID, signal) {
    return this._json(`/projects/${projectID}/versions`, { signal });
  },
  renameSBOM(projectID, name, newName) {
    return this._json(`/projects/${projectID}/sboms/${encodeURIComponent(name)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: newName }),
    });
  },
  deleteSBOM(projectID, name) {
    return this._json(`/projects/${projectID}/sboms/${encodeURIComponent(name)}`, { method: "DELETE" });
  },

  getTopology(projectID, name, signal) {
    return this._json(`/projects/${projectID}/sboms/${encodeURIComponent(name)}/topology`, { signal });
  },
  getComponent(projectID, sbom, comp, signal) {
    return this._json(`/projects/${projectID}/sboms/${encodeURIComponent(sbom)}/topology/component?component=${encodeURIComponent(comp)}`, { signal });
  },
  getVulnDep(projectID, sbom, comp, signal) {
    return this._json(`/projects/${projectID}/sboms/${encodeURIComponent(sbom)}/topology/component/vuln-dep?component=${encodeURIComponent(comp)}`, { signal });
  },
  search(projectID, q, signal) {
    return this._json(`/projects/${projectID}/search?q=${encodeURIComponent(q)}`, { signal });
  },
  diff(projectID, a, b, signal) {
    return this._json(`/projects/${projectID}/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`, { signal });
  },
};
