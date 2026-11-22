# ex-sbom

正體中文說明請參考 [README.zh-TW.md](README.zh-TW.md)

ex-sbom, short for Explorer of SBOM, is a local web application for visualizing, analyzing, and version-controlling SBOM scan results.

[![Go Reference](https://pkg.go.dev/badge/github.com/nics-tw/ex-sbom.svg)](https://pkg.go.dev/github.com/nics-tw/ex-sbom)
![GitHub license](https://img.shields.io/github/license/nics-tw/ex-sbom)

ex-sbom is packaged as a single executable that embeds the application pages, local JavaScript, and static assets. No server setup is required — run it and a local web UI opens in your browser. Vulnerability data is sourced from the OSV (Open Source Vulnerabilities) ecosystem via the osv-scanner library, so no API subscription is needed.

> Note: A working internet connection is required at startup and when uploading an SBOM, because osv-scanner queries the OSV API for vulnerability data.

## How to use it
1. Download the executable from the Release page (recommended), or build the project yourself.
2. Run it, and your browser opens the local web UI at `http://localhost:8080`.
3. Create or select a project. Projects group related SBOM versions for the same product or system.
4. In the **SBOM Analysis** tab, add a version by uploading a CycloneDX JSON or SPDX JSON file.
5. Preview the parsed result, give it a version name, and save it.
6. Explore the dependency graph, search across versions, compare two versions in the **Diff** tab, or export a PDF report.

## Features

- **Multi-project management** — organize your SBOMs into named projects, so you can manage them per software product or system.
- **Dual-format import** — parse and normalize both CycloneDX JSON and SPDX JSON into a unified internal representation.
  CycloneDX JSON is read directly through 1.7. For a newer declared version, ex-sbom attempts import using 1.7 compatibility and may ignore fields introduced after 1.7.
- **Dependency graph visualization** — explore the full dependency tree layer by layer, and see the relationships between components.
- **Vulnerability impact chains** — reverse-dependency traversal shows how a vulnerable component impacts the rest of your system along the supply chain.
- **Version control** — each scan result is persisted as a version, keeping the history so you can trace and compare over time.
- **Cross-version diff** — compare two SBOMs within a project to list added, removed, and changed components by dependency level, along with vulnerability summary metrics.
- **Cross-version search** — search across all SBOM versions within a project by component name, CVE ID, or vulnerability summary, and locate which versions are affected.
- **Rich vulnerability metrics** — view CVE, CVSS, EPSS and LEV (Likelihood of Exploitation in the Wild) information for components.
- **Component & license details** — inspect detailed information and license data for each component to help plan remediation.
- **PDF report export** — generate a portable PDF snapshot of the vulnerability findings for any SBOM.
- **Local persistence** — processed results are stored in an embedded DuckDB database and loaded back into memory on startup.

## To whom this tool is for
This tool is designed for developers, security engineers, and anyone who wants to analyze the SBOM of their software projects. It can help you:
- Visualize the SBOM of your software projects.
- Understand the relationships between different components in your software.
- Analyze the vulnerabilities in your software and their impact on the software supply chain.
- Track how components and vulnerabilities change across versions.
- Plan the remediation of the vulnerabilities in your software.

## Why we make this project

In the very beginning, we were looking for a tool that could visualize the SBOM and the vulnerabilities in it (indeed, there's not-so-many options for us to choose from). And since we are also surveying the impact of the vulnerabilities among the software supply chain, we thought it would be great if we could visualize that along with the SBOM data. Existing tooling also lacked a way to version-control scan results over time and to visually diff SBOMs across versions, so we decided to homebrew this tool to integrate SBOM import, vulnerability scanning, version control, and graph-based analysis into one.

On the part of retrieving the SBOM data from external sources, we considered the [osv-scanner](https://github.com/google/osv-scanner) and [osv-scalibr](https://github.com/google/osv-scalibr) as an excellent work in the open source community. Hence we applied part of the util from them to retrieve data of the component in the SBOM, especially information with CVE vulnerabilities. As a result, we would like to address our most sincere gratitude to the authors of these two projects.

## Install

0. Install Golang, version 1.25 or later.

For MacOS, you can use Homebrew to install Golang. If you don't have Homebrew installed, you can find the installation instructions [here](https://brew.sh/).
```bash
brew install go
```

1. Clone the repository:
```bash
git clone git@github.com:nics-tw/ex-sbom.git
```

2. Execute the following command to install the required dependencies:
```bash
go mod tidy
```

3. Build the project:
```bash
go build -o ex-sbom
```

4. Run the project:
```bash
./ex-sbom
```

5. Your browser should automatically open a new tab with the URL `http://localhost:8080`. If it doesn't, you can manually open your browser and enter the URL.

（If for local development, you can merely run the command `go run main.go` to start the server.）

## Configuration

The following environment variables can be used to configure the tool:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Port the local web server listens on. |
| `BIND_ADDR` | `127.0.0.1` | Loopback IP address, such as `127.0.0.1` or `::1`. Other addresses are rejected. |
| `AUTO_OPEN_BROWSER` | `true` | Set to `false` to prevent automatically opening the browser on startup. |
| `DB_PATH` | OS-specific (see below) | Path to the DuckDB database file. |

By default, the database file is stored under the platform-native config directory:
- macOS: `~/Library/Application Support/ex-sbom/data.duckdb`
- Linux: `~/.config/ex-sbom/data.duckdb`
- Windows: `%AppData%\ex-sbom\data.duckdb`

Deleting a project hides it and its SBOMs from the app; their rows remain in DuckDB, and the app has no restore action.

## API documentation

We use Postman to document our API. You can find the documentation json file in the root directory with name `ex-sbom.postman_collection.json`. You can import this file into Postman to view the API documentation.

### Migrating from the pre-project API

The HTTP API was restructured around projects and versions. The old flat routes were removed without a deprecation period, because the bundled web UI (shipped in the same binary) is the only supported client. Scripts written against the old API need to be updated:

| Old route | New route |
|-----------|-----------|
| `POST /sbom/upload` | `POST /projects/:id/sboms/preview` (parse + scan), then `POST /projects/:id/sboms` (save as a version) |
| `DELETE /sbom/delete` | `DELETE /projects/:id/sboms/:name` |
| `GET /sbom/report/:name` | `GET /projects/:id/sboms/:name/report` |
| `GET /topology/get_list_by_level` | `GET /projects/:id/sboms/:name/topology` |
| `GET /topology/relations` | `GET /projects/:id/sboms/:name/topology/relations` |
| `GET /topology/component` | `GET /projects/:id/sboms/:name/topology/component` |
| `GET /topology/get_component_vuln_dep` | `GET /projects/:id/sboms/:name/topology/component/vuln-dep` |

Every SBOM now belongs to a project: list projects with `GET /projects` (a `default` project is created on first start) or create one with `POST /projects`, then use its `id` in the routes above. `:name` is the version name chosen when saving. Requests for a project id that does not exist return `404`.

## Testing

All Go test files carry a build tag, so a bare `go test ./...` runs nothing. Pass the tags explicitly:

```bash
go build ./...
go test -tags "unit integration" ./...
node --test "tests/js/*.test.mjs"   # frontend tests, Node.js 22+, no dependencies
```

The same commands run in CI (`.github/workflows/ci.yml`) on every pull request.

## Contributing

As this is an experimental project, we welcome any contributions or suggestions. If you have any ideas or feedback, please feel free to open an issue or submit a pull request.

By contributing to this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md) and the [Contributing Guidelines](CONTRIBUTING.md).
