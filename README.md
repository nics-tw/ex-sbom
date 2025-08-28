# ex-sbom

正體中文說明請參考 [README.zh-TW.md](README.zh-TW.md)

ex-sbom, abbreviation for Explorer of SBOM, is currently an experimental visualization tool for SBOM analysis.

Disclaimer: This tool is still in the early stages of development and may not be fully functional.(We considering the current state is in pre-alpha status) We welcome any feedback or suggestions for improvement.

[![Go Reference](https://pkg.go.dev/badge/github.com/nics-tw/ex-sbom.svg)](https://pkg.go.dev/github.com/nics-tw/ex-sbom)

## How to use it
1. Download the executable from the Release page (recommended), or build the project yourself.
2. Run it, and you can start using it.

## Usage

- The main page of the tool is a graph visualization of the SBOM.
- Through the dependency graph, you can see the relationships between different components.
- Also, the impact chain of the vulnerabilities in the system can be visualized, analyzed, which helps you understand the potential risks in your system.
- Aside from visualization, the detailed information of each component can be viewed, which may be helpful for you to plan the remediation of the vulnerabilities.

## To whom this tool is for
This tool is designed for developers, security engineers, and anyone who wants to analyze the SBOM of their software projects. It can help you:
- Visualize the SBOM of your software projects.
- Understand the relationships between different components in your software.
- Analyze the vulnerabilities in your software and their impact on the software supply chain.
- Plan the remediation of the vulnerabilities in your software.

## Why we make this project

In the very beginning, we were looking for a tool that could visualize the SBOM and the vulnerabilities in it(indeed, there's not-so-many options for us to choose from). And since we are also surveying the impact of the vulnerabilities among the software supply chain, we thought it would be great if we could visualize that along with the SBOM data. Hence, we decided to homebrew this tool.

On the part of retrieving the SBOM data from external sources, we considered the [osv-scanner](https://github.com/google/osv-scanner) and [osv-scalibr](https://github.com/google/osv-scalibr) as an excellent work in the open source community. Hence we applied part of the util from them to retrieve data of the component in the SBOM, especially information with CVE vulnerabilities. As a result, we would like to address our most sincere gratitude to the authors of these two projects.

## Install

0. Install Golang, version 1.24 or later.

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

## API documentation

We use Postman to document our API. You can find the documentation json file in the root directory with name `ex-sbom.postman_collection.json`. You can import this file into Postman to view the API documentation.

## Contributing

As this is an experimental project, we welcome any contributions or suggestions. If you have any ideas or feedback, please feel free to open an issue or submit a pull request.

By contributing to this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md) and the [Contributing Guidelines](CONTRIBUTING.md).
