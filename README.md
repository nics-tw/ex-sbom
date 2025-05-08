# ex-s
ex-s, abbreviation for Explorer of SBOM, is currently an experimental visualization tool for SBOM analysis.

Disclaimer: This tool is still in the early stages of development and may not be fully functional.(We considering the current state is in pre-alpha status) We welcome any feedback or suggestions for improvement.

## Usage

- The main page of the tool is a graph visualization of the SBOM.
- Through the dependency graph, you can see the relationships between different components.
- Also, the impact chain of the vulnerabilities in the system can be visualized, analyzed, which helps you understand the potential risks in your system.
- Aside from visualization, the detailed information of each component can be viewed, which may be helpful for you to plan the remediation of the vulnerabilities.

## Install

0. Install Golang, version 1.24 or later.

For MacOS, you can use Homebrew to install Golang. If you don't have Homebrew installed, you can find the installation instructions [here](https://brew.sh/).
```bash
brew install go
```

1. Clone the repository:
```bash
git clone git@github.com:nics-tw/ex-s.git
```

2. Execute the following command to install the required dependencies:
```bash
go mod tidy
```

3. Build the project:
```bash
go build -o ex-s
```
4. Run the project:
```bash
./ex-s
```

5. Your browser should automatically open a new tab with the URL `http://localhost:8080`. If it doesn't, you can manually open your browser and enter the URL.

## API documentation

We use Postman to document our API. You can find the documentation json file in the root directory with name `ex-s.postman_collection.json`. You can import this file into Postman to view the API documentation.
