# ex-s
ex-s, abbreviation for Explorer of SBOM, is currently an experimental visualization tool for SBOM analysis.

# Usage

## Install

0. Install Golang, version 1.24 or later.

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
