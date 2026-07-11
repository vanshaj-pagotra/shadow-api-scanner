# Shadow API Scanner

A fast, passive API attack surface discovery tool designed to identify undocumented (Shadow) APIs by reconciling web server access logs against OpenAPI and Swagger specifications. 
## 🚀 Features

- **Passive Analysis**: Parses standard Nginx/Apache access logs directly. No active interception, no network overhead, and zero performance impact on your live servers.
- **Multi-Spec Support**: Natively parses and understands both **OpenAPI 3.0** and **Swagger 2.0** in both YAML and JSON formats.
- **Intelligent Path Reconciliation**: Automatically normalizes base paths, converts parameterized paths (e.g., `/user/{id}` matches `/user/123`), and handles dynamic routing.
- **Noise Reduction**: Automatically filters out failed requests (404, 403, 500) to ensure the scanner only flags endpoints that actually exist and are actively resolving.
- **Vulnerability Heuristics**: Flags discovered Shadow APIs with potential **OWASP API Security Top 10 (2023)** risks (e.g., Broken Object Level Authorization, Broken Function Level Authorization, Security Misconfiguration) based on path analysis and naming conventions.
- **Interactive Reporting**: Generates a beautiful, sleek, and searchable HTML dashboard detailing Documented vs. Shadow APIs.

## 🛠️ Installation

Ensure you have [Go](https://go.dev/) (1.20+) installed.

```bash
git clone https://github.com/vanshaj-pagotra/shadow-api-scanner.git
cd shadow-api-scanner

# Download dependencies
go mod download

# Build the executable
go build -o shadow-api-scanner
```

## 💻 Usage

The CLI tool is extremely simple to use and takes three main flags:
* `--log`: Path to the web server access log (Combined Log Format).
* `--spec`: Path to your API specification file (YAML or JSON).
* `--out`: Output path for the generated HTML report.

### Example Run
```bash
./shadow-api-scanner --log <path-to-access.log> --spec <path-to-api-spec.yaml> --out <output-report.html>
```

## 🧠 How It Works

1. **Log Ingestion**: The `parser` reads and normalizes the raw access log using standard Combined Log Format regex, extracting the IP, Method, Path, and Status Code.
2. **Spec Parsing**: The `spec` module loads the provided file, identifies the version (OpenAPI 3 or Swagger 2), extracts the server/base paths, and flattens all documented endpoints into regular expressions.
3. **Reconciliation Engine**: The core `engine` iterates through the live traffic. It checks each successful log entry against the compiled spec regex patterns. If a path resolves successfully on the server but doesn't exist in the spec, it is immediately flagged as a Shadow API.
4. **Report Generation**: The `report` module analyzes the shadow APIs for high-risk naming patterns (like `/admin`, `/debug`, `/[0-9]+/`) and outputs a static, stylized HTML dashboard.

## 📊 The HTML Report

The generated HTML file is entirely static and requires no web server to view. Just double click it to open it in your browser. It includes:
* **Dashboard Stats**: A high-level overview of total scanned logs, documented hits, and discovered shadow endpoints.
* **Documented APIs Tab**: Shows the actively used APIs grouped by their Swagger tags.
* **Shadow APIs Tab**: Highlights the undocumented endpoints, tagged with computed Risk Severity (High, Medium, Low) and potential OWASP vulnerabilities.
* **Live Search**: A client-side search bar to instantly filter the attack surface by path, method, or summary.
