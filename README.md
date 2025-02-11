# rapid7exporter

**rapid7exporter** is a Go-based Prometheus exporter that fetches vulnerability data from the Rapid7 API and exposes it as Prometheus metrics. The tool supports various configuration options—including filtering by retention days, allowed severities, grouping by the latest scan, renaming apps for unified grouping, and caching raw API responses—to help you monitor your Rapid7 vulnerability data.

## Features

- **Data Ingestion:** Fetches vulnerability data from the Rapid7 API.
- **Filtering:**  
  - **Retention Filter:** Include only vulnerabilities discovered within a configurable number of days.  
  - **Severity Filter:** Process only allowed severities (e.g., CRITICAL, HIGH, MEDIUM, LOW).
- **Latest Scan Grouping:** Optionally process only vulnerabilities from the latest scan for each app.
- **App Name Transformation:** Rename apps (via a mapping) and remove the `app_id` label so that metrics group by app name.
- **Dummy Apps:** Add dummy app entries (with a low severity metric set to 0) for apps you plan to onboard.
- **Caching:** Cache raw API responses in a specified folder and reuse them if they’re not older than *(updatePeriod – 10 minutes)*.
- **Configurable Update Period and Log Level:** Set the data refresh interval and adjust log verbosity.

## Prerequisites

- Go 1.16 or later.
- A valid Rapid7 API key. Set it in your environment:
  ```bash
  export RAPID7_API_KEY=your_actual_api_key_here
  ```

## Installation

### Building a Statically Linked Binary

To build a statically linked binary for Linux (amd64), run:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o rapid7exporter .
```

## Usage

You can configure **rapid7exporter** either via command-line flags or by providing a YAML configuration file.

### Using Command-Line Flags

For example:

```bash
export RAPID7_API_KEY=your_actual_api_key_here
./rapid7exporter \
  -retention=7 \
  -latestScan=true \
  -updatePeriod=20 \
  -loglevel=debug \
  -severities=CRITICAL,HIGH,MEDIUM,LOW \
  -cacheDir=./cache
```

### Using a YAML Configuration File

Create a file (e.g., `config.yaml`) with the following content:

```yaml
retention: 7
latestScan: true
updatePeriod: 20
loglevel: debug
severities:
  - CRITICAL
  - HIGH
  - MEDIUM
  - LOW
dummyApps:
  - id: "dummy-001"
    name: "App To Onboard 1"
  - id: "dummy-002"
    name: "App To Onboard 2"
renameApps:
  "Legacy App A": "Unified App"
  "Legacy App B": "Unified App"
cacheDir: "./cache"
```

Then run:

```bash
export RAPID7_API_KEY=your_actual_api_key_here
./rapid7exporter -config=config.yaml
```

## Metrics

The exporter exposes metrics on port **9090** at the `/metrics` endpoint. The primary metric is:

- **`rapid7_vulnerabilities_count`**

  with the following labels:
  
  - **`app_name`**: The transformed application name (apps with the same name are grouped together).
  - **`severity`**: The vulnerability severity.
  - **`state`**:  
    - `"live"` if the metric data comes from Rapid7, or  
    - `"dummy"` if it is from the dummy configuration.

## Prometheus Configuration

Point your Prometheus server to scrape from:

```yaml
scrape_configs:
  - job_name: "rapid7exporter"
    static_configs:
      - targets: ["<exporter-host>:9090"]
```

## License

This project is licensed under the Apache 2.0 License.