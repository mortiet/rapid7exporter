# rapid7exporter

**rapid7exporter** is a Prometheus exporter written in Go that retrieves vulnerability data from the Rapid7 API and exposes it as metrics. It supports extensive configuration via command‑line flags or a YAML configuration file. New features include regex‑based renaming of app names, environment and group labeling, caching of API responses, and flexible filtering and grouping options.

## Features

- **Data Retrieval:**  
  Fetches vulnerability data and app information from the Rapid7 API.

- **Filtering & Grouping:**  
  - **Retention Filter:** Only include vulnerabilities discovered within a specified number of days.
  - **Severity Filter:** Process only vulnerabilities with allowed severities.
  - **Latest Scan Mode:** Optionally, only aggregate vulnerabilities from the latest scan per app.
  
- **Name Transformation:**  
  Use regex‑based rename patterns to transform app names.  
  - If a rename pattern matches, the matched portion is replaced with the new name.
  - If no pattern matches, the original name is used.

- **Environment & Group Labeling:**  
  - **Environment Labeling:** Use regex patterns to assign an `env` label (e.g., "staging", "dev") based on the app name.
  - **Group Labeling:** Use regex patterns to assign a `group` label to each app.
  - **Composite Key Grouping:** Live data is grouped by a composite key made up of the final (renamed) app name, environment, and group. This ensures that if multiple apps are renamed to the same name, they’re only merged if their environment and group labels also match. If the names are identical but environments or groups differ, they remain separate.

- **Dummy Apps:**  
  Add dummy apps (planned apps not yet onboarded) with a default `"LOW"` severity (value 0), a state label of `"dummy"`, and a `scan_date` of `"n/a"`.

- **Metric Enhancements:**  
  Each metric has the following labels:
  - **`app_name`**: The final (renamed) app name.
  - **`severity`**: Vulnerability severity (e.g., CRITICAL, HIGH, MEDIUM, LOW).
  - **`state`**: `"live"` for actual data from Rapid7 or `"dummy"` for dummy apps.
  - **`scan_date`**: The scan date in `YYYY-MM-DD` format (derived from the vulnerability’s `LastDiscovered` field), or `"n/a"` for dummy apps.
  - **`env`**: The environment label (e.g., "staging", "dev"), based on regex matching.
  - **`group`**: The group label, based on regex matching.

- **Caching:**  
  Optionally cache raw API responses in a specified directory and reuse them if they’re not older than *(updatePeriod – 10 minutes)*, reducing API calls and improving performance.

- **Flexible Configuration:**  
  Configure via command‑line flags or a YAML config file.

## Metric Format

The primary metric exported is `rapid7_vulnerabilities_count`. An example metric:

```promql
rapid7_vulnerabilities_count{
    app_name="Unified App",
    severity="HIGH",
    state="live",
    scan_date="2024-11-27",
    env="staging",
    group="Group A"
} 5
```

## Installation

### Prerequisites

- Go 1.16 or later.
- A valid Rapid7 API key (set it in your environment, e.g., `export RAPID7_API_KEY=your_actual_api_key_here`).

### Building a Statically Linked Binary

For example, to build for Linux (amd64):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o rapid7exporter .
```

## Configuration

You can configure **rapid7exporter** via command‑line flags or a YAML configuration file.

### Command‑Line Flags

Example:
```bash
./rapid7exporter \
  -retention=7 \
  -latestScan=true \
  -updatePeriod=20 \
  -loglevel=debug \
  -severities=CRITICAL,HIGH,MEDIUM,LOW \
  -cacheDir=./cache
```

### YAML Configuration File

Below is an example `config.yaml`:

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
renamePatterns:
  - pattern: "(?i)Legacy App"
    newName: "Unified App"
cacheDir: "./cache"
envPatterns:
  - pattern: "(?i).*staging.*"
    env: "staging"
  - pattern: "(?i).*dev.*"
    env: "dev"
groupPatterns:
  - pattern: "(?i)^Group A.*"
    group: "Group A"
  - pattern: "(?i)^Group B.*"
    group: "Group B"
```

Run using:
```bash
./rapid7exporter -config=config.yaml
```

## Prometheus Integration

Add the following to your `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: "rapid7exporter"
    static_configs:
      - targets: ["<exporter-host>:9090"]
```

## Running the Exporter

After building, start the exporter:
```bash
./rapid7exporter -config=config.yaml
```
Metrics will be available at [http://localhost:9090/metrics](http://localhost:9090/metrics).

## Prometheus Timestamps

Prometheus assigns the scrape timestamp to each sample. The `scan_date` label provides metadata about the scan’s date.
