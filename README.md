# Spring Managed Dependency Evaluation

A tool for analyzing Spring Boot managed dependencies, including version information, CVE data, and patch availability.

## Overview

This toolset parses Spring Boot's managed dependency definitions and enriches them with:
- Publish dates from Maven Central
- Latest available patch versions
- CVE (vulnerability) counts from OSV.dev
- Date-based metrics for staleness analysis

## Prerequisites

- **Python 3.9+** (no external dependencies required)
- Internet access for API queries

## Quick Start

Run the analyzer with the default input file:
```bash
python3 managed-dependency-analysis.py managed-dep-input.csv
```

### Examples

**Basic usage with default output:**
```bash
python3 managed-dependency-analysis.py managed-dep-input.csv
```
This produces `dependency-analysis.json` and `dependency-analysis.csv`.

**Custom output file prefix:**
```bash
python3 managed-dependency-analysis.py managed-dep-input.csv -o spring-boot-2.7-analysis
```
This produces `spring-boot-2.7-analysis.json` and `spring-boot-2.7-analysis.csv`.

**Quiet mode (suppress progress output):**
```bash
python3 managed-dependency-analysis.py managed-dep-input.csv --quiet
```

**Show help:**
```bash
python3 managed-dependency-analysis.py --help
```

## Input File Format

The input file is a CSV with three columns (no header row):
```
groupId,artifactId,version
```

Example (`managed-dep-input.csv`):
```csv
ch.qos.logback,logback-classic,1.2.13
com.fasterxml.jackson.core,jackson-databind,2.13.5
io.netty,netty-handler,4.1.130.Final
org.apache.tomcat.embed,tomcat-embed-core,9.0.113
```

## Output Files

The script produces two output files:
- `dependency-analysis.json` - Complete data in JSON format
- `dependency-analysis.csv` - Complete data in CSV format

### Output Fields

| Field | Description |
|-------|-------------|
| `library` | Library name (artifact ID) |
| `version` | Managed version in Spring Boot |
| `artifact` | Maven artifact ID |
| `publishDate` | When the managed version was published |
| `latestPatch` | Latest available patch version |
| `latestPatchPublishDate` | When the latest patch was published |
| `patchStatus` | Status: `up-to-date`, `update-available`, or `skipped: <reason>` |
| `groupId` / `groups` | Maven group ID(s) |
| `versionTotalCveCount` | Total CVEs affecting the managed version |
| `versionCriticalCveCount` | Critical severity CVEs (managed version) |
| `versionHighCveCount` | High severity CVEs (managed version) |
| `latestPatchTotalCveCount` | Total CVEs affecting the latest patch |
| `latestPatchCriticalCveCount` | Critical severity CVEs (latest patch) |
| `latestPatchHighCveCount` | High severity CVEs (latest patch) |
| `daysBetweenManagedAndLatestVersions` | Days between managed and latest patch publish dates |
| `daysSinceLatestPatch` | Days since the latest patch was published |

## Web Dashboard

A web dashboard is included to visualize the analysis results:

```bash
# Start a local server
python3 -m http.server 8000

# Open http://localhost:8000 in your browser
```

The dashboard (`index.html`) provides:
- Summary cards for key metrics
- Sortable and filterable table
- Color-coded rows for staleness and security issues
- CSV export functionality

## Data Sources

- **Maven Central** - Version information and publish dates
- **OSV.dev** - Open Source Vulnerabilities database for CVE data

## Example Output

```json
{
  "library": "undertow-core",
  "version": "2.2.28.Final",
  "artifact": "undertow-core",
  "publishDate": "2023-10-17",
  "latestPatch": "2.2.38.Final",
  "latestPatchPublishDate": "2024-05-15",
  "patchStatus": "update-available",
  "groups": ["io.undertow"],
  "versionTotalCveCount": 11,
  "versionCriticalCveCount": 1,
  "versionHighCveCount": 7,
  "latestPatchTotalCveCount": 2,
  "latestPatchCriticalCveCount": 1,
  "latestPatchHighCveCount": 1,
  "daysBetweenManagedAndLatestVersions": 211,
  "daysSinceLatestPatch": 253
}
```

## Notes

- The script includes rate limiting (0.3s between API calls) to avoid throttling
- Variable versions (e.g., `${tomcatVersion}`) are skipped
- Non-semver versions may be skipped for patch detection
- Full analysis of ~950 dependencies takes approximately 30-45 minutes due to API rate limiting
- The script uses only Python standard library modules (no pip install required)

## Legacy Shell Scripts

The original shell script implementation is also available in numbered scripts (`1-parse-boot-versions.sh` through `6-calculate-data.sh`). These can be run sequentially, but the Python version is recommended as it consolidates all functionality into a single file with identical output.

## License

Internal use only.
