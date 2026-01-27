#!/usr/bin/env python3
"""
Managed Dependency Analysis Tool

Analyzes Maven dependencies from a CSV input file and enriches them with:
- Publish dates from Maven Central
- Latest patch versions available
- CVE data from OSV.dev
- Date-based metrics

Input: CSV file with format: groupId,artifactId,version
Output: JSON and CSV files with comprehensive dependency analysis
"""

import argparse
import csv
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, date
from typing import Optional
import urllib.request
import urllib.error
import urllib.parse


# Configuration
MAVEN_CENTRAL_SEARCH_URL = "https://search.maven.org/solrsearch/select"
MAVEN_CENTRAL_REPO_URL = "https://repo1.maven.org/maven2"
OSV_API_URL = "https://api.osv.dev/v1/query"
REQUEST_DELAY = 0.3  # Delay between API calls to avoid rate limiting


def parse_csv_input(input_file: str) -> list[dict]:
    """Parse the input CSV file (groupId,artifactId,version)."""
    dependencies = []
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 3 and row[1]:  # Skip empty rows
                dependencies.append({
                    'groupId': row[0].strip(),
                    'artifactId': row[1].strip(),
                    'version': row[2].strip(),
                })
    return dependencies


def fetch_url(url: str, method: str = 'GET', data: Optional[bytes] = None,
              headers: Optional[dict] = None) -> Optional[str]:
    """Fetch URL with error handling."""
    try:
        req = urllib.request.Request(url, data=data, method=method)
        if headers:
            for key, value in headers.items():
                req.add_header(key, value)
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8')
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None


def get_publish_date(group_id: str, artifact_id: str, version: str) -> Optional[str]:
    """Query Maven Central for the publish date of a specific version."""
    if '$' in version or not artifact_id or artifact_id == '(no artifact)':
        return None

    query = f"g:{group_id}+AND+a:{artifact_id}+AND+v:{version}"
    url = f"{MAVEN_CENTRAL_SEARCH_URL}?q={query}&rows=1&wt=json"

    response = fetch_url(url)
    if not response:
        return None

    try:
        data = json.loads(response)
        docs = data.get('response', {}).get('docs', [])
        if docs:
            timestamp = docs[0].get('timestamp', 0)
            if timestamp:
                # Convert milliseconds to date
                publish_date = datetime.fromtimestamp(timestamp / 1000)
                return publish_date.strftime('%Y-%m-%d')
    except (json.JSONDecodeError, KeyError, ValueError):
        pass

    return None


def is_semver_3_parts(version: str) -> bool:
    """Check if version follows semver with 3 numeric parts (major.minor.patch)."""
    # Remove trailing qualifiers like .Final, .RELEASE, etc.
    base_version = re.sub(r'\.(Final|RELEASE|RC\d+|M\d+|Alpha\d*|Beta\d*).*$', '', version, flags=re.IGNORECASE)
    return bool(re.match(r'^\d+\.\d+\.\d+$', base_version))


def get_major_minor(version: str) -> Optional[str]:
    """Extract major.minor from a version string."""
    base_version = re.sub(r'\.(Final|RELEASE|RC\d+|M\d+|Alpha\d*|Beta\d*).*$', '', version, flags=re.IGNORECASE)
    match = re.match(r'^(\d+\.\d+)\.\d+', base_version)
    return match.group(1) if match else None


def get_version_suffix(version: str) -> str:
    """Extract the suffix after the patch number (e.g., .Final, .RELEASE)."""
    match = re.match(r'^\d+\.\d+\.\d+(.*)', version)
    return match.group(1) if match else ''


def get_all_versions(group_id: str, artifact_id: str) -> list[str]:
    """Fetch all available versions from Maven Central metadata."""
    group_path = group_id.replace('.', '/')
    metadata_url = f"{MAVEN_CENTRAL_REPO_URL}/{group_path}/{artifact_id}/maven-metadata.xml"

    response = fetch_url(metadata_url)
    if not response:
        return []

    try:
        root = ET.fromstring(response)
        versions = []
        for version_elem in root.findall('.//version'):
            if version_elem.text:
                versions.append(version_elem.text.strip())
        return versions
    except ET.ParseError:
        return []


def find_latest_patch(current_version: str, all_versions: list[str]) -> tuple[str, str]:
    """Find the latest patch version for the same major.minor."""
    major_minor = get_major_minor(current_version)
    if not major_minor:
        return current_version, 'skipped: cannot parse version'

    current_suffix = get_version_suffix(current_version)

    # Get current patch number
    current_patch_match = re.match(rf'^{re.escape(major_minor)}\.(\d+)', current_version)
    current_patch = int(current_patch_match.group(1)) if current_patch_match else 0

    latest_version = current_version
    highest_patch = current_patch  # Start with current patch to avoid downgrades

    for version in all_versions:
        # Check if version matches our major.minor
        if not re.match(rf'^{re.escape(major_minor)}\.\d+', version):
            continue

        version_suffix = get_version_suffix(version)

        # Only consider versions with the same suffix
        if current_suffix != version_suffix:
            continue

        # Extract patch number
        match = re.match(rf'^{re.escape(major_minor)}\.(\d+)', version)
        if match:
            patch = int(match.group(1))
            if patch > highest_patch:
                highest_patch = patch
                latest_version = version

    if latest_version == current_version:
        return latest_version, 'up-to-date'
    else:
        return latest_version, 'update-available'


def get_cve_counts(group_id: str, artifact_id: str, version: str) -> dict:
    """Query OSV.dev for CVE counts."""
    result = {'total': 0, 'critical': 0, 'high': 0}

    if not artifact_id or artifact_id == '(no artifact)' or '$' in version:
        return result

    package_name = f"{group_id}:{artifact_id}"
    request_body = json.dumps({
        'package': {
            'name': package_name,
            'ecosystem': 'Maven'
        },
        'version': version
    }).encode('utf-8')

    response = fetch_url(
        OSV_API_URL,
        method='POST',
        data=request_body,
        headers={'Content-Type': 'application/json'}
    )

    if not response:
        return result

    try:
        data = json.loads(response)
        vulns = data.get('vulns', [])
        result['total'] = len(vulns)

        for vuln in vulns:
            severity = vuln.get('database_specific', {}).get('severity', '')
            if severity == 'CRITICAL':
                result['critical'] += 1
            elif severity == 'HIGH':
                result['high'] += 1
    except json.JSONDecodeError:
        pass

    return result


def calculate_days_between(date1: Optional[str], date2: Optional[str]) -> Optional[int]:
    """Calculate days between two date strings (YYYY-MM-DD format)."""
    if not date1 or not date2:
        return None

    try:
        d1 = datetime.strptime(date1, '%Y-%m-%d')
        d2 = datetime.strptime(date2, '%Y-%m-%d')
        return (d2 - d1).days
    except ValueError:
        return None


def analyze_dependencies(dependencies: list[dict], verbose: bool = True) -> list[dict]:
    """Main analysis pipeline - processes all dependencies."""
    results = []
    total = len(dependencies)

    for i, dep in enumerate(dependencies, 1):
        group_id = dep['groupId']
        artifact_id = dep['artifactId']
        version = dep['version']

        if verbose:
            print(f"[{i}/{total}] {artifact_id} ({version})...", end=' ', flush=True)

        result = {
            'library': artifact_id,
            'version': version,
            'artifact': artifact_id,
            'groups': [group_id],
        }

        # Step 1: Get publish date for current version
        if verbose:
            print("publish date...", end=' ', flush=True)
        publish_date = get_publish_date(group_id, artifact_id, version)
        result['publishDate'] = publish_date or 'unknown'
        time.sleep(REQUEST_DELAY)

        # Step 2: Find latest patch version
        if '$' in version:
            result['latestPatch'] = version
            result['patchStatus'] = 'skipped: variable version'
            result['latestPatchPublishDate'] = None
        elif not is_semver_3_parts(version):
            result['latestPatch'] = version
            result['patchStatus'] = 'skipped: not 3-part semver'
            result['latestPatchPublishDate'] = None
        else:
            if verbose:
                print("versions...", end=' ', flush=True)
            all_versions = get_all_versions(group_id, artifact_id)
            time.sleep(REQUEST_DELAY)

            if not all_versions:
                result['latestPatch'] = version
                result['patchStatus'] = 'error: no versions found'
                result['latestPatchPublishDate'] = None
            else:
                latest_patch, patch_status = find_latest_patch(version, all_versions)
                result['latestPatch'] = latest_patch
                result['patchStatus'] = patch_status

                # Step 3: Get publish date for latest patch
                if latest_patch != version:
                    if verbose:
                        print("latest date...", end=' ', flush=True)
                    latest_date = get_publish_date(group_id, artifact_id, latest_patch)
                    result['latestPatchPublishDate'] = latest_date or 'unknown'
                    time.sleep(REQUEST_DELAY)
                else:
                    result['latestPatchPublishDate'] = publish_date or 'unknown'

        # Step 4: Get CVE data for current version
        if verbose:
            print("CVEs...", end=' ', flush=True)
        version_cves = get_cve_counts(group_id, artifact_id, version)
        result['versionTotalCveCount'] = version_cves['total']
        result['versionCriticalCveCount'] = version_cves['critical']
        result['versionHighCveCount'] = version_cves['high']
        time.sleep(REQUEST_DELAY)

        # Step 5: Get CVE data for latest patch (if different)
        if result.get('latestPatch') and result['latestPatch'] != version:
            latest_cves = get_cve_counts(group_id, artifact_id, result['latestPatch'])
            result['latestPatchTotalCveCount'] = latest_cves['total']
            result['latestPatchCriticalCveCount'] = latest_cves['critical']
            result['latestPatchHighCveCount'] = latest_cves['high']
            time.sleep(REQUEST_DELAY)
        else:
            result['latestPatchTotalCveCount'] = version_cves['total']
            result['latestPatchCriticalCveCount'] = version_cves['critical']
            result['latestPatchHighCveCount'] = version_cves['high']

        # Step 6: Calculate date metrics
        pub_date = result.get('publishDate') if result.get('publishDate') != 'unknown' else None
        latest_pub_date = result.get('latestPatchPublishDate') if result.get('latestPatchPublishDate') != 'unknown' else None
        today = date.today().strftime('%Y-%m-%d')

        result['daysBetweenManagedAndLatestVersions'] = calculate_days_between(pub_date, latest_pub_date)
        result['daysSinceLatestPatch'] = calculate_days_between(latest_pub_date, today)

        if verbose:
            status = result['patchStatus']
            if status == 'update-available':
                print(f"update: {result['latestPatch']}")
            elif status == 'up-to-date':
                print("up-to-date")
            else:
                print(status)

        results.append(result)

    return results


def write_json_output(results: list[dict], output_file: str):
    """Write results to JSON file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)


def write_csv_output(results: list[dict], output_file: str):
    """Write results to CSV file."""
    fieldnames = [
        'library', 'version', 'artifact', 'publishDate', 'latestPatch',
        'latestPatchPublishDate', 'patchStatus', 'groupId',
        'versionTotalCveCount', 'versionCriticalCveCount', 'versionHighCveCount',
        'latestPatchTotalCveCount', 'latestPatchCriticalCveCount', 'latestPatchHighCveCount',
        'daysBetweenManagedAndLatestVersions', 'daysSinceLatestPatch'
    ]

    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for result in results:
            days_between = result.get('daysBetweenManagedAndLatestVersions')
            days_since = result.get('daysSinceLatestPatch')
            row = {
                'library': result['library'],
                'version': result['version'],
                'artifact': result['artifact'],
                'publishDate': result.get('publishDate', ''),
                'latestPatch': result.get('latestPatch', ''),
                'latestPatchPublishDate': result.get('latestPatchPublishDate', ''),
                'patchStatus': result.get('patchStatus', ''),
                'groupId': result['groups'][0] if result.get('groups') else '',
                'versionTotalCveCount': result.get('versionTotalCveCount', 0),
                'versionCriticalCveCount': result.get('versionCriticalCveCount', 0),
                'versionHighCveCount': result.get('versionHighCveCount', 0),
                'latestPatchTotalCveCount': result.get('latestPatchTotalCveCount', 0),
                'latestPatchCriticalCveCount': result.get('latestPatchCriticalCveCount', 0),
                'latestPatchHighCveCount': result.get('latestPatchHighCveCount', 0),
                'daysBetweenManagedAndLatestVersions': days_between if days_between is not None else '',
                'daysSinceLatestPatch': days_since if days_since is not None else '',
            }
            writer.writerow(row)


def print_statistics(results: list[dict]):
    """Print summary statistics."""
    total = len(results)

    up_to_date = sum(1 for r in results if r.get('patchStatus') == 'up-to-date')
    updates_available = sum(1 for r in results if r.get('patchStatus') == 'update-available')
    skipped = sum(1 for r in results if r.get('patchStatus', '').startswith('skipped'))

    with_version_cves = sum(1 for r in results if r.get('versionTotalCveCount', 0) > 0)
    with_latest_cves = sum(1 for r in results if r.get('latestPatchTotalCveCount', 0) > 0)
    total_version_cves = sum(r.get('versionTotalCveCount', 0) for r in results)
    total_latest_cves = sum(r.get('latestPatchTotalCveCount', 0) for r in results)
    total_version_critical = sum(r.get('versionCriticalCveCount', 0) for r in results)
    total_version_high = sum(r.get('versionHighCveCount', 0) for r in results)
    total_latest_critical = sum(r.get('latestPatchCriticalCveCount', 0) for r in results)
    total_latest_high = sum(r.get('latestPatchHighCveCount', 0) for r in results)

    days_between = [r['daysBetweenManagedAndLatestVersions'] for r in results
                    if r.get('daysBetweenManagedAndLatestVersions') is not None]
    days_since = [r['daysSinceLatestPatch'] for r in results
                  if r.get('daysSinceLatestPatch') is not None]

    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)

    print(f"\nTotal libraries analyzed: {total}")
    print(f"  Up to date: {up_to_date}")
    print(f"  Updates available: {updates_available}")
    print(f"  Skipped: {skipped}")

    print(f"\nCurrent Version CVEs:")
    print(f"  Libraries with CVEs: {with_version_cves}")
    print(f"  Total CVEs: {total_version_cves}")
    print(f"  Critical: {total_version_critical}")
    print(f"  High: {total_version_high}")

    print(f"\nLatest Patch CVEs:")
    print(f"  Libraries with CVEs: {with_latest_cves}")
    print(f"  Total CVEs: {total_latest_cves}")
    print(f"  Critical: {total_latest_critical}")
    print(f"  High: {total_latest_high}")

    if days_between:
        avg_days_between = sum(days_between) // len(days_between)
        max_days_between = max(days_between)
        print(f"\nDays between managed and latest patch:")
        print(f"  Average: {avg_days_between} days")
        print(f"  Maximum: {max_days_between} days")

    if days_since:
        avg_days_since = sum(days_since) // len(days_since)
        print(f"\nAverage days since latest patch published: {avg_days_since} days")

    # Top libraries with most CVEs
    libs_with_cves = sorted(
        [r for r in results if r.get('versionTotalCveCount', 0) > 0],
        key=lambda x: x['versionTotalCveCount'],
        reverse=True
    )[:10]

    if libs_with_cves:
        print("\nTop 10 libraries with most CVEs in current version:")
        for r in libs_with_cves:
            print(f"  {r['versionTotalCveCount']} total ({r['versionCriticalCveCount']} critical, "
                  f"{r['versionHighCveCount']} high): {r['library']} v{r['version']}")

    # Libraries where updating reduces CVEs
    reducible = [r for r in results
                 if r.get('versionTotalCveCount', 0) > r.get('latestPatchTotalCveCount', 0)][:10]

    if reducible:
        print("\nLibraries where updating would reduce CVE count:")
        for r in reducible:
            print(f"  {r['library']}: {r['versionTotalCveCount']} -> {r['latestPatchTotalCveCount']} CVEs "
                  f"(v{r['version']} -> v{r['latestPatch']})")

    # Libraries with largest gap
    with_gaps = sorted(
        [r for r in results if r.get('daysBetweenManagedAndLatestVersions') and
         r['daysBetweenManagedAndLatestVersions'] > 0],
        key=lambda x: x['daysBetweenManagedAndLatestVersions'],
        reverse=True
    )[:10]

    if with_gaps:
        print("\nTop 10 libraries with largest gap between managed and latest patch:")
        for r in with_gaps:
            print(f"  {r['daysBetweenManagedAndLatestVersions']} days: {r['library']} "
                  f"({r['version']} -> {r['latestPatch']})")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Maven dependencies for versions, CVEs, and update status.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  %(prog)s managed-dep-input.csv
  %(prog)s managed-dep-input.csv -o analysis-results
  %(prog)s managed-dep-input.csv --quiet
        '''
    )
    parser.add_argument(
        'input_file',
        help='Input CSV file (format: groupId,artifactId,version)'
    )
    parser.add_argument(
        '-o', '--output',
        default='dependency-analysis',
        help='Output file prefix (default: dependency-analysis)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output'
    )

    args = parser.parse_args()

    # Validate input file
    try:
        with open(args.input_file, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found", file=sys.stderr)
        sys.exit(1)

    print(f"Reading dependencies from {args.input_file}...")
    dependencies = parse_csv_input(args.input_file)
    print(f"Found {len(dependencies)} dependencies to analyze")
    print()

    print("Analyzing dependencies...")
    print("This may take several minutes due to API rate limiting...")
    print()

    results = analyze_dependencies(dependencies, verbose=not args.quiet)

    # Write outputs
    json_output = f"{args.output}.json"
    csv_output = f"{args.output}.csv"

    print(f"\nWriting JSON output to {json_output}...")
    write_json_output(results, json_output)

    print(f"Writing CSV output to {csv_output}...")
    write_csv_output(results, csv_output)

    # Print statistics
    print_statistics(results)

    print(f"\nOutput files:")
    print(f"  JSON: {json_output}")
    print(f"  CSV: {csv_output}")


if __name__ == '__main__':
    main()
