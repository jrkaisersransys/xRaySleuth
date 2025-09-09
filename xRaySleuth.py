#!/usr/bin/env python3
import argparse
import requests
import json
import datetime
import sys

def scan_api(repo_key, artifact_path, api_key, base_url, username=None, password=None):
    headers = {"Content-Type": "application/json"}
    auth = None
    if api_key:
        headers["X-JFrog-Art-Api"] = api_key
    elif username and password:
        auth = (username, password)
    else:
        print("Error: Must provide either API key or username and password for authentication.", file=sys.stderr)
        return None
    endpoint = base_url.rstrip("/") + "/xray/api/v1/summary/artifact"
    art_path = f"{repo_key}/{artifact_path}"
    payload = {"paths": [art_path]}
    try:
        resp = requests.post(endpoint, headers=headers, data=json.dumps(payload), auth=auth)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            print(f"Non-JSON response from {endpoint} (status {resp.status_code}):\n{resp.text[:500]}", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error scanning {endpoint}: {e}", file=sys.stderr)
        return None

def filter_vulns(scan_data):
    issues = []
    if not scan_data:
        return issues
    items = scan_data.get("data") or scan_data.get("resources") or []
    for item in items:
        vulns = item.get("vulnerabilities") or []
        for v in vulns:
            sev = v.get("severity")
            if sev in ("High", "Critical"):
                issues.append({
                    "cve_id": v.get("cve") or v.get("id") or "",
                    "severity": sev,
                    "package": item.get("name") or item.get("component_id") or "",
                    "path": item.get("path") or "",
                    "description": v.get("description") or "",
                })
    return issues

def generate_md(results, output_file):
    now = datetime.datetime.now().isoformat()
    total_high = sum(1 for r in results.values() for v in r if v["severity"] == "High")
    total_critical = sum(1 for r in results.values() for v in r if v["severity"] == "Critical")
    lines = []
    lines.append(f"# xRaySleuth Report\n")
    lines.append(f"Generated: {now}\n")
    lines.append("## Summary\n")
    lines.append(f"- Critical: {total_critical}\n")
    lines.append(f"- High: {total_high}\n")
    for url, vulns in results.items():
        lines.append(f"## Scan: {url}\n")
        if not vulns:
            lines.append("_No High or Critical vulnerabilities found._\n")
            continue
        lines.append("| CVE ID | Severity | Package | Path | Description |\n")
        lines.append("| --- | --- | --- | --- | --- |\n")
        for v in vulns:
            cve = v["cve_id"].replace("|", "\\|")
            desc = v["description"].replace("\n", " ").replace("|", "\\|")
            pkg = v["package"].replace("|", "\\|")
            path = v["path"].replace("|", "\\|")
            lines.append(f"| {cve} | {v['severity']} | {pkg} | {path} | {desc} |\n")
    with open(output_file, "w") as f:
        f.writelines(lines)

def main():
    parser = argparse.ArgumentParser(description="Scan JFrog Xray and report High/Critical vulnerabilities in Markdown.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--api-key", "-k", help="JFrog Xray API key")
    group.add_argument("--username", help="JFrog username")
    parser.add_argument("--password", help="JFrog password (use with --username)")
    parser.add_argument("--repo-key", required=True, help="Artifactory repository key (e.g., v252_Build)")
    parser.add_argument("--artifact-path", required=True, help="Artifact path within the repo (e.g., winx64/mcre/WINX64.7z)")
    parser.add_argument("--base-url", required=True, help="Base URL to your Artifactory instance (e.g., https://artifactory.ansys.com)")
    parser.add_argument("--output", "-o", default="xray_report.md", help="Output Markdown file")
    args = parser.parse_args()
    results = {}
    data = scan_api(args.repo_key, args.artifact_path, args.api_key, args.base_url, args.username, args.password)
    print("--- RAW API RESPONSE ---")
    import pprint; pprint.pprint(data)
    vulns = filter_vulns(data)
    results[f"{args.repo_key}/{args.artifact_path}"] = vulns
    generate_md(results, args.output)

if __name__ == "__main__":
    main()