#!/usr/bin/env python3
"""
Объединяет отчёты Semgrep, Gitleaks, Dependency Check в один JSON.
Запуск: python merge_reports.py
"""

import json
import os
from datetime import datetime

REPORTS_DIR = "."  # папка, где лежат отчёты (можно заменить на reports/)
OUTPUT_FILE = "merged-report.json"

def load_json(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def parse_semgrep(data):
    findings = []
    if not data or "results" not in data:
        return findings
    for finding in data.get("results", []):
        findings.append({
            "tool": "semgrep",
            "id": finding.get("check_id"),
            "message": finding.get("extra", {}).get("message"),
            "severity": finding.get("extra", {}).get("severity", "INFO"),
            "location": f"{finding.get('path')}:{finding.get('start', {}).get('line')}",
            "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe"),
            "cvss_score": None
        })
    return findings

def parse_gitleaks(data):
    findings = []
    if not data or "leaks" not in data:
        return findings
    for finding in data.get("leaks", []):
        findings.append({
            "tool": "gitleaks",
            "id": finding.get("ruleID"),
            "message": finding.get("description", "Hardcoded secret detected"),
            "severity": "HIGH",
            "location": f"{finding.get('file')}:{finding.get('line')}",
            "cwe": "CWE-798",
            "cvss_score": None
        })
    return findings

def parse_dependencycheck(data):
    findings = []
    if not data:
        return findings
    for item in data.get("runs", [{}])[0].get("results", []):
        findings.append({
            "tool": "dependency-check",
            "id": item.get("ruleId"),
            "message": item.get("message", {}).get("text", "Vulnerable dependency"),
            "severity": item.get("level", "WARNING").upper(),
            "location": item.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri"),
            "cwe": item.get("ruleId"),
            "cvss_score": None
        })
    return findings

def main():
    all_findings = []

    # Загружаем и парсим отчёты (если они есть)
    semgrep = load_json("semgrep.json")
    if semgrep:
        all_findings.extend(parse_semgrep(semgrep))

    gitleaks = load_json("gitleaks-report.json")
    if gitleaks:
        all_findings.extend(parse_gitleaks(gitleaks))

    depcheck = load_json("depcheck-report.json")
    if depcheck:
        all_findings.extend(parse_dependencycheck(depcheck))

    # Сортируем по severity (ERROR/HIGH > WARNING > INFO)
    severity_order = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "INFO": 2}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 3))

    output = {
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "findings": all_findings
    }

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"✅ Сохранён объединённый отчёт: {OUTPUT_FILE}")
    print(f"📊 Всего находок: {len(all_findings)}")

if __name__ == "__main__":
    main()