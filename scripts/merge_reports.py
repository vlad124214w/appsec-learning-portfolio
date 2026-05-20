#!/usr/bin/env python3
"""
Объединяет отчёты Semgrep, Gitleaks, Dependency Check в один JSON.
Добавляет CVSS-оценки через NVD API и фильтрует false positives.
Запуск: python merge_reports.py
"""

import json
import os
import requests
import time
from datetime import datetime
from pathlib import Path

REPORTS_DIR = "."  
OUTPUT_FILE = "merged-report.json"
FILTERED_OUTPUT = "filtered-issues.json"  

# ---------- CVSS через NVD API ----------
def fetch_cvss(cwe_id):
    """Получает CVSS-оценку для CWE через NVD API (кеширование в словаре)"""
    if not cwe_id or not str(cwe_id).startswith("CWE-"):
        return None
    
    cache_file = "cvss_cache.json"
    cache = {}
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cache = json.load(f)
    
    if cwe_id in cache:
        return cache[cwe_id]
    
    try:
        # NVD API
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={cwe_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerabilities"):
                cve = data["vulnerabilities"][0]["cve"]
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_score = cvss_v3.get("baseScore")
                if cvss_score:
                    cache[cwe_id] = cvss_score
                    with open(cache_file, 'w') as f:
                        json.dump(cache, f)
                    return cvss_score
        time.sleep(0.5)  
    except Exception as e:
        print(f"   Ошибка получения CVSS для {cwe_id}: {e}")
    
    return None

# ---------- Фильтрация false positives ----------
FP_PATHS = [
    "tests/", "test_", "mock_", "examples/", 
    "venv/", ".venv/", "__pycache__/", 
    "node_modules/", ".github/", "docs/"
]

FP_CWE_ALLOWLIST = [89, 79, 20]  # SQLi, XSS, Path Traversal

def is_false_positive(finding):
    """Проверяет, является ли уязвимость ложным срабатыванием"""
    location = finding.get("location", "").lower()
    
    # 1. Фильтр по пути
    for fp_path in FP_PATHS:
        if fp_path.lower() in location:
            return True
    
    # 2. Фильтр по CWE + тестовые файлы
    cwe = finding.get("cwe")
    if cwe:
        cwe_num = int(cwe.replace("CWE-", "")) if isinstance(cwe, str) and cwe.startswith("CWE-") else None
        if cwe_num in FP_CWE_ALLOWLIST and ("test" in location or "example" in location):
            return True
    
    # 3. Фильтр по сообщению (фейковые/учебные уязвимости)
    msg = finding.get("message", "").lower()
    if "placeholder" in msg or "dummy" in msg or "example only" in msg:
        return True
    
    return False

# ---------- Парсеры отчётов (дополнены CVSS) ----------
def parse_semgrep(data):
    findings = []
    if not data or "results" not in data:
        return findings
    for finding in data.get("results", []):
        cwe = finding.get("extra", {}).get("metadata", {}).get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        
        finding_dict = {
            "tool": "semgrep",
            "id": finding.get("check_id"),
            "message": finding.get("extra", {}).get("message"),
            "severity": finding.get("extra", {}).get("severity", "INFO"),
            "location": f"{finding.get('path')}:{finding.get('start', {}).get('line')}",
            "cwe": cwe,
            "cvss_score": None
        }
        # Получаем CVSS
        if cwe:
            finding_dict["cvss_score"] = fetch_cvss(cwe)
        findings.append(finding_dict)
    return findings

def parse_gitleaks(data):
    findings = []
    if not data or "leaks" not in data:
        return findings
    for finding in data.get("leaks", []):
        finding_dict = {
            "tool": "gitleaks",
            "id": finding.get("ruleID"),
            "message": finding.get("description", "Hardcoded secret detected"),
            "severity": "HIGH",
            "location": f"{finding.get('file')}:{finding.get('line')}",
            "cwe": "CWE-798",
            "cvss_score": 7.5  # У секретов высокий CVSS по умолчанию
        }
        findings.append(finding_dict)
    return findings

def parse_dependencycheck(data):
    findings = []
    if not data:
        return findings
    for item in data.get("runs", [{}])[0].get("results", []):
        finding_dict = {
            "tool": "dependency-check",
            "id": item.get("ruleId"),
            "message": item.get("message", {}).get("text", "Vulnerable dependency"),
            "severity": item.get("level", "WARNING").upper(),
            "location": item.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri"),
            "cwe": item.get("ruleId"),
            "cvss_score": None
        }
        findings.append(finding_dict)
    return findings

# ---------- Основная функция ----------
def main():
    all_findings = []
    
    print("🔍 Загрузка отчётов...")
    
    # Загружаем и парсим отчёты
    semgrep = None
    if os.path.exists("semgrep.json"):
        with open("semgrep.json", 'r') as f:
            semgrep = json.load(f)
        all_findings.extend(parse_semgrep(semgrep))
        print("Semgrep загружен")
    
    gitleaks = None
    if os.path.exists("gitleaks-report.json"):
        with open("gitleaks-report.json", 'r') as f:
            gitleaks = json.load(f)
        all_findings.extend(parse_gitleaks(gitleaks))
        print("Gitleaks загружен")
    
    depcheck = None
    if os.path.exists("depcheck-report.json"):
        with open("depcheck-report.json", 'r') as f:
            depcheck = json.load(f)
        all_findings.extend(parse_dependencycheck(depcheck))
        print("Dependency-Check загружен")
    
    print(f"\n Всего находок (до фильтрации): {len(all_findings)}")
    
    # ---------- Фильтрация false positives ----------
    filtered_findings = []
    fp_count = 0
    for finding in all_findings:
        if is_false_positive(finding):
            fp_count += 1
            print(f"  [FP] {finding['tool']}: {finding['message'][:60]} в {finding['location']}")
        else:
            filtered_findings.append(finding)
    
    print(f"\n После фильтрации FP: {len(filtered_findings)} (удалено {fp_count})")
    
    # ---------- Фильтр по CVSS (только HIGH/CRITICAL) ----------
    CVSS_THRESHOLD = 7.0
    critical_findings = []
    for finding in filtered_findings:
        cvss = finding.get("cvss_score", 0.0)
        if cvss is None:
            cvss = 0.0
        if cvss >= CVSS_THRESHOLD:
            critical_findings.append(finding)
        else:
            print(f"  [INFO] Пропуск (CVSS={cvss}): {finding['message'][:50]}")
    
    print(f"\n Критических/высоких (CVSS>={CVSS_THRESHOLD}): {len(critical_findings)}")
    
    # ---------- Сортировка ----------
    severity_order = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "INFO": 2}
    critical_findings.sort(key=lambda x: severity_order.get(x["severity"], 3))
    
    # ---------- Сохраняем полный отчёт ----------
    full_output = {
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "false_positives_removed": fp_count,
        "findings": all_findings
    }
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(full_output, f, indent=2, ensure_ascii=False)
    
    # ---------- Сохраняем ОТФИЛЬТРОВАННЫЕ критичные уязвимости (для Jira) ----------
    filtered_output = {
        "scan_date": datetime.now().isoformat(),
        "total_critical_findings": len(critical_findings),
        "findings": critical_findings
    }
    with open(FILTERED_OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(filtered_output, f, indent=2, ensure_ascii=False)
    
    print(f"\n Сохранён полный отчёт: {OUTPUT_FILE}")
    print(f" Сохранён отфильтрованный отчёт (для Jira): {FILTERED_OUTPUT}")
    
    # Вывод статистики по инструментам
    print("\n📈 Статистика:")
    tools = {}
    for f in critical_findings:
        tools[f["tool"]] = tools.get(f["tool"], 0) + 1
    for tool, count in tools.items():
        print(f"   {tool}: {count}")

if __name__ == "__main__":
    main()