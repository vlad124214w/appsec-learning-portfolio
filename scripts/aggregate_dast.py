#!/usr/bin/env python3
"""Агрегатор результатов ZAP и Nuclei"""
import json
import re

def parse_nuclei(filepath):
    findings = []
    try:
        with open(filepath) as f:
            for line in f:
                if 'Found' in line:
                    match = re.search(r'Found (.*?) vulnerability: (http.*?)(?:\s|$)', line)
                    if match:
                        findings.append({
                            'type': match.group(1),
                            'url': match.group(2),
                            'tool': 'nuclei'
                        })
    except FileNotFoundError:
        print(f"Файл {filepath} не найден, использую тестовые данные")
        findings = [
            {'type': 'SQL Injection', 'url': 'http://localhost:3000/rest/products/search', 'tool': 'nuclei'},
            {'type': 'XSS', 'url': 'http://localhost:3000/#/search', 'tool': 'nuclei'}
        ]
    return findings

def parse_zap(filepath):
    """Парсит JSON отчёт ZAP"""
    try:
        with open(filepath) as f:
            data = json.load(f)
        findings = []
        for alert in data.get('alerts', []):
            findings.append({
                'type': alert['name'],
                'url': alert['url'],
                'risk': alert['risk'],
                'tool': 'zap'
            })
        return findings
    except FileNotFoundError:
        print(f"⚠️ Файл {filepath} не найден, использую тестовые данные")
        return [
            {'type': 'SQL Injection', 'url': 'http://localhost:3000/rest/products/search', 'risk': 'High', 'tool': 'zap'},
            {'type': 'Cross Site Scripting (XSS)', 'url': 'http://localhost:3000/#/search', 'risk': 'Medium', 'tool': 'zap'},
            {'type': 'Missing Secure Flag', 'url': 'http://localhost:3000/', 'risk': 'Low', 'tool': 'zap'}
        ]

def main():
    zap_findings = parse_zap('../tests/fixtures/zap-sample.json')
    nuclei_findings = parse_nuclei('../tests/fixtures/nuclei_results.txt')
    
    print("=== NUCLEI FINDINGS ===")
    for f in nuclei_findings:
        print(f"  {f['type']}: {f['url']}")
    
    print("\n=== ZAP FINDINGS ===")
    for f in zap_findings:
        print(f"  {f['type']}: {f['url']}")
    
    
    confirmed = []
    for n in nuclei_findings:
        for z in zap_findings:
            if n['url'] == z['url']:
                confirmed.append({
                    'type': n['type'],
                    'url': n['url'],
                    'tools': ['nuclei', 'zap']
                })
    
    print("\n=== CONFIRMED VULNERABILITIES (found by BOTH tools) ===")
    if confirmed:
        for c in confirmed:
            print(f"{c['type']}: {c['url']}")
    else:
        print("  No overlaps found")
    
    print(f"\n=== SUMMARY ===")
    print(f"ZAP: {len(zap_findings)} | Nuclei: {len(nuclei_findings)} | Confirmed: {len(confirmed)}")

if __name__ == "__main__":
    main()
