#!/usr/bin/env python3
"""
Мок-интеграция с Jira: создаёт тикеты из отфильтрованных уязвимостей
Запуск: python jira_mock.py --input filtered-issues.json --no-dry-run
"""

import json
import datetime
import argparse
from pathlib import Path

def create_mock_ticket(issue, ticket_num):
    """Создаёт запись о тикете в лог-файл"""
    ticket = {
        "id": f"APPSEC-{ticket_num:04d}",
        "title": issue.get("message", "No title")[:80],
        "severity": issue.get("severity", "unknown"),
        "cvss": issue.get("cvss_score", 0.0),
        "location": issue.get("location", "unknown"),
        "tool": issue.get("tool", "unknown"),
        "cwe": issue.get("cwe", "unknown"),
        "created_at": datetime.datetime.now().isoformat()
    }
    
    log_file = Path("reports/tickets.log")
    log_file.parent.mkdir(exist_ok=True)
    
    with open(log_file, "a") as f:
        f.write(json.dumps(ticket) + "\n")
    
    print(f"  [MOCK JIRA] {ticket['id']}: {ticket['title'][:50]} (CVSS: {ticket['cvss']})")
    return ticket

def create_jira_tickets(input_file, dry_run=True):
    """
    Создаёт тикеты из JSON-файла с уязвимостями
    dry_run=True — только вывод в консоль
    """
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    issues = data.get("findings", [])
    if not issues:
        print("Нет уязвимостей для создания тикетов")
        return []
    
    print(f"\n Найдено {len(issues)} критических уязвимостей")
    print(f"{'='*60}")
    
    tickets = []
    for i, issue in enumerate(issues, 1):
        if dry_run:
            print(f"  [DRY RUN] {issue.get('message', '')[:60]}")
            print(f"     → Локация: {issue.get('location', 'unknown')}")
            print(f"     → CVSS: {issue.get('cvss_score', 0)}")
        else:
            ticket = create_mock_ticket(issue, i)
            tickets.append(ticket)
    
    print(f"{'='*60}")
    if dry_run:
        print("\n Это был DRY RUN. Для реального создания тикетов запусти с флагом --no-dry-run")
    else:
        print(f"\n Создано {len(tickets)} тикетов в reports/tickets.log")
    
    return tickets

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jira mock integration")
    parser.add_argument("--input", default="filtered-issues.json", help="JSON файл с уязвимостями")
    parser.add_argument("--no-dry-run", action="store_true", help="Реальное создание тикетов")
    args = parser.parse_args()
    
    create_jira_tickets(args.input, dry_run=not args.no_dry_run)