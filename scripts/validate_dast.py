#!/usr/bin/env python3
"""Валидатор уязвимостей DAST (ZAP)"""
import json
import requests
from urllib.parse import urlparse, parse_qs, urlunparse

def validate_sqli(url, param, evidence):
    """Проверяет SQLi через тестовую ' OR '1'='1"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    test_payload = "' OR '1'='1"
    query[param] = test_payload
    new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
    test_url = urlunparse(parsed._replace(query=new_query))
    
    try:
        r = requests.get(test_url, timeout=5)
        # Простая проверка: признаки SQL ошибки
        if "sql" in r.text.lower() or "mysql" in r.text.lower() or "syntax" in r.text.lower():
            return {"confirmed": True, "evidence": "SQL error in response"}
        # Или, что evidence есть в ответе
        if evidence and evidence in r.text:
            return {"confirmed": True, "evidence": "Original evidence found"}
        return {"confirmed": False, "evidence": "No SQL error detected"}
    except Exception as e:
        return {"confirmed": False, "evidence": f"Error: {str(e)}"}

def validate_xss(url, param, evidence):
    """Проверяет XSS через внедрение <img src=x onerror=alert()>"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    # payload
    test_payload = "<img src=x onerror=alert(1)>"
    query[param] = test_payload
    new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
    test_url = urlunparse(parsed._replace(query=new_query))
    
    try:
        r = requests.get(test_url, timeout=5)
        if test_payload in r.text:
            return {"confirmed": True, "evidence": "Payload reflected in response"}
        # Альтернатива: проверка на alert
        if "alert" in r.text.lower():
            return {"confirmed": True, "evidence": "Alert found in response"}
        return {"confirmed": False, "evidence": "Payload not reflected"}
    except Exception as e:
        return {"confirmed": False, "evidence": f"Error: {str(e)}"}

def main():
    with open("../tests/fixtures/zap-sample.json") as f:
        data = json.load(f)
    
    print("=== DAST VALIDATION RESULTS ===\n")
    for alert in data["alerts"]:
        name = alert["name"]
        risk = alert["risk"]
        url = alert["url"]
        param = alert.get("param", "")
        evidence = alert.get("evidence", "")
        
        print(f"Checking: {name} ({risk})")
        print(f"URL: {url}")
        print(f"Param: {param}")
        
        if "SQL" in name and param:
            result = validate_sqli(url, param, evidence)
        elif "XSS" in name and param:
            result = validate_xss(url, param, evidence)
        else:
            result = {"confirmed": False, "evidence": "Not supported for validation"}
        
        status = "CONFIRMED" if result["confirmed"] else "⚠️ POTENTIAL (FP possible)"
        print(f"   Status: {status}")
        print(f"   Evidence: {result['evidence']}\n")
    
    
    print("=== END ===")

if __name__ == "__main__":
    main()