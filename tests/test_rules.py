import sys
import os
import json
import yaml
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../scripts"))

ES_URL= "http://localhost:9200"
SIGMA_DIR= os.path.join(os.path.dirname(__file__), "../sigma/rules")

def test_elasticsearch_connection():
    print("Test: Elasticsearch connection")
    try:
        r= requests.get(ES_URL, timeout=5)
        assert r.status_code == 200
        data= r.json()
        assert "cluster_name" in data
        print("PASSED")
        return True
    except Exception as e:
        print(f" FAILED: {e}")
        return False

def test_indices_exist():
    print("Test: Required indices exist")
    required= ["soc-macos-logs", "soc-alerts"]
    passed= True
    for index in required:
        try:
            r= requests.get(f"{ES_URL}/{index}", timeout=5)
            if r.status_code == 200:
                count_r= requests.get(f"{ES_URL}/{index}/_count")
                count= count_r.json().get("count", 0)
                print(f"{index}: {count} documents")
            else:
                print(f"{index}: NOT FOUND")
                passed= False
        except Exception as e:
            print(f"{index}: ERROR — {e}")
            passed = False
    return passed

def test_sigma_rules_valid():
    print("Test: SIGMA rules are valid YAML")
    passed= True
    for filename in os.listdir(SIGMA_DIR):
        if not filename.endswith(".yml"):
            continue
        filepath= os.path.join(SIGMA_DIR, filename)
        try:
            with open(filepath) as f:
                content= f.read().split("---")[0]
            rule= yaml.safe_load(content)
            assert "title" in rule, "Missing title"
            assert "detection" in rule, "Missing detection"
            assert "level" in rule, "Missing level"
            assert "tags" in rule, "Missing tags"
            assert "id" in rule, "Missing id"
            keywords= rule.get("detection", {}).get("keywords", [])
            assert len(keywords) > 0, "No keywords in detection"
            print(f"{filename}: OK ({len(keywords)} keywords)")
        except Exception as e:
            print(f"{filename}: FAILED — {e}")
            passed= False
    return passed

def test_detection_rules_syntax():
    print("Detection engine rules have required fields")
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../scripts"))
        from detection_engine import RULES
        required_fields= ["description", "phrases", "threshold",
                          "window_min", "severity"]
        passed= True
        for rule_name, rule in RULES.items():
            for field in required_fields:
                if field not in rule:
                    print(f"{rule_name}: Missing field '{field}'")
                    passed = False
                    continue
            assert rule["threshold"] > 0, f"{rule_name}: threshold must be > 0"
            assert rule["window_min"] > 0, f"{rule_name}: window_min must be > 0"
            assert rule["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"], \
                f"{rule_name}: invalid severity"
            print(f"{rule_name}: OK")
        return passed
    except Exception as e:
        print(f"FAILED: {e}")
        return False

def test_es_query_returns_results():
    print("Elasticsearch queries return valid responses")
    try:
        query= {
            "query": {"range": {"timestamp": {"gte": "now-24h"}}},
            "size": 1
        }
        r= requests.post(
            f"{ES_URL}/soc-macos-logs/_search",
            json=query, timeout=5
        )
        assert r.status_code == 200
        data= r.json()
        assert "hits" in data
        count= data["hits"]["total"]["value"]
        print(f" soc-macos-logs: {count} events in last 24h")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False

def run_all():
    print("\n" + "="*50)
    print("SOC Lab — Test Suite")
    print("="*50 + "\n")

    tests= [
        test_elasticsearch_connection,
        test_indices_exist,
        test_sigma_rules_valid,
        test_detection_rules_syntax,
        test_es_query_returns_results,
    ]

    results= []
    for test in tests:
        result= test()
        results.append(result)
        print()

    passed= sum(results)
    total= len(results)

    print("="*50)
    print(f"Results: {passed}/{total} tests passed")
    if passed == total:
        print("ALL TESTS PASSED")
    else:
        print(f"{total - passed} test(s) FAILED")
    print("="*50 + "\n")

    return passed == total

if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)