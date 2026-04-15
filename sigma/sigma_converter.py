import yaml
import json
import os
from datetime import datetime

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
}


def load_sigma_rule(filepath):
    with open(filepath, "r") as f:
        content = f.read()
    yaml_part = content.split("---")[0]
    return yaml.safe_load(yaml_part)


def sigma_to_elasticsearch(rule):
    detection = rule.get("detection", {})
    keywords = detection.get("keywords", [])

    should_clauses = [
        {"match_phrase": {"message": kw}} for kw in keywords
    ]

    es_query = {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1
            }
        },
        "_source": rule.get("fields", ["message", "process", "timestamp"])
    }

    return es_query


def sigma_to_detection_rule(rule):
    detection_rule = {
        "description": rule.get("description", "").strip().replace("\n", " "),
        "phrases":     rule.get("detection", {}).get("keywords", []),
        "exclude_processes": [],
        "threshold":   1,
        "window_min":  5,
        "severity":    SEVERITY_MAP.get(rule.get("level", "medium"), "MEDIUM"),
    }
    return detection_rule


def generate_report(rules):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SOC Lab - SIGMA Rules Report</title>
    <style>
        body {{ font-family: monospace; margin: 40px; background: #0d1117; color: #c9d1d9; }}
        h1 {{ color: #58a6ff; }}
        h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
        .rule {{ background: #161b22; border: 1px solid #30363d; 
                 border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .tag {{ background: #1f6feb; color: #fff; padding: 2px 8px; 
                border-radius: 4px; font-size: 12px; margin: 2px; display: inline-block; }}
        .critical {{ color: #ff7b72; font-weight: bold; }}
        .high {{ color: #f0883e; font-weight: bold; }}
        .medium {{ color: #e3b341; }}
        .low {{ color: #3fb950; }}
        pre {{ background: #0d1117; padding: 12px; border-radius: 6px; 
               overflow-x: auto; border: 1px solid #30363d; }}
        .meta {{ color: #8b949e; font-size: 13px; }}
    </style>
</head>
<body>
    <h1>SOC Lab - SIGMA Detection Rules</h1>
    <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 
    | Rules: {len(rules)} | Author: Krysti4n16</p>
"""

    for rule in rules:
        level = rule.get("level", "medium")
        tags = rule.get("tags", [])
        tags_html = " ".join(f'<span class="tag">{t}</span>' for t in tags)
        keywords = rule.get("detection", {}).get("keywords", [])
        keywords_str = "\n".join(f'  - "{kw}"' for kw in keywords)
        fps = rule.get("falsepositives", [])
        fps_html = "<br>".join(f"• {fp}" for fp in fps)

        html += f"""
    <div class="rule">
        <h2>{rule.get('title', 'Unknown')}</h2>
        <p><strong>ID:</strong> <code>{rule.get('id', '')}</code></p>
        <p><strong>Level:</strong> <span class="{level}">{level.upper()}</span></p>
        <p><strong>Status:</strong> {rule.get('status', '')}</p>
        <p><strong>Description:</strong> {rule.get('description', '').strip()}</p>
        <p><strong>Tags:</strong> {tags_html}</p>
        <p><strong>Detection keywords:</strong></p>
        <pre>{keywords_str}</pre>
        <p><strong>False positives:</strong><br>{fps_html}</p>
        <p class="meta"><strong>References:</strong> 
        {' | '.join(f'<a href="{r}" style="color:#58a6ff">{r}</a>'
                    for r in rule.get('references', []))}</p>
    </div>
"""

    html += "</body></html>"
    return html


def convert_all():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    rules = []
    converted = 0

    print("SIGMA Rule Converter")
    print(f"Loading rules from: {RULES_DIR}\n")

    for filename in sorted(os.listdir(RULES_DIR)):
        if not filename.endswith(".yml"):
            continue

        filepath = os.path.join(RULES_DIR, filename)
        rule = load_sigma_rule(filepath)
        rules.append(rule)

        es_query = sigma_to_elasticsearch(rule)
        es_output = os.path.join(
            OUTPUT_DIR,
            filename.replace(".yml", "_elasticsearch.json")
        )
        with open(es_output, "w") as f:
            json.dump(es_query, f, indent=2)

        det_rule = sigma_to_detection_rule(rule)
        det_output = os.path.join(
            OUTPUT_DIR,
            filename.replace(".yml", "_detection_rule.json")
        )
        with open(det_output, "w") as f:
            json.dump(det_rule, f, indent=2)

        level = rule.get("level", "?").upper()
        title = rule.get("title", filename)
        print(f"[{level}] {title}")
        print(f"-> {es_output}")
        converted += 1

    report_path = os.path.join(OUTPUT_DIR, "sigma_rules_report.html")
    with open(report_path, "w") as f:
        f.write(generate_report(rules))

    print(f"\nConverted {converted} rules")
    print(f"HTML report: {report_path}")
    print(f"\nopen {report_path}")


if __name__ == "__main__":
    convert_all()
