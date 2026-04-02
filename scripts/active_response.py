import subprocess
import requests
import os
import json
from datetime import datetime, timezone
import sys

sys.path.insert(0, os.path.dirname(__file__))
from slack_notifier import send_alert as slack_alert

ES_URL= "http://localhost:9200"
RESPONSE_INDEX= "soc-responses"
PF_BLOCKLIST= "/etc/pf.anchors/soc-blocklist"
PF_ANCHOR= "soc-blocklist"

WHITELIST_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "8.8.8.8", "8.8.4.4",       # Google DNS
    "1.1.1.1", "1.0.0.1",       # Cloudflare DNS
    "17.0.0.0",                  # Apple range
}

def create_response_index():
    mapping= {
        "mappings": {
            "properties": {
                "timestamp":  {"type": "date"},
                "action":     {"type": "keyword"},
                "ip":         {"type": "keyword"},
                "reason":     {"type": "text"},
                "vt_score":   {"type": "integer"},
                "success":    {"type": "boolean"},
            }
        }
    }
    r= requests.put(f"{ES_URL}/{RESPONSE_INDEX}", json=mapping)
    if r.status_code in (200, 400):
        print(f"Response index '{RESPONSE_INDEX}' ready")

def log_response(action, ip, reason, vt_score, success):
    doc= {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "ip":        ip,
        "reason":    reason,
        "vt_score":  vt_score,
        "success":   success,
    }
    requests.post(f"{ES_URL}/{RESPONSE_INDEX}/_doc", json=doc)

def setup_pf_anchor():
    if not os.path.exists(PF_BLOCKLIST):
        subprocess.run(
            ["sudo", "touch", PF_BLOCKLIST],
            capture_output=True
        )

    result= subprocess.run(
        ["sudo", "grep", "-q", PF_ANCHOR, "/etc/pf.conf"],
        capture_output=True
    )

    if result.returncode != 0:
        anchor_rules= (
            f'\nanchor "{PF_ANCHOR}"\n'
            f'load anchor "{PF_ANCHOR}" from "{PF_BLOCKLIST}"\n'
        )
        subprocess.run(
            ["sudo", "tee", "-a", "/etc/pf.conf"],
            input=anchor_rules.encode('utf-8'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        print(f"PF anchor '{PF_ANCHOR}' added to /etc/pf.conf")

def block_ip(ip, reason, vt_score):

    if ip in WHITELIST_IPS:
        print(f"{ip} is whitelisted — skipping block")
        return False

    result= subprocess.run(
        ["sudo", "grep", "-q", "-w", ip, PF_BLOCKLIST],
        capture_output=True
    )
    if result.returncode == 0:
        print(f"  [=] {ip} already blocked")
        return True

    rule= f"block drop quick from {ip} to any\n"
    
    add_result= subprocess.run(
        ["sudo", "tee", "-a", PF_BLOCKLIST],
        input=rule.encode('utf-8'),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )

    if add_result.returncode != 0:
        print(f"Failed to write blocklist: {add_result.stderr.decode()}")
        log_response("block_ip", ip, reason, vt_score, False)
        return False

    reload_result= subprocess.run(
        ["sudo", "pfctl", "-f", "/etc/pf.conf"],
        capture_output=True
    )

    subprocess.run(["sudo", "pfctl", "-e"], capture_output=True)

    success= reload_result.returncode == 0
    log_response("block_ip", ip, reason, vt_score, success)

    if success:
        print(f"BLOCKED: {ip} — {reason}")
        slack_alert(
            rule_name="active_response_block",
            severity="CRITICAL",
            description=f"Automatic IP block executed — {reason}",
            count=vt_score,
            window_min=0,
            samples=[
                f"Blocked IP: {ip}",
                f"VirusTotal score: {vt_score}/72 engines",
                f"PF rule added to {PF_BLOCKLIST}"
            ]
        )
    else:
        print(f"Block failed for {ip}: {reload_result.stderr.decode()}")

    return success

def unblock_ip(ip):
    
    result= subprocess.run(
        ["sudo", "grep", "-v", "-w", ip, PF_BLOCKLIST],
        capture_output=True, text=True
    )
    
    write_result= subprocess.run(
        ["sudo", "tee", PF_BLOCKLIST],
        input=result.stdout.encode('utf-8'),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    
    subprocess.run(["sudo", "pfctl", "-f", "/etc/pf.conf"], capture_output=True)
    print(f"UNBLOCKED: {ip}")
    log_response("unblock_ip", ip, "manual unblock", 0, True)

def list_blocked():
    if not os.path.exists(PF_BLOCKLIST):
        print("No blocklist found")
        return []

    result= subprocess.run(
        ["sudo", "cat", PF_BLOCKLIST],
        capture_output=True, text=True
    )
    lines= [l.strip() for l in result.stdout.splitlines() if l.strip()]
    if not lines:
        print("Blocklist is empty")
        return []

    print(f"Blocked IPs ({len(lines)}):")
    for line in lines:
        print(f"{line}")
    return lines

def check_vt_results_and_respond():
    query= {
        "query": {
            "bool": {
                "must": [
                    {"term": {"verdict": "MALICIOUS"}},
                    {"range": {"timestamp": {"gte": "now-1h"}}}
                ]
            }
        },
        "size": 10,
        "_source": ["ip", "malicious", "as_owner", "country"]
    }

    r= requests.post(
        f"{ES_URL}/soc-virustotal/_search",
        json=query
    )
    if r.status_code != 200:
        return

    hits= r.json().get("hits", {}).get("hits", [])
    if not hits:
        print("No malicious IPs found in VirusTotal results")
        return

    print(f"Found {len(hits)} malicious IP(s) — initiating block")
    for hit in hits:
        src= hit["_source"]
        ip= src.get("ip", "")
        score= src.get("malicious", 0)
        owner= src.get("as_owner", "unknown")
        country= src.get("country", "?")
        reason= f"VT score {score}/72 — {owner} ({country})"
        block_ip(ip, reason, score)

def run():
    print("SOC Lab — Active Response Engine")
    create_response_index()
    setup_pf_anchor()
    print("Checking VirusTotal results for malicious IPs\n")
    check_vt_results_and_respond()
    print("\nCurrent blocklist:")
    list_blocked()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SOC Lab Active Response")
    parser.add_argument("--block",   metavar="IP", help="Manually block an IP")
    parser.add_argument("--unblock", metavar="IP", help="Manually unblock an IP")
    parser.add_argument("--list",    action="store_true", help="List blocked IPs")
    parser.add_argument("--auto",    action="store_true",
                        help="Auto-block malicious IPs from VirusTotal")
    args= parser.parse_args()

    create_response_index()
    setup_pf_anchor()

    if args.block:
        block_ip(args.block, "manual block", 0)
    elif args.unblock:
        unblock_ip(args.unblock)
    elif args.list:
        list_blocked()
    elif args.auto:
        check_vt_results_and_respond()
    else:
        run()