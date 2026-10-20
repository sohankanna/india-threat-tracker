#!/usr/bin/env python3
"""Replay every detection fixture through a real Wazuh manager's logtest.

Runs on a host with wazuh-manager installed and detections/wazuh/local_rules.xml
copied to /var/ossec/etc/rules/ (see .github/workflows/wazuh-integration.yml).
It talks to the logtest socket directly, the same interface wazuh-logtest uses,
so each event can carry its real log format and location (eventchannel for
Sysmon, syslog for PAN-OS, JSON for Azure Graph).

For every fixture it records the decoder and rule the engine actually chose and
compares that with the expectation:
  should_match      -> the tracker rule must fire
  should_not_match  -> the tracker rule must not fire

Writes the observed-versus-expected table as JSON and Markdown and exits 1 on
any mismatch. Needs root (the socket is owned by wazuh).

    sudo python3 detections/tests/wazuh_logtest.py --out wazuh-logtest-results
"""
import argparse
import json
import os
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tests"))
import wazuh_logs  # noqa: E402

SOCKET = os.environ.get("WAZUH_LOGTEST_SOCKET", "/var/ossec/queue/sockets/logtest")

# fixture stem -> (log kind, tracker rule id expected to fire)
RULES = {
    "office_document_spawns_script_interpreter": ("sysmon", "100210"),
    "office_archive_lnk_spawns_lolbin": ("sysmon", "100211"),
    "windows_suspicious_dns_server_change": ("sysmon", "100212"),
    "pan_os_mgmt_auth_from_unexpected_source": ("paloalto", "100220"),
    "entra_aitm_risky_signin_token_replay": ("graph", "100230"),
}


def logtest(raw, kind, token=None):
    params = {"event": raw, **wazuh_logs.LOGTEST[kind]}
    if token:
        params["token"] = token
    payload = json.dumps({"version": 1, "origin": {"name": "india-threat-tracker", "module": "ci"},
                          "command": "log_processing", "parameters": params}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET)
        s.sendall(struct.pack("<I", len(payload)) + payload)
        size = struct.unpack("<I", _recv(s, 4))[0]
        return json.loads(_recv(s, size))


def _recv(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("logtest closed the connection")
        buf += chunk
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="wazuh-logtest-results")
    a = ap.parse_args()

    rows, failures = [], 0
    for stem, (kind, rule_id) in RULES.items():
        with open(os.path.join(HERE, f"{stem}.events.json")) as f:
            fx = json.load(f)
        cases = [(e, True) for e in fx["should_match"]] + [(e, False) for e in fx["should_not_match"]]
        for event, expected in cases:
            raw = wazuh_logs.RAW[kind](event)
            resp = logtest(raw, kind)
            if resp.get("error"):
                observed_rule, decoder, note = None, None, f"logtest error {resp['error']}: {resp.get('message')}"
            else:
                out = resp.get("data", {}).get("output", {})
                observed_rule = out.get("rule", {}).get("id")
                decoder = out.get("decoder", {}).get("parent") or out.get("decoder", {}).get("name")
                note = ""
            fired = observed_rule == rule_id
            ok = fired == expected and not note
            failures += not ok
            rows.append({
                "rule": f"{stem} ({rule_id})",
                "case": event.get("_case") or event.get("_why") or "",
                "expected": "fires" if expected else "does not fire",
                "observed_rule": observed_rule,
                "decoder": decoder,
                "result": "pass" if ok else "FAIL",
                "note": note,
                "raw": raw,
            })

    with open(a.out + ".json", "w") as f:
        json.dump({"failures": failures, "results": rows}, f, indent=2)
    lines = ["| Rule | Case | Expected | Observed rule | Decoder | Result |", "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['rule']} | {r['case']} | {r['expected']} | {r['observed_rule'] or '-'} | "
                     f"{r['decoder'] or '-'} | {r['result']}{' ' + r['note'] if r['note'] else ''} |")
    md = "\n".join(lines) + f"\n\n{len(rows) - failures}/{len(rows)} fixture events behaved as expected.\n"
    with open(a.out + ".md", "w") as f:
        f.write(md)
    print(md)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
