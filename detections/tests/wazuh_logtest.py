#!/usr/bin/env python3
"""Replay every detection fixture through a real Wazuh manager.

Runs on a host with wazuh-manager installed and detections/wazuh/local_rules.xml
copied to /var/ossec/etc/rules/ (see .github/workflows/wazuh-integration.yml).

Two paths, because Wazuh decodes the sources differently:

* PAN-OS syslog and Azure Graph JSON go through the logtest socket, the
  interface wazuh-logtest uses. It returns the decoder and rule directly.
* Sysmon goes through the analysisd queue socket as an agent sends it
  ("f:EventChannel:{json}"). wazuh-logtest cannot test Windows events: it
  always uses the generic decoder path and never calls the eventchannel
  decoder, so a Sysmon event replayed there decodes as plain JSON and no
  Windows rule can fire. Each event carries a unique Computer name, and the
  result is read back from alerts.json.

For every fixture it records what the engine did and compares it with the
expectation (should_match -> the tracker rule fires; should_not_match -> it
does not). Writes the table as JSON and Markdown; exits 1 on any mismatch.
Needs root.

    sudo python3 detections/tests/wazuh_logtest.py --out wazuh-logtest-results
"""
import argparse
import json
import os
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tests"))
import wazuh_logs  # noqa: E402

OSSEC = os.environ.get("WAZUH_HOME", "/var/ossec")
LOGTEST_SOCKET = os.environ.get("WAZUH_LOGTEST_SOCKET", f"{OSSEC}/queue/sockets/logtest")
QUEUE_SOCKET = os.environ.get("WAZUH_QUEUE_SOCKET", f"{OSSEC}/queue/sockets/queue")
ALERTS = os.environ.get("WAZUH_ALERTS_JSON", f"{OSSEC}/logs/alerts/alerts.json")
WAIT_SECONDS = int(os.environ.get("WAZUH_ALERT_WAIT", "45"))

# fixture stem -> (log kind, tracker rule id expected to fire)
RULES = {
    "office_document_spawns_script_interpreter": ("sysmon", "100210"),
    "office_archive_lnk_spawns_lolbin": ("sysmon", "100211"),
    "windows_suspicious_dns_server_change": ("sysmon", "100212"),
    "pan_os_mgmt_auth_from_unexpected_source": ("paloalto", "100220"),
    "entra_aitm_risky_signin_token_replay": ("graph", "100230"),
}


# ── logtest (PAN-OS, Graph) ───────────────────────────────────────────────
def _recv(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("logtest closed the connection")
        buf += chunk
    return buf


def logtest(raw, kind):
    params = {"event": raw, **wazuh_logs.LOGTEST[kind]}
    payload = json.dumps({"version": 1, "origin": {"name": "india-threat-tracker", "module": "ci"},
                          "command": "log_processing", "parameters": params}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(LOGTEST_SOCKET)
        s.sendall(struct.pack("<I", len(payload)) + payload)
        size = struct.unpack("<I", _recv(s, 4))[0]
        resp = json.loads(_recv(s, size))
    if resp.get("error"):
        return None, None, f"logtest error {resp['error']}: {resp.get('message')}"
    out = resp.get("data", {}).get("output", {})
    dec = out.get("decoder", {})
    return out.get("rule", {}).get("id"), dec.get("parent") or dec.get("name"), ""


# ── Agent queue + alerts.json (Sysmon) ────────────────────────────────────
def send_agent_event(raw):
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.connect(QUEUE_SOCKET)
        s.send(f"f:EventChannel:{raw}".encode())


def read_alerts(offset):
    try:
        with open(ALERTS, encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def alerts_by_computer(alerts):
    found = {}
    for a in alerts:
        comp = a.get("data", {}).get("win", {}).get("system", {}).get("computer")
        if comp:
            found.setdefault(comp, []).append(a)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="wazuh-logtest-results")
    a = ap.parse_args()

    rows, pending = [], []
    offset = os.path.getsize(ALERTS) if os.path.exists(ALERTS) else 0

    for stem, (kind, rule_id) in RULES.items():
        with open(os.path.join(HERE, f"{stem}.events.json")) as f:
            fx = json.load(f)
        cases = [(e, True) for e in fx["should_match"]] + [(e, False) for e in fx["should_not_match"]]
        for n, (event, expected) in enumerate(cases):
            row = {"rule": f"{stem} ({rule_id})", "rule_id": rule_id,
                   "case": event.get("_case") or event.get("_why") or "",
                   "expected": "fires" if expected else "does not fire", "_expected": expected,
                   "path": "agent queue" if kind == "sysmon" else "logtest"}
            if kind == "sysmon":
                marker = f"itt-{rule_id}-{n:02d}"
                raw = wazuh_logs.sysmon(event, computer=marker)
                row.update(marker=marker, raw=raw)
                send_agent_event(raw)
                pending.append(row)
            else:
                raw = wazuh_logs.RAW[kind](event)
                observed, decoder, note = logtest(raw, kind)
                row.update(observed_rule=observed, decoder=decoder, note=note, raw=raw)
            rows.append(row)

    # Sysmon alerts are written asynchronously. Wait until every event that must
    # alert has, then a few seconds more for anything that must not.
    must = {r["marker"] for r in pending if r["_expected"]}
    deadline = time.time() + WAIT_SECONDS
    while time.time() < deadline:
        if must <= set(alerts_by_computer(read_alerts(offset))):
            break
        time.sleep(1)
    time.sleep(5)
    seen = alerts_by_computer(read_alerts(offset))
    for r in pending:
        hits = seen.get(r["marker"], [])
        ids = [h.get("rule", {}).get("id") for h in hits]
        r["observed_rule"] = r["rule_id"] if r["rule_id"] in ids else (",".join(ids) or None)
        r["decoder"] = hits[0].get("decoder", {}).get("name") if hits else None
        r["note"] = "" if hits or not r["_expected"] else "no alert (level >= 3) for this event"

    failures = 0
    for r in rows:
        fired = r["observed_rule"] == r["rule_id"]
        ok = fired == r["_expected"] and not (r["note"] and r["path"] == "logtest")
        r["result"] = "pass" if ok else "FAIL"
        failures += not ok

    with open(a.out + ".json", "w") as f:
        json.dump({"failures": failures, "results": [{k: v for k, v in r.items() if not k.startswith("_")}
                                                     for r in rows]}, f, indent=2)
    lines = ["| Rule | Case | Path | Expected | Observed rule | Decoder | Result |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['rule']} | {r['case']} | {r['path']} | {r['expected']} | {r['observed_rule'] or '-'} | "
                     f"{r['decoder'] or '-'} | {r['result']}{' (' + r['note'] + ')' if r['note'] else ''} |")
    md = "\n".join(lines) + f"\n\n{len(rows) - failures}/{len(rows)} fixture events behaved as expected.\n"
    with open(a.out + ".md", "w") as f:
        f.write(md)
    print(md)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
