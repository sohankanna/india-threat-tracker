"""Turn detection fixtures into the raw logs a Wazuh manager actually receives.

Used twice:
* tests/wazuh_eval.py decodes these raw logs the way Wazuh does, so decoder
  behaviour (such as the Palo Alto decoder cutting a field at the first comma)
  is part of every offline test run;
* detections/tests/wazuh_logtest.py sends the same raw logs to a real
  wazuh-logtest in CI (.github/workflows/wazuh-integration.yml).

Formats:
* sysmon   Windows eventchannel JSON as the Wazuh agent ships it
           (win.system.*, win.eventdata.* with lower-camel-case keys).
* paloalto PAN-OS 10.x SYSTEM syslog CSV. The description is double-quoted
           because it contains commas, as PAN-OS sends it.
* graph    Entra ID sign-in record as the azure-logs Graph integration ships
           it, tagged azure_tag=azure-ad-graph.
"""
import json

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PAN_STAMP = "2026/10/20 10:00:00"


def _lower_camel(name):
    return name[:1].lower() + name[1:]


def sysmon(fixture):
    eventdata = {_lower_camel(k): str(v) for k, v in fixture.items()
                 if not k.startswith("_") and k != "EventID"}
    return json.dumps({"win": {
        "system": {
            "providerName": SYSMON_PROVIDER,
            "eventID": str(fixture["EventID"]),
            "channel": SYSMON_CHANNEL,
            "severityValue": "INFORMATION",
            "computer": "WS-TEST-01",
        },
        "eventdata": eventdata,
    }}, separators=(",", ":"))


def _csv(value):
    value = "" if value is None else str(value)
    return f'"{value.replace(chr(34), chr(34) * 2)}"' if any(c in value for c in ',"') else value


def paloalto(fixture):
    """Syslog header + PAN-OS 10.x SYSTEM log fields, in documented order."""
    fields = [
        "1", PAN_STAMP, "012801000001", fixture.get("type", "SYSTEM"), fixture.get("subtype", ""),
        "0", PAN_STAMP, "", fixture.get("event", ""), "", "0", "0", "general", "informational",
        fixture.get("description", ""), "7300000001", "0x0", "0", "0", "0", "0", "", "PA-VM",
        "0", "0", "2026-10-20T10:00:00.000+05:30",
    ]
    return "Oct 20 10:00:00 PA-VM " + ",".join(_csv(f) for f in fields)


def graph(fixture):
    return json.dumps({
        "azure_tag": "azure-ad-graph",
        "activityDisplayName": "Sign-in activity",
        "userPrincipalName": fixture.get("UserPrincipalName", "user@contoso.com"),
        "ipAddress": fixture.get("IPAddress", "203.0.113.9"),
        "riskLevelAggregated": fixture.get("RiskLevelAggregated"),
        "status": {"errorCode": fixture.get("ResultType")},
    }, separators=(",", ":"))


RAW = {"sysmon": sysmon, "paloalto": paloalto, "graph": graph}
# What wazuh-logtest needs to treat the line like the real source.
LOGTEST = {
    "sysmon": {"log_format": "eventchannel", "location": "EventChannel"},
    "paloalto": {"log_format": "syslog", "location": "/var/log/paloalto.log"},
    "graph": {"log_format": "json", "location": "azure-logs"},
}
