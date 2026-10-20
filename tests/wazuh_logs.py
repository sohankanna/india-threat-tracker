"""Turn detection fixtures into the raw logs a Wazuh manager actually receives.

Used twice:
* tests/wazuh_eval.py decodes these raw logs the way Wazuh does, so decoder
  behaviour (such as the Palo Alto decoder cutting a field at the first comma)
  is part of every offline test run;
* detections/tests/wazuh_logtest.py sends the same raw logs to a real
  manager in CI (.github/workflows/wazuh-integration.yml): PAN-OS and Graph
  through logtest, Sysmon through the analysisd queue like an agent.

Formats:
* sysmon   What the Wazuh Windows agent sends: {"Message", "Event"} where
           Event is the raw event XML. The manager's eventchannel decoder
           (analysisd DecodeWinevt) turns it into win.system.* and
           win.eventdata.*, lower-casing the first letter of each name.
           It only runs for events on the analysisd queue with type 'f';
           wazuh-logtest never calls it, so the integration job sends
           Sysmon events through the queue socket, like an agent.
* paloalto PAN-OS 10.x SYSTEM syslog CSV. The description is double-quoted
           because it contains commas, as PAN-OS sends it.
* graph    Entra ID sign-in record as the azure-logs Graph integration ships
           it, tagged azure_tag=azure-ad-graph.
"""
import json
from xml.sax.saxutils import escape, quoteattr

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PAN_STAMP = "2026/10/20 10:00:00"


def sysmon(fixture, computer="WS-TEST-01"):
    data = "".join(
        f"<Data Name={quoteattr(k)}>{escape(str(v))}</Data>"
        for k, v in fixture.items() if not k.startswith("_") and k != "EventID")
    xml = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='{SYSMON_PROVIDER}' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/>"
        f"<EventID>{fixture['EventID']}</EventID><Version>5</Version><Level>4</Level><Task>{fixture['EventID']}</Task>"
        "<Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
        "<TimeCreated SystemTime='2026-10-20T04:30:00.000000000Z'/><EventRecordID>1</EventRecordID>"
        "<Execution ProcessID='3000' ThreadID='4000'/>"
        f"<Channel>{SYSMON_CHANNEL}</Channel><Computer>{escape(computer)}</Computer>"
        "<Security UserID='S-1-5-18'/></System>"
        f"<EventData>{data}</EventData></Event>"
    )
    return json.dumps({"Message": "Sysmon test event", "Event": xml}, separators=(",", ":"))


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
# Sysmon is absent on purpose: see the module docstring.
LOGTEST = {
    "paloalto": {"log_format": "syslog", "location": "/var/log/paloalto.log"},
    "graph": {"log_format": "json", "location": "azure-logs"},
}
