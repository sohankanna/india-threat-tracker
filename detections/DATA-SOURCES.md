# Data sources, telemetry & validation

What each detection needs to actually fire, and how to prove it works in your
environment before you trust it. Every rule here is `experimental` — this
document is the honest part: a rule you can't feed is a rule that silently
never alerts.

Rules live in four formats, same logic in each:
`sigma/` (canonical) · `splunk/` (SPL) · `elastic/` (EQL/KQL) · `wazuh/local_rules.xml`.

---

## Endpoint rules (Windows + Sysmon)

Three rules depend on **Sysmon**. Without it they will never fire — the native
Windows Security log does not carry parent-process image or registry-value data
at the fidelity these need.

| | |
|---|---|
| **Sensor** | [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with a config that logs **Event ID 1** (process create) and **Event ID 13** (registry value set) |
| **Config** | A maintained config such as [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) or [Olaf Hartong's modular](https://github.com/olafhartong/sysmon-modular) one. Confirm `ProcessCreate` and `RegistryEvent (Set)` for `...\Tcpip\Parameters\Interfaces` are **not** excluded |
| **Ship to Splunk** | Splunk Add-on for Microsoft Sysmon → `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| **Ship to Elastic** | Elastic Defend (recommended) or Winlogbeat Sysmon module → `logs-endpoint.events.*` / `winlogbeat-*` |
| **Ship to Wazuh** | wazuh-agent on the host + Sysmon channel in `ossec.conf` `<localfile>`; the Sysmon ruleset maps EID 1→`61603`, EID 13→`61615` |

**Rule → fields → validation**

| Rule | Key fields | Benign validation |
|------|-----------|-------------------|
| `office_document_spawns_script_interpreter` | `ParentImage` (winword/excel/powerpnt), `Image` (wscript/cscript/powershell/mshta/cmd) | Atomic Red Team **T1059** / **T1204.002**; or open a test macro-enabled doc whose macro runs `cmd /c whoami`. Rule should alert on `winword.exe → cmd.exe` |
| `office_archive_lnk_spawns_lolbin` | `ParentImage` (explorer/7zFM/WinRAR/Winzip), `Image` (mshta/powershell/pwsh/rundll32/cmd), `CommandLine` contains `.lnk` | Extract a ZIP in Explorer containing a benign `.lnk` that launches `powershell -c exit`. Rule should alert on the `explorer.exe/7zFM.exe → powershell.exe` parentage |
| `windows_suspicious_dns_server_change` | `TargetObject` ends `NameServer`/`DhcpNameServer`, `Details` (the new resolver IP) | In an **isolated VM**: `Set-DnsClientServerAddress -InterfaceIndex <n> -ServerAddresses 9.9.9.9`. Rule should alert (9.9.9.9 is outside RFC1918). Revert with `-ResetServerAddresses` |

> **Tuning that matters:** the DNS rule excludes RFC1918 resolvers by default
> (`10.`, `172.16–31.`, `192.168.`). Add your **public** ISP/corporate resolver
> IPs to the negate/`where` clause or it will alert on every legitimate public
> resolver you use.

---

## PAN-OS management auth (`pan_os_mgmt_auth_from_unexpected_source`) — CVE-2026-0322

| | |
|---|---|
| **Sensor** | PAN-OS firewall **SYSTEM** log, subtype `auth`, forwarded via syslog |
| **Splunk** | Splunk Add-on for Palo Alto Networks → `sourcetype=pan:system` |
| **Elastic** | Elastic PAN-OS integration / Filebeat `panw` module → `logs-panw.panos-*` |
| **Wazuh** | PAN-OS syslog to the manager (Palo Alto decoder); pair with a CDB allowlist (see `wazuh/local_rules.xml`) |
| **Must TUNE** | The admin **source allowlist**. The rule's value is *"admin auth from a host that isn't a jump box"* — with no allowlist it just lists every admin login |
| **Validation** | Log into the firewall management UI from a host **outside** your allowlist. The event should surface. Then confirm a login **from** a jump box does **not**. |

Why it matters: CVE-2026-0322 needs an authenticated admin session as its
precondition. You usually can't see the exploit; you *can* see admin auth from
somewhere it should never come from.

---

## Entra ID AiTM sign-in (`entra_aitm_risky_signin_token_replay`) — FrostArmada / APT28

| | |
|---|---|
| **Sensor** | Entra ID **sign-in logs** (needs Entra ID **P1/P2** for `riskLevelAggregated`) |
| **Splunk** | Splunk Add-on for Microsoft Azure → `sourcetype=azure:aad:signin` |
| **Elastic** | Elastic Azure integration → `azure.signinlogs` |
| **Wazuh** | Azure integration (`wodle azure-logs`) pulling sign-in logs |
| **Logic** | `riskLevelAggregated = high` **and** result `0` (success) or `50140` (interrupted by "keep me signed in" / MFA) |
| **Validation** | Don't fake a risky sign-in in prod. Instead replay a known high-risk event from history: filter sign-in logs to a past `riskLevelAggregated=high, errorCode in (0,50140)` entry and confirm the rule would have matched it. Field names vary by TA version — verify `riskLevelAggregated` / `errorCode` paths against a real event first. |

> Tier this by context: a high-risk sign-in that also follows a **DNS change**
> (`windows_suspicious_dns_server_change`) on the same user's device is the
> FrostArmada chain, not an isolated travel alert.

---

## Fraud signals (`fraud/upi-fraud-signals.yaml`)

These are **not** log-source rules — they run on your own payments/risk
telemetry. They assume you are a PSP, bank, or app with access to these
streams. Map each to your schema; none are drop-in.

| Signal | Telemetry required | Source |
|--------|-------------------|--------|
| `fraud-otp-read-then-transfer` | OTP issuance events (timestamp, account) **and** an app-side signal that the OTP SMS was read programmatically (not shown to user) | OTP service + mobile SDK / RASP |
| `fraud-new-device-binding-highvalue` | Device-binding events with per-device trust age; transaction amounts | UPI/app binding service + txn stream |
| `fraud-recent-sim-swap` | SIM swap / MNP port events per MSISDN | Telco feed / NPCI mobile-change signal |
| `fraud-first-payee-velocity` | Per-account payee history (first-seen flag); per-payee transfer sums over short windows | Transaction stream + payee graph |
| `fraud-mule-fanout` | Per-beneficiary distinct-sender counts and inflow/outflow ratios over 24h; ATM withdrawal events | Transaction stream (beneficiary-centric view) |
| `fraud-upi-pin-context-anomaly` | The UI context a UPI PIN was solicited in (e.g. NPCI common library vs webview) | App SDK instrumentation |

**Reality check on availability:** the hardest inputs are the SIM-swap feed and
the PIN-context signal — most teams don't have them day one. The signals that
run on **transaction + device-binding data you already hold**
(`first-payee-velocity`, `mule-fanout`, `new-device-binding-highvalue`) are the
ones to implement first. Validate with **labelled historical fraud cases**:
replay confirmed mule/drain incidents and confirm the signal fires, then measure
false positives against a clean baseline week before you set thresholds.

---

## Converting the Sigma rules yourself

The `splunk/`, `elastic/` and `wazuh/` files are provided for convenience. To
regenerate for any backend (QRadar, Sentinel, Chronicle, etc.) from the
canonical rules:

```bash
pip install sigma-cli
sigma convert -t splunk          sigma/*.yml
sigma convert -t esql            sigma/office_document_spawns_script_interpreter.yml
sigma convert -t 'microsoft365defender'  sigma/entra_aitm_risky_signin_token_replay.yml
```

## Honest status

Every rule is `status: experimental`. These are written from the behavioural
patterns in the write-ups and standard log schemas — **they are not
lab-validated detection content with published true/false-positive rates.**
Treat them as a tuned starting point: deploy in audit/alert-only mode, run the
validation step, tune the `TUNE` markers, and measure against your own baseline
before you page anyone on them.
