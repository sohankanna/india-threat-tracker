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
| **Ship to Elastic** | **ECS / Elastic Defend (Elastic Agent)** → `logs-endpoint.events.*`. The queries use ECS fields (`process.name`, `process.parent.name`, `registry.path`, `registry.value`, `registry.data.strings`). The DNS rule is ES\|QL and needs Elastic **8.14 or later**. **Raw Winlogbeat Sysmon is not covered** — its fields live under `winlog.event_data.*` and would need separate mapping, which isn't provided here. |
| **Ship to Wazuh** | wazuh-agent on the host + Sysmon channel in `ossec.conf` `<localfile>`. In the Wazuh 4.14 ruleset, Sysmon Event 1 is rule `61603` and Event 13 is `61615`, with fields under `win.eventdata.*` (`parentImage`, `image`, `targetObject`, `details`). |

**Rule → fields → validation**

| Rule | Key fields | Benign validation |
|------|-----------|-------------------|
| `office_document_spawns_script_interpreter` | `ParentImage` (winword/excel/powerpnt), `Image` (wscript/cscript/powershell/mshta/cmd) | Atomic Red Team **T1059** / **T1204.002**; or open a test macro-enabled doc whose macro runs `cmd /c whoami`. Rule should alert on `winword.exe → cmd.exe` |
| `office_archive_lnk_spawns_lolbin` | `ParentImage` (explorer/7zFM/WinRAR/Winzip), `Image` (mshta/powershell/pwsh/rundll32/cmd) | Extract a ZIP in Explorer containing a benign `.lnk` that launches `powershell -c exit`. Rule should alert on the `explorer.exe/7zFM.exe → powershell.exe` parentage. **Scope:** this is the archive/Explorer → LOLBin parent-child only; it does not prove the full ZIP→LNK→payload chain (that needs event correlation). `.lnk` in the command line is investigation context, not a match condition. |
| `windows_suspicious_dns_server_change` | `TargetObject` ends `NameServer`/`DhcpNameServer`, `Details` (the new value; it can hold several resolvers, comma- or space-separated) | See the required cases below. |

> **How the DNS rule decides (read this):** the value can list several
> resolvers, so every backend checks **each address on its own** and alerts if
> **any** of them is outside the trusted-resolver policy, whatever order they
> appear in. Splunk splits the value and `cidrmatch`es each resolver; Elastic
> does the same in ES|QL with `SPLIT`, `MV_EXPAND` and `CIDR_MATCH`; Sigma and
> Wazuh use a pattern that inspects every address in the string. CI checks that
> all four agree on thousands of addresses, alone and in mixed lists.
>
> **Trusted-resolver policy:** RFC1918 (`10/8`, `172.16/12`, `192.168/16`),
> identical in all four backends.
> **An RFC1918 address is not automatically a trusted resolver**, and legitimate
> **public** ISP/corporate resolvers (e.g. your ISP's DNS, 1.1.1.1 if you use it)
> will fire unless you add them to the allowlist. Tune it.
>
> **Test these cases in your own environment** (isolated VM, `Set-DnsClientServerAddress`):
> 1. **Trusted internal DNS** only (e.g. `10.0.0.53`) → must **not** alert.
> 2. **Approved public DNS** you've allowlisted → must **not** alert.
> 3. **Unapproved public resolver** (e.g. `9.9.9.9`) → **must** alert.
> 4. **Mixed list, both orders** (`10.0.0.53,9.9.9.9` and `9.9.9.9,10.0.0.53`) →
>    **must** alert both times (an attacker resolver alongside a legitimate one
>    still matters).
>
> IPv6 resolvers are not covered (they are stored under `Tcpip6`).
>
> Revert with `Set-DnsClientServerAddress -InterfaceIndex <n> -ResetServerAddresses`.

---

## PAN-OS management auth (`pan_os_mgmt_auth_from_unexpected_source`) — CVE-2026-0322

| | |
|---|---|
| **Sensor** | PAN-OS firewall **SYSTEM** log, subtype `auth`, forwarded via syslog |
| **Where the source address is** | PAN-OS records an admin login as event `auth-success`, and the source address appears **only inside the description**, ending `From: <address>.` ([Palo Alto system log reference](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/system-log-reference/informational-system-log-messages)). Common parsers do not lift it into a field, so every shipped backend extracts it itself. |
| **Splunk** | `sourcetype=pan:system`. The search matches `auth-success` and extracts the address from the raw event with `rex`, so it does not depend on add-on field names. |
| **Elastic** | Palo Alto Networks integration → `logs-panw.panos-*`. Its SYSTEM pipeline sets `panw.panos.type`, `panw.panos.sub_type`, `panw.panos.event.id` and `panw.panos.description`, but no `source.ip`, so the ES\|QL query extracts the address with `GROK`. Needs Elastic 8.14+. |
| **Wazuh** | PAN-OS syslog to the manager. The built-in decoder (parent rule `64500`) gives `type`, `content_threat_type`, `event_id` and `description`, and no source IP, so rule `100220` matches the `From:` text and excludes the allowlist with a pattern. |
| **Must TUNE** | The admin **source allowlist**. The rule's value is *"admin auth from a host that isn't a jump box"* — with no allowlist it just lists every admin login |
| **Validation** | Log into the firewall management UI from a host **outside** your allowlist. The event should surface. Then confirm a login **from** a jump box does **not**. |

Why it matters: CVE-2026-0322 needs an authenticated admin session as its
precondition. You usually can't see the exploit; you *can* see admin auth from
somewhere it should never come from. **To be explicit: a hit is unexpected
management-plane authentication, not proof the CVE was exploited.**

> **CIDR matching, done right:** the Sigma rule uses the `|cidr` modifier, Splunk
> uses `cidrmatch()` and Elastic uses `CIDR_MATCH`, all with the same allowlist
> (CI checks this). A *generic* `sigma convert -t splunk` with no CIDR-aware
> pipeline renders `|cidr` as a literal string compare (`src_ip="10.0.0.0/8"`),
> which is wrong, so use the shipped query rather than a naive conversion.
>
> **Wazuh limitation, stated plainly:** Wazuh can CIDR-match only a field its
> decoder extracted as an IP, and the PAN-OS decoder extracts none from SYSTEM
> logs. Rule `100220` therefore expresses the allowlist as a pattern on the
> description. That is exact for octet-aligned networks (`/8`, `/16`, `/24`);
> for other prefix lengths, write the pattern per range. CI checks the default
> pattern against `10.0.0.0/8` on 3,000 random addresses.

---

## Entra ID AiTM sign-in (`entra_aitm_risky_signin_token_replay`) — FrostArmada / APT28

| | |
|---|---|
| **Sensor** | Entra ID **sign-in logs** (needs Entra ID **P1/P2** for `riskLevelAggregated`) |
| **Splunk** | Splunk Add-on for Microsoft Azure → `sourcetype=azure:aad:signin` |
| **Elastic** | Elastic Azure integration → `azure.signinlogs` |
| **Wazuh** | The `azure-logs` Microsoft Graph integration with `<query>auditLogs/signIns</query>`. Events arrive under parent rule `87802` (`azure_tag` `azure-ad-graph`) and keep Graph's field names: `riskLevelAggregated` and `status.errorCode`. Confirm with `wazuh-logtest` on one real event. |
| **Logic (primary)** | `riskLevelAggregated = high` **and** `ResultType = 0` (a **successful** high-risk sign-in) |
| **ResultType 50140** | This is **KmsiInterrupt** — an interruption at the *"Keep me signed in"* prompt. It is **not** a successful authentication and **not** evidence of token replay. It's handled as a *separate, lower-confidence hunt* (see below), not by the primary rule. |
| **Validation** | Don't fake a risky sign-in in prod. Replay a known high-risk event from history: filter sign-in logs to a past `riskLevelAggregated=high, ResultType=0` entry and confirm the rule matches it. Test a `ResultType=50140` entry **separately** and confirm it lands in the context hunt, not the primary alert. Field names vary by TA version — verify the `riskLevelAggregated` / `ResultType` paths against a real event first. |

**This is a lead, not a verdict.** A high-risk successful sign-in means Entra's
risk engine flagged it and it still worked — it is an investigation starting
point, not confirmation of AiTM. Verify IP, user agent, geo and the session/token
before concluding anything.

> **Lower-confidence hunt (50140):** high-risk sign-ins interrupted at KMSI are
> worth reviewing in bulk but shouldn't page anyone — the shipped Splunk/Elastic
> queries and Wazuh rule `100231` carry this as a separate, lower-severity signal.
>
> **Tier by context:** a high-risk successful sign-in that also follows a **DNS
> change** (`windows_suspicious_dns_server_change`) on the same user's device is
> the FrostArmada chain, not an isolated travel alert.

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
