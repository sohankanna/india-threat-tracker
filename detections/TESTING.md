# Testing the detections

Every rule ships with fixture events in [`tests/`](tests/): events that **must**
alert and events that **must not**, each labelled with why. CI runs them on
every push and pull request (`python -m unittest discover -s tests`).

## What is actually tested, per backend

Be precise about what a green build means. It does **not** mean every rule
catches real attacks in your environment. It means the following:

| Backend | How the fixtures are run | What a pass shows |
|---------|--------------------------|-------------------|
| **Sigma** (canonical) | **Executed.** [`tests/sigma_eval.py`](../tests/sigma_eval.py) evaluates each rule against every fixture, following the Sigma specification for the features these rules use (and refusing anything else). | The canonical logic produces the expected result for every fixture. |
| **Wazuh** | **Emulated on every run, and on a real manager in a separate CI job.** Every fixture is turned into the raw log a manager receives ([`tests/wazuh_logs.py`](../tests/wazuh_logs.py): eventchannel JSON, PAN-OS syslog CSV, Graph JSON). [`tests/wazuh_eval.py`](../tests/wazuh_eval.py) decodes it as Wazuh 4.14.9 does (the PAN-OS decoder regexes are copied from the ruleset) and applies the rules. The [Wazuh integration workflow](../.github/workflows/wazuh-integration.yml) installs `wazuh-manager` 4.14.9, loads `local_rules.xml` and replays the same raw logs on the real manager ([`tests/wazuh_logtest.py`](tests/wazuh_logtest.py)): PAN-OS and Graph through the logtest socket, Sysmon through the analysisd queue exactly as a Windows agent sends it, read back from `alerts.json`. It publishes expected versus observed per event. | Emulation: rule logic and the decoding steps modelled. The integration job: what a real 4.14.9 manager decodes and fires. Check its latest run in the Actions tab; until it has passed, the Wazuh rules are validated by emulation only. |
| **Splunk** | **Not executed.** The DNS and PAN-OS searches are emulated from their own query text (split pattern, extraction regex and CIDR ranges are read out of the `.spl` file and applied to the fixtures). The rest are checked statically. | The parts that previously went wrong behave as intended. SPL is not run against a Splunk instance. |
| **Elastic** | **Not executed.** Same approach for the ES\|QL DNS and PAN-OS queries; the EQL/KQL rules are checked statically. | As for Splunk. Queries are not run against Elasticsearch. |

On top of the fixtures, CI checks that the backends agree with each other:

- **Process lists** for the two process-creation rules are identical in Sigma,
  Splunk, Elastic and Wazuh.
- **The trusted-resolver policy** is identical everywhere: the Sigma and Wazuh
  regexes are compared against the CIDR ranges in Splunk and Elastic on
  boundary addresses and 4,000 random ones, alone and in mixed lists in both
  orders.
- **The PAN-OS admin allowlist** is the same CIDR set in all four backends.
- **The archive rule** has no `.lnk` command-line shortcut in any backend, and
  **the Entra primary rule** never matches error 50140.

The real manager also showed why Sysmon cannot be checked with `wazuh-logtest`:
logtest always takes the generic decoder path and never calls the Windows
eventchannel decoder, so a Sysmon event replayed there is decoded as plain JSON
and no Windows rule (60000 and below) can fire. The integration job therefore
sends Sysmon events through the agent queue instead; tests that "pass" a Windows
rule in logtest prove nothing.

Decoding raw logs found a real defect the earlier emulation (which started from
pre-decoded fields) could not: Wazuh's Palo Alto decoder captures every field as
`[^,]*`, so an `auth-success` description, which PAN-OS quotes because it
contains commas, is cut at the first comma and never contains `From:`. A rule on
the decoded `description` field can therefore never fire. Rule 100220 now
matches the full log with `<regex>`, and a regression test proves the
field-based version fails.

The suite has been checked against the bugs it is meant to prevent: each one
was re-introduced deliberately (prefix-only DNS check, string-compared CIDR,
`.lnk` alternative, 50140 in the primary rule, Wazuh rules on non-existent
fields, the field-based PAN-OS Wazuh rule, allowlist drift, process-list drift)
and every one fails the build.

**Validation level, in one line:** Sigma executed; Wazuh emulated plus a
real-manager CI job; Splunk and Elastic not run against a live instance. All
rules stay `experimental`.

**No test here produces a detection rate.** For that, run the rules on your
own telemetry, in your own SIEM, against a real baseline.

---

## Per-rule cases

### `office_document_spawns_script_interpreter`
- **Fields:** `ParentImage`, `Image` (Sysmon Event 1 / ECS `process.parent.name`, `process.name`)
- **Alerts:** Word → `cmd.exe`; Excel → PowerShell (matching is case-insensitive)
- **Silent:** Explorer → `cmd.exe` (parent isn't Office); Word → `spoolsv.exe` (child isn't an interpreter)
- **Known false positives:** enterprise macros and Office automation that legitimately launch scripts

### `office_archive_lnk_spawns_lolbin`
- **Fields:** `ParentImage`, `Image`. A `.lnk` in the command line is investigation context, never a match condition.
- **Alerts:** 7-Zip → PowerShell; Explorer → `mshta.exe`
- **Silent:** 7-Zip → Notepad; WinRAR → Acrobat (ordinary applications); `services.exe` → `cmd.exe` (not an archive tool or Explorer)
- **Scope:** the archive/Explorer → LOLBin step only, not the full ZIP → LNK → payload chain

### `windows_suspicious_dns_server_change`
- **Fields:** `TargetObject` (ends `NameServer` / `DhcpNameServer`), `Details` (the new value, which can hold several resolvers)
- **Logic:** alert if **any** resolver in the value is outside the trusted-resolver policy (RFC1918 by default)
- **Alerts:** `9.9.9.9`; `10.0.0.53,9.9.9.9`; `9.9.9.9,10.0.0.53`; `10.0.0.53 9.9.9.9`; `192.168.1.1,172.32.0.1` (172.32/16 is outside 172.16/12); `1.1.1.1` until you allowlist it
- **Silent:** `10.0.0.53`; `10.0.0.53,10.0.0.54`; `192.168.1.1 172.16.0.10`; an empty value; a non-resolver registry value
- **Not covered:** IPv6 resolvers (they live under `Tcpip6`)

### `pan_os_mgmt_auth_from_unexpected_source`
- **Fields:** PAN-OS SYSTEM log, subtype `auth`, event `auth-success`; the source address is taken from the description's `From: <address>.` (In Wazuh, from the full log, because the decoder truncates the description at its first comma.)
- **Alerts:** a login from `203.0.113.9`; from `11.0.0.5` (outside `10.0.0.0/8` despite the leading 1)
- **Silent:** a login from `10.0.0.5` (allowlisted); an `auth-fail` event
- **Meaning:** unexpected management-plane authentication, **not** proof of CVE-2026-0322

### `entra_aitm_risky_signin_token_replay`
- **Fields:** `RiskLevelAggregated`, `ResultType` (Entra sign-in logs; P1/P2 for risk)
- **Alerts:** high risk **and** `ResultType` 0 (success)
- **Silent:** `ResultType` 50140 (KmsiInterrupt; goes to the separate lower-confidence hunt, Wazuh rule 100231); 50126 (failed password); low risk
- **Meaning:** a lead for investigation, not confirmation of AiTM

## Running the tests

```bash
pip install -r requirements.txt -r requirements-ci.txt
python -m unittest discover -s tests -v
```

Against a real Wazuh manager (Linux host or VM with `wazuh-manager` installed):

```bash
sudo cp detections/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-control restart
sudo python3 detections/tests/wazuh_logtest.py --out wazuh-logtest-results
```
