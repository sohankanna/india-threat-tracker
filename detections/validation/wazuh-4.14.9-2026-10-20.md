# Validation report: Wazuh 4.14.9, real engine

**Result:** 29 of 29 fixture events behaved as expected on a real Wazuh 4.14.9
manager, across all five detections.

**Status after this test:** all rules remain `experimental`. This shows the
rules decode and fire as designed on synthetic events in a real engine. It does
not show a detection rate, false-positive rate or behaviour on real telemetry.

| | |
|---|---|
| SIEM | Wazuh manager `4.14.9-1` (official apt package, unmodified built-in ruleset and decoders) |
| Host | GitHub Actions `ubuntu-22.04` runner, disposable |
| Run | [Wazuh integration](../../.github/workflows/wazuh-integration.yml) run #3, 2026-10-20 ~15:08 UTC |
| Code under test | commit `abd981e` ([`wazuh/local_rules.xml`](../wazuh/local_rules.xml), fixtures in [`tests/`](../tests/)) |
| Raw evidence | [`wazuh-4.14.9-2026-10-20.json`](wazuh-4.14.9-2026-10-20.json): every event sent, the rule observed, the decoder |
| Data | Synthetic only. No production, customer or employer telemetry. |

## Rules under test

| Detection (Sigma id) | Wazuh rule | Level | Parent rule | Telemetry |
|---|---|---|---|---|
| Suspicious DNS server change on endpoint (`3b9318cc-5b56-4f08-8f7b-fb3c8c8425e9`) | 100212 | 10 | 61615 (Sysmon 13) | Sysmon Event 13 via the Wazuh Windows agent |
| Office document spawns script interpreter (`cd76273c-2d07-4d91-8d42-ba73e559ec37`) | 100210 | 12 | 61603 (Sysmon 1) | Sysmon Event 1 via the agent |
| Archive/Explorer spawns LOLBin (`c8b896ee-107a-4dc2-985c-b96cf33f6228`) | 100211 | 12 | 61603 (Sysmon 1) | Sysmon Event 1 via the agent |
| PAN-OS admin auth from unexpected source (`b7262907-f6fe-420f-b098-ae8904c8f5fd`) | 100220 | 8 | 64500 (Palo Alto) | PAN-OS SYSTEM logs by syslog to the manager |
| Entra high-risk successful sign-in (`62e7aec0-cf86-418a-9635-bd6cb8fc1893`) | 100230 (+100231 context) | 12 / 6 | 87802 (Azure Graph) | `azure-logs` Graph integration, `auditLogs/signIns` |

**Configuration the rules need, and nothing else:** copy `local_rules.xml` to
`/var/ossec/etc/rules/`; no built-in rule or decoder is modified. Allowlists
live in the rules themselves and were tested at their shipped defaults: trusted
resolvers RFC1918 for 100212, PAN-OS admin sources `10.0.0.0/8` for 100220.
Changing either needs a pattern edit, as documented in the rule comments.

## How events were delivered

Each fixture was turned into the raw log the manager would receive
([`tests/wazuh_logs.py`](../../tests/wazuh_logs.py)) and sent by
[`tests/wazuh_logtest.py`](../tests/wazuh_logtest.py):

* **Sysmon (rules 100210–100212):** the JSON a Windows agent sends,
  `{"Message", "Event": "<Event XML>"}`. It is written to the analysisd queue
  socket as `f:EventChannel:…`, so the manager's real eventchannel decoder runs,
  and the result is read back from `alerts.json`. `wazuh-logtest` cannot be used
  for these (see finding 2).
* **PAN-OS and Entra (100220, 100230/100231):** through the logtest socket, as
  `wazuh-logtest` does, which returns the decoder and rule chosen.

## Expected versus observed

"Observed rule" is the rule the manager reported for the event: an alert for
the agent-queue path, the logtest result otherwise. "–" means no alert at level
3 or above.

### DNS server change (100212): the primary detection

| Case | Expected | Observed | Decoder | |
|---|---|---|---|---|
| single unapproved public resolver | fires | 100212 | windows_eventchannel | pass |
| mixed: trusted first, unapproved second | fires | 100212 | windows_eventchannel | pass |
| mixed: unapproved first, trusted second | fires | 100212 | windows_eventchannel | pass |
| mixed, space-separated | fires | 100212 | windows_eventchannel | pass |
| 172.32.0.1 (outside 172.16/12) | fires | 100212 | windows_eventchannel | pass |
| public resolver not allowlisted | fires | 100212 | windows_eventchannel | pass |
| DhcpNameServer with an unapproved resolver | fires | 100212 | windows_eventchannel | pass |
| single trusted resolver | does not fire | – | – | pass |
| several trusted resolvers | does not fire | – | – | pass |
| trusted resolvers from different RFC1918 ranges | does not fire | – | – | pass |
| empty value (resolver cleared) | does not fire | – | – | pass |
| different registry value, not a resolver setting | does not fire | – | – | pass |

### The other four

| Rule | Case | Expected | Observed | |
|---|---|---|---|---|
| 100210 | Word spawning cmd.exe | fires | 100210 | pass |
| 100210 | Excel spawning PowerShell | fires | 100210 | pass |
| 100210 | Explorer → cmd.exe (parent not Office) | does not fire | 100211 | pass, see note |
| 100210 | Word → non-interpreter | does not fire | – | pass |
| 100211 | 7-Zip spawning PowerShell | fires | 100211 | pass |
| 100211 | Explorer launching mshta | fires | 100211 | pass |
| 100211 | child is not a LOLBin | does not fire | – | pass |
| 100211 | parent is not an archive tool or Explorer | does not fire | – | pass |
| 100211 | archive tool opening an ordinary app | does not fire | – | pass |
| 100220 | admin login from outside the allowlist | fires | 100220 | pass |
| 100220 | 11.0.0.5 (outside 10.0.0.0/8) | fires | 100220 | pass |
| 100220 | login from allowlisted 10.0.0.5 | does not fire | 64501 | pass |
| 100220 | auth-fail, not a success | does not fire | 64501 | pass |
| 100230 | high-risk and successful | fires | 100230 | pass |
| 100230 | KmsiInterrupt (50140) | does not fire | 100231 | pass |
| 100230 | successful, not high-risk | does not fire | 87802 | pass |
| 100230 | high-risk, failed password (50126) | does not fire | 87802 | pass |

Notes on the observations:

* **Explorer → cmd.exe fired 100211, not 100210.** Correct: Explorer launching
  `cmd.exe` is in scope for the archive/Explorer rule. The two process rules
  overlap on Explorer by design; expect 100211 for it in production.
* **64501 and 87802** are Wazuh's built-in generic rules for Palo Alto and Azure
  Graph events; seeing them on a negative case means the event decoded and our
  rule correctly did not match. 100231 is the shipped lower-confidence
  KmsiInterrupt rule, as intended.
* **Sysmon negatives show "–" (no alert).** The harness cannot separately prove
  that a non-alerting event was decoded. The positives in the same run use the
  identical event format and decoded as `windows_eventchannel`, which is the
  evidence that the path works.

## What the real engine found

These were found by running the real manager. Each is fixed, and each now fails
the offline test suite if re-introduced.

1. **PAN-OS description truncation.** Wazuh's Palo Alto decoder captures fields
   as `[^,]*`. PAN-OS quotes the auth-success description because it contains
   commas, so the decoded `description` stops at the first comma, before
   `From: <address>`. A rule on that field can never fire. Rule 100220 now
   matches the full log with `<regex>`.
2. **`wazuh-logtest` cannot test Windows rules.** Logtest always uses the generic
   decoder path and never calls the eventchannel decoder; a Sysmon event
   replayed there decodes as plain JSON and no Windows rule can fire. Any
   logtest "pass" for a Windows rule proves nothing, so the harness uses the
   agent queue.
3. **Doubled backslashes broke the DNS rule.** The eventchannel decoder
   JSON-prints the event XML before parsing it, so every backslash in a value
   arrives doubled (`HKLM\\System\\…`). Rule 100212 matched
   `\Services\Tcpip\…` with single separators and could never fire on a real
   manager. It now accepts `\\+`. (The same step means double-quoted XML
   attributes break the whole event, which is why Windows-rendered
   single-quoted XML is used.)

## Known false positives and limitations

* **100212:** VPN clients, DNS-filtering agents and admins setting public
  resolvers (8.8.8.8, 1.1.1.1) alert until allowlisted. It sees the resolver a
  device is given, including through DHCP (`DhcpNameServer`, tested above), so
  it covers a router that hands out an attacker's resolver, the technique
  reported for FrostArmada. It cannot see a router that keeps handing out its
  own private address and forwards queries to the attacker. IPv6 (`Tcpip6`) is
  not covered.
* **100210 / 100211:** legitimate macros and automation, and admins using
  Explorer to start `cmd.exe`, alert.
* **100220:** any admin login from outside the allowlist, legitimate or not; not
  evidence of CVE-2026-0322. Only octet-aligned allowlists can be expressed.
* **100230:** an investigation lead, not confirmation of AiTM; requires Entra ID
  P1/P2 for risk and the Graph integration.
* Synthetic events only, one Wazuh version, default configuration otherwise.

## Reproduce

In CI: Actions → **Wazuh integration** → Run workflow. On a disposable Linux
host or VM (Ubuntu 22.04) with internet access:

```bash
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update && sudo apt-get install -y wazuh-manager=4.14.9-1
git clone https://github.com/sohankanna/india-threat-tracker && cd india-threat-tracker
sudo cp detections/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo /var/ossec/bin/wazuh-control start
sudo python3 detections/tests/wazuh_logtest.py --out wazuh-logtest-results
```

Clean up by deleting the VM, or `sudo apt-get purge -y wazuh-manager && sudo rm -rf /var/ossec`.
Allow about 2 GB of RAM.

## Validation level per backend

| Backend | State | Evidence |
|---|---|---|
| Sigma | Behaviour tested by unit fixtures; conversion check passed | [`tests/sigma_eval.py`](../../tests/sigma_eval.py), `sigma check`, `sigma convert` in CI |
| **Wazuh** | **Executed in the real target engine** (4.14.9) | This report; re-run on every change to `detections/` |
| Splunk | Behaviour tested by unit fixtures, from the query text (DNS, PAN-OS); others structural check only | Not run in Splunk |
| Elastic | Same as Splunk (ES\|QL DNS and PAN-OS); EQL/KQL structural check only | Not run in Elasticsearch |
