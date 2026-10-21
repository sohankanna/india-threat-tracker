# Detection pack

Open, tunable detections for the threats tracked in this repo. The Sigma rules
are the canonical logic; the same five rules are also shipped pre-converted for
Splunk, Elastic and Wazuh so you can drop them straight into your SIEM.

| Folder | What | Format |
|--------|------|--------|
| [`sigma/`](sigma/) | Canonical endpoint / cloud / network detections | [Sigma](https://sigmahq.io) YAML |
| [`splunk/`](splunk/) | Same 5 rules as Splunk searches | SPL |
| [`elastic/`](elastic/) | Same 5 rules for Elastic (ECS) | EQL, KQL and ES\|QL |
| [`wazuh/`](wazuh/) | Same 5 rules as Wazuh local rules | `local_rules.xml` |
| [`fraud/`](fraud/) | Payments-fraud detection logic for the UPI / fake-APK kill chain | schema-agnostic YAML |

**→ [`DATA-SOURCES.md`](DATA-SOURCES.md)** is the first thing to read: what log
source and telemetry each rule needs to actually fire, and a benign validation
step for each. A rule you can't feed is a rule that silently never alerts.

**→ [`TESTING.md`](TESTING.md)** explains exactly what CI runs: every fixture is
executed against the Sigma rules and, by emulation from raw logs, the Wazuh
rules; a separate CI job replays the same raw logs through a real Wazuh 4.14.9
manager ([validation report](validation/wazuh-4.14.9-2026-10-20.md): 29/29). The Splunk and Elastic queries are emulated from their text where it
matters and checked for agreement with Sigma everywhere else; they are not run
against a live instance. No test claims a detection rate.

Every rule links back to the write-up on [sohankanna.com](https://www.sohankanna.com) that explains the threat it covers.

## Sigma rules

| Rule | Covers |
|------|--------|
| `pan_os_mgmt_auth_from_unexpected_source` | PAN-OS management auth from a non-jump-box source (CVE-2026-0322) |
| `entra_aitm_risky_signin_token_replay` | High-risk Entra ID sign-in / AiTM token theft (FrostArmada) |
| `windows_suspicious_dns_server_change` | Endpoint DNS pointed at an untrusted resolver (FrostArmada) |
| `office_archive_lnk_spawns_lolbin` | ZIP→LNK→LOLBin delivery (SideCopy / APT36) |
| `office_document_spawns_script_interpreter` | Malicious-macro execution (Crimson RAT / APT36) |

Convert to your SIEM with [`sigma`](https://github.com/SigmaHQ/sigma-cli):

```bash
sigma convert -t splunk detections/sigma/*.yml
sigma convert -t 'microsoft365defender' detections/sigma/entra_aitm_risky_signin_token_replay.yml
```

## Fraud signals

`fraud/upi-fraud-signals.yaml` expresses the detection logic for each step of the
UPI fraud kill chain as conditions over your own transaction / device / auth
telemetry. They are **templates to implement and tune**, not drop-in rules.

## Status & caveats

All rules are `status: experimental`. They contain **TUNE** markers (allowlists,
thresholds) you must set for your environment. Expect to tune false positives.
Defensive and research use only.
