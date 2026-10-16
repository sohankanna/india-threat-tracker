# Detection pack

Open, tunable detections for the threats tracked in this repo. Two parts:

| Folder | What | Format |
|--------|------|--------|
| [`sigma/`](sigma/) | Endpoint / cloud / network detections for the CVEs, APT TTPs and malware in the tracker | [Sigma](https://sigmahq.io) YAML |
| [`fraud/`](fraud/) | Payments-fraud detection logic for the UPI / fake-APK kill chain | schema-agnostic YAML |

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
