# Testing the detections

Every rule here ships with a reproducible test: one event that **should** match,
one that **should not**, the fields the rule needs, known false-positive
scenarios, and the expected outcome. Sample events live in
[`tests/`](tests/) as synthetic JSON — clearly labelled, **not** real telemetry.

**What these tests prove, and what they don't.** Parsing a rule, or converting
it to SPL, proves the *syntax* is valid — not that the logic catches the intended
behaviour. These fixtures prove the *logic* against known-good and known-bad
events. They do **not** produce production detection rates: for that you need
your own telemetry, in your own SIEM, measured against a real baseline. Nothing
here claims a true/false-positive rate.

Run the events through one SIEM and record what you observe. Use synthetic logs
or an isolated lab — never generate malicious activity in production.

---

## `office_document_spawns_script_interpreter`
- **Fields:** `ParentImage`, `Image` (Sysmon EID 1 / ECS `process.parent.name`, `process.name`)
- **Should match:** `WINWORD.EXE → cmd.exe` (Office app spawns an interpreter)
- **Should not match:** `explorer.exe → cmd.exe` (parent isn't Office); `WINWORD.EXE → spoolsv.exe` (child isn't an interpreter)
- **Known FPs:** enterprise macros / Office automation that legitimately launch scripts
- **Expected:** alert on the first, silence on the other two
- Fixtures: [`tests/office_document_spawns_script_interpreter.events.json`](tests/office_document_spawns_script_interpreter.events.json)

## `office_archive_lnk_spawns_lolbin`
- **Fields:** `ParentImage`, `Image` (EID 1 / ECS). `.lnk` in `CommandLine` is *investigation context*, not a match condition.
- **Should match:** `7zFM.exe → powershell.exe`
- **Should not match:** `7zFM.exe → notepad.exe` (child isn't a LOLBin); `services.exe → cmd.exe` (parent isn't an archive utility/Explorer)
- **Known FPs:** admin/scripted workflows that extract archives and run tooling
- **Scope:** proves the archive/Explorer → LOLBin parent-child only — **not** the full ZIP→LNK→payload chain (that needs correlation across events)
- Fixtures: [`tests/office_archive_lnk_spawns_lolbin.events.json`](tests/office_archive_lnk_spawns_lolbin.events.json)

## `windows_suspicious_dns_server_change`
- **Fields:** `TargetObject` (ends `NameServer`/`DhcpNameServer`), `Details` (new resolver value) — Sysmon EID 13 / ECS `registry.path`, `registry.data.strings`
- **Four required cases:**
  1. Trusted internal DNS `10.0.0.53` → **no alert**
  2. Approved public DNS (allowlisted) → **no alert**
  3. Unapproved public resolver `9.9.9.9` → **alert**
  4. Multiple resolvers `10.0.0.53,9.9.9.9` → **alert**
- **Known FPs:** legitimate public ISP/corporate resolvers you haven't allowlisted; VPN clients
- **Expected:** cases 3 and 4 alert; 1 and 2 don't. Trusted = RFC1918 by default, same policy in all four backends.
- Fixtures: [`tests/windows_suspicious_dns_server_change.events.json`](tests/windows_suspicious_dns_server_change.events.json)

## `pan_os_mgmt_auth_from_unexpected_source`
- **Fields:** `subtype=auth`, `event=auth-success`, `src_ip` (PAN-OS SYSTEM log)
- **Should match:** `auth-success` from `203.0.113.9` (outside the `10.0.0.0/8` allowlist)
- **Should not match:** `auth-success` from `10.0.0.5` (allowlisted jump box); `auth-fail` from anywhere
- **Known FPs:** admin access from a source not yet allowlisted; break-glass during an incident
- **Expected:** alert only on successful auth from a non-allowlisted source. A hit = unexpected management auth, **not** proof of CVE-2026-0322.
- Fixtures: [`tests/pan_os_mgmt_auth_from_unexpected_source.events.json`](tests/pan_os_mgmt_auth_from_unexpected_source.events.json)

## `entra_aitm_risky_signin_token_replay`
- **Fields:** `RiskLevelAggregated`, `ResultType` (Entra sign-in logs; needs P1/P2 for risk)
- **Should match (primary):** `RiskLevelAggregated=high` **and** `ResultType=0` (high-risk success)
- **Should not match (primary):** `ResultType=50140` (KmsiInterrupt — goes to the lower-confidence hunt, not the primary alert); `RiskLevelAggregated=low, ResultType=0` (not high-risk)
- **Known FPs:** high-risk flags from travel/new device — verify IP, UA, geo
- **Expected:** primary alert on the high-risk success only; the 50140 event surfaces separately as context. A hit is a **lead**, not AiTM confirmation.
- Fixtures: [`tests/entra_aitm_risky_signin_token_replay.events.json`](tests/entra_aitm_risky_signin_token_replay.events.json)

---

Each fixture's `should_match` / `should_not_match` arrays carry a `_why` / `_case`
on the negative and edge events so a reviewer can see the intended boundary
without running anything.
