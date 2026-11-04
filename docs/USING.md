# Using the tracker in your SOC

Recipes for getting the tracker's data and rules into the tools a security team
already runs. Everything is free to use (data CC-BY-4.0, code MIT). Each recipe
says how far it has been tested; "untested" means it follows the tool's
documented format but has not been run end to end.

Base URL for every raw file:

```
https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/
```

Versioned bundles (the rule pack and all data as zips, with SHA256SUMS) are on
the [releases page](https://github.com/sohankanna/india-threat-tracker/releases).
Pin a release if you need the data to stay still while you test.

## 1. A daily patch list (any SOC, 2 minutes)

India-relevant, actively exploited CVEs, newest first:

```bash
curl -s https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/watchlist.json \
  | jq -r '.items | sort_by(.date_added) | reverse | .[]
           | select(.india_relevance == "high")
           | [.date_added, .cve, .vendor, .product, (.epss // "n/a")] | @tsv'
```

Run it from cron and diff against yesterday's output to see what is new. The
[Exposure Matcher](https://www.sohankanna.com/tracker/exposure) checks an asset
inventory against the full list in your browser. *Tested.*

## 2. MISP: subscribe to the feed

**Sync Actions → Feeds → Add Feed**, source format **MISP Feed**, URL:

```
https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/misp-feed
```

Enable it and fetch. You get one event per fraud campaign with indicators and
one event with the high-relevance KEV CVEs. Details:
[misp-feed/README.md](../misp-feed/README.md).
*Tested: `interop-misp.yml` subscribes a real MISP instance to the feed and
checks every event and attribute arrives.*

Prefer STIX? Import `data/india-threat-tracker-stix.json` with **Events →
Import from → STIX 2.x**. *Tested in the same workflow; see
[STIX-GUIDE.md](../STIX-GUIDE.md) for what MISP keeps and drops.*

## 3. Wazuh: rules and an IOC list

Rules: copy `detections/wazuh/local_rules.xml` into
`/var/ossec/etc/rules/local_rules.xml` (or merge it), then restart the manager.
The rules use ids 100210-100240; renumber if your own local rules already use any of them. *Tested: CI replays every rule's fixtures
through a real Wazuh 4.14 manager.*

Domain indicators as a CDB list:

```bash
curl -s https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/iocs.csv \
  | awk -F, 'NR > 1 && $2 == "domains" { gsub(/\[\.\]/, ".", $1); print $1 ":" $3 }' \
  > /var/ossec/etc/lists/india-threat-tracker-domains
```

Add `<list>etc/lists/india-threat-tracker-domains</list>` to the `<ruleset>`
block of `ossec.conf`, and a rule that looks DNS queries up in it:

```xml
<rule id="100299" level="10">  <!-- pick a free id in your own ruleset -->
  <if_sid>61650</if_sid>
  <list field="win.eventdata.queryName" lookup="match_key">etc/lists/india-threat-tracker-domains</list>
  <description>DNS lookup of an India Threat Tracker campaign domain: $(win.eventdata.queryName)</description>
</rule>
```

*List format and rule untested end to end; the parent rule 61650 is Sysmon
Event 22.*

## 4. Splunk: rules and a lookup

Rules: the `.spl` files in `detections/splunk/` are ready-to-paste searches for
the Splunk Add-on for Sysmon field names. Or convert the Sigma rules with your
own pipeline: `sigma convert -t splunk -p splunk_windows detections/sigma/*.yml`.
*The conversion runs in CI; the searches themselves are untested on a live
Splunk.*

Indicators as a lookup (re-fanged):

```bash
curl -s https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/iocs.csv \
  | sed 's/\[\.\]/./g' > india_threat_tracker_iocs.csv
```

Upload it as a lookup table file, then:

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| lookup india_threat_tracker_iocs.csv indicator AS QueryName OUTPUT campaign, confidence, source_url
| where isnotnull(campaign)
```

## 5. Elastic

Rules: `detections/elastic/` has each rule as EQL, KQL or ES|QL for Elastic
Defend / ECS fields; paste them into a custom rule of that type. *Untested on a
live stack; they are written against the documented ECS fields.*

Indicators: load the re-fanged CSV from step 4 into an index (Kibana's file
upload works) and point an **indicator match** rule at it. *Untested.*

## 6. OpenCTI and other STIX consumers

Import `data/india-threat-tracker-stix.json` (STIX 2.1, validated with the
OASIS validator in CI). *OpenCTI is untested.* Object ids are stable across
updates, so re-importing updates objects rather than duplicating them.

<<<<<<< ours
## 7. Fraud and payments teams
=======
## 7. Brand-protection and fraud teams: lookalike domains

New lookalikes of Indian banks, payment apps and government sites, newest first:

```bash
curl -s https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/lookalike-domains.json \
  | jq -r '.items[] | select(.baseline == false and .active) | [.first_seen, .domain, .brand_name, (.first_cert // "-")] | @tsv'
```

Want your own brand watched? Add it to `config/lookalike-brands.json` in a pull
request. *The scan runs daily in GitHub Actions.*

## 8. Fraud and payments teams
>>>>>>> theirs

`detections/fraud/upi-fraud-signals.yaml` describes six risk-engine signals for
the fake-APK and UPI fraud chain (OTP read then instant transfer, new-device
binding, SIM swap, and so on). They are templates to implement against your own
transaction, device and authentication data, not drop-in rules.

## Before you deploy anything

* Every rule is `experimental`. Run in alert-only mode, check what fires, tune
  the `TUNE:` comments, then decide.
* The indicators are as reported by the cited source and not re-validated;
  last-seen dates are not tracked. Review before blocking.
* India relevance is a keyword heuristic. It tells you where to look first, not
  that you are exposed.

<<<<<<< ours
=======
* Lookalike-domain leads (`data/lookalike-domains.json`, and the lookalike
  event in the MISP feed) are leads, not confirmed phishing. They are never
  marked for blocking. Check who registered one before acting.

>>>>>>> theirs
Found a false positive, a broken recipe or a missing indicator? Open an issue;
the [issue forms](https://github.com/sohankanna/india-threat-tracker/issues/new/choose)
ask for what is needed.
