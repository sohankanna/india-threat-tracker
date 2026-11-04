## What this changes

<!-- One or two sentences. Link the issue if there is one: "Closes #12". -->

## Checklist

- [ ] Every new or changed claim has a public source that I have read
- [ ] Ran `python scripts/validate.py`
- [ ] Changed `smishing-apk.json`? Ran `python scripts/build_iocs.py`
- [ ] Changed any feed? Ran `python scripts/build_stix.py` (CI fails if the bundle is stale)
- [ ] Changed a detection? Updated the Splunk, Elastic and Wazuh versions and the fixtures
- [ ] Domains and URLs are defanged; no malware samples or live payload links
