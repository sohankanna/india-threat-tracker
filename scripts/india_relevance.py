"""Coarse India-relevance heuristic for KEV entries.

This is deliberately simple and transparent: it tags a CVE by the vendor/
product string, using a keyword list of technologies with a heavy footprint in
Indian enterprise, government and consumer environments. It is a *starting
filter*, not ground truth -- real exposure needs scan data (Shodan/Censys) and
sector context, which can be layered on later. Tags are meant to be overridable
by hand in the data file.
"""

# Products/vendors with notably heavy India deployment. Lowercase substrings.
HIGH = [
    "zoho", "manageengine",            # Zoho is Indian; ManageEngine is everywhere here
    "fortinet", "fortios", "fortigate",
    "palo alto", "pan-os", "globalprotect",
    "citrix", "netscaler",
    "ivanti", "pulse",
    "sonicwall",
    "cisco",
    "vmware",
    "microsoft", "windows", "exchange", "sharepoint", "outlook",
    "apache", "tomcat", "struts",
    "wordpress",
    "adobe",
    "google chrome", "chromium", "android",
    "atlassian", "confluence", "jira",
    "progress", "moveit",
    "zimbra",
    "oracle", "weblogic",
    "php",
]

# Broadly present but less India-specific -> "medium"
MEDIUM = [
    "linux", "openssl", "gitlab", "jenkins", "elastic", "mongodb",
    "f5", "big-ip", "juniper", "sophos", "qnap", "dlink", "d-link",
    "tp-link", "netgear", "mikrotik",
]


def relevance(vendor: str, product: str) -> str:
    blob = f"{vendor} {product}".lower()
    for kw in HIGH:
        if kw in blob:
            return "high"
    for kw in MEDIUM:
        if kw in blob:
            return "medium"
    return "global"
