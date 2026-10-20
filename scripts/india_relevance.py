"""India-relevance heuristic for KEV entries.

"high" is meant to be a real filter, not a catch-all: the internet-facing edge,
VPN, identity and enterprise-server products that make up the attack surface
Indian orgs actually expose and that attackers actually hit. Ubiquitous desktop
and consumer software (Windows client, Chrome, Adobe, Android...) is real risk
but not an India-specific signal, so it lands in "medium". Everything else is
"global". It's a transparent heuristic over the vendor/product string, meant to
be overridden by hand where needed (set india_relevance + "_manual_relevance").
"""

# India-critical attack surface: edge / VPN / identity / enterprise-server, and
# vendors with a heavy India footprint. Matched as lowercase substrings of
# "<vendor> <product>".
HIGH = [
    # edge / VPN / firewall
    "fortinet", "fortios", "fortigate", "fortimail", "fortiweb", "forticlient",
    "pan-os", "globalprotect", "palo alto",
    "netscaler", "citrix",
    "ivanti", "pulse connect", "connect secure", "policy secure", "pulse secure",
    "sonicwall", "sonic wall",
    "f5 ", "big-ip",
    "sophos", "watchguard", "zyxel usg", "draytek vigor",
    # Cisco: network / security / edge products only (not every Cisco CVE)
    "cisco asa", "adaptive security", "firepower", "ios xe", "ios xr",
    "cisco secure", "cisco small business", "cisco rv", "cisco vpn", "cisco ise",
    "catalyst", "cisco nexus",
    # identity / mail / collaboration servers
    "zimbra", "synacor", "exchange server", "microsoft exchange",
    "sharepoint", "confluence", "atlassian", "bitbucket", "jira",
    # file transfer / enterprise apps heavily run in India
    "moveit", "progress", "manageengine", "zoho",
    "weblogic", "sap ", "netweaver",
    # virtualization
    "vmware", "vcenter", "esxi", "vrealize", "vmware aria",
    # web / app servers commonly exposed
    "struts", "apache tomcat", "jboss", "wildfly",
    # devops / CI commonly self-hosted
    "gitlab", "jenkins", "jetbrains teamcity",
]

# Ubiquitous but not India-specific.
MEDIUM = [
    "microsoft windows", "windows", "microsoft office", "office", "outlook",
    "internet explorer", "edge",
    "chrome", "chromium", "google", "android",
    "adobe", "acrobat", "reader",
    "apple", "macos", "ios", "safari", "webkit",
    "mozilla", "firefox",
    "oracle", "mysql", "java",
    "wordpress", "php", "drupal", "joomla",
    "apache http", "apache httpd", "openssl", "linux kernel", "samba",
    "qnap", "d-link", "dlink", "netgear", "tp-link", "mikrotik",
]


def relevance_detail(vendor: str, product: str):
    """Return (tier, matched_keyword). matched_keyword is None for "global"."""
    blob = f"{vendor} {product}".lower()
    for kw in HIGH:
        if kw in blob:
            return "high", kw.strip()
    for kw in MEDIUM:
        if kw in blob:
            return "medium", kw.strip()
    return "global", None


def relevance(vendor: str, product: str) -> str:
    return relevance_detail(vendor, product)[0]
