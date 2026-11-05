"""Northwind asset and software inventory (the hunter's context).

A hunt is only as good as the context used to dismiss benign look-alikes. In a
real SOC this comes from the CMDB, the software inventory, the proxy category
feed and the IAM system; here it is a small, explicit, reviewable table. Every
suppression a hunt applies points back to an entry here, so a false-positive
decision is auditable rather than buried in a query.
"""

from __future__ import annotations

INTERNAL_DOMAIN_SUFFIX = "northwind.example"
INTERNAL_PREFIXES = ("10.", "192.168.") + tuple(f"172.{i}." for i in range(16, 32))

# Sanctioned external destinations: domain -> (product / owner, why it beacons)
SOFTWARE_INVENTORY = {
    "updates.contoso-software.example": ("Contoso Updater 4.2 (all endpoints)", "hourly randomized check-in"),
    "time.ntp-pool.example": ("Windows Time service", "fixed 2048s NTP poll"),
    "telemetry.vendor-apm.example": ("Vendor APM agent (servers)", "fixed 15-min metrics push"),
    "ocsp.ca-provider.example": ("Certificate revocation (OCSP)", "on demand"),
    "sync.collab-suite.example": ("Collab Suite file sync (15 endpoints)", "event-driven sync"),
}

# CDNs whose random-looking subdomains are expected (registered domains)
KNOWN_CDNS = {
    "akamai-cdn.example": "CDN edge hostnames",
    "cloudfront-dist.example": "CDN distribution hostnames",
}

ADMIN_HOSTS = {"WKS-0003", "WKS-0011", "WKS-0027"}
SERVICE_ACCOUNT_PREFIX = "svc-"


def is_internal(domain: str = "", ip: str = "") -> bool:
    if domain and domain.endswith(INTERNAL_DOMAIN_SUFFIX):
        return True
    if ip and ip.startswith(INTERNAL_PREFIXES):
        return True
    return False


def sanctioned(domain: str):
    """Return the inventory entry for a sanctioned destination, or None."""
    return SOFTWARE_INVENTORY.get(domain)
