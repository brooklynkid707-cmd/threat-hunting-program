# H02 - Document-launched process lineage (fleet stacking)

PEAK type: **baseline (stacking)** | ATT&CK: **T1204.002** User Execution: Malicious File (with T1059.003, T1218.011) | Status: **closed - new detection created**

## Prepare

**Hypothesis.** A user opened a weaponised document, and the Office application started a command shell that loaded a payload through a signed Windows proxy binary. Stacking every grandparent -> parent -> child process lineage across the fleet will show that chain in the long tail (on one host) while legitimate lineages sit in the head (on every host).

**Why this hypothesis now.** The Q2 phishing post-incident review found a macro that launched a loader through `cmd.exe`. The process-creation data was already collected but had never been baselined. Backlog priority 25 (highest this cycle).

**Data sources.** Process creation (Sysmon event 1 shape): host, user, image, parent, grandparent, command line, hash.

**Assumptions.**
- Process creation is collected on every host with parent and grandparent context. Where it is not, the lineage would be truncated.
- Legitimate software is deployed fleet-wide, so its lineages appear on many hosts. A one-off legitimate chain will still land in the tail and has to be reviewed.
- IT admins legitimately run rare tools (psexec, nmap, procmon, wireshark) on their own workstations.

**Scope.** 65 hosts, 14 days, all process-creation events (13.7k).

## Execute

**Method.** `hunt/hunts/h02_lineage.py`; production `query.kql` / `query.spl`.

1. Build the `gparent -> parent -> child` triple for every event (lower-cased image names).
2. Stack the triples: count events and **distinct hosts** per triple.
3. Rarity = 1.0 on one host, falling linearly to 0 at nine or more hosts.
4. Add shape weights: Office -> shell (+0.6), shell -> LOLBin (+0.4), image or arguments in a user-writable path (+0.5).
5. Down-weight known admin tools on admin hosts x0.15 (documented FP class).

**Execution notes.** 20 distinct lineages in total. The head (svchost, chrome, teams, Office launched from explorer/outlook) is on every workstation. The tail held 7 lineages on 1-3 hosts.

## Act with Knowledge

**Findings.** `excel.exe -> cmd.exe -> rundll32.exe` on **WKS-0042** (user rbaxter) scored **100**: one host, one event, `rundll32.exe C:\Users\rbaxter\AppData\Local\Temp\u3d9a.dll,Start`, at 2026-09-10 10:15. All four shape weights fired. The next two tail entries, `cmd.exe -> cmd.exe -> mshta.exe` and `-> regsvr32.exe` (43.3), are on the same host one minute later; they are the H04 LOLBin downloads. See [`results.md`](results.md).

**False-positive review.** psexec, nmap, procmon and wireshark appear only on the three IT admin workstations (WKS-0003/0011/0027), launched from explorer/cmd, never from an Office parent. They score 2-3 after the admin down-weight. Confirmed with IT that these are sanctioned tools.

**Outcome.** True positive: the initial-access execution on the beachhead. It ties H01 (the beacon starts 6 minutes later), H04 and H06 to the same host and user. The DLL hash and path went into the incident record.

**Detection decision: new detection created.** The Office -> shell -> signed proxy binary chain is fleet-rare, appears in the benign baseline zero times, and can be expressed as a single event with no allowlist. It graduated as [`H02-office-shell-lolbin`](../../hunt/detections/rules/h02_office_shell_lolbin.yml) (1 alert on the hunt data, 0 on the benign-only baseline). Fleet stacking stays a monthly hunt for lineages that do not match a known shape.
