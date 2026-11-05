# H07 - Service accounts with interactive or off-hours logons

PEAK type: **baseline (per-entity)** | ATT&CK: **T1078.002** Valid Accounts: Domain Accounts (with T1021.001 Remote Desktop Protocol) | Status: **closed - new detection created**

## Prepare

**Hypothesis.** An attacker has the password of a Northwind service account and is using it interactively, at the console or over RDP, probably outside business hours. Service accounts authenticate as a service (type 5) or over the network (type 3), so an interactive logon (type 2/10/11) is a never-before-seen behaviour for that account. A fleet-wide rule on "logons at 2am" would drown in scheduled jobs; a per-account baseline catches it.

**Why this hypothesis now.** An internal audit found service-account passwords written in an operations runbook (incident-driven hypothesis). 4624 is collected from all servers and DCs. Backlog priority 16.

**Data sources.** Security 4624 (successful logon): account, logon type, host, source address, time; 4672 (special privileges) for context.

**Assumptions.**
- Service accounts follow the `svc-*` naming convention. Accounts outside the convention are only covered by the per-account baseline, not by the graduated rule.
- 14 days is enough history to call a behaviour "never seen". Monthly or quarterly maintenance logons would need a longer baseline.
- Hours are UTC. Northwind operates in one time zone, so the off-hours window is 22:00-06:00.

**Scope.** 74 accounts with 4624 activity, 14 days.

## Execute

**Method.** `hunt/hunts/h07_logon.py`; production `query.kql` / `query.spl`.

1. Per account, build the logon-type distribution and the hour distribution of its non-interactive logons.
2. Keep accounts whose history is predominantly non-interactive and where interactive logons are <= 10% of the history. That is the definition of "novel for this account", and it removes ordinary users, whose interactive logons are their baseline.
3. Score each interactive logon: 0.7 for being novel, +0.25 if off-hours, +0.05 if the hour's robust (MAD) z-score against the account's own hours is >= 3.5.

**Execution notes.** 74 accounts profiled; 5 service accounts; 1 account met the novelty condition.

## Act with Knowledge

**Findings.** **svc-backup** (normally ~3 type-5 logons a day on SRV-0001) had a **type 10 (RemoteInteractive / RDP)** logon on SRV-0001 at **02:10 on 2026-09-13**, from 10.20.42.42, followed by a 4672 privileged-logon event. That is 1 interactive logon in 50 (2.0%). Score 99.8. See [`results.md`](results.md).

**False-positive review.**
- `achen`: one interactive logon at 23:40 on 2026-09-17 on her own workstation (WKS-0054). Interactive logons are 28% of her history, so off-hours work is unusual but not novel; she was confirmed as working to a deadline.
- `svc-scan`: 42 logons between 00:00 and 06:00 (the nightly vulnerability scan), all type 3. Off-hours is its baseline.
- `svc-legacy`, `svc-sql`, `svc-web`: type 5 only.

**Outcome.** True positive. The svc-backup password was rotated and the account was given a deny-interactive-logon right ("Deny log on locally" / "Deny log on through Remote Desktop Services") by GPO. The source address was traced back for the investigation. New backlog item **H10** (lateral movement from workstations) was opened from this finding.

**Detection decision: new detection created.** "svc-* account with logon type 2/10/11" has zero occurrences in the baseline, so it graduated as a single-event rule: [`H07-service-account-interactive-logon`](../../hunt/detections/rules/h07_svc_interactive_logon.yml) (1 alert on the hunt data, 0 on the benign-only baseline). The per-account hour and type baseline stays as a hunt for accounts outside the naming convention.
