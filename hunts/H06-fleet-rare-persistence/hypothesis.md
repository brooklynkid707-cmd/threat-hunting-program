# H06 - Fleet-rare services and scheduled tasks

PEAK type: **baseline (stacking)** | ATT&CK: **T1543.003** Create or Modify System Process: Windows Service (also T1053.005 Scheduled Task, T1036.004 Masquerade Task or Service) | Status: **closed - new detection created**

## Prepare

**Hypothesis.** An intruder has installed a service or scheduled task for persistence on the first host they compromised. Management tooling deploys legitimate services to many hosts at once, from Program Files or System32. Attacker persistence starts on one host, usually runs from a user-writable path, and often has a name that imitates a Windows component. Stacking service and task names across the fleet will put it in the tail.

**Why this hypothesis now.** Persistence had never been baselined here (ATT&CK coverage review). Event 7045 and 4698 are collected from all hosts. Backlog priority 16.

**Data sources.** System 7045 (service installed) and Security 4698 (scheduled task created): host, name, image path, hash, account, time.

**Assumptions.**
- 7045/4698 collection is complete. Persistence installed before collection started would show up as "fleet baseline", not as new.
- Software deployment uses managed paths. A badly packaged app that installs into a profile is a known FP risk.
- Service *modification* (sc config) is not in this dataset and is out of scope.

**Scope.** 65 hosts, 14 days, 7 distinct service/task names (265 creation events).

## Execute

**Method.** `hunt/hunts/h06_persistence.py`; production `query.kql` / `query.spl`.

1. Stack by name: distinct hosts, first-seen time, image path, hash, account.
2. Drop anything on more than 3 hosts (managed deployment).
3. Score = rarity x (0.3 + 0.45 user-writable path + 0.15 system-imitating name + 0.10 late first-seen relative to the fleet baseline). Managed install paths x0.4.

**Execution notes.** Four names are present on all 65 hosts. Three are in the tail.

## Act with Knowledge

**Findings.** `WinSyncHelper` scored **96.7**: one host (**WKS-0042**), image `C:\Users\rbaxter\AppData\Local\Temp\wsh.exe`, LocalSystem, first seen 2026-09-10 10:20, 3.3 days after the fleet baseline and five minutes after the H02 execution chain. See [`results.md`](results.md).

**False-positive review.**
- `FinanceLedger Sync` (score 18.9): also on exactly one host (SRV-0002), but `C:\Program Files\FinLedger\sync.exe`, runs as `svc-sql`, first seen on day 1. Confirmed with the finance applications team as the ledger integration.
- `\NW-IT\InventoryScan` (4.1): three admin workstations, Program Files, IT-owned.

Rarity alone would have ranked FinanceLedger level with the implant. The path and first-seen context separate them.

**Outcome.** True positive. The service was removed after evidence capture and the binary hash was added to EDR block. Because the implant first ran as rbaxter from Temp, rbaxter's sessions were revoked.

**Detection decision: new detection created.** No legitimate service in 14 days used a user-writable image path. That makes "7045 with image in AppData / Temp / PerfLogs / Public / Downloads" a zero-baseline, single-event condition. It graduated as [`H06-service-user-writable-path`](../../hunt/detections/rules/h06_service_user_path.yml) (1 alert on the hunt data, 0 on the benign-only baseline). Fleet stacking stays a monthly hunt for rare services in *managed* paths (the rule cannot see those). Data gap logged: 7045 carries no signer/publisher, so publisher checks are manual.
