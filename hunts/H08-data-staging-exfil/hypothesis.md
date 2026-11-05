# H08 - Archive staging followed by an external egress spike

PEAK type: **hypothesis-driven** | ATT&CK: **T1074.001** Data Staged: Local Data Staging, **T1560.001** Archive via Utility, **T1567.002** Exfiltration to Cloud Storage | Status: **closed - new detection created**

## Prepare

**Hypothesis.** Before encrypting anything, a double-extortion operator collects data into a compressed archive on a host they control and uploads it to cloud storage. If so, an archive creation (7z/zip/rar) will be followed within minutes by outbound bytes from the same host far above that host's normal egress, to an external destination. A nightly backup does the same thing every night, but its destination is internal.

**Why this hypothesis now.** Threat intel: double-extortion crews active against logistics firms exfiltrate to cloud storage with rclone before encryption. File-creation summaries and proxy bytes are both collected. Backlog priority 16.

**Data sources.** File-creation summary (`files`: host, user, path, size, extension) joined to outbound connections (`network`: bytes_out, destination, user agent).

**Assumptions.**
- Archive creation is logged, from EDR file events or Sysmon 11, filtered to archive extensions.
- Exfiltration happens within 30 minutes of staging. A patient actor who stages and waits a day would need a longer join window.
- The per-host 95th percentile of bytes_out per connection is a stable egress baseline over 14 days.
- Internal destinations (`*.northwind.example`, RFC 1918) are not exfiltration in this hunt. Insider moves to internal shares are out of scope.

**Scope.** 65 hosts, 14 days, 45 archive-creation events.

## Execute

**Method.** `hunt/hunts/h08_staging.py`; production `query.kql` / `query.spl`.

1. Per host, baseline = 95th percentile of bytes_out per connection over the period.
2. For each archive creation, sum the bytes_out of connections in the next 30 minutes that exceed the host baseline, split into external and internal destinations.
3. Require at least 50 MB moved (an absolute floor: browsing after zipping a report moves kilobytes).
4. Score on ratio above baseline, magnitude, external destination (+0.35) and staging path (PerfLogs, Windows\Temp, ProgramData, Public; +0.10). Egress only to internal destinations x0.2.

**Execution notes.** 45 archives: 30 user `report.zip` files, 14 nightly backups, 1 other.

## Act with Knowledge

**Findings.** **WKS-0042** (rbaxter): `C:\PerfLogs\archive.7z` (327 MB) created at **01:05 on 2026-09-16**. Four minutes later, 8 uploads totalling **266 MB** went to `eu-west.cloudbox-storage.example` (203.0.113.77) with user agent `rclone/v1.65`, between 01:09 and 01:12. That is ~197,000 times the host's p95 per-connection egress. Score 100. See [`results.md`](results.md).

**False-positive review.**
- Nightly backup on SRV-0001 (svc-backup): 14 archives of 0.9-1.4 GB in `D:\Backups`, each followed by ~0.5 GB of egress, more than the exfil and also off-hours. All of it went to `backup-target.northwind.example` (internal), so each scores 11.0. Volume and timing alone would have ranked the backup first every night.
- 30 user `report.zip` archives in Documents: no follow-on egress above the 50 MB floor.

**Outcome.** True positive: the exfiltration step. The file list was reconstructed from the host. Legal and privacy were engaged on the data-exposure question. The rclone user agent and the destination were blocked at the proxy. Seven of the eight hunts now converge on WKS-0042 / rbaxter.

**Detection decision: new detection created.** Archive creation in a staging-prone path never happens in the baseline; the backup writes to `D:\Backups`. It graduated as [`H08-archive-staging-path`](../../hunt/detections/rules/h08_archive_staging_path.yml) (1 alert on the hunt data, 0 on the benign-only baseline). The archive-to-egress correlation, which also catches staging in *normal* paths, stays a scheduled analytic (`query.kql`). Data gap logged: no file-share access auditing (5145), so the archive's source files had to be reconstructed from the endpoint rather than from logs.
