# Hunting methodology

How the Northwind hunt program decides what to hunt, how a hunt is run, and when a hunt becomes a detection. Every hunt in `hunts/` follows this document.

## 1. What a hunt is (and is not)

A detection rule answers a question we already know how to ask, automatically and forever. A hunt asks a question we do not yet know how to automate. It starts from an explicit, falsifiable hypothesis, uses a baseline to decide what "normal" looks like, ranks outliers instead of producing binary alerts, and ends in a decision: escalate, document, graduate, or log a gap.

A hunt that ends with "found nothing" is still a result, provided the baseline and the method are written down. The next analyst then knows what was checked, over which data, with which assumptions.

## 2. Where hypotheses come from

| Source | Example in this program | What it gives you |
|---|---|---|
| **Threat intelligence** | H01 (loader beacon sleep/jitter), H08 (rclone to cloud storage before encryption) | A specific procedure, often with parameters such as interval or tooling |
| **ATT&CK coverage review** | H03 (Kerberoasting), H06 (persistence never baselined) | Techniques common in the threat model with no detection or hunt yet |
| **Incidents and audits** | H02 (Q2 macro loader post-incident review), H07 (service-account passwords found in a runbook) | Known weaknesses in *this* environment |
| **Red team / pentest findings** | H05 (DNS egress unrestricted at the resolver) | Paths that are proven to work here |
| **Previous hunts** | H10 from H07, H11 from H05 | Follow-up questions and data gaps |

Hypotheses are prioritised in `program/backlog.yaml`:

```
priority = threat_intel_relevance (1-5) x data_availability (1-5) x (6 - effort) / 5
```

Data availability is a multiplier, not a footnote. A hunt with no data cannot be executed, so a high-relevance hypothesis without telemetry becomes a **data-gap request** (backlog H09, H11, H12) rather than a hunt.

## 3. The PEAK framework

This program uses **PEAK** (Prepare, Execute, Act with Knowledge), the hunting framework published by the SURGe team at Splunk. It has three hunt types:

- **Hypothesis-driven**: test a specific behavioural claim (H01, H03, H04, H05, H08).
- **Baseline**: characterise normal and read the outliers (H02 and H06 by fleet stacking, H07 by per-account baselines).
- **Model-assisted (M-ATH)**: an algorithm does the first pass. H01's statistical scoring sits between baseline and model-assisted.

Each phase maps to a section of `hypothesis.md`:

| Phase | Contents | Written when |
|---|---|---|
| **Prepare** | hypothesis, ATT&CK technique, data sources, assumptions, scope, and (for H01) why the obvious approach fails | **before** touching the data |
| **Execute** | method, statistics, scoring, execution notes | during the hunt |
| **Act with Knowledge** | findings, FP review, outcome, detection decision, gaps | after review |

### PEAK vs TaHiTI (briefly)

**TaHiTI** (Targeted Hunting integrating Threat Intelligence, from the Dutch financial sector) has three phases: *Initiate* (trigger -> abstract), *Hunt* (define/refine, execute) and *Finalize* (validate, document, hand over). It puts more weight on the intake and on threat-intel handover, and it explicitly feeds results back into TI, incident response and security monitoring.

PEAK puts more weight on the *type* of hunt (hypothesis / baseline / model-assisted) and on the "Act" outputs: detections, documentation, data-gap tickets. The two are compatible. This program uses PEAK's structure with TaHiTI's habit of recording the trigger (the "hypothesis source" column in the backlog) and handing every outcome to a named consumer (IR, detection engineering, the TI platform, the logging team).

## 4. Baselining

A baseline is what makes "rare" or "unusual" a number instead of an opinion. Four kinds are used here, all implemented in `hunt/stats.py` with the standard library only:

| Baseline | Used in | Statistic |
|---|---|---|
| **Fleet stacking** (frequency of occurrence across hosts) | H02 lineages, H06 services/tasks | `stack_counts`, `long_tail`, `fleet_rarity` (distinct hosts per value) |
| **Per-entity behaviour** | H07 logon types and hours per account | type distribution, robust z-score of hour (`mad_zscore`) |
| **Per-host volume** | H04 LOLBin runs per host, H08 egress | run counts; `percentile(bytes_out, 95)` |
| **Distribution shape** | H01 inter-arrival times, H05 subdomain labels | `coefficient_of_variation`, robust CV (MAD / median), `shannon_entropy` |

Notes on the statistics:

- **Coefficient of variation (CV = stdev / mean)** measures regularity independent of scale. A 300 s beacon and a 2,048 s NTP poll can both have CV near 0.
- **Robust statistics (median, MAD)** are preferred to mean/stdev because the thing being hunted is an outlier, and outliers distort means. One long overnight gap gave the NTP client a classic CV of 2.1 while its robust CV was 0.02. The MAD z-score uses the 0.6745 consistency constant so its thresholds read like ordinary z-scores (|z| >= 3.5 is the usual cut-off).
- **Shannon entropy** (bits/char) quantifies how random a string looks. English-like labels are ~2-3.5 bits/char; base32/base36-encoded payloads are 4+.
- **Percentile baselines** (p95) are used instead of mean + k x stdev for byte volumes, which are heavy-tailed.
- **Absolute floors** go alongside relative ones. H08 requires 50 MB *and* a ratio above baseline, because a host with a tiny baseline can show a huge ratio on a trivial transfer.

## 5. Avoiding confirmation bias

A hunter who expects to find something will find something. The program uses these controls:

1. **Write Prepare before Execute.** Hypothesis, assumptions and scope are fixed before the data is queried. Changing the scope mid-hunt is allowed, but it is recorded in the execution notes.
2. **State what would disprove the hypothesis.** For H01: "if every regular (host, domain) pair maps to inventoried software, the hypothesis is not supported for this window."
3. **Rank, don't filter.** Every hunt outputs a ranked list including benign look-alikes, with scores and reasons, instead of a filtered "hits" list. The analyst reviews the top N and sees what was close.
4. **Every suppression is explicit and attributable.** Allowlists live in `hunt/inventory.py` with an owner and a reason. A suppressed entity stays visible in the output (H01 shows NTP at 4.8 "sanctioned -> suppressed"). It is not dropped.
5. **Review the look-alikes on purpose.** Each `results.md` has a false-positive review section generated from the data. It shows why the update agent, backup job, admin tools and CDNs scored the way they did, so a reviewer can disagree with a number.
6. **Contrast with the naive method.** Where a simpler approach exists, run it and report how it would have done. H01 reports that ranking by connection count put the implant at #15 of 559.
7. **Score against ground truth when you can.** In this lab, `python -m hunt score` checks rank and precision against planted activity. In production the equivalent is purple-team replay: re-run the hunt after an emulated procedure and confirm it ranks first.
8. **Peer review before closing.** A second analyst reads Prepare and the FP review before the decision is final.

## 6. When a hunt becomes a detection

A hunt **graduates** when its signal can run unattended without flooding the queue. The criteria used here:

| Criterion | Question | Example |
|---|---|---|
| **Expressible** | Can the logic run as a rule (single event, or a simple correlation/threshold) in our SIEM? | H03 is a value-count correlation; H01's interval statistics over 14 days are not |
| **Low or zero baseline** | How often does the condition occur in known-benign data? | H06: zero services with user-writable paths in 14 days |
| **No fragile allowlist** | Does precision depend on an inventory that will drift? | H01 depends on the sanctioned-beacon list, so it stays a hunt |
| **Proven** | Does the rule fire on the activity and stay silent on a benign-only replay? | `metrics.detection_proof` runs every rule over the benign-only dataset |
| **Actionable** | Will a Tier 1/2 analyst know what to do with the alert? | Each Sigma rule has a description and false-positive notes |

The outcomes, as recorded in each `results.md`:

- **new detection created**: Sigma rule in `hunt/detections/rules/`, proven by the evaluator, handed to detection engineering for SIEM conversion.
- **baseline documented, no detection**: the hunt stays scheduled (weekly or monthly) with its baseline and look-alike profiles written down. IOCs from any finding go to the blocklist.
- **data gap found**: the hunt cannot answer its question with current telemetry. A logging request is opened and a backlog item is created as blocked.

A detection that generates noise is demoted back to a hunt. The loop runs in both directions.

## 7. Program metrics

Reported in `program/program_report.md`:

- **Hunts executed / true positives / detections created / data gaps.**
- **Hunt-to-detection conversion rate** = detections created / hunts executed. 100% would suggest the program is only hunting for things that were easy to automate; 0% would suggest the hunts are not producing durable value.
- **Dwell vs time-to-find.** Dwell is how long planted activity sat in the window before the dataset ended. Time-to-find is how soon a daily run of the hunt would have ranked it #1 (replayed with `Dataset.until()`). The gap between them is the argument for running a hunt on a cadence, or for graduating it.
- **Rank of first true positive** per hunt. A hunt that finds the activity at rank 40 is not useful at Tier 2 volumes even if recall is 1.0.
