# HNN - <short title>

PEAK type: **hypothesis-driven | baseline | model-assisted** | ATT&CK: **Txxxx.xxx** <name> | Status: **open | closed - <decision>**

<!--
Copy this file to hunts/HNN-<slug>/hypothesis.md. Fill PREPARE before you query anything.
Fill EXECUTE while hunting and ACT WITH KNOWLEDGE after review. Keep it factual: numbers, entities, times.
Also create: query.kql, query.spl, the Python hunt module in hunt/hunts/, and generate results.md with
`python -m hunt report`.
-->

## Prepare

**Hypothesis.** <One or two sentences: who is doing what, observable how. Specific enough to be wrong.>

**Why this hypothesis now.** <Source: threat intel / ATT&CK coverage / incident / red team / previous hunt. Backlog priority.>

**Data sources.** <Tables/indexes and the fields used. Say what is NOT collected.>

**Assumptions.**
- <Telemetry completeness assumption>
- <Behavioural assumption about the adversary>
- <Known benign look-alikes expected>

**Scope.** <Hosts / accounts / time range / volume.>

**What would disprove it.** <The result that means "not supported in this window".>

## Execute

**Method.** <Steps. Name the baseline and statistic: stacking, CV, MAD z-score, entropy, percentile.>

1. <Step>
2. <Step>
3. <Scoring and suppression - every suppression must reference an inventory entry>

**Execution notes.** <What happened: volumes, scope changes, surprises.>

## Act with Knowledge

**Findings.** <Top entity, score, the evidence that convinced you, times. Link results.md.>

**False-positive review.** <Each benign look-alike, its numbers, and why it is benign. Who confirmed it.>

**Outcome.** <True positive -> incident #; or no finding; containment and IOC actions taken.>

**Detection decision: <new detection created | baseline documented, no detection | data gap found>.**
<Why, using the graduation criteria in docs/methodology.md section 6. Rule id or gap/backlog id.>

**Lessons for the next iteration.** <Optional.>
