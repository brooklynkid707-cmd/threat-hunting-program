# H03 - Kerberoasting: RC4 service-ticket bursts

PEAK type: **hypothesis-driven** | ATT&CK: **T1558.003** Steal or Forge Kerberos Tickets: Kerberoasting | Status: **closed - new detection created**

## Prepare

**Hypothesis.** An attacker holding a domain user's credentials is requesting service tickets for many service accounts at once, with RC4 (etype 0x17) so the tickets can be cracked offline. If so, one account will show a burst of 4769 events for many *distinct* SPNs in minutes. Legitimate users request a few AES tickets a day for the services they actually use.

**Why this hypothesis now.** Kerberoasting is the most common credential-access step after initial access in ransomware-precursor intrusions (ATT&CK prevalence, sector reporting). DC security logs are fully collected. Backlog priority 20.

**Data sources.** Windows Security 4769 (TGS requested) from both domain controllers: account, service name, ticket encryption type, client address.

**Assumptions.**
- 4769 auditing is enabled on every DC (Audit Kerberos Service Ticket Operations: Success).
- The domain functional level supports AES, so RC4 is the exception. Known RC4-only applications are documented.
- A roasting tool requests tickets in a short burst; a slow roast spread over hours would need a longer window.

**Scope.** 2 DCs, 14 days, every account with 4769 activity (67 accounts).

## Execute

**Method.** `hunt/hunts/h03_kerberoast.py`; production `query.kql` / `query.spl`.

1. Filter 4769 to `TicketEncryptionType = 0x17`.
2. Per account, slide a 10-minute window over its RC4 requests and record the peak count of **distinct SPNs** in any window.
3. Score = distinct SPNs / 9, capped at 100. Fewer than 5 distinct SPNs is multiplied by 0.3 and never called malicious.

**Execution notes.** Only two accounts used RC4 at all during the 14 days.

## Act with Knowledge

**Findings.** **rbaxter** requested RC4 tickets for **9 distinct SPNs in 144 seconds** on 2026-09-11 at 11:10 (all nine RC4 requests the account ever made), from WKS-0042. Targets included both MSSQL service accounts, HTTP, CIFS, LDAP and TERMSRV principals. Score 100. See [`results.md`](results.md).

**False-positive review.** `svc-legacy` made 63 RC4 requests over 14 days, all for one SPN (`MSSQLSvc/srv01...:1433`): a legacy application that cannot negotiate AES. Its peak distinct-SPN count is 1, so it never approaches the threshold. A ticket was opened to migrate it to AES. 66 other accounts requested only AES tickets.

**Outcome.** True positive. The nine targeted service accounts were treated as compromised: password rotation forced to 30+ random characters, AES-only enforced where supported. rbaxter's session was revoked.

**Detection decision: new detection created.** "Distinct RC4 SPNs per account per 10 minutes >= 5" separates the roast (9) from every benign account (max 1) with no allowlist. It graduated as the Sigma correlation rule [`H03-kerberoasting-rc4-burst`](../../hunt/detections/rules/h03_kerberoasting_rc4.yml) (1 alert on rbaxter, 0 on the benign-only baseline). The existing Sentinel hunting query in the portfolio counts RC4 requests; this one counts distinct SPNs per window, which is what separates `svc-legacy` from a roast.
