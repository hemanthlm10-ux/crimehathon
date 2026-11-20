# CR-26-047 Final Technical Report: TrustLine (Defense)

## 1. Conclusion in one paragraph
Harbor & Finch's TallyBridge integration keys were used by an unauthorised party from **9 Aug to 6 Sep 2026** (UTC). The activity came in four waves across five systems. It ended with an unapproved bank-account change on **V-0412 Coastal Packaging Ltd** on 3 Sep, five days before the 8 Sep payment run. The most likely root cause is a compromise inside TallyBridge's build or credential environment. That is an inference: we have no vendor-side evidence. The intrusion was possible and went unseen for four weeks because of H&F's own control gaps: keys with no IP limit, no expiry and admin scope; secrets pasted into tickets; no alerting on exports; and audit findings left open since 2025.

## 2. Reconstructed timeline (all UTC; E02 converted from IST −5:30; E05 from raw epoch, a few minutes fast)
| When | What the records show | Evidence |
|---|---|---|
| 12 Jun 2024 | `key-tb-07` (LedgerOne read/write all-modules) and `tb-sync-svc` (HelpDeskr admin) issued with no IP restriction or expiry. Never reviewed since. | E04, E07 |
| Sep 2025 | Internal Audit: no expiry or IP limits on 5/8 keys, no export alerting, credentials in tickets. All findings open. CISO leaves. | E11 |
| 12 Jun 2026 | TallyBridge advertises for an engineer to "scan our build pipelines for stored secrets… reduce long-lived credentials". | E20-D |
| 25 Jun | Support asks a customer to paste config. Storage key `bvk-7f3a` (read: all folders) lands in TKT-48213. | E13, E02, E04 |
| 9 Jul 22:00–22:52 | Build host `tb-build-02` (10.20.4.77) contacts LedgerOne-*sandbox* over the private link, inside an announced maintenance window. **Ambiguous.** | E15, E20-B |
| 10 Jul | Sync 3.5.0 released; 3.4.x retired. All six sync hosts switch the same night. | E01, E20-C, E13 |
| **9 Aug 03:12–03:44** | `key-tb-07` from 198.18.7.41 (home broadband), client "3.4.1" (retired): `/me`, `/schema`, `limit=1/5` probes of vendors, payments, invoices and exports. | E01 req-c28d87e49d…req-b7f4b937ed |
| **11 Aug 17:42–19:03** | `tb-sync-svc` from 198.18.7.41: 16 ticket searches for password, api_key, token, private key, **bvk-**, vpn login. Then 10 export→download→delete cycles from .41/.58. The last delete times out. | E02 EXP-5410…5419 |
| 12 Aug 03:41–04:02 | Vendor master exported twice (9,840 / 9,835 rows), 7 payment searches. Export 9931 deleted, **export 9932 never deleted**. Staff see "a lot of export jobs" and dismiss them as the sync. | E01, E13 |
| **14 Aug 21:06 – 16 Aug 04:43** | `bvk-7f3a` from 198.18.7.23/.24/.77 (plus 2 rows with no IP) lists `/`, `/finance`, `/hr`. It reads vendor-bank-details-2026.xlsx ×13, payment-run-template.xlsx ×13 and statements Jan–May: 84.6 MB. Normally the key only reads `/customer-docs` from 172.16.9.40 between 04:00 and 11:00. | E05 |
| 15 Aug 16:20–16:24 | 198.18.7.77 fails 3 sign-ins to `a.kapoor` (IT Security Admin). MFA blocks it. | E03, E13 |
| 16 Aug 18:00–21:00 | TallyBridge "re-provisions" tb-build-02. | E20-B |
| **17–19 Aug 12:10–13:01** | tb-build-02 uses `key-tb-07` with a *current* "3.5.0" user agent, at midday (the sync runs ~01:30). It makes 45 payment searches, 9 bank-detail reads (3,121 rows), a **payments export of 4,210 rows deleted after 6 min**, and HelpDeskr searches for bank, iban, swift, payment instruction and vendor change. | E01, E02, E15 |
| 19 Aug | `tallybridge-support.example` registered (privacy-withheld, low-cost host). Possible impersonation infrastructure. **Unverified.** | E20-F |
| 21 Aug | Vendor "precaution" notice goes to the billing mailbox only. | E12, E13 |
| 24 Aug | HelpDeskr overage: 13 jobs by 24 Aug, 14 in August (4 weekly + 10 attacker). It is treated as an accrual line. | E06 |
| 28 Aug | Vendor declares the matter closed (see §4). | E16 |
| 1 Sep | Contact-detail sync starts: about 70 legitimate `write.contact` calls from the sync pool. | E16-7, E19 |
| **3 Sep 01:41–01:44** | tb-build-02, inside the sync window and among the contact writes: reads V-0412, its bank details and the scheduled payments, then **PATCHes the bank account ****4417→****9083** with no approval reference. | E18 req-5f61b0de8 = E19 chg-8b9888c39b |
| 6 Sep 01:36 | tb-build-02 checks scheduled payments again (15 rows). | E18 req-bb819dfe0c |

## 3. Assumptions
* **A1.** Host labels in E15 are as supplied by the vendor. We rely on the IP-to-label pairing being consistent, not on the labels being honest.
* **A2.** The BlueVault offset is minutes, not hours. Day and order of events are unaffected.
* **A3.** "Normal" is learned from the first 21 days (3–23 Jun). We assume the attack had not started then. E01 retention is 90 days, so anything earlier is invisible.
* **A4.** Records are complete except where the case says otherwise (E13 excludes DMs; E05 lacks some IPs).
* **A5.** Ground truth for scoring is our own analyst labelling (`tools/make_labels.py`), based on concrete indicators that the detector never sees.

## 4. The vendor's account (E16/E17) against the records
| Vendor claim | Records | Verdict |
|---|---|---|
| Activity on 11–12 Aug only | 9 Aug recon; 14–16, 17–19 Aug; 3 and 6 Sep | False |
| Ticket metadata only; no finance records or files | Vendor master ×2, payments, bank details, payments export, BlueVault finance files | False |
| All export files removed | Export 9932 never deleted; EXP-5419 delete failed | False |
| Entirely outside our network; private link not involved | 10.20.4.77 = tb-build-02 on tun-tb-01 | False |
| Credentials rotated 24 Aug | E04 (2 Sep): same keys from 2024, active; abused on 3 Sep | Not effective (H&F owns these keys: E08 5.3) |
| Indicator: python-requests/2.31.0 | Appears in no log. Attacker presented as TallyBridge-Sync 3.4.1, then 3.5.0 | Misleading |
| Status page: "no incidents" 1 Aug–2 Sep | Two incident notices were sent in that period | Inconsistent |

The vendor gains from a narrow account: under E08 14.3 it is not liable for losses from credentials *the customer failed to restrict*. Its notices went to billing only and asked not to be forwarded.

## 5. Alternative explanations ruled out
* **Legitimate sync or a new release.** Real sync uses six known hosts, 01:30–02:15 UTC, four endpoint types, and the newest client version. The suspect calls break 3–6 of those properties at once (retired version, public IP, build host, midday, export→delete, secret searches).
* **Insider in Finance or Support.** Every staff export is attributable. Farah's 22 Jul vendor export was announced in chat (E13) and run from her office PC. Sunita runs the Tuesday 09:10 exports from 172.16.8.12, and her 28 Jul delete was explained in chat. No staff account touched the attacker's IPs except the blocked attempt on a.kapoor.
* **Ordinary events set aside:** the 31 Jul bulk bank import (BULK-0731, month-end clean-up); Colin Lawson's multi-city sign-ins (contractor travel, E13); the sync start moving to 01:30 (E20-C); occasional 429 rate-limit responses; the 63 staff on 198.18.7.x home broadband; svc-reporting's failure loop (stuck internal script, E13 3 Jul).
* **Real but unrelated governance issues:** r.menon's password-only sign-in after leaving, which contradicts the audit's "MFA enforced, no exceptions"; 8 leavers still "active" in the roster; dormant keys `key-tb-03` and `key-app-12` still active.
* **Not resolved:** V-0233's 20 Aug bank change by f.dsouza with an out-of-sequence approval ref (APR-1182). It is flagged for verification, not accused. The 3 Sep dashboard slowness has no link we can find.

## 6. Why it was not caught
1. No control checks *how* a key is used: no IP restriction, no expiry, admin scope. This breaches policy E10 §2 and the 1 Jan 2026 transition deadline (§7).
2. No export or deletion alerting (E10 §4.1, E11 #6) and nobody reads the logs (case §5).
3. Each department saw one fragment: Support saw exports, Finance saw an invoice, Accounts got the notice, IT saw a failed login. No one joined them.
4. Vendor assurance was accepted as self-reported, and its SOC 2 carves out the credential vault (E07). The risk was rated LOW, although policy says HIGH, and it was never reviewed (E09 R-031).

## 7. Our solution and what it showed
TrustLine learns a behaviour contract per non-human identity, scores every event against it, and stitches violations across systems into incidents. It then emits a playbook: revoke and re-issue each key with its learned least-privilege contract, **hold the V-0412 payment and revert to ****4417**, find and purge exports 9932 and EXP-5419, and give Legal an exposure summary (first event 9 Aug 03:12 UTC; about 40.9k ledger records; 10 helpdesk exports; 7 finance files).

On the supplied data it finds all 241 labelled malicious events with 0 false alarms. The vendor IOC list finds 28%; a /24 block raises 291 false alarms. Enforcing the learned contracts (replay) would have blocked 177/177 malicious requests. Its only cost is the vendor's unannounced contact-sync capability, which should go through change approval anyway. Variation testing is in the Proof Pack.

## 8. Recommendations (in order)
1. **Before 8 Sep:** hold V-0412 and call back on the number on file before 3 Sep. Verify V-0233 against the approval register. Revoke `key-tb-07`, `tb-sync-svc`, `bvk-7f3a`, `key-tb-03` and `key-app-12`.
2. Re-issue keys with the generated IP allow-list, scope and 90-day expiry (E10 §2). Make bank-detail writes UI-only with dual approval.
3. Legal: treat 9 Aug as the earliest known exposure. Customer documents were *not* shown accessed by the attacker, but HelpDeskr tickets were exported. Request the per-job breakdown (E06) to identify which customers.
4. Demand a forensic report from TallyBridge on tb-build-02 and its credential storage. Re-rate the vendor HIGH and add a security contact for notices.
5. Close audit findings 2–7. Run TrustLine nightly (it runs in seconds on 109k events).
