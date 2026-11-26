```
  BIP: ?
  Layer: Applications
  Title: Payment Allowances
  Authors: John Carvalho <bitcoinerrorlog@gmail.com>
           dzdidi
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause OR CC0-1.0
  Requires: ? (Payment Endpoint Discovery), ? (Payment Requests, Private Lists and Receipts)
```

## Abstract

An Allowance is a bounded, revocable permission that a payer grants a payee. Under it, one application of the payer, the executor, may pay the payee's qualifying Payment Requests without asking its user each time. This document specifies the Allowance messages, their terms and period arithmetic, the terms hash, conflicts, the executor's signed grant, the ledger by which the payer's applications count usage, how a request is matched to an Allowance, and when automatic payment pauses. The payer keeps custody, and every payment is made by the payer's own application. This is the third of three documents.

## Copyright

This document and its auxiliary files are licensed under the BSD-2-Clause license or, at the reader's option, CC0-1.0.

## Motivation

A recurring request accepted under the Payment Requests, Private Lists and Receipts document still needs the payer's approval for each payment unless a wallet decides on its own. Wallets that decide on their own without a shared definition of the limits leave the payee unable to know what will be paid, and the payer's other applications unable to know what has been spent. An Allowance states the limits once, is accepted explicitly, and can be ended by either party. It is stated in one asset, authorizes only payments that one named application of the payer makes, and records each payment in a ledger that every application of the payer can check.

## Specification

The conventions of the Payment Endpoint Discovery document and the message, activity record and payment rules of the Payment Requests, Private Lists and Receipts document apply. Transport, admission, sealing, claims, shared records, the chain and transition proofs are the identity service's (Payment Endpoint Discovery, "The identity service"; Dispatch spec 5 to 13), and claims and the paying order are those of Paykit spec Section 7. This document specifies what an implementation needs to check Allowance values and count usage; Paykit spec Section 8.3 holds the operational detail.

The *Allower* is the identity that pays, the *Allowee* the identity that is paid, and the *executor* the one application of the Allower that the Allowance record names, by its own signed grant, to pay automatically. An Allowance is identified by its two identities and its `allowance_id`, a lower-case UUID version 4 (Paykit wire 1.3), which grants nothing to its holder.

`paykit_allowance` lets an application receive Allowance messages, send `allowance_end` and `executor_notice`, send proposals, acceptances and rejections when it also holds `paykit_contacts`, read and write `allowance_proposals` and `allowances`, and read `allowance_ledgers` and claims. `paykit_allowance_execute` lets it act as executor and write the ledger; it requires `paykit_allowance`, `paykit_pay` and `paykit_contacts` (Paykit spec 3.1). No proposal, acceptance or rejection is sent to a counterparty the sender's deny list holds, or while its copy of the deny list is unknown; the user's `allowance_end` is never held for the deny list.

### Messages

All five kinds use the identity service's common message fields (`v`, `kind`, `msg_id`, `created_at`, `from`, `to`, `refs`, `body`; Dispatch wire 5.1). A message hash is `hash(message JSON bytes)`, `hash` being BLAKE3 with a 32-byte output (Dispatch wire 1.5). Readers ignore unknown members.

| Kind | `refs` | Body | Sent by |
| --- | --- | --- | --- |
| `paykit.allowance_proposal` | none | `allowance_id`, `proposer_role`, `allower_generation`, `terms` | either party |
| `paykit.allowance_acceptance` | proposal hash | `allowance_id`; optional `executor_app_id` | the proposal's recipient |
| `paykit.allowance_rejection` | proposal hash | `allowance_id` | the proposal's recipient |
| `paykit.allowance_end` | proposal hash, then acceptance hash | `allowance_id` | either party |
| `paykit.executor_notice` | none | `reason`, `allowance_record` | an own application, to the executor |

`proposer_role` is `allower` or `allowee`, the sender's role. `allower_generation` is an integer from 1 to 2^53 - 1, the generation read from the Allower's verified `identity.json`. `executor_app_id` appears only in an acceptance from the Allower; it names the executor at acceptance and is informational, and a rejection or end carrying it is dropped. An end with only the proposal hash is a withdrawal of a proposal not yet accepted, and only the proposal's sender sends it. An `executor_notice` goes only between applications of one identity, through its own inbox; `reason` is `ended` or `handed_off`, and `allowance_record` is the 32-byte key of the Allowance record. Its only effect is on the executor's consent list.

A proposal body (Paykit wire 4.15):

```json
{
  "allowance_id": "d0efffb7-191b-4709-b6c7-e343af5500b4",
  "proposer_role": "allowee",
  "allower_generation": 7,
  "terms": {
    "active_from": "2026-01-01T00:00:00.000Z",
    "allowed_payment_endpoint_identifiers": ["btc-lightning-bolt11"],
    "asset": "btc",
    "expires_at": null,
    "lifetime_amount_limit": "0.10",
    "per_payment_amount": { "maximum": "0.01", "minimum": "0.0001" },
    "period_limits": [
      { "amount_limit": "0.03", "payment_count_limit": 5,
        "period": { "anchor": "2026-01-31T00:00:00.000Z", "every": 1, "kind": "anchored", "unit": "month" } }
    ]
  }
}
```

### Terms

Every member of `terms` is required.

| Member | Rule |
| --- | --- |
| `asset` | non-empty, no control characters; compared exactly |
| `per_payment_amount` | `null`, or `{"minimum":a,"maximum":a}` with `minimum` not above `maximum` |
| `period_limits` | array of zero or more distinct period limits |
| `lifetime_amount_limit` | `null` or an amount |
| `active_from` | `null` or the first eligible time |
| `expires_at` | `null` or the first ineligible time, later than `active_from` |
| `allowed_payment_endpoint_identifiers` | `null`, or a non-empty array of distinct Payment Endpoint Identifiers (Payment Endpoint Discovery document): the only ones the executor may pay to |

Amounts are decimal strings in whole units of the asset (`0.00025` `btc`), at most 18 fraction digits, compared and added exactly as integers scaled by 10^18; an overflow fails closed (Paykit wire 1.2). Times follow Dispatch wire 1.6.

A *period limit* is `{"amount_limit":a,"payment_count_limit":c,"period":p}`. Both members MUST be present, each possibly `null`, not both `null`. Period limits are duplicates only when every member is equal as spelled: `amount_limit` and `anchor` compare as strings, so `1` and `1.0` are distinct; integers compare as integers.

The terms MUST set a monetary ceiling (`per_payment_amount`, an `amount_limit` or `lifetime_amount_limit`) or `expires_at`. Limits are inclusive and apply together: a candidate of value `x` fits a period limit if the period's counted amount plus `x` is at most `amount_limit` and its counted payments plus one at most `payment_count_limit`, and fits the lifetime limit if the lifetime amount plus `x` is at most `lifetime_amount_limit`. Zero is a valid limit.

Applications check the whole table when a proposal arrives, dropping one that fails; when they verify an Allowance record, which such terms make invalid; and before each automatic payment. A time that does not parse is never read as no limit. A later version that adds a restriction must change `v` or the kind, since readers ignore unknown members. Terms do not change; changed terms need a new `allowance_id`.

### Periods

A period is `{"kind":"anchored","every":n,"unit":u,"anchor":t}` with `u` one of `minute`, `hour`, `day`, `week`, `month`, `year`, or `{"kind":"rolling","every":n,"unit":u}` with `u` one of `minute`, `hour`, `day`, `week`; `n` is at least 1.

For an anchored period in minutes to weeks, let `L` be `n` times 60, 3600, 86400 or 604800 seconds; period `k` is `[anchor + kL, anchor + (k+1)L)` for every integer `k`, negative ones included. For months and years, boundary `k` is the date `k·n` months or years after the original anchor, at its time of day, falling on the month's last day when the anchor's day does not exist. Every boundary is computed from the original anchor. A rolling period has length `L`. A period whose length or boundary cannot be represented makes every evaluation that needs it ineligible, never the terms invalid.

### Terms hash

The terms hash is `hash(lp(proposal message JSON bytes, acceptance message JSON bytes))` over the exact signed messages (Paykit wire 1.5; `lp` is Dispatch wire 1.4). It includes the proposal's `allower_generation`.

### Lifecycle

A pending proposal is an ordinary record in `allowance_proposals`; an accepted Allowance is a permanent record in `allowances`. Both are keyed by the counterparty and the `allowance_id` and kept by each party at its own identity service. Paykit wire 5.4 gives their formats and binding checks, and Paykit spec 8.3.1 the ordering, delivery and restore rules summarized here.

* **Proposing.** An application records its signed proposal at the pending key, only where the permanent key is absent, verifies that the write applied, and sends it. The recipient records it in its own pending collection. Proposals have no expiry. An application that sees eight or more live pending proposals in one direction with one counterparty creates no new one in that direction.
* **Rejecting and withdrawing.** Each deletes the exact pending version on the sender's account, then sends the original message. They close the pending lifetime and create no permanent record.
* **Accepting.** Only the recipient of the proposal P signs the acceptance Q. On the Allower's side, P's `allower_generation` MUST be at most the current generation and strictly greater than any verified `recovery_from`. Each party applies one atomic batch at its own identity service that creates the permanent record holding P and Q and deletes the exact pending P: the answering party before it sends Q, the proposer when Q arrives. On the Allower's side, the batch also creates the permanent ledger with exactly these bytes (Paykit wire 5.9):

  ```json
  {"v":1,"counterparty":"<allowee pubky>","allowance_id":"<same UUID>","acceptance":"<hash of Q>"}
  ```

  The approving Allower application is the one that signed P or Q. Its user approves the counterparty, the terms and that application's role as executor in one decision; a message signed by the other party conveys no consent.
* **Ending.** An application with `paykit_allowance` stores its `allowance_end` in the record's `end`, then sends it. A withdrawal that crosses an acceptance is answered by an end naming both messages. The service refuses deletion of a permanent Allowance or ledger record.
* **Conflicts.** One `allowance_id` has one proposal and one response. A second proposal, from either side, with another hash than the proposal held, or a second acceptance or rejection from the proposal's recipient with another hash than the response held, makes the Allowance conflicted, whichever came first. A copy with the same hash is the message itself. A conflicted Allowance is never cleared by any message, grant or confirmation; it has no current grant, nothing is paid under it, and no acceptance, rejection, end or grant is sent or written for it. An application that verifies a conflicting message keeps it durably before anything else, then writes it into the record's `conflicted` member. A second, different end changes nothing.

| Messages | State | Automatic payment |
| --- | --- | --- |
| proposal | pending | no |
| proposal, acceptance | accepted | under the rules below |
| proposal, rejection or withdrawal | closed | no |
| proposal, acceptance, end | ended | no |
| a conflicting second proposal or response | conflicted | never |

### Executor

**Executor grant** (Paykit wire 3.3):

| Member | Rule |
| --- | --- |
| `app_id` | the executor application |
| `terms_hash` | the terms hash of the record's proposal and acceptance |
| `confirmed_generation` | the generation in which the executor's user last confirmed the Allowance |
| `cert` | the executor's certificate, holding `paykit_allowance_execute` |
| `sig` | Ed25519 (Dispatch wire 2.1) by the executor's signing key over `lp("paykit/v1/executor-grant", identity, counterparty identity, allowance_id text, terms hash, u64(confirmed_generation), u64(generation), u64(seq))` |

`generation` and `seq` are the Allowance record version the grant's write builds on, (0, 0) for a new record. The record's `grants` array keeps every grant it has held, oldest first, each as `{"generation","version","grant"}` naming that version: the signed `seq` is the entry's `version`, and `grant` is the last entry's grant; writers only append. A grant counts only if its certificate verifies for the own identity, names `app_id` and holds `paykit_allowance_execute`, its signature verifies at its entry's version, its `terms_hash` matches, the history's versions strictly increase, and the record holds no `conflicted`. A grant moved within the history no longer verifies.

**Setting up.** The approving application checks the accepted terms against P and Q in the record, writes its grant, and then adds the Allowance to its *consent list* in its own durable state. In the first release only that application can take the first grant; another application leaves execution held, and changing the executor (handoff) is reserved for a later release.

**Stops.** An application that ends an Allowance, or records a counterparty's end, sends `executor_notice` to the executor. An application that verifies a counterparty's `allowance_end` MUST keep it durably before it does anything else with it, and from then on MUST make no new attempt under that Allowance, whatever the record shows. The executor removes an Allowance from its consent list for good once it sees it ended, rejected, handed off or conflicted.

**Conditions.** Besides the checks of Paykit spec 8.3, Executor, the executor pays automatically only while the record holds its own current grant and no end, rejection or conflict; its consent list holds the Allowance; the request matches (below); the deny list, read again before dispatch, does not hold the counterparty; the occurrence is not marked `manual_only`; no restore, `missed` item or provider loss holds the Allowance; its ledger anchor is established; and the obligation is not doubtful (Paykit spec 7.1). The executor enforces the limits; Paykit coordinates the reservation and never enforces limits at the protocol level.

### Ledger

The ledger record holds `v`, `counterparty` (the Allowee), `allowance_id`, `acceptance` (the hash of Q, kept by every later version), `entries` and `totals` (Paykit wire 5.5). It is read under `paykit_allowance` and written under `paykit_allowance_execute`. An entry holds `obligation` (the claim key of the request or, for a Billing Period, of that period), `attempt_id`, `value`, `asset`, `at` and, once known, `outcome` (`done` or `failed`). `value` is the amount the payment transfers in the requested asset, never less than the requested amount; fees are not counted. `totals` is `{"spent","count","failed"}`: the amount and count of compacted `done` entries, and compacted failed entries as `{"obligation","attempt_id","value"}`. `entries` and `totals` may be absent, as empty. `obligation` is `b64(32)`, `attempt_id` `b64(16)`, `value` and `spent` amounts (`spent` may be `""` for none), `count` an integer, and `failed` absent when empty. A ledger with a member of another form, an entry of another asset than the terms, an `attempt_id` repeated among entries and `totals.failed`, or a value or time that does not parse is invalid and is never read as smaller.

**Executor batch.** Each automatic payment is one atomic batch (Dispatch spec 10.1): the `attempt` on the request's claim, with the request's deadline and the request record version read; the ledger with the new entry; the activity record showing the payment in progress; and the request record and `payment_lists` writes of Paykit spec 7.2 and 8.2. These activity and `payment_lists` writes are subject to the hold on potentially protected records (Payment Requests, Private Lists and Receipts, "Protected records"). It carries `record_version(Allowance record) == r` and `server_time_in(at, end)`, where `at` is the server time of the service's latest response and `end` is `at + 60 s` cut at the next boundary of any anchored limit. The service thereby vouches for each entry's time, and each entry lies in one period of every anchored limit. If a condition fails, nothing is written. If another application already attempts the request, no entry is added.

**Counting.** Usage is computed at the current server time `t`. An anchored limit counts entries whose `at` lies in the period containing `t`. A rolling limit of length `L` counts an entry while `t < at + 60 s + L`, with no lower bound. The lifetime amount counts every entry and `totals.spent`. Each entry counts by its attempt's outcome, from the entry or its claim (Dispatch spec 10.2):

| Attempt | Counts as |
| --- | --- |
| `open`, or `unknown` until reported | reserved |
| `done` in the entry or claim, or a proof of this attempt naming this Allowance in the payer's record | spent |
| `failed`, whoever wrote it | spent, unless the executor's durable journal proves the attempt ended before the payment method's call and can never dispatch |
| no outcome, claim gone or not holding the attempt | spent |

Reserved and spent entries count against every limit. A `done` or matching paid proof always spends, even beside never-dispatched evidence; a call already made, an ambiguous result, a user's confirmation alone and a restored journal release nothing. A `totals.failed` item counts by the same rule in the lifetime amount only, until a later `done` moves it into `spent` and `count`, once. A retry is a new attempt with its own entry. Candidates are refused in this order: the per-payment range, each period limit in order, amount before count, then the lifetime limit.

**Outcomes and compaction.** The current executor writes each outcome into its entry as it learns it: `done` from a claim or a matching proof, `failed` only when the attempt's owner wrote it or the user released it with never-dispatched evidence, and `done` over `failed` when a claim later shows it. Near the 256 KiB record limit it drops entries whose own outcome is final and whose `at + longest period + 60 s` precedes its latest verified service time, the longest period of an anchored limit being the length of its period containing that time. A dropped `done` entry adds its value and one count to `totals`; a dropped `failed` one moves to `totals.failed`, and the ledger keeps it at least as long as the service keeps its claim, 30 days after the deadline, so a late receipt is seen. A ledger that cannot take a new entry even after compaction pays nothing automatically.

**Successor versions.** A reader holding a ledger version accepts a newer one only if it counts no less: every held entry keeps its `obligation`, `attempt_id`, `value`, `asset` and `at`, and its outcome stays or moves from none to `done` or `failed`, or from `failed` to `done`, unless it was compacted while old enough at some service time between the two writes; held `totals.failed` items remain or move into the totals; and `spent` and `count` grow by at least what entered them. A version that breaks this is ignored and flagged (Dispatch spec 8.2).

**Who wrote it.** A ledger write after the first counts only if it carries `record_version` on the Allowance record at some version `v` and its writer is the executor at `v`, the application of the last grant history entry older than `v`. A ledger written otherwise stops automatic payment until the user confirms again.

**Last ledger version.** The executor keeps the last ledger write it wrote or read with an authenticated version, and its item hash (Dispatch wire 6.6). Before an automatic payment, the ledger shown must be that write or one signed as built on it or later. A verified write built on an earlier version, an authenticated deletion, or confirmed absence contradicting the kept version raises the rollback alarm (Dispatch spec 10.1); an unavailable answer holds spending.

**Anchor, handoff and repair.** A grant authorizes payment only once its executor holds a complete current anchor: the original ledger under a proved first grant (Paykit wire 5.9), a valid `ledger_handoff`, a successful repair, or its own verified continuation in one uninterrupted grant term and account history. An absent, deleted, unreadable or recovered ledger never means zero, and reacceptance, a new grant or a confirmation never initializes one. `ledger_handoff`, written by the previous executor and signed under `paykit/v1/ledger-handoff`, names its last ledger version and item hash (Paykit wire 2 and 5.4). A repair, confirmed by the user with its figures shown, rewrites the ledger as a merge that never counts less than any of its inputs. It requires complete usage authority and durable evidence of each included attempt's transferred amount; without them it writes nothing and the Allowance stays unavailable for automatic payment, possibly indefinitely (Paykit spec 8.3; Paykit wire 5.5). Each executor instance serializes its ledger writes and keeps one complete accepted ledger and at most one prepared write of unknown result.

### Matching a request

A Payment Request is the only message paid under an Allowance; a request names no Allowance. An executor may accept a recurring request, or pay a one-time request, under an accepted Allowance only if the request's sender is the Allowee; its amount asset equals `terms.asset`; the amount lies within `per_payment_amount`, if set; it can be paid to an endpoint of the requested asset that no rate prices and that the allowlist, if set, includes; and `active_from` and `expires_at` admit the service time of the batch. A payment priced by the request's fixed rates or by period details' rates is never automatic. So an Allowance in `btc` does not match a request in another asset, nor pay an endpoint to which a `btc` request attaches a rail surcharge rate.

At most one Allowance authorizes an occurrence. The executor's acceptance of a recurring request, or first automatic payment of a one-time request, writes the Allowance's ID into the request record, and later occurrences are paid only under it; among several covering Allowances the executor chooses. An occurrence attempted outside its Allowance is paid again only by hand. Only the user moves a recurring request's later Billing Periods to another Allowance of the same counterparty; usage already counted stays in the earlier ledger.

### Automatic destinations

An automatic payment uses only a destination signed by a current application of the payee: the request's `payment_endpoints`, period details, a Private Payment List, or a public endpoint in the payee's app record. The message or record MUST verify (Dispatch spec 8.2) and not have expired by the device clock or the highest verified service time. For a public endpoint, an automatic payment waits for the payee's identity service to confirm the identity document and stops if that lookup fails (Paykit spec 7.2).

Before the batch, the payment method reports the asset, amount and largest fee it will transfer. A destination that would transfer another amount or asset, or whose amount the method cannot tell, is not used automatically, nor, where the application configures a fee cap for the asset, one whose largest fee exceeds it.

### Time

No automatic payment is attempted while the device clock and the service's signed time differ by more than the 5-minute clock tolerance, or the highest verified service time is more than that ahead of the device clock (Dispatch spec 10.1, Clock bound).

Every attempt on a Billing Period carries `server_time_in(s, null)` with `s` the period's start, so the service applies none before the period starts. The executor pays automatically from the first period if the acceptance was recorded before it started, else from the period containing the acceptance's service time, and pays each period only within its automatic window, which ends at the earlier of its attempt deadline and the next period's start, judged on the highest verified service time and again before dispatch. A period whose window ended unpaid is paid only by hand (Paykit spec 8.2).

### Restore and provider loss

After a restore that the identity service's held-cursor report does not show clean, or after a `missed` item, the application pays and accepts nothing automatically under any Allowance until its record shows it ended or the user confirms it; the executor asks its user to confirm each Allowance on its consent list again, and asks counterparties to re-send (Paykit spec 7.2). A restored zero ledger, a backup or a version number never establishes the anchor.

While a grant's `confirmed_generation` is lower than `recovery_from + 1` in the current `identity.json`, the executor makes no automatic payment. After its user confirms, it writes a new grant with the current generation; no other application ends this pause, and the confirmation establishes no usage authority. Obligations from before the loss stay uncertain (Dispatch spec 12.6), and delayed outcomes of earlier attempts still count at their entries' times.

### Limitations

Handoff between executors is reserved for a later release. A reading application that is not the executor cannot yet check a newer ledger version, because the reference client does not hand it both writes' authenticated service times (Paykit spec Section 17, question 37). No interface or vector supplies a proof of complete inventory for a repair. Allowances that pay requests priced in another asset are left for later (Paykit spec Section 16).

## Rationale

**Separate from requests.** A request remains valid without an Allowance, and an Allowance does not change how requests flow. Either party may propose, since a merchant may suggest limits that the payer then accepts.

**Exact asset and no rates.** An Allowance counts in its own asset. A rate could make the amount transferred differ from the amount counted, so rate-priced payments are left to the user, and the counted value is the amount transferred, so a transfer rounded up at a limit's edge counts whole.

**Payee-signed destinations.** An automatic payment has no user to notice a substituted destination. A destination signed by a current application of the payee cannot be replaced by a storage provider, and waiting for the payee's identity service keeps a stale identity document from directing one.

**A ledger at the identity service.** Usage kept in one application's state is invisible to the others, and an unordered shared file can be served back older. Writing each entry in the claim attempt's batch, conditioned on the Allowance record and dated by the service, makes every application count each payment in the same period, fails a stale executor's batch, and lets the executor's kept version detect a ledger served older.

**Failed attempts spend.** A payment method can report failure and still settle. Counting a failure as spent unless the executor's journal proves it never reached the method costs capacity only on a genuine early failure.

**Conflicts are final.** Two different proposals or responses under one ID leave both parties unsure which terms bind, so neither binds and the parties set up a new Allowance.

**Related work.** [NIP-47](https://github.com/nostr-protocol/nips/blob/c53877571f96eb423661fc23c620d629d37b8f19/47.md) gives an application a connection secret with which it asks a remote wallet to pay invoices, within budgets the wallet attaches. An Allowance grants the payee no credential: the payee sends Payment Requests, and the payer's executor decides each payment against limits the payee cannot change. A proposed extension to BOLT 12 ([lightning/bolts#1240](https://github.com/lightning/bolts/pull/1240)) adds recurrence to offers, for Lightning only, with limits the payer's wallet sets alone; an Allowance states its limits as terms both parties hold, for on-chain and Lightning endpoints.

## Backward Compatibility

The deployed protocol is Paykit v0.1, whose Allowance bodies are defined in `specs/allowances.md` of the reference repository: version 1 Event messages with top-level `version`, `kind`, `app_id` and `event_id`, references by `proposal_event_id` and `acceptance_event_id`, and the same terms and period arithmetic, exchanged over Noise links between Homeserver files. Usage and lifecycle live in a shared-state file on the Homeserver, evaluated against a wallet-kept watermark of trusted local time.

Paykit v0.2 replaces the top-level fields with the identity service's common fields and the event references with message hashes in `refs`, ignores unknown members, and adds `allower_generation`. A second, different response makes an Allowance conflicted, where v0.1 made it invalid history pending review. One executor named by a signed grant pays, and a ledger at the identity service, written in the claim's batch and dated by the service, replaces the shared-state usage and the watermark; a rolling limit counts an entry while `t < at + 60 s + L`, where v0.1 counted payments admitted in `(t - L, t]`. Rate-priced payments are never automatic, failed attempts count as spent unless proven never dispatched, and Billing Periods have a bounded automatic window.

There is no migration (Paykit spec Section 16): v0.1 and v0.2 applications cannot pay each other, v0.1 Allowances do not carry over, and limits count from the v0.2 acceptance.

## Security Considerations

An Allowance lets the Allowee cause payments, up to its limits, without the Allower's approval of each one; a compromised Allowee application can request payments up to those limits. Every Allowance therefore has a monetary limit or an expiry, and wallets SHOULD present Allowances as standing permission to pay.

The identity service is trusted for coordination, meaning ordering, time, availability and delivery, not for content (Dispatch spec 14 and 16; Paykit spec Sections 11 and 13). It cannot forge or move ledger amounts, which are writer-signed and sealed to their record key, nor roll back history an application has seen unnoticed: the executor's kept ledger version and item hash detect an older, deleted or omitted ledger write, and automatic payment stops. A split view, in which the service shows different applications different histories, is not detected; on a split an obligation can be paid once per branch (Dispatch spec 10.1).

The executor enforces the limits, and a faulty or malicious executor can exceed them (Paykit spec Section 13). A compromised own application with `paykit_allowance` can rewrite the Allowance record, which pauses automatic payment until the user confirms, but cannot forge a grant or move it to other terms or another counterparty. If it rewrote an ended Allowance as running before a restore, the user's confirmation is the only remaining check.

A restored or new executor relies only on evidence that cannot omit a payment: a valid handoff naming the previous executor's last version, its own retained complete ledger with a verified continuation, or a repair under complete usage authority. A backup, a version number or a zero ledger never supplies capacity. As stated in the Payment Endpoint Discovery document, the key that identifies a payee does not establish who controls the funds sent to a destination.

An endpoint whose instruction a third party supplies at payment time, such as `btc-lightning-lnurl`, is signed by the payee only as the server's address. The invoice comes from that server, authenticated by the Web PKI, so a compromised server or domain can make an automatic payment go elsewhere, up to the Allowance's limits. An Allower that does not accept this names only other identifiers in `allowed_payment_endpoint_identifiers`, and a wallet's local policy may refuse such endpoints for automatic payment.

## Privacy Considerations

Allowance messages and records are sealed. The identity service's operator sees their sizes and times, the counterparty of each message, and the link between an executor batch and its claim (Dispatch spec 15); record keys and obligations are blinded with the payer's naming key. Every application of the Allower holding `paykit_allowance` reads the terms and the ledger. An acceptance carrying `executor_app_id` tells the Allowee which of the Allower's applications pays.

## Reference Implementation

paykit-rs branch `v0.2`, commit `aba097fa015e98f7b2926fce662d68b34ad56280`: https://github.com/pubky/paykit-rs/tree/aba097fa015e98f7b2926fce662d68b34ad56280. `paykit-lib` implements the terms, periods, terms hash, grant signatures, record binding, ledger and usage counting; `paykit-sdk` implements the proposal and acceptance flows and the executor. The specification is `specs/v0.2/spec.md` and `specs/v0.2/wire-format.md` at that commit, on Pubky Dispatch at commit `5f3209aae28d1b538a31c8ce43506b39df828b61`, where it carries its earlier name, Pubky Switch. Paykit v0.2 is a draft and not frozen.

## Test Vectors

The auxiliary file [allowances/vectors.json](allowances/vectors.json), derived from the pinned Paykit v0.2 vectors, is recomputed by the runner of the Payment Endpoint Discovery document. Its groups:

* `keys`, `certificates`, `executor_certificates`: the fixed keys, and certificates with and without what `paykit_allowance_execute` requires.
* `messages`: the Allowance messages and the executor notice in signed form.
* `terms_hash`, `executor_grant`, `signatures`: the terms hash, the executor grant and its grant history entry, and the grant and ledger handoff signatures.
* `period_limit_spellings`, `period_limit_members`: terms whose period limits differ only in spelling, duplicates, and period limits missing a member.
* `policies`, `record_keys`, `initial_ledger`: the policy hashes and record keys of the Allowance collections, and the initial ledger bytes with their refusals.
* `usage`, `failure_evidence`: usage and limit decisions (per-payment range, anchored and rolling windows, counts, lifetime limits with compacted totals, failed attempts, never-dispatched releases, paid proofs) and the limit that refuses each candidate.
* `allowed_identifiers`: proposals whose allowed identifiers are valid Payment Endpoint Identifiers, and proposals refused for a reserved, malformed, repeated or missing one.
* `compaction`, `successors`, `ledger_shapes`: compacted ledgers, whether a reader accepts a newer ledger version, and ledger values refused for the form of a member.

Billing Periods are in the vectors of the Payment Requests, Private Lists and Receipts document.

An anchored monthly period from `2026-01-31T00:00:00.000Z` contains `2026-03-10T00:00:00.000Z` in `[2026-02-28T00:00:00.000Z, 2026-03-31T00:00:00.000Z)`. Under a 7-day rolling limit, an entry at `2026-01-01T00:00:00.000Z` counts at `2026-01-08T00:00:59.999Z` and not at `2026-01-08T00:01:00.000Z`.

## References

* Paykit v0.2 [specification](https://github.com/pubky/paykit-rs/blob/aba097fa015e98f7b2926fce662d68b34ad56280/specs/v0.2/spec.md) and [wire format](https://github.com/pubky/paykit-rs/blob/aba097fa015e98f7b2926fce662d68b34ad56280/specs/v0.2/wire-format.md).
* Pubky Dispatch, under its earlier name Pubky Switch at this commit: [specification](https://github.com/pubky/pubky-dispatch/blob/5f3209aae28d1b538a31c8ce43506b39df828b61/spec/spec.md) and [wire format](https://github.com/pubky/pubky-dispatch/blob/5f3209aae28d1b538a31c8ce43506b39df828b61/spec/wire-format.md).
* [NIP-47](https://github.com/nostr-protocol/nips/blob/c53877571f96eb423661fc23c620d629d37b8f19/47.md), Nostr Wallet Connect.
* [BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md); recurrence proposal [lightning/bolts#1240](https://github.com/lightning/bolts/pull/1240).
