```
  BIP: ?
  Layer: Applications
  Title: Payment Requests, Private Lists and Receipts
  Authors: John Carvalho <bitcoinerrorlog@gmail.com>
           dzdidi
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause OR CC0-1.0
  Requires: ? (Payment Endpoint Discovery)
```

## Abstract

This document specifies the payment messages two identities exchange as messages through each identity's service. A payee shares payment endpoints with one counterparty only, in versioned Private Payment Lists that expire. A payee asks for a one-time or recurring payment in a Payment Request; the payer accepts or rejects it, pays, and sends a proof naming its payment attempt. Either side can cancel. The payee confirms a credited proof with a signed receipt. The document also states how a payer chooses and checks a destination and records a payment before paying, and how a payee credits a settlement once. It is the second of three documents.

## Copyright

This document and its auxiliary files are licensed under the BSD-2-Clause license or, at the reader's option, CC0-1.0.

## Motivation

A merchant that knows its customer's key, or a person paying a contact, should not need a public address or a payment server. The payee should be able to give each counterparty fresh receiving details nobody else sees, ask for a specific amount and reference and get a durable answer, and set up a recurring payment the payer's wallet makes each period without the payee gaining authority over the payer's funds. A payer with several wallets should pay each obligation once, and a payee with several receiving applications should credit each settlement once.

## Specification

### Conventions

The conventions and terms of the Payment Endpoint Discovery document apply. The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT" and "MAY" are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

This document specifies Paykit v0.2 at the revisions under Reference Implementation. "Paykit spec N" and "Paykit wire N" cite its specification and wire format, "Dispatch spec N" and "Dispatch wire N" those of the identity service (Payment Endpoint Discovery, "The identity service"). Rules cited and not restated are part of this specification.

* JSON follows Dispatch wire 1.1: duplicate member names make a document invalid, numbers are integers from 0 to 2^53 - 1 outside opaque members, and unknown members of message bodies are ignored. A body's `metadata` and a proof's `proof` are opaque (Paykit wire 1.1).
* A *time* is `YYYY-MM-DDTHH:MM:SS[.F]Z` in UTC. Writers emit three fraction digits; comparisons use milliseconds (Dispatch wire 1.6).
* An *amount* is a decimal string `[0-9]+(\.[0-9]*)?` or `\.[0-9]+` with at most 18 fraction digits, compared exactly, in whole units of its asset (Paykit wire 1.2). This series uses the asset `btc`.
* A *message hash* is the BLAKE3 hash of a message's exact JSON bytes, as unpadded base64url (Dispatch wire 1.5). The *request hash* is that of a `paykit.payment_request` and identifies the request.
* A *payer app* holds `paykit_pay`; a *payee app* holds `paykit_request` or a labelled selling scope. *Service time* is a time signed by the identity's own Dispatch; each app keeps the highest it has verified (Dispatch spec 10.1).

### Messages through the identity service

Every message here is a message of the identity service: a signed plaintext in a sealed envelope, delivered to the recipient's inbox (Dispatch spec 5; Dispatch wire 4, 5.1). The sender must be admitted by the recipient's allowlist, for example as a contact (Paykit spec 1; Dispatch spec 7). Paykit relies on these common fields:

| Field | Paykit's use |
| --- | --- |
| `v` | `1` |
| `kind` | `paykit.` and a name below; recipients drop unknown kinds |
| `msg_id` | fresh lowercase UUID v4; with the sender identity, the deduplication key; a re-send keeps it |
| `created_at` | when the sender signed; informational except where a rule uses it |
| `from` | `{ "identity", "app_id" }`, equal to the inbox entry's certificate |
| `to` | the recipient identity, covered by the signature |
| `refs` | message hashes in the order each kind fixes; always written, `[]` when empty |
| `body` | per kind, below |

The sending app signs the recipient identity and the exact JSON bytes. A recipient runs the ten checks of Dispatch wire 5.1; Paykit fixes check 8, the scopes of each kind, and check 10, each kind's body rules. A message failing a check is dropped. A kind that activity records store is at most 16384 bytes (Paykit wire 4.1).

There is no order between the two directions, nor within one that a recipient relies on. Each party derives state from the messages, claims and records it holds, following `refs` (Dispatch spec 5.3). Crossing rules are stated with each kind.

### Scopes

`paykit_pay` requires `paykit_contacts`. `paykit_request` and each labelled selling scope `paykit_request:<label>` require `paykit_settlements` and `paykit_contacts`. A certificate holds plain `paykit_request` or labelled scopes, never both, and at most 8 labels. A label is 1 to 32 characters of `a-z`, `0-9` and `-`, starting with a letter or digit; payers and the Dispatch see it, so it SHOULD be opaque (Paykit spec 3.1; Paykit wire 3.1).

A recipient drops a message whose sender lacks the sender scope. A sender wraps a message only to apps whose certificate holds the recipient scope and whose app record's `accepts` lists the kind (Dispatch spec 3.4; Paykit spec 3.3; Paykit wire 4.3):

| Kind | Sender | Recipient | `refs`, in order |
| --- | --- | --- | --- |
| `payment_request` | selling scope | `paykit_pay` | none |
| `payment_request_acceptance`, `_rejection` | `paykit_pay` | request's selling scope | request hash |
| `payment_request_cancellation` | `paykit_pay` or request's selling scope | the other role | request hash |
| `payment_period_details` | request's selling scope | `paykit_pay` | request hash |
| `payment_proof` | `paykit_pay` | request's selling scope; plain `paykit_request` without a request | request hash, then period details hash if used; none without a request |
| `payment_receipt` | request's selling scope; plain `paykit_request` without a request | `paykit_pay` | proof hash, then request hash if any |
| `private_payment_list` | plain `paykit_request` | `paykit_pay` | none |
| `private_payment_list_request` | `paykit_pay` | plain `paykit_request` | none |
| `resend_request` | `paykit_contacts` | any Paykit scope | none |

*The request's selling scope* is plain `paykit_request`, or `paykit_request:<label>` for a request with that `label`. Any app of the payee identity whose original certificate holds it may send the payee's cancellation, details and receipt; the recipient checks this against the request once it can read it (Paykit spec 3.4).

**Labels.** A labelled request carries `label`. The payer's acceptance, rejection, cancellation and proof copy it and go only to the payee's apps holding `paykit_request` or that label; replies about an unlabelled request go only to apps holding `paykit_request`. Recipients drop replies that break this. An app with only labelled scopes publishes no Private Payment Lists (Paykit wire 3.1, 4.3).

### Body types

* **Amount:** `{ "value": amount, "asset": string }`.
* **Payment endpoints:** a non-empty object mapping Payment Endpoint Identifiers to non-empty payloads (Payment Endpoint Discovery document), owned by the sending app.
* **Recurrence:** `{ "every", "unit", "starts_at", "anchor", "ends_at" }`, all present; `every` at least 1; `unit` one of `minute`, `hour`, `day`, `week`, `month`, `year`; `ends_at` `null` or after `starts_at`.
* **Billing Period:** `{ "starts_at", "ends_at" }`, `ends_at` after `starts_at`, equal as instants to a period the recurrence computes. Recipients drop a message whose Billing Period ends at or before it starts.
* **Payment deadline:** `{ "type": "at", "timestamp": time }` for a one-time request; `{ "type": "period_start", "seconds": int }` for a recurring one.
* **Conversion:** `{ "type": "fixed", "rates": rates }`, or `{ "type": "per_period" }` on a recurring request. **Rates:** a non-empty array of `{ "asset": selector, "value": amount }`, selectors unique, values positive (Paykit wire 4.4).

### Payment Requests

#### Request

The body of `paykit.payment_request` is the request's terms (Paykit wire 4.5):

| Member | Req | Rules |
| --- | --- | --- |
| `amount` | yes | Amount |
| `payment_reference` | yes | 1 to 256 characters, no control characters |
| `proposal_expires_at` | yes, always written | time or `null` |
| `payment_deadline` | no | matching the request's type |
| `recurrence` | no | absent or `null` for a one-time request |
| `payment_endpoints` | no | the only destinations the payer may pay |
| `required_app_id` | no | only without `payment_endpoints`; pay only that payee app |
| `per_period_endpoints` | no | only with `recurrence`; default `false` |
| `label` | no | the label scope it is sent under |
| `accepted_payment_endpoint_identifiers` | no | non-empty, each identifier once; narrows usable identifiers; contains every key of `payment_endpoints` |
| `conversion` | no | Conversion |
| `metadata` | no | opaque |

Terms never change; the payee cancels and sends a new request instead. The payer SHOULD carry `payment_reference` in the payment where the method allows.

```json
{
  "v": 1,
  "kind": "paykit.payment_request",
  "msg_id": "04660a75-8d0e-46a9-a230-3d9e3d5e7d75",
  "created_at": "2026-01-01T00:00:00.000Z",
  "from": {
    "identity": "7p4fn44qoshcwgfndz5grt7fyyz1eycqyduxdqe8o58of1byzodo",
    "app_id": "brrz3m6g5rci6iqnzke44q4djc"
  },
  "to": "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy",
  "refs": [],
  "body": {
    "amount": { "asset": "btc", "value": "0.00025" },
    "payment_deadline": { "timestamp": "2026-01-03T00:00:00.000Z", "type": "at" },
    "payment_endpoints": { "btc-lightning-bolt11": "lnbc250u1pjexample0request0invoice" },
    "payment_reference": "order-1042",
    "proposal_expires_at": "2026-01-02T00:00:00.000Z"
  }
}
```

**Destination.** A request with `payment_endpoints` is paid only to those, even if unusable. One with `required_app_id` is paid only to that app's Private Payment List or public endpoints, while the app is current. Otherwise Paying, below, applies.

#### Acceptance, rejection and cancellation

The acceptance body is `{}`, or `{ "label": label }`. Rejection and cancellation carry an optional `reason`, and a payer's carries the request's `label`. A payee's cancellation MUST NOT carry `label`; recipients drop one that does (Paykit wire 4.6 to 4.8, 5.3; Paykit spec 8.1, 8.2).

* A payer sends at most one response, only while it has recorded no response or cancellation. After acceptance it may cancel; after rejection it sends nothing more.
* A one-time request is answered by paying it. Its acceptance becomes sendable once the payment method's call is made, never while a pre-dispatch check can stop the payment or after a reported failure.
* A recurring request is accepted once, before any payment, by the user or an executor under an Allowance (Payment Allowances document).
* A payer records a rejection or cancellation before sending it, and only while no attempt of the request, or of any Billing Period it lists as attempted, is open, `unknown` or paid.
* Either side may cancel alone. A payer app that verifies the payee's cancellation MUST keep it durably before acting on anything else and then makes no new attempt; an attempt under way finishes and sends its proof.
* A payee treats a valid proof as payment even after cancelling. A refund is a new request in the other direction (Paykit spec 5).

#### Conversion and amounts

Conversion terms carry rates the payee agreed; nobody fetches a market rate (Paykit wire 4.4; `specs/payment-conversion.md`).

* A rate is units of the payment asset per unit of the requested asset. Under conversion terms identifiers have the form `<asset>-<rail>-<format>`, and each selector, `<asset>` or `<asset>-<rail>`, matches the asset, and the rail when it names one, of an identifier the request names in `accepted_payment_endpoint_identifiers` or `payment_endpoints`, when it names any; recipients drop a request that breaks this.
* For `asset-rail-format` the rate is the `asset-rail` rate, else the `asset` rate, else 1 when `asset` is the requested asset; otherwise the endpoint is unusable.
* The amount to pay is the requested amount times the rate, rounded up once to the endpoint's smallest unit: the satoshi on-chain, the millisatoshi on a Lightning endpoint that supports it (Paykit spec 7.2 step 1). Fees are on top.
* With fixed rates `[{"asset":"btc-lightning","value":"1.01"}]`, a request of `0.0025` `btc` costs 250,000 satoshis on `btc-bitcoin-p2wpkh` and 252,500,000 millisatoshis on `btc-lightning-bolt11`.
* `per_period` takes cross-asset rates from period details; an endpoint of the requested asset is paid 1:1. Without terms another asset is paid only by hand.

The payment method must report the asset and amount it would transfer, and a destination fixing another amount or asset is unusable automatically (Paykit spec 7.2 step 1).

#### Deadlines and payment time

* A one-time request's attempt carries the claim `deadline` `d + 1 ms`, `d` the earlier of `proposal_expires_at` and `payment_deadline.timestamp`; with only one of them, `d` is that one, and with neither the attempt carries no `deadline`. A Billing Period's attempt carries the period start plus `seconds` plus 1 ms, or none. The service refuses an attempt from its deadline on (Paykit wire 4.5; Dispatch spec 10.2). A recurring request's `proposal_expires_at` bounds only acceptance.
* The payee checks the inclusive deadline against the payment time the method's evidence gives, never the proof's arrival; a Bitcoin application documents its rule, as a block timestamp may run about 2 hours ahead (`specs/payment-conversion.md`).
* Evidence earlier than the payee's record of its request, less a method tolerance, does not prove the request (Paykit spec 7.1).
* Late funds are credited as received, labelled late or underpaid, but pay no occurrence and get no receipt (Paykit spec 8.2).

#### Recurring requests

**Billing Periods.** Boundary `k` is `anchor` plus `k * every` units: fixed seconds for minutes to weeks, a calendar step from the original anchor for months and years, clamped to month end. Period `k` is `[boundary(k), boundary(k+1))`. The first period contains `starts_at`; with `ends_at`, the last contains the instant before `ends_at` and is whole. A message naming another period is rejected (Paykit spec 8.2; Paykit wire 4.4).

**Accepting and paying.** When `proposal_expires_at` is a time, the payer records its acceptance conditioned on `server_time_in(null, proposal_expires_at + 1 ms)` (Dispatch wire 6.3), so its own service decides timeliness; a `null` proposal expiry adds no condition (Paykit spec 8.2, wire 4.5). Each period then has its own obligation, attempts, proof, details and receipt. The payer's wallet decides a period is due, pays and sends a proof. A payment without the user's confirmation, under an Allowance or the app's policy, covers only periods from the one containing or following the acceptance, each until the earlier of its attempt deadline and the next period's start (Paykit spec 8.2).

**Not before its start.** Each attempt on a period carries `server_time_in(s, null)`, `s` the period start; paying early is by hand only, after confirmation, with `s` a service time verified after it (Paykit wire 4.5).

**Destinations per period.** With `per_period_endpoints`, `payment_endpoints` serve only the first period; later periods are paid and credited only to the destination of period details the proof names.

**Ending.** Either side's cancellation ends it. A request with `ends_at` has ended once its last period has ended by service time; a proof of an earlier period may still arrive.

#### Period details

`paykit.payment_period_details` carries `billing_period` and `expires_at` (required), and `payment_endpoints` and/or `rates`; `rates` only under `per_period` terms and not for the requested asset (Paykit wire 4.9; Paykit spec 8.2).

```json
{
  "billing_period": { "ends_at": "2026-03-31T00:00:00.000Z", "starts_at": "2026-02-28T00:00:00.000Z" },
  "expires_at": "2026-03-01T00:00:00.000Z",
  "payment_endpoints": { "btc-lightning-bolt11": "lnbc10u1pjexample0february0period" }
}
```

* The payee sends details only after acceptance, at most 8 per period, recording each first so every payee app can check a proof naming it.
* Each stays valid until its own `expires_at`; none replaces another. *Later* means later `created_at`, then greater `msg_id`; equally late details with another hash are an equivocation.
* The payer uses details only while its device clock and verified service time are before `expires_at`, never mixes two, and names the one used in its proof.
* Rates apply from `created_at`, cut to whole seconds, through `expires_at`; the payee never backdates it. The payer pays by them only while its device clock and its highest verified service time are both at or after that start and before `expires_at`, checked again just before money moves (Paykit spec 8.2).
* Details for a request not accepted, rejected or cancelled, for a period paid or not payable, or invalid against the request, have no effect.

### Proofs and receipts

#### Proof

`paykit.payment_proof` reports one payment attempt (Paykit wire 4.10):

| Member | Req | Rules |
| --- | --- | --- |
| `attempt_id` | yes | the claim attempt, 16 bytes as unpadded base64url |
| `billing_period` | recurring request | the period paid |
| `payment_endpoint_identifier` | yes | the identifier paid |
| `payment_app_id` | yes | the payee app whose endpoint was paid |
| `list_version` | paid to a list | that list's version |
| `amount` | only without a request | the amount transferred |
| `allowance_id` | only under an Allowance | |
| `label` | labelled request | |
| `payment_reference` | no | equals the request's |
| `proof` | yes | opaque method object, by convention `{ "type": string, ... }` |

A proof with `refs` carries no `amount`; one without carries no `billing_period`, `label`, `payment_reference` or `allowance_id`; one naming period details carries their `billing_period`. Recipients drop proofs that break this.

```json
{
  "attempt_id": "mAFdg5_0tVNjmrgiTUZW4g",
  "amount": { "asset": "btc", "value": "0.0015" },
  "list_version": { "generation": 1, "counter": 12 },
  "payment_app_id": "brrz3m6g5rci6iqnzke44q4djc",
  "payment_endpoint_identifier": "btc-bitcoin-p2wpkh",
  "proof": { "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", "type": "bitcoin-txid" }
}
```

| `type` | Members | Settlement ID |
| --- | --- | --- |
| `bitcoin-txid` | `txid`: 64 lowercase hex characters | the `txid` text, without output index |
| `bitcoin-bolt11-preimage` | `data`: the payment preimage in hex | not defined |

A *settlement ID* names one settlement identically in every proof of it (Paykit wire 1.5). A `bitcoin-txid` settlement ID ignores members such as `vout`: one transaction is one settlement, so two occurrences take two transactions. Each `type` has one spelling; an uppercase `txid` is not credited, and an invalid encoding is refused. A method whose IDs could collide with another's prefixes them with its name. Paykit defines no Lightning settlement ID; without one, a Lightning payment without a request is never credited, and a Lightning proof for a request only by hand (Paykit spec 8.1 step 4).

#### Receipt

`paykit.payment_receipt` is the payee's signed confirmation that it credited a proof. Its body carries `attempt_id` (the proof's), `billing_period` (for a recurring request), optional `metadata`, and, only without a request, an optional `payment_reference` of 1 to 256 characters without control characters. `refs` holds the proof hash, then the request hash if any. A receipt carries no amount and does not confirm a proof with another `attempt_id` or `billing_period` (Paykit wire 4.11).

A payee app stores the receipt in the same batch as the credit; sending it is optional. After verifying issuer, request, period and proof, a payer may settle the attempt's claim with `done`, basis `evidence`, citing the receipt (Paykit spec 7.3; Dispatch spec 10.2). Nothing from the payee shows that an attempt was not paid.

#### Crediting once

The payee verifies a payment by its own method, such as an output to an address it issued or a settled invoice, of the expected amount at the endpoint the proof names (Paykit spec 7.2). It credits each settlement to at most one occurrence (Paykit spec 8.1 step 4, 8.4):

* A credit writes the settlement's mark into the `settlements` record in the batch storing its receipt. While a mark exists no own app credits the settlement again (Paykit wire 5.7).
* A second proof of a credited settlement gets no new receipt; one without a request is a replay, answered at most with the receipt already issued.
* A proof whose method gives no settlement ID is credited only by hand, never without a request; such a credit is outside the one-credit guarantee (Paykit spec 13).
* A proof naming a list is credited by the publishing app only for a payload it offered that payer at that version, while it keeps the offer, until 30 days after the list's `expires_at`. Another own app, which does not know what was offered, checks such a proof by its payment method alone, and so does the publishing app after that time: a late proof of a real payment is still credited and gets its receipt (Paykit spec 8.4).

### Private Payment Lists

#### List

`paykit.private_payment_list` is the latest list of one publishing app for one recipient identity (Paykit wire 4.13; Paykit spec 8.4):

| Member | Req | Rules |
| --- | --- | --- |
| `version` | yes | `{ "generation": int, "counter": int }`, each 1 to 2^53 - 1 |
| `payment_endpoints` | yes | identifier to `{ "payload", "single_use" }`; empty for a withdrawal |
| `expires_at` | yes | 30 days after publishing is recommended |

`single_use` defaults to `false` and is omitted when `false`.

```json
{
  "expires_at": "2026-01-31T00:00:00.000Z",
  "payment_endpoints": {
    "btc-bitcoin-p2wpkh": { "payload": "bc1qexample0single0use0address0000000000", "single_use": true },
    "btc-lightning-bolt12": { "payload": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzr" }
  },
  "version": { "generation": 1, "counter": 12 }
}
```

A payer drops a list, withdrawal included, whose publisher lacks plain `paykit_request`, before comparing versions.

#### Versions

Versions compare generation first, then counter, never packed into one number or compared as text (Paykit wire 4.13).

* `generation` is the publisher's verified `identity.json` generation (Dispatch spec 4.3). `counter` is a per-recipient counter the publishing app reserves by a conditional write to `private_list_publications` before queueing the list (Paykit spec 8.4.1; Paykit wire 5.8). Each new publication takes a strictly greater pair, also after a restore; a re-send keeps its bytes. No time enters a version.
* For one publisher identity, app and recipient, a greater pair replaces the held list, and the same pair with the same hash is a duplicate. The same pair with another hash is an equivocation: the payer rejects it, reports the writer and keeps its list.
* A payer pays from a list only when the payee's `identity.json`, verified freshly, has a generation at least the list's.

#### Expiry and the 30-day use bound

A payer uses a list only while the earlier of `expires_at` and 30 days after its inbox accepted the list is after both its device clock and its verified service time (Paykit spec 5). A stolen app key therefore cannot sign a list that stays payable long.

#### Single-use endpoints, renewal and withdrawal

* Paying a `single_use` endpoint consumes the whole list version, even if the payment fails. The payer marks it used in `payment_lists` in the batch of its claim attempt, so two own apps cannot both pay it (Paykit spec 7.2, 8.4).
* The publisher sends a newer version when its list changes, on a proof for a single-use endpoint, in answer to a list request, and once less than half the list's lifetime remains.
* An empty `payment_endpoints` withdraws the list. A publisher that stops sending a counterparty lists sends a withdrawal at once, also to a blocked one; it adds no conversation entry (Paykit spec 8.4.1; Dispatch spec 7). A withdrawal cannot recall a copy already held (Paykit spec 4).

#### List requests

`paykit.private_payment_list_request` carries `held_version`, the pair the sender holds or `null`, always written, and optional `app_id`, the only app that may answer (Paykit wire 4.14; Paykit spec 8.4).

* A payer sends one when its list is missing, expired or used up, at most once in 24 hours, only to apps holding plain `paykit_request`.
* A publisher answers only counterparties it sends lists to: the newest it sent gets a newer version, an older unexpired one gets the newest re-sent, an expired one or none gets a newer version.
* At most one newer version per version named, a small number per counterparty per 24 hours, re-sends at most hourly. `held_version` never moves the counter.

### Paying

#### Choosing destinations

A payer pays only destinations from verified messages of the payee's current apps or its public records (Paykit spec 6, 8.1, 8.4): the request's or used period details' `payment_endpoints`; otherwise an endpoint of the latest Private Payment List or a public endpoint, limited by `required_app_id` and `accepted_payment_endpoint_identifiers`.

Private and public payment are separate modes. The app or user chooses one before resolving, and a payer MUST NOT change from one to the other on its own. With no usable list it sends a list request and tells its user it is waiting; it may offer public endpoints, paid only if the user chooses.

#### Checking the destination

Before money moves, judging expiry by device clock and verified service time, the payer checks (Paykit spec 4, 7.2):

* the carrying message or record verifies and has not expired;
* the sending or publishing app is current in the payee's `identity.json` read at most 10 minutes earlier, with its unexpired certificate holding plain `paykit_request` for a list or public endpoint, or the request's selling scope for a request or details;
* a list's generation, as above;
* the method will transfer exactly the computed amount.

A payer that sees two valid identity documents of the payee at one version pays nothing to it (Paykit spec 4).

#### Protected records

The payer's and payee's activity records (`payer_activity`, `payee_activity`), the `payment_lists` record and the `block_floor` record are *potentially protected*: once one is deleted, an application that holds no copy cannot tell what the deleted value withheld (Paykit spec 6). Three operations on such a key need authenticated evidence, each its own (Paykit spec 6, "Creation and later writes"; Paykit wire 5):

* *First creation* of usable state needs evidence, enforced when the create applies, that the key holds no value and no retained delete.
* *Putting a record back* over a retained delete needs evidence, enforced when the put-back applies, that the current delete is the exact item it answers.
* *Later authority* from a current value, for a reader that has not seen its history, needs evidence of the record's incarnation: an authenticated absence at its creation, or a verified put-back, followed by exact-predecessor continuity with every required restriction preserved.

The identity service specification at the pinned revision distinguishes absence from a retained delete when a write applies, but supplies no lineage proof for the incarnation, and the mapping is incomplete (Paykit wire 5, "Incomplete protected-record contract").

Until an adopted revision of the identity service and its Paykit mapping supply that evidence, an implementation MUST withhold these three operations and any payment, credit, acceptance, grant or endpoint use that depends on them, and keeps every known restriction and delete hold. The one positive path defined at this revision is publishing a payee receipt already signed for a one-time request (Paykit wire 5). In the procedures below, each step that creates, puts back or relies on such a record is withheld in this way; formats and steps that touch no potentially protected record are unaffected. A zero-version write, a preflight read, a signature, a current version or a user's confirmation does not supply the evidence.

#### Recording before paying

A payment is recorded as a claim attempt at the payer's own Dispatch before money moves, so its apps pay each obligation once (Paykit spec 7.1 to 7.3; Dispatch spec 10.2):

1. Derive the obligation from the payee identity, request hash and period start, blinded with the payer's naming key (Paykit wire 1.5), and write `attempt` with a fresh attempt ID, conditioned on the request record and the deadline, with any single-use reservation.
2. Pay only after a verified answer shows the app's own attempt open, using the attempt ID as idempotency key where supported.
3. Write `done`, or `failed` only when the payment definitively cannot settle; a timeout or ambiguous result keeps the attempt open.
4. Send the proof.

Another wallet finding the attempt open is told the payment is being handled. An `unknown` attempt is paid again only by a user warned it may be paid.

**Blocked counterparties.** A payer pays and accepts a blocked counterparty only by hand, and sends it no new request, details, nonempty list, list request or re-send request; cancellations, withdrawals, receipts and the acceptance and proof of a payment made still go (Paykit spec 8.1).

#### Paying without a request

A payer may pay a list or public endpoint without a request (Paykit spec 8.4). The obligation derives from the fresh attempt ID, and the attempt's `deadline` is 10 minutes after the latest service time seen. The proof has no `refs`, carries `amount` and, for a list, `list_version`, and reaches only apps holding plain `paykit_request`. A payment to a public endpoint may go ahead while the payer's Dispatch does not answer and is recorded later under its original attempt ID; a list payment needs the Dispatch.

### Re-send requests

`paykit.resend_request` asks for messages again, best effort (Paykit wire 4.12; Paykit spec 9). It selects by `msg_ids`, by acceptance window `accepted_from`/`accepted_until`, or by `request_hashes`, optionally narrowed to a `billing_period`; selectors combine as a union. The sender keeps what it sent at least 30 days and re-sends only messages first accepted within that time, with their original bytes and `msg_id`, only kinds the requester receives, each at most hourly and up to a daily number it chooses. It adds no conversation entry.

### Shared records

An identity's apps coordinate through sealed records at their own Dispatch (Dispatch spec 10.3; Paykit spec 6; Paykit wire 5): `payer_activity`, `payee_activity`, `payment_lists`, `settlements` and `private_list_publications`. Their formats concern one identity's apps. The rules they produce between identities are stated above: one credit per settlement, strictly increasing list versions.

## Rationale

**Requests from the payee.** The payee knows the amount, reference and timing; the payer keeps control by paying from its own wallet and accepting recurring requests explicitly. No pull authority exists; automatic payment is a separate grant in the Payment Allowances document.

**Hashes and attempts.** A request is named by the hash of its signed bytes, so a reference names one set of terms. A proof names its attempt and a receipt its proof. The claim at the payer's own Dispatch, checked against service time, is where every wallet checks before paying; a wallet with a wrong clock cannot pay early or late automatically.

**No order between directions.** Two inboxes at two services share no order, so crossing rules decide the races that matter, such as a proof against a cancellation (Paykit spec 11).

**Method-specific proofs.** Bitcoin methods prove payment differently, so the protocol carries a method object. A settlement ID without output index makes one transaction one settlement, at the cost of one transaction per occurrence.

**List versions without time.** A generation and a counter reserved by conditional write increase across restores and between two instances of an app, which timestamps do not guarantee, and reveal nothing about other recipients.

**Signed receipts** need no encryption scheme, storage location or key delivery of their own.

**Related work.** [BIP 70](https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki) tied payment requests to X.509 certificate authorities and a merchant server reachable at payment time, and was removed from Bitcoin Core. [BIP 75](https://github.com/bitcoin/bips/blob/master/bip-0075.mediawiki) added encrypted, store-and-forward invoice requests, the closest Bitcoin precedent, but kept BIP 70's formats and identities. [BIP 321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki) URIs are one-way and fixed when shared. [BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) is Lightning-only and payer-initiated; an offer can be a payload in a Private Payment List. Here the payee is its own key, messages are asynchronous, requests can recur, be cancelled and receipted, and a payer's wallets coordinate so each obligation is paid once.

## Backward Compatibility

The deployed protocol is Paykit v0.1 (`v0.1.1-rc9`). Its messages travel over Noise links between homeserver files, with top-level `version`, `kind`, `app_id` and `event_id`, a `payment_request_id`, terms in a `request` object, per-period rates in `paykit.payment_conversion_quote`, a 1000-byte limit and mandatory delivery confirmations. Receipts are encrypted homeserver files opened by a Receipt Access message. Objects are closed. List endpoints are bare payloads and lists carry no expiry (Paykit wire 4.2; Paykit spec 5, 15).

In v0.2 `msg_id` replaces `event_id`, the request hash in `refs` replaces `payment_request_id`, period details replace the quote, and signed receipts replace encrypted ones. Unknown members are ignored, `required_app_id` is optional, list endpoints carry `single_use`, lists carry a (generation, counter) version and `expires_at`, proofs name their attempt, and Billing Periods follow one rule. `per_period_endpoints`, `label`, `resend_request` and `private_payment_list_request` are new.

There is no migration (Paykit spec 16). v0.1 and v0.2 apps cannot pay each other; a v0.2 app reads and writes no v0.1 state. Open recurring requests are sent and accepted again, and v0.1 history stays with the v0.1 application. Paykit v0.2 is itself not frozen.

## Security Considerations

The threat model is the identity service's (Dispatch spec 14) with Paykit's additions (Paykit spec 11).

* **Proofs are assertions.** A payee establishes payment from settlement it observes. A transaction ID is public and does not identify the payer; a payee needing attribution issues a request-specific address.
* **No silent downgrade.** Since a payer never switches between private and public destinations on its own, an operator withholding a list cannot steer payment to instructions the payee did not choose. No own app can redirect a payment by writing shared state (Paykit spec 6).
* **Stolen app keys.** A list is payable at most 30 days after acceptance and only while its app is current in an `identity.json` read within 10 minutes (Paykit spec 4).
* **Non-repudiation.** Every message is signed over the recipient identity and its exact bytes, so a counterparty can show anyone the request, acceptance, proof or receipt it received (Dispatch spec 14, 15). A signed proof remains only the payer's assertion.
* **Duplicates.** No obligation is paid twice with compliant apps and a consistent Dispatch. Not covered: a user paying after a warning, a malicious or split-view Dispatch, a method reporting failure and then completing, or hand credits without a mark (Paykit spec 13).
* **Compromised own apps** can hide records they may write, such as a cancellation not yet read by another own app (Paykit spec 11).
* **Payloads** are authenticated, not validated; the payer checks each instruction (Payment Endpoint Discovery document).
* **Withheld paths.** Positive paths on shared records that need evidence the identity service specification does not yet supply stay withheld (Paykit spec 6, 8.4.1; Paykit wire 5). The open questions of Paykit spec 17 apply, including what a payer does when its `payment_lists` record is full.

## Privacy Considerations

What each party learns is in Dispatch spec 15 and Paykit spec 12.

* **The Dispatch operator** cannot read messages or sealed records but sees each message's sender, time, size and target apps, the identity's contacts and deny list, and claim states and times, so with whom an identity has obligations and when.
* **A counterparty** learns which of the other side's apps sent each message and a request's label.
* **Private Payment Lists** are seen only by their recipient. Single-use payloads keep payments unlinked; reused and public endpoints link every payment to them.
* **Public endpoints** are visible to all; reading the payee's `identity.json` before paying tells its Dispatch that someone is about to pay.
* **On-chain proofs** tie the conversation to public chain data.

## Reference Implementation

paykit-rs commit `aba097fa015e98f7b2926fce662d68b34ad56280` (branch `v0.2`): https://github.com/pubky/paykit-rs/tree/aba097fa015e98f7b2926fce662d68b34ad56280. `paykit-lib` implements formats, hashes, derivations and conversion amounts; `paykit-sdk` the request, list, proof and receipt flows. Pubky Dispatch, under its earlier name Pubky Switch, commit `5f3209aae28d1b538a31c8ce43506b39df828b61`: https://github.com/pubky/pubky-dispatch/tree/5f3209aae28d1b538a31c8ce43506b39df828b61.

## Test Vectors

The auxiliary file [requests-lists-receipts/vectors.json](requests-lists-receipts/vectors.json) holds these groups. Each case names its source in the reference implementation or, when written by hand, the rule it was written from.

* `keys`, `certificates`, `payee_certificates`, `payer_certificates`: the fixed keys and the certificates of senders and recipients, accepted and refused.
* `amounts`: the decimal amount grammar, its bounds and normalized spelling.
* `request_hashes`, `obligations`: request message hashes and the claim obligations derived from them.
* `messages`: every kind of this document in signed form, with hash, signature, plaintext and the verdicts of checks 6, 8 and 10 of Dispatch wire 5.1. The recurring request, its period details, the proof of a period and a request with fixed rates are the reference implementation's messages of those names written in Bitcoin and signed again, since it gives them in another asset.
* `conversion_terms`: requests with conversion terms and period details with rates, accepted and refused at check 10 and, for period details, against their request.
* `billing_period_forms`: messages naming a Billing Period whose `ends_at` is at or before its `starts_at`, all refused.
* `label_rejections`, `cancellation_roles`, `multi_protocol_senders`, `payee_label_senders`, `proof_members`, `receipt_members`, `list_versions`: messages refused for their label, role, payee authority, scopes of several protocols, proof members, receipt members and list versions, with the accepted counterparts.
* `billing_periods`, `details_rates`: Billing Periods computed from recurrences and the interval in which period details' rates apply.
* `policies`, `record_keys`, `settlement_ids`: shared record policy hashes and record keys, and `bitcoin-txid` settlement IDs.

The runner of the Payment Endpoint Discovery document recomputes every case.

## References

* [BIP 70](https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki), [BIP 75](https://github.com/bitcoin/bips/blob/master/bip-0075.mediawiki), [BIP 321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki), [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md), [BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md).
* Paykit v0.2: https://github.com/pubky/paykit-rs/tree/aba097fa015e98f7b2926fce662d68b34ad56280/specs/v0.2.
* Pubky Dispatch (under its earlier name Pubky Switch): https://github.com/pubky/pubky-dispatch/tree/5f3209aae28d1b538a31c8ce43506b39df828b61/spec.
* [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).
