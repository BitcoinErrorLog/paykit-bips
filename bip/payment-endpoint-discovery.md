```
  BIP: ?
  Layer: Applications
  Title: Payment Endpoint Discovery
  Authors: John Carvalho <bitcoinerrorlog@gmail.com>
           dzdidi
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause OR CC0-1.0
```

## Abstract

A payer who knows only a payee's public key has no standard way to learn which Bitcoin payment instructions the payee currently accepts. This document specifies how a payee identified by an Ed25519 key publishes, under that key, signed records of the applications that receive payments for it and of their public payment endpoints, and how a payer resolves, authenticates and reads them. It is the first of three documents and stands alone. The second specifies payment requests, per-counterparty payment lists and receipts exchanged between two such keys, and the third standing permissions to pay.

## Copyright

This document and its auxiliary files are licensed under the BSD-2-Clause license or, at the reader's option, CC0-1.0.

## Motivation

A payee hands out one instruction at a time: an address, an invoice, an offer or a URI. Each is passed out of band and fixed when it is shared. When the payee rotates an address, lets an invoice expire or adds a Lightning wallet, payers who hold the earlier instruction are not told.

Existing standards cover parts of this:

* [BIP 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) and [BIP 321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki) carry one or more instructions in a URI. The URI is a snapshot and cannot change after it is shared.
* [BIP 353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki) resolves a human-readable name to a BIP 321 URI through DNSSEC. It needs a domain and a DNS operator.
* LNURL-pay and Lightning Address return a fresh invoice from an HTTPS server under a domain, for Lightning only.
* BOLT 12 offers are reusable and avoid repeated payment hashes, for Lightning only.
* [BIP 352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) silent payment addresses and [BIP 47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) payment codes avoid on-chain address reuse, for on-chain payments only.

None lets a payee identified only by a key publish the current set of instructions it accepts, across on-chain and Lightning formats and across the applications that receive for it, change that set without telling each payer, and let the payer verify that each instruction was published by an application the key authorized. In this document the payee's key resolves to a storage server that the payee designates in a signed record. The key signs a document listing its current applications, each application signs its own record, and a payer verifies both before it uses an instruction.

Public endpoints are visible to everyone and are paid by every payer who reads them. The second document adds per-counterparty endpoints and payment requests, which use the same keys, certificates and records.

### How the documents fit

One payment through the series runs as follows:

1. The payer has the payee's key, for example from a contact entry, a checkout page or a QR code.
2. It resolves the key to the payee's homeserver through the payee's signed record (this document).
3. It reads the payee's identity document, compares it with the copy the payee's identity service serves, and reads the signed record of each current application (this document).
4. For a payer without a relationship, the records' public endpoints are the destinations (this document). For a known counterparty, the payee sends a Private Payment List with receiving details for that payer only, and a Payment Request for an amount, as signed messages delivered through the payer's identity service (Payment Requests, Private Lists and Receipts).
5. The payer records its attempt, pays from its own wallet and sends a proof.
6. The payee confirms settlement itself and may send a signed receipt.
7. For recurring payments the payer may grant an Allowance under which one of its applications pays qualifying requests without asking its user each time (Payment Allowances).

## Specification

### Conventions

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT" and "MAY" are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

These definitions are used by all three documents of the series. The series builds on an identity service specified separately (The identity service, below), whose rules are cited as "Switch spec N" and "Switch wire N".

* *JSON* documents are UTF-8 without a byte order mark and hold exactly one JSON value. A member name repeated at any depth, compared after unescaping, and a lone surrogate make a document invalid. Integers are JSON numbers without sign, fraction or exponent, from 0 to 2^53 - 1; any other number outside a member defined as opaque makes the document invalid. Unknown members are ignored in records, identity documents and message bodies, and make a certificate invalid (Switch wire 1.1).
* *Exact bytes.* Signatures and hashes cover the exact bytes a writer produced. A reader never re-serializes JSON to check a signature or a hash, and anything forwarded keeps its bytes.
* *base64url* is RFC 4648 section 5 without padding. A decoder rejects `=`, `+`, `/`, whitespace, a length of the form 4k + 1 and non-zero trailing bits, so each byte string has one text (Switch wire 1.2). `b64(n)` is the base64url text of n bytes.
* *z-base-32* uses the alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`, most significant bit first, the last group filled with zero bits, lower case, without padding. A decoder rejects a wrong length, a character outside the alphabet and non-zero trailing bits (Switch wire 1.3).
* A *Pubky ID* is the z-base-32 text of a 32-byte Ed25519 public key: 52 characters. An *App ID* is the z-base-32 text of the first 16 bytes of the BLAKE3 hash of an application's Ed25519 signing public key: 26 characters.
* `lp(x1, ..., xn)` is `BE32(len(x1)) || x1 || ... || BE32(len(xn)) || xn`. Inside `lp()`, a Pubky ID is its 32 key bytes, an App ID its 16 bytes, an integer `BE64`, and a label or other text its UTF-8 bytes (Switch wire 1.4). `BE32` and `BE64` are 4- and 8-byte big-endian unsigned integers; `||` is byte concatenation.
* `hash(x)` is BLAKE3 with a 32-byte output. `derive(label, parts...)` is BLAKE3 in key-derivation mode with context string `label` and key material `lp(parts...)`, 32 bytes (Switch wire 1.5).
* A *time* is `YYYY-MM-DDTHH:MM:SS[.F]Z` in UTC with a four-digit year, upper-case `T` and `Z` and an optional fraction of 1 to 9 digits. Times before 1970 and a second of 60 are invalid. Writers emit exactly three fraction digits. Times compare as instants at millisecond precision, further digits truncated (Switch wire 1.6).
* *Ed25519* signatures (RFC 8032) are verified as follows, with A the public key, R and S the two halves of the signature, M the signature input, B the base point and L the group order. A verifier accepts only if, in this order: S < L; A and R each decode to a curve point (RFC 8032, section 5.1.3) whose encoding is again exactly the same 32 bytes; neither `[8]A` nor `[8]R` is the identity point; and the encoding of `[S]B - [k]A` equals R byte for byte, where k is SHA-512(R || A || M) reduced modulo L. The equation is not multiplied by the cofactor (Switch wire 2.1).
* A *signature input* is `lp(label, field1, ..., fieldn)`. Every signed object of the series names its label and fields. Signers keep the signed bytes and send exactly those bytes again; they never sign the same body twice.
* A *signed document* travels as the JSON object `{"body": b64(body bytes), "sig": b64(signature)}`, its *carrying form*. Its *document bytes* are `lp(body bytes, signature)` and its *document hash* is `hash(document bytes)`. A reader verifies the signature first and then parses the body (Switch wire 2.2).
* *Invalid* data is treated as not received: it has no effect and is not shown as valid.

Amounts in this series are decimal strings: ASCII digits with at most one `.` and at least one digit, at most 18 digits after the `.`, and the value times 10^18 below 2^128. `.5` and `10.` are valid; signs, exponents, grouping separators and whitespace are not. Arithmetic and comparison are exact. Amounts are in whole units of their asset. The asset of the Bitcoin identifiers of this series is `btc`, and amounts in `btc` are in bitcoin (`0.00025`, not satoshis). Other asset strings are outside this series.

### Roles and terms

* *Identity*: an Ed25519 key pair. Its Pubky ID identifies a payer or payee.
* *Signer*: the software that holds the identity's secret key. It signs the identity document and application certificates, and nothing else of this series.
* *Application*: software acting for an identity, such as a wallet or a payment service, with its own Ed25519 *signing key*, its App ID and a *certificate* the signer issued for it. One identity can have several. An application may run on several devices with the same keys; it is then one application.
* *Homeserver*: an HTTP storage server, itself identified by an Ed25519 key, that stores an identity's public files.
* *Identity service*: the inbox and coordination service named in an identity's identity document (The identity service).
* *Payment endpoint*: a *payment endpoint identifier*, naming an instruction format, and a *payload*, carrying one instruction in that format.
* *Public payment list*: the public endpoints of all current applications of an identity.

### The identity service

An identity names one identity service in its identity document (`inbox`). The series relies on that service for exactly these functions:

* a public, signed copy of the identity document (The service's copy);
* the formats of identity documents, certificates and application records, which this document restates for readers;
* delivery of the signed messages of the second and third documents to the recipient's applications, and the common fields of those messages;
* coordination among one identity's own applications: claims on payment attempts, shared records and signed service time.

The series relies on no notification or wake-up mechanism. How an application learns that a message is waiting is outside the series.

The identity service is Paykit Dispatch, specified separately at the revisions under Reference Implementation. Its specification is published in the `pubky-switch` repository under the service's earlier name, Pubky Switch, and its rules are cited as "Switch spec N" and "Switch wire N". Where the series restates one of its rules, that specification governs any difference. The service keeps one inbox per identity for every protocol the identity's applications take part in, of which the payment protocol of this series is one (Switch spec 1). Its wire constants, the paths, document kinds and signature labels that contain `pubky-switch`, still carry the earlier name and may be renamed. A renamed wire changes this section, the citations and those constants, not the payment messages and records of the series.

### Resolving an identity

An identity designates its homeserver in a signed DNS packet published on the Mainline DHT, as defined by the PKARR base specification at version 8.1.0 and summarized here.

A *signed packet* is

```
public_key (32) || signature (64) || BE64(timestamp) || dns_packet
```

where `timestamp` is microseconds since the Unix epoch and `dns_packet` is an encoded DNS answer packet of less than 1000 bytes whose names are relative to the identity's key text. `signature` is an Ed25519 signature by the identity key over the bencoded string `3:seqi<timestamp>e1:v<length>:<dns_packet>`, with `<timestamp>` and `<length>` in decimal. The packet is stored on the DHT as a BEP 44 mutable item with `k` the public key, `seq` the timestamp, `sig` the signature and `v` the DNS packet. HTTP relays may forward such items; validity depends only on the signature.

A reader MUST verify the signature and parse the DNS packet, and MUST NOT accept a packet older than one it has already accepted for the same key.

The packet contains an HTTPS record (RFC 9460) named `_pubky`. Its TargetName is the key text of the homeserver. Writers publish SvcPriority 0 and a TTL of 3600 seconds. The homeserver republishes the identity's latest signed packet on the identity's behalf while the record designates it, so the identity key is needed only to change the record.

The homeserver publishes its own signed packet with HTTPS records at its apex. A record whose TargetName is `.` designates the addresses in the packet's A and AAAA records and the record's `port` parameter; a record whose TargetName is a domain name designates a conventional HTTPS host. A reader connecting to a `.` target uses TLS with raw public keys (RFC 7250) and MUST require the server to present the homeserver key. A reader connecting to a domain target authenticates the host with the Web PKI. A reader that can open TCP connections SHOULD use the `.` target when a connection to it succeeds; browser readers use the domain.

### Reading and writing data

A resource is addressed by an owner key and an absolute path. Paths under `/pub/` are readable without authentication.

* A reader reads a file with `GET /storage/<owner key text><path>` on the owner's homeserver. HTTP 404 and 410 mean the file does not exist.
* `GET /info` returns `{"features":[...]}`, the optional features the homeserver supports. `path-addressed-storage` means it serves the `/storage/` form above; a reader that does not find it uses the earlier form `GET <path>` with the owner's key text in a `pubky-host` request header.
* Writes require a session on the homeserver authorized by the owner. The signer grants each application write access to its own record path and never a capability that covers `/pub/pubky-switch/v1/identity.json` or a folder containing it, so that only the signer writes the identity document (Switch spec 3.4).
* A reader MUST bound the size of each response before parsing it.

The paths this document uses:

| Path | Content | Written by |
| --- | --- | --- |
| `/pub/pubky-switch/v1/identity.json` | the identity document, a signed document | the signer |
| `/pub/pubky-switch/v1/apps/<app_id>.json` | the application's record, a signed document | that application |

Both are publicly readable. The Privacy Considerations say what that exposes.

### The identity document

The *identity document* is a signed document whose body is a JSON object of kind `pubky-switch.identity`, signed by the identity key under the label `pubky-switch/v1/identity` with the body as its one field (Switch spec 4.3, Switch wire 3.3). Example body:

```json
{ "v": 1, "kind": "pubky-switch.identity",
  "identity": "<pubky id>",
  "version": 12, "generation": 3, "signer": "<b64(16)>",
  "inbox": { "url": "https://switch.example", "service_key": "<b64(32)>" },
  "policy": { "admission": "contacts_and_conversations",
              "connect_requests": { "enabled": false, "max_pending": 50, "push": false } },
  "apps": [ { "app_id": "<app id>", "cert": "<b64(32)>" } ],
  "removed": [ { "app_id": "<app id>", "distrust_from": "<time>" } ],
  "data_epoch": 4,
  "recovery_from": null,
  "record_max_age": 7776000 }
```

The members a payer uses:

* `v` is 1, `kind` is `pubky-switch.identity` and `identity` is the Pubky ID whose key verifies the signature.
* `version` is at least 1 and increases with every update. `generation` is at least 1 and increases with each change of identity service provider.
* `inbox.url` is the origin of the identity's service: exactly `https://host[:port]`, with no user info, path, query, fragment or trailing slash, at most 267 bytes, and a domain host of at most 253 bytes with labels of at most 63 (Switch wire 3.3, 7.1). `inbox.service_key` is the Ed25519 key that signs its responses.
* `apps` lists every *current* application with the document hash of its certificate, `cert`. `removed` lists removed applications with `distrust_from`, a time. An App ID appears at most once in `apps`, at most once in `removed`, and never in both.
* `renewed`, absent when empty, lists earlier certificates of listed applications during and after a certificate renewal: `{"app_id", "cert", "until"}`, `until` a time or `null` (Switch wire 3.3).
* `record_max_age`, optional, is the longest time in seconds that a reader trusts an application record after its `updated_at`. It is at least 1; absent means 7776000 (90 days).

The other members (`signer`, `policy`, `data_epoch`, `recovery_from`, `service_keys`) are defined by the identity service specification and checked for form as Switch wire 3.3 specifies; a payer reading public endpoints does not otherwise use them.

A reader MUST verify the signature with the key of the Pubky ID it resolved and the checks above. It keeps, for each identity, the highest `version` and `generation` it has accepted and the hash of each body it has seen at each version, and:

* MUST reject a document whose `version` or `generation` is lower than one it has accepted for that identity;
* MUST treat two documents with the same `version` and different body bytes as *equivocation*: it stops acting on that identity, makes no payment to it and alerts its user;
* MUST reject a document that lists in `apps` an App ID that a version it accepted lists in `removed`.

A reader uses a copy of an identity document for at most 10 minutes from the start of the request that supplied it, and reads it again after any failure (Switch spec 4.3).

### The service's copy

The identity's service serves the newest identity document it holds with a public, unauthenticated `GET /v1/<pubky id>/identity` at `inbox.url`, in a response signed with `inbox.service_key` as Switch wire 7.1 and 7.4.15 specify.

A payer about to act on an identity's public application records that holds no copy of the identity document fresher than 10 minutes:

1. reads the homeserver copy;
2. then, in parallel with the application record reads that follow, reads the service's copy at the `inbox.url` the homeserver copy names;
3. waits for the service's answer at most until its record reads finish plus a short grace;
4. uses the copy with the higher `version`. The same body at an equal version confirms it; a different body at the same version is equivocation. If the service's copy lists an application the homeserver copy does not, the payer reads that application's record too.

If the service answers with a signed freeze naming a next service, the payer verifies the freeze with the identity key, reads the public copy once at the next service and uses the highest copy it holds. It follows at most one freeze (Switch spec 4.3, Switch wire 3.6 and 7.4.15).

If the lookup has failed, or has not answered when the payer is about to act:

* a payment its user starts goes ahead only after the user explicitly confirms it although the identity's service could not confirm the identity's applications, and the payer records that confirmation;
* a payment without the user, such as one under an Allowance, waits for the lookup with one retry and is not made if the lookup fails. It never acts on the homeserver copy alone.

An answer that arrives before the payment is dispatched is used.

The two observations are timed together (Paykit spec 7.2). An observation's time is when the payer sent the read that gave it: the homeserver read of the identity document version used, and the service lookup, taken no later than the signed service time of its answer (Switch spec 4.3). When the lookup succeeds, each record read the payer relies on begins and ends within the interval that starts at the later of the two observation times and ends 10 minutes after the earlier one, the end excluded; this holds for the record reads started in parallel with the lookup too. Both observations must still be within their 10 minutes when the payer uses an endpoint, immediately before dispatch included; otherwise it repeats the identity lookup and reads the records again. After a user's confirmation without the service, the interval is the 10 minutes of the homeserver observation alone. A change to the identity document requires new record reads.

### Certificates

A *certificate* is a signed document whose body is a JSON object of kind `pubky-switch.app_cert`, signed by the identity key under the label `pubky-switch/v1/app-cert` (Switch spec 3.2, Switch wire 3.1):

```json
{ "v": 1, "kind": "pubky-switch.app_cert",
  "identity": "<pubky id>", "app_id": "<app id>",
  "signing_key": "<b64(32)>", "bundle_key": "<b64(32)>",
  "scopes": ["paykit_request", "paykit_settlements", "paykit_contacts"],
  "permissions": ["lists.read", "conversation.add"],
  "issued_at": "<time>", "expires_at": "<time>" }
```

A verifier checks, and rejects the certificate on any failure: the signature with the identity's key; `v` and `kind`; that the body has no unknown members; that `identity` is that identity; that `app_id` is the App ID of `signing_key`; that `signing_key` and `bundle_key` are 32 bytes and `bundle_key` is not an X25519 key of low order; that `scopes` holds at most 32 names, each once, each `name` or `name:<sub>` with `name` 1 to 32 characters of `a-z`, `0-9`, `_` and `-` starting with a letter or digit and `<sub>` 1 to 32 characters of `a-z`, `0-9` and `-` starting with a letter or digit, never a `name` beside one of its `name:<sub>`; that `permissions` holds only `claims.read`, `claims.write`, `lists.read`, `lists.manage` and `conversation.add`, each at most once and in that order; that `suite_keys`, if present, has the form of Switch wire 3.1; and that `expires_at` is later than `issued_at` and at most 730 days after it. A certificate has expired when the verifier's time is at or past `expires_at`.

The scopes of the payment protocol of this series begin with `paykit` (Switch wire 3.1, "Scope roots"). After the checks above, a payer applies the scope rules of the protocol (Paykit wire 3.1):

* Each scope's requirements hold: `paykit_pay` requires `paykit_contacts`; `paykit_request` and each labelled selling scope `paykit_request:<label>` require `paykit_settlements` and `paykit_contacts`; `paykit_allowance_execute` requires `paykit_allowance`, `paykit_pay` and `paykit_contacts`; `paykit_manage_contacts` requires `paykit_contacts`.
* A certificate never holds plain `paykit_request` together with a labelled `paykit_request:<label>`, holds at most 8 labelled selling scopes and at most 8 extension scopes `paykit_ext:<prefix>`, and holds no name beginning `paykit_ext:` that is not a valid extension scope. A valid `<prefix>` is `paykit-` followed by 1 to 25 characters of `a-z`, `0-9` and `-`, so `paykit_ext:paykit-cap` is valid and `paykit_ext:cap` and `paykit_ext:paykit` are not.
* `permissions` holds every permission the protocol's scopes need: `claims.read` for `paykit_pay` or `paykit_allowance`; `claims.write` for `paykit_pay`; `lists.read` for `paykit_contacts`; `lists.manage` for `paykit_manage_contacts`; `conversation.add` for `paykit_pay`, `paykit_request`, a labelled selling scope, `paykit_allowance` or an extension scope. When the certificate holds no scope of another protocol, the list is exactly those permissions.

A certificate that fails these rules is invalid for the payment protocol even though the identity service accepts it. The second document defines what each scope authorizes. For this document, only plain `paykit_request` matters: an application publishes public endpoints only if its certificate holds it.

A certificate is *current* for an identity when its document hash is the `cert` of its App ID in the identity document the reader uses, or is listed for that App ID in `renewed` with `until` `null`, and it has not expired (Switch spec 3.2, 3.4).

### Application records

An *application record* is a signed document whose body is a JSON object of kind `pubky-switch.app`, signed by the application's signing key under the label `pubky-switch/v1/app-record` (Switch spec 4.2, Switch wire 3.2). Example body:

```json
{ "v": 1, "kind": "pubky-switch.app",
  "identity": "<pubky id>", "app_id": "<app id>", "signing_key": "<b64(32)>",
  "cert": { "body": "<b64>", "sig": "<b64>" },
  "accepts": ["paykit.payment_proof", "paykit.private_payment_list_request"],
  "protocols": { "paykit": {
      "capabilities": { "endpoint_identifiers": ["btc-lightning-bolt11", "btc-bitcoin-p2tr"] },
      "public_endpoints": {
        "btc-lightning-bolt12": "lno1...",
        "btc-bitcoin-p2tr": "bc1p..." } } },
  "updated_at": "2026-12-01T00:00:00.000Z",
  "expires_at": null }
```

A reader reads `signing_key` from the body, verifies the signature with it, and checks:

1. `v` is 1, `kind` is `pubky-switch.app` and `identity` is the identity being resolved;
2. `app_id` equals the `<app_id>` of the path the record was read from;
3. `cert` is a valid certificate for that identity (Certificates) naming the same `app_id` and `signing_key`;
4. `protocols`, if present, is an object whose member names have the syntax of a scope `name` and whose values are objects or `null`;
5. `accepts` is an array of strings;
6. `updated_at` is a time and `expires_at` a time or `null`.

A record that fails any of these is invalid. Unknown members are ignored.

The member `protocols.paykit` holds the payment protocol's data (Paykit wire 3.2):

* `capabilities`, optional, is `{"endpoint_identifiers": [...]}`: the payment endpoint identifiers the application can pay to.
* `public_endpoints`, optional, is an object mapping payment endpoint identifiers to payloads, each a non-empty string.

A missing or `null` `paykit` member, `capabilities`, `endpoint_identifiers` or `public_endpoints` is empty. A reader MUST reject the record if `capabilities` or `public_endpoints` is not an object, `endpoint_identifiers` is not an array of strings, a payload is not a string or is empty, or an identifier in either is not a valid payment endpoint identifier.

When a reader holds two valid records of one application, it uses the one with the later `updated_at`. Two records of one application with the same `updated_at` and different body bytes are a conflict: the reader uses neither, keeps using an earlier record of that application it already holds, if any, and tells its user; the identity's other applications are unaffected. A record whose `updated_at` is more than 5 minutes ahead of the reader's clock is not used at all (Switch spec 4.2).

An application publishes its record on the homeserver only after its identity service has accepted it, and republishes the newest accepted record while the homeserver copy differs. An application that publishes no record has no public endpoints and appears publicly only as an App ID and certificate hash in the identity document (Switch spec 4.2).

### Using a record

A payer uses an application's public endpoints only while all of these hold (Paykit spec 4 and 7.2; Paykit wire 3.2):

* the application is current: its App ID is in `apps` of the identity document the payer uses, with the record's certificate current as defined above;
* the certificate holds plain `paykit_request`;
* the record is within its *trust window*: both the payer's clock and the highest service time the payer has verified are strictly before `updated_at` plus `record_max_age`, and, if `expires_at` is a time, strictly before `expires_at`.

A removed application's endpoints are ignored even if its record is still on the homeserver. A record past its trust window is unusable until the application publishes a fresh one. A payer applies these checks when it reads and again when it uses the endpoint, immediately before dispatch.

An application that holds plain `paykit_request` renews its record once less than half of its effective lifetime remains, measured from `updated_at` to the earlier of `updated_at` plus `record_max_age` and a finite `expires_at`. A renewed record cannot extend a finite `expires_at` the application chose for its endpoints (Paykit wire 3.2).

### Payment endpoint identifiers

An identifier is 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `-`, `_` and `.`, other than `.`, `..` and `private` (Paykit wire 1.4). Identifiers are compared byte for byte; implementations MUST NOT fold case, normalize or alias them.

New identifiers SHOULD follow the form `{asset}-{rail}-{format}`, three non-empty segments of lowercase letters and digits: the unit of value, the settlement system and the instruction format on it. This form is a subset of the identifier syntax. Conversion terms in Payment Requests require it.

The auxiliary file [identifiers.md](payment-endpoint-discovery/identifiers.md) lists the Bitcoin identifiers defined by this document and, for each, what payer and payee agree on: the content of its payload, its asset and the precision of its endpoint, its network and the proof that settles a payment to it. An application MAY publish an identifier that is not listed; the meaning of an identifier in use MUST NOT change, and a new format on an existing rail takes a new format segment. Identifiers are added to the list by amending that file.

For the test networks, the rail `bitcoin` is replaced by `testnet`, `signet` or `regtest`, for example `btc-signet-p2tr`. `testnet` denotes testnet3. testnet4 and later test networks take a new rail name, for example `testnet4`. Lightning identifiers do not encode a network. The network of a BOLT 11 invoice or BOLT 12 offer is in the payload; for `btc-lightning-lnurl` it is that of the invoice the LNURL server returns, which the payer checks before paying.

### Payloads

A payload is a non-empty UTF-8 string. The record and message formats treat it as opaque; its content is defined by its identifier (Paykit wire 1.4). For the identifiers listed in identifiers.md the payload is the instruction itself: the address, invoice, offer or LNURL text, without leading or trailing whitespace.

A payer MUST validate a payload before using it: the address network and script type against the identifier, and the expiry, network and amount of an invoice or offer. Amounts and descriptions for one payment belong in a Payment Request.

### Reading the public payment list

To read an identity's public endpoints, a payer:

1. resolves the identity's homeserver and reads its identity document, with the service's copy as above;
2. reads the record of each application in `apps`, in the document's order, from `/pub/pubky-switch/v1/apps/<app_id>.json`;
3. keeps the usable endpoints of each record (Using a record).

A record that is absent, invalid, refused or past its trust window is reported as that application's failure; the other applications' usable endpoints remain available. An application without a record has no public endpoints. A payer bounds the whole read to 256 endpoints and 4 MiB of payloads; an application whose endpoints do not fit in what remains of that budget is reported as over the bound and is not cut to fit. If a Payment Request names a required application, the payer reads only that application's record (Paykit spec 4).

An identity whose current records list no public endpoint has no public payment list. Choosing among the candidates is the payer's local policy.

### Public and private destinations

Public endpoints are optional. They are for payers without a relationship with the payee; the second document gives each known counterparty its own destinations in Private Payment Lists. Private and public payment are separate modes: the payer or its user chooses one, and a payer never changes from one to the other on its own, for example after a failure (Paykit spec 8.4).

Removing an endpoint from the current record does not recall a copy a payer already holds within its trust window. A payee whose destination is compromised removes it and also revokes the application, or replaces it with a new one, so that payers stop paying it once their copy of the identity document shows the application removed (Paykit spec 4).

### Address reuse

A public on-chain endpoint is one address that every reader can pay, so publishing one is address reuse by construction. A published address is also publicly associated with the identity: every payment to it, and every transaction that later spends it, can be attributed to the identity by anyone who saw the record, including archives of the homeserver and of its event feed. Replacing the address limits reuse; the association remains.

* A payee SHOULD prefer, in this order:
  1. Private Payment Lists for known counterparties, which give each counterparty its own addresses;
  2. instructions that tolerate reuse and that its payers can pay, such as a silent payment address (BIP 352, which an identifier such as `btc-bitcoin-sp` could carry) or a BOLT 12 offer (`btc-lightning-bolt12`);
  3. on-chain addresses that it replaces once a payment to them confirms.
* A payee SHOULD NOT publish an on-chain address it will not replace.
* An LNURL-pay endpoint also tolerates reuse. Each payment to it depends on the LNURL server, which is authenticated by the Web PKI and learns the payer's network address and the amount.
* A BOLT 11 invoice is single-use. A payee SHOULD NOT publish one that it does not replace after payment.
* A payer SHOULD NOT cache a public on-chain endpoint beyond the payment it fetched it for.

Replacing an address on confirmation tells anyone who polls the record when the payee was paid. A payee for whom that is unacceptable SHOULD NOT publish on-chain addresses.

## Rationale

### Keys instead of names

BIP 353 maps a human-readable name to instructions and inherits DNSSEC's proofs. This series identifies a payee by a key that anyone can create without a registrar or domain, and uses PKARR only as a signed pointer from that key to a server. The two are compatible: a BIP 353 record or a BIP 321 URI can carry such a key, and a payload can carry any BIP 321 instruction. The BIP 353 rationale warns that a separate naming system without broad adoption may not be sustainable. This series uses no name system. PKARR stores one signed record per key in the Mainline DHT, the public network that BitTorrent clients operate, and the identity can move its data to another homeserver by publishing a new record.

### Why not BIP 321 URIs behind BIP 353

A URI with `lno=` or `sp=` behind a DNS name gives reusable instructions, but one set per payee, the same for everyone, with no attribution to the receiving application and no way to give one counterparty an endpoint that others cannot see. Per-application records and the private lists of the second document add those.

### Signed records under a cold key

Every public file a payer acts on is signed. The identity key signs the identity document and the certificates, which change when an application is added, removed or renewed, not when an endpoint changes. Each application signs its own record with its own key whenever its endpoints change. The identity key therefore stays with the signer and is used occasionally, never per payment, while a homeserver operator, a network attacker or one application cannot substitute another application's endpoints. A substituted response can only make an endpoint unavailable.

Each application holds its own key and only its own grant on the homeserver, so a compromised application can sign endpoints only for itself, and only until it is revoked and its records leave their trust window. The record age limit, set by the signer, bounds how long a record signed by a stolen key stays payable.

### The service's copy instead of a PKARR anchor

A homeserver can serve an older identity document that still lists an application since revoked. A reader that has seen a newer version rejects it, but a first-time reader cannot tell. Publishing the document's version or hash in the PKARR packet would give every reader a floor, at the cost of PKARR space and of coupling every identity document update to the PKARR record. This series instead has the payer compare the homeserver's copy with the copy the identity's service serves, which the signer delivers before it publishes, and use the higher version. The lookup runs in parallel with reads the payer makes anyway. Its limits are in Security Considerations.

### Format in the identifier

BIP 321 keys instructions by prefix so that a new address type needs no new parameter. Here the format is part of the identifier because payers filter by format before parsing payloads, and because a payee may accept only some formats on a rail. Each format therefore needs its own identifier, which the open grammar allows without coordination.

### Related work

| | Payee identifier | Infrastructure | Updates after sharing | Scope |
| --- | --- | --- | --- | --- |
| BIP 21 / BIP 321 | none | none | no | instructions in one URI |
| BIP 353 | DNS name | DNS, DNSSEC | yes | name to URI |
| LNURL-pay, Lightning Address | domain | HTTPS server | yes | Lightning invoice |
| BOLT 12 | offer | Lightning network | no | Lightning offer |
| BIP 47, BIP 352 | payment code, address | Bitcoin | no | on-chain |
| BIP 77 | none (session) | directory over Oblivious HTTP | n/a | one payjoin transaction |
| This series | Ed25519 key | PKARR, homeserver, identity service | yes | signed lists across formats and applications; private lists and requests |

## Backward Compatibility

This document changes no consensus, peer-to-peer or wallet standard. Wallets that do not implement it are unaffected.

### Deployed implementations

The deployed protocol, Paykit v0.1, publishes an unsigned App Registry at `/pub/paykit/v0/app-registry.json` and each public endpoint as an unsigned file under `/pub/paykit/v0/apps/{app_id}/endpoints/`, and authorizes one key per identity generation for an encrypted channel in an identity-signed record at `/pub/paykit-authority/v0/current-key.json`. Every application of an identity holds the same derived secret. The protocol in this document replaces it with no migration (Paykit spec 16):

* A reader of this document does not read the v0.1 paths, and a v0.1 reader does not read the identity document or application records. A payer and a payee both need this protocol to pay through it.
* Public endpoints are published again in each application's record.
* Payment endpoint identifier strings are unchanged.

## Security Considerations

The chain of authority is: the identity key signs the PKARR packet, the identity document and each certificate; the identity document lists each current application by the hash of its certificate; the certificate names the application's signing key and scopes; the application's key signs its record and endpoints. A homeserver operator, an application holding a grant on the homeserver or a network attacker cannot forge any link. They can withhold, delay or serve older signed copies:

* *Stale records.* A homeserver can serve an older record of an application, whose endpoints remain payable within its trust window. The record age limit (90 days unless the identity sets a shorter one) and a finite `expires_at` bound this. A payee that withdraws an endpoint because it is compromised revokes the application.
* *Stale identity documents.* A homeserver can serve an older identity document that still lists a revoked application. The service's copy closes this for every payer whose lookup succeeds. After a cooperative move a stale copy names the old service, which answers with the freeze naming the next one. After a provider loss, an old service that is gone does not answer, so the payer pays only with its user's explicit confirmation and never automatically; a hostile old service can answer with its last document and no freeze, and the old document's own limits then apply (Paykit spec 11, Switch spec 4.3, 14).
* *Withholding.* A homeserver can withhold the identity document or records, which makes the identity's public endpoints unavailable. Flooding the service's public read cannot silently disable it: the service limits it per network source, answers may be cached, and a payment the service could not confirm needs the user (Switch spec 4.3).

An application whose key is stolen can sign records for itself until it is revoked and its records leave their trust window. A stolen identity key controls everything the identity signs.

Payers MUST verify every signature and check before using an endpoint, and MUST apply the trust window both when reading and immediately before paying. A payer that has not verified an endpoint MUST NOT present it as verified. A reader MUST NOT fall back to another source for an identity's public data; if resolution fails, public resolution is unavailable.

PKARR packets carry no expiry. A reader that has never seen a newer packet can be served an older valid packet that designates a previous homeserver. Records it serves still have to verify and fall within their trust window. When a reader reaches a homeserver through its domain target, the connection is authenticated by the Web PKI; because every record is signed, a substituted response can only make endpoints unavailable.

Verifiers MUST implement the Ed25519 verification of the Conventions exactly. A verifier that skips the canonical-encoding or small-order checks, or multiplies by the cofactor, accepts signatures that conforming verifiers reject.

The Ed25519 key that identifies a payee authenticates who published an endpoint. It says nothing about who controls the funds sent there.

## Privacy Considerations

* Anyone holding a payee's key can read its identity document, which shows how many applications it has and the hash of each certificate, and each published record whole: its accepted message kinds, its certificate with scopes and permissions, its capabilities and its public endpoints. An application that publishes no record appears only as an App ID and certificate hash.
* A public lookup reveals the payer's network address and the payee key to the DHT nodes or relays queried and to the payee's homeserver, with the time of the lookup. The lookup at the payee's identity service also reveals that someone is about to pay the identity shortly before a public payment, but not who. Payers that need to hide this SHOULD resolve through Tor or a proxy.
* Homeservers offer a public event feed of writes under `/pub/`, which reveals when a payee changes its records.
* A published address labels its payments with the identity, as described in Address reuse.

## Reference Implementation

* paykit-rs, branch `v0.2`, commit `aba097fa015e98f7b2926fce662d68b34ad56280`: https://github.com/pubky/paykit-rs/tree/aba097fa015e98f7b2926fce662d68b34ad56280. The library `paykit-lib` implements identifiers, the protocol member of application records and the certificate scope rules; `paykit-sdk` implements reading public endpoints. The specification files `specs/v0.2/spec.md` and `specs/v0.2/wire-format.md` at that commit are cited as "Paykit spec" and "Paykit wire". The protocol they specify is a draft and not frozen.
* pubky-switch, the Paykit Dispatch specification under its earlier name, commit `5f3209aae28d1b538a31c8ce43506b39df828b61`: https://github.com/pubky/pubky-switch/tree/5f3209aae28d1b538a31c8ce43506b39df828b61, with `spec/spec.md` and `spec/wire-format.md` cited as "Switch spec" and "Switch wire". For the outer application record body the series follows revision `250cd60e98eecb2a0357e55257d5b0dad2d583a4`, which keeps an application's display name out of the signed record, and for reading the identity document revision `63e8a9232ba6ff8d3e4e6508e892a64073a137da`.
* pkarr 8.1.0, the record format used by the reference implementation: https://github.com/pubky/pkarr (tag `v8.1.0`).

## Test Vectors

The auxiliary file [payment-endpoint-discovery/vectors.json](payment-endpoint-discovery/vectors.json) contains the vectors of this document, taken from the vectors published with the reference specifications (Bitcoin cases only) and, where marked, written from the rules here. Each case names its source. The groups:

* `keys`, `app_ids`: identity and application keys from their seeds, Pubky IDs and App IDs.
* `pkarr_record`: the signed PKARR packet below.
* `zbase32`, `base64url`, `lp`, `u64_be`, `derive`, `rfc3339`, `json`: the encodings of the Conventions, valid and refused.
* `ed25519_strict`: signatures each verification step refuses, and an accepted mixed-order key.
* `signature_inputs`, `signed_documents`: signature inputs, carrying and compact forms, document bytes and document hashes.
* `identity_documents`: identity documents, their verification, record age limit and certificate listing, and documents signed again with one member changed (the service origin, `service_keys`, `renewed`), valid and refused.
* `certificates`, `certificate_rejections`, `labelled_scope_rejections`, `multi_protocol_certificates`, `extension_certificate`, `switch_scope_rule`, `switch_permission_rejections`: certificate verdicts and the permissions derived from the payment protocol's scopes.
* `app_records`, `extension_app_record`, `switch_app_record_protocols`: application records accepted and refused, each with the identity and path App ID it was read under, records refused for those alone, and the endpoints a reader takes from each.
* `endpoint_identifiers`: identifier validity and the recommended form.
* `destination_expiry`, `record_usability`: when a record's public endpoints may be used.

The script [payment-endpoint-discovery/run_vectors.py](payment-endpoint-discovery/run_vectors.py) recomputes every value and every validity verdict in the vectors of all three documents from the rules, independently of the reference implementation:

```
pip install cryptography pynacl blake3
python3 payment-endpoint-discovery/run_vectors.py
```

The identity with secret key `61` × 32 has public key `ihdk8a3jnhkqjh4sagqjsfqpdfe6a5ugcki8xxo8kt91trhdgoqo`. Its signed packet with timestamp 1790000000000000 designates the homeserver `k1apo8exw9eyh1u7cyg9iquxfctygs3n9a3ihf9p6zh4ws7okb4y` in an HTTPS record `_pubky` with SvcPriority 0 and TTL 3600:

```
af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d
03c0fbc9a9b34ee1fa960fe1902076c84600c610d447a4967234e0fb8fce57f3
1e8e3e4db95057158c5346644e4f4c04796091732483486ff64fbee92532be09
00065bfeda25e000
000080000000000100000000065f7075626b79346968646b3861336a6e686b71
6a6834736167716a736671706466653661357567636b693878786f386b743931
74726864676f716f000041000100000e1000380000346b3161706f3865787739
6579683175376379673969717578666374796773336e3961336968663970367a
68347773376f6b62347900
```

## References

* [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): requirement levels.
* [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) (JSON), [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) (base64url), [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) (timestamps).
* [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519), [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250) (raw public keys in TLS), [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) (HTTPS records).
* Paykit Dispatch specification and wire format, published as the Pubky Switch, commit `5f3209aae28d1b538a31c8ce43506b39df828b61`: https://github.com/pubky/pubky-switch/blob/5f3209aae28d1b538a31c8ce43506b39df828b61/spec/spec.md and https://github.com/pubky/pubky-switch/blob/5f3209aae28d1b538a31c8ce43506b39df828b61/spec/wire-format.md
* Paykit v0.2 specification and wire format, commit `aba097fa015e98f7b2926fce662d68b34ad56280`: https://github.com/pubky/paykit-rs/blob/aba097fa015e98f7b2926fce662d68b34ad56280/specs/v0.2/spec.md and https://github.com/pubky/paykit-rs/blob/aba097fa015e98f7b2926fce662d68b34ad56280/specs/v0.2/wire-format.md
* PKARR base specification and endpoints, version 8.1.0: https://github.com/pubky/pkarr/tree/v8.1.0/design
* [BEP 5](https://www.bittorrent.org/beps/bep_0005.html) (Mainline DHT) and [BEP 44](https://www.bittorrent.org/beps/bep_0044.html) (mutable items).
* z-base-32: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
* BLAKE3 specification, commit `ac784c9f22a48327782f042ec2f4d8126b3b1744`: https://github.com/BLAKE3-team/BLAKE3-specs/blob/ac784c9f22a48327782f042ec2f4d8126b3b1744/blake3.pdf
* [BIP 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki), [BIP 47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki), [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md), [BIP 173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), [BIP 321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki), [BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki), [BIP 352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki), [BIP 353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki).
* [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md), [BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md), [LUD-06](https://github.com/lnurl/luds/blob/luds/06.md).
