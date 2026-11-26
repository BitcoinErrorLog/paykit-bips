# Paykit BIP draft

A draft specification, in three documents, of how Bitcoin payment instructions are discovered and exchanged between identities keyed by Ed25519 public keys: signed public payment endpoints resolved through a PKARR record, a homeserver and the identity's service; Payment Requests, Private Payment Lists and receipts exchanged as signed messages; and standing Payment Allowances. It specifies Paykit v0.2 on Pubky Dispatch, the identity service formerly called the Pubky Switch (paykit-rs branch `v0.2`, commit `aba097f`; pubky-dispatch commit `5f3209a`, from before the rename, with the scoped revisions the Paykit spec names), Bitcoin methods only, with no proposed changes. Paykit v0.2 is itself a draft and not frozen; the series follows it.

Authors: John Carvalho <bitcoinerrorlog@gmail.com>, dzdidi.

## Status

Draft. Not yet posted to the bitcoin-dev mailing list or submitted to the BIPs repository.

The first document, Payment Endpoint Discovery, is the narrow BIP: it stands alone and needs only PKARR, a homeserver, Ed25519 and BLAKE3, plus the public read of the identity's service. The second and third documents depend on that service for message transport and coordination. The service is Pubky Dispatch. At the pinned commit its specification and wire constants carry the earlier name `pubky-switch`. Pubky Dispatch `main`, and paykit-rs `v0.2` since pubky/paykit-rs#762, spell them `pubky-dispatch`, and the series takes that spelling up when it moves its pin. The documents keep every dependency on the service in one section, "The identity service" of the first document, and cite its specification elsewhere only as "Dispatch spec N" and "Dispatch wire N".

## Reading order

Each document requires the ones before it.

1. [Payment Endpoint Discovery](bip/payment-endpoint-discovery.md): resolving a payee's key to its homeserver, the identity document, certificates and application records, payment endpoint identifiers and payloads, reading the public payment list, address reuse. Auxiliary files: [identifiers.md](bip/payment-endpoint-discovery/identifiers.md), [vectors.json](bip/payment-endpoint-discovery/vectors.json), and the checker for the whole series, [run_vectors.py](bip/payment-endpoint-discovery/run_vectors.py).
2. [Payment Requests, Private Lists and Receipts](bip/requests-lists-receipts.md): Paykit's message kinds carried by the identity service, one-time and recurring Payment Requests, period details, conversion terms, proofs, receipts, Private Payment Lists, and the payer's paying order. Auxiliary file: [vectors.json](bip/requests-lists-receipts/vectors.json).
3. [Payment Allowances](bip/allowances.md): standing, bounded permission for one of a payer's applications to pay qualifying requests automatically, with its executor grant and usage ledger. Auxiliary file: [vectors.json](bip/allowances/vectors.json).

[tools/](tools/README.md) describes how the vector files are assembled from the reference vectors.

## Checking the vectors

```
pip install cryptography pynacl blake3
cd bip
python3 payment-endpoint-discovery/run_vectors.py
```

The checker recomputes every value and validity verdict in the three `vectors.json` files from the rules in the documents, independently of the reference code.

## Licensing

| Path | License |
| --- | --- |
| `bip/` documents and their auxiliary files (`identifiers.md`, `run_vectors.py`) | BSD-2-Clause or, at the reader's option, CC0-1.0, as each document's Copyright section states |
| `bip/**/vectors.json` (test vectors) | BSD-2-Clause or, at the reader's option, CC0-1.0, unchanged; anyone may use them under CC0-1.0 |
| `tools/` | BSD-2-Clause, see [tools/LICENSE](tools/LICENSE) |
| `README.md` | BSD-2-Clause |
