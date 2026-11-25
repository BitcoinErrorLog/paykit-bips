# Payment endpoint identifiers

This auxiliary file of the Payment Endpoint Discovery document lists the Bitcoin payment endpoint identifiers it defines, and for each one the facts payer and payee must agree on. The payload is the instruction text itself (that document's Payloads section).

| Identifier | Payload | Asset, endpoint precision | Network | Proof `type` and settlement ID |
| --- | --- | --- | --- | --- |
| `btc-bitcoin-p2wpkh` | Bech32 P2WPKH address ([BIP 173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)) | `btc`, satoshi | the rail | `bitcoin-txid`; the `txid` |
| `btc-bitcoin-p2tr` | Bech32m P2TR address ([BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)) | `btc`, satoshi | the rail | `bitcoin-txid`; the `txid` |
| `btc-bitcoin-p2sh` | Base58Check P2SH address | `btc`, satoshi | the rail | `bitcoin-txid`; the `txid` |
| `btc-bitcoin-p2pkh` | Base58Check P2PKH address | `btc`, satoshi | the rail | `bitcoin-txid`; the `txid` |
| `btc-lightning-bolt11` | [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) invoice | `btc`, millisatoshi where the endpoint supports it | the invoice | `bitcoin-bolt11-preimage`; none |
| `btc-lightning-bolt12` | [BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) offer | `btc`, millisatoshi where the endpoint supports it | the offer | none defined |
| `btc-lightning-lnurl` | LNURL-pay request ([LUD-06](https://github.com/lnurl/luds/blob/luds/06.md)) | `btc`, millisatoshi where the endpoint supports it | the invoice the server returns | none defined |

* **Asset, endpoint precision.** Amounts for these identifiers are in the asset `btc`, in whole bitcoin. A payable amount computed under conversion terms is rounded up once to the endpoint's precision, given here (Payment Requests, Private Lists and Receipts, "Conversion and amounts").
* **Network.** For the on-chain identifiers the rail names the network: `bitcoin`, or a test network in its place as below. The address in the payload belongs to that network. For the Lightning identifiers the network is in the invoice or offer, which the payer checks before paying.
* **Proof.** The `type` a payer puts in the `proof` of its `paykit.payment_proof`, and the settlement ID a payee credits by (Payment Requests, Private Lists and Receipts, "Proof" and "Crediting once"). An identifier without a defined settlement ID is credited for a request only by hand, and never without a request.

The on-chain identifiers also exist for the test networks, with the rail `testnet` (testnet3), `signet` or `regtest` in place of `bitcoin`, for example `btc-signet-p2tr`.

`btc-bitcoin-p2wpkh`, `btc-bitcoin-p2tr`, `btc-lightning-bolt11` and `btc-lightning-bolt12` appear in the Paykit v0.2 specification, its identifier convention (`specs/payment-endpoint-identifier.md`) or its vectors at the commit pinned in the Reference Implementation section. That carries no normative weight.

An identifier is added by amending this file with a row that names the payload content, asset and endpoint precision, network and proof. The meaning of a listed identifier does not change once listed.
