# Vector tooling

`assemble_vectors.py` builds the three `vectors.json` files in [../bip/](../bip/) from the test vectors published with the reference specifications:

| Source | Commit | Directory |
| --- | --- | --- |
| [pubky/paykit-rs](https://github.com/pubky/paykit-rs) | `aba097fa015e98f7b2926fce662d68b34ad56280` | `specs/v0.2/vectors/` |
| [pubky/pubky-switch](https://github.com/pubky/pubky-switch) | `5f3209aae28d1b538a31c8ce43506b39df828b61` | `spec/vectors/` |

The script pins the SHA-256 of every source file it reads and refuses any other content, so a checkout at another commit fails instead of producing different vectors. Each case keeps its upstream name and carries a `source` member naming the file and the JSON path it came from. Members added here, such as `refused_at_step` and `recipient_app`, are listed in each file's `notes`.

The series is Bitcoin-only. Upstream cases that name another asset, a fiat currency, a token rail or the test-only `fake` rail are left out, together with the cases whose checks depend on them. The script refuses to write a file in which a kept case names one. Where upstream gives a message only in another asset, the script writes it in Bitcoin and signs it again with the published test keys; such a case carries `hand_written`, `basis` and `base`, the upstream message it changes. The script hashes those messages with its own BLAKE3 and signs them with its own Ed25519, so it still needs only the standard library.

## Requirements

Python 3.9 or later. The assembler uses only the standard library. The checker, [../bip/payment-endpoint-discovery/run_vectors.py](../bip/payment-endpoint-discovery/run_vectors.py), also needs `cryptography`, `pynacl` and `blake3` (`pip install cryptography pynacl blake3`).

## Running

```
git clone https://github.com/pubky/paykit-rs && git -C paykit-rs checkout aba097fa015e98f7b2926fce662d68b34ad56280
git clone https://github.com/pubky/pubky-switch && git -C pubky-switch checkout 5f3209aae28d1b538a31c8ce43506b39df828b61
python3 tools/assemble_vectors.py --paykit-rs paykit-rs --pubky-switch pubky-switch --check
python3 bip/payment-endpoint-discovery/run_vectors.py
```

`--check` compares the output with the files in `bip/` byte for byte and writes nothing; it prints `same` or `DIFFERS` per file and exits non-zero on a difference. Without it the files are rewritten. `--out DIR` writes into another directory laid out like `bip/`.

The checker recomputes every expected value from the case inputs and exits non-zero on any mismatch.

The files in this directory are licensed under BSD-2-Clause ([LICENSE](LICENSE)).
