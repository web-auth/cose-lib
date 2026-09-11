# RFC 9864 fixtures

Cross-verification vectors for the fully-specified signature identifiers of
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html): ESP256 (-9), ESP384 (-51), ESP512 (-52), Ed25519 (-19)
and Ed448 (-53).

[cose-wg/Examples](https://github.com/cose-wg/Examples) — vendored under [`../cose-wg/`](../cose-wg/) — predates
RFC 9864 and has no vector for these identifiers (checked at upstream commit `53c9d634`, still its head on
2026-09-11). The messages below were therefore produced with **another implementation**, and the harness of
[`tests/CoseWg/`](../../CoseWg/) verifies them the way it verifies the upstream files.

## Provenance

| | |
|---|---|
| Generator | [`generate.py`](generate.py), in this directory |
| COSE implementation | [python-cwt](https://github.com/dajiaji/python-cwt) 3.3.0 (`pip install cwt`) |
| Cryptography | [pyca/cryptography](https://github.com/pyca/cryptography) 50.0.1, bundling OpenSSL 4.0.2 |
| CBOR | [cbor2](https://github.com/agronholm/cbor2) 5.9.0 |
| Python | 3.14.4 |
| Produced on | 2026-09-11 |

Every message was verified by python-cwt itself (`COSE.decode()`) before being written, and each fail fixture was
checked to be rejected by it. The keys are the signing keys of cose-wg/Examples (`ecdsa-examples`, `eddsa-examples`),
unchanged, so that each fixture here has a polymorphic twin upstream that differs by the `alg` label alone:

| Fixture | Key (`kid`) | Upstream twin |
|---|---|---|
| `esp256-*` | P-256 `11` | `ecdsa-examples/ecdsa-sig-01`, `ecdsa-01` (ES256) |
| `esp384-*` | P-384 `P384` | `ecdsa-examples/ecdsa-sig-02`, `ecdsa-02` (ES384) |
| `esp512-*` | P-521 `bilbo.baggins@hobbiton.example` | `ecdsa-examples/ecdsa-sig-03`, `ecdsa-03` (ES512) |
| `ed25519-*` | Ed25519 `11` | `eddsa-examples/eddsa-sig-01`, `eddsa-01` (EdDSA) |
| `ed448-*` | Ed448 `ed448` | `eddsa-examples/eddsa-sig-02`, `eddsa-02` (EdDSA) |

The Brainpool identifiers ESB256/320/384/512 (-265 to -268) have no fixture here: python-cwt does not implement the
Brainpool curves. They are covered by the library's own vectors in
[`tests/Algorithm/Signature/FullySpecified/`](../../Algorithm/Signature/FullySpecified/).

## Files

The files follow the schema of cose-wg/Examples ([`../cose-wg/examples.cddl`](../cose-wg/examples.cddl)) and are
formatted the way upstream formats its own.

| Directory | Content | Specification |
|---|---|---|
| `fully-specified-examples/` | `<alg>-sig-01`: COSE_Sign1; `<alg>-01`: COSE_Sign with one signer; `<alg>-sig-fail-01`: the COSE_Sign1 with its last signature byte changed, flagged `"fail": true` | RFC 9864 §2.1, §2.2 |

`intermediates.ToBeSign_hex` is the Sig_structure computed with cbor2 from the protected header python-cwt emitted,
so that a failure names what diverged, the structure or the primitive — see `CoseWgFixtureTestCase`.

## Regenerating

```sh
python3 -m venv venv && venv/bin/pip install cwt
venv/bin/python3 generate.py
```

ECDSA is randomised: a new run gives new signatures for the `esp*` files. The `ed25519-*` and `ed448-*` files are
deterministic and must come out byte for byte the same. Update the table above with the versions of the run.

The suite over these files is [`tests/CoseWg/Rfc9864FixtureTest.php`](../../CoseWg/Rfc9864FixtureTest.php).
