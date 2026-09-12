# RFC 9162 Merkle proof vectors

Verification probes for the inclusion and consistency proofs of the binary Merkle Tree of
[RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1) — the `RFC9162_SHA256` verifiable data structure
of [RFC 9942 §5](https://www.rfc-editor.org/rfc/rfc9942#section-5) — vendored from the Certificate Transparency
implementation of Google / the transparency.dev team, <https://github.com/transparency-dev/merkle>.

| | |
|---|---|
| Upstream commit | [`a09734cdbeb471b1dac7760f893665483661320b`](https://github.com/transparency-dev/merkle/tree/a09734cdbeb471b1dac7760f893665483661320b) (2026-09-10) |
| Upstream path | `testdata/inclusion/`, `testdata/consistency/` |
| Licence | [Apache License 2.0](LICENSE) |

The files are copied as they are: nothing in them is edited, reformatted or renamed. RFC 9942 itself publishes no
test vectors and elides the middle bytes of every hash of its EDN examples, so these are the vectors of record for
the algorithms of RFC 9162 §2.1.3.2 and §2.1.4.2: the eight leaves are the classic RFC 6962 inputs (`""`, `00`,
`10`, `2021`, `3031`, `40414243`, `5051…57`, `6061…6f`), and each happy path is surrounded by its mutations — a
flipped bit in a node, a node inserted, removed or duplicated, the leaf index or a tree size moved, the roots swapped
or replaced, garbage before or after the path.

## Files

Each JSON file is one probe. The byte strings are base64.

| Directory | Fields | Meaning |
|---|---|---|
| `inclusion/<n>/` | `leafIdx`, `treeSize`, `leafHash`, `proof`, `root`, `wantErr` | Does `proof` lead from `leafHash` at `leafIdx` in a tree of `treeSize` to `root`? |
| `consistency/<n>/` | `size1`, `size2`, `root1`, `root2`, `proof`, `wantErr` | Does `proof` bind the tree head `root1` of size `size1` to the tree head `root2` of size `size2`? |

`leafHash` is the leaf hash `HASH(0x00 ‖ entry)`, not the entry: the probes exercise the path walk, not the leaf
hashing, which is why the harness feeds them to `verifyLeafHash()` rather than to `verify()`.

## Two probes the harness reads differently

The upstream verifier extends the algorithms beyond the domain the RFC defines them on, and two probes rely on it:

- `consistency/0/happy-path.json` and `consistency/additional/sizes-are-equal-one-and-proof-is-empty.json` ask for
  a consistency proof between two trees **of the same size** with an **empty** path to verify. RFC 9162 §2.1.4.2 is
  defined for `0 < first < second` and its first step is "If consistency_path is an empty array, stop and fail the
  proof verification"; the CDDL of RFC 9942 §5.3 writes the path as `[ + bstr ]`. Such a proof cannot be built
  here — `create()` and `fromCBOR()` refuse an empty path — and the harness asserts that refusal instead of a
  positive verification.

Every other probe, `wantErr` or not, is asserted as upstream states it. A probe whose index or size exceeds the
platform integer range (`leafIdx: 18446744073709551615`) is asserted through the CBOR decoder, which is where such a
value is refused.

The suite over these files is
[`tests/Structure/VerifiableDataStructure/Rfc9162FixtureTest.php`](../../Structure/VerifiableDataStructure/Rfc9162FixtureTest.php).
