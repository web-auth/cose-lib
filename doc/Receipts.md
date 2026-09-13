# COSE Receipts

[← Documentation index](README.md)

> [!IMPORTANT]
> **No trust in a receipt issuer is established by this library.** [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html)
> defines how a COSE message carries the receipts of a transparency service and how a receipt proves that an entry is
> in the service's log. This library reads the receipts, walks their proofs and verifies their signature with the key
> *you* hand it. A `true` result means exactly this: **the entry is a leaf of a tree whose head the holder of that key
> signed.** It does not mean the key belongs to a service you should trust, that the service shows the same tree to
> everyone, or that the receipt is still valid — RFC 9942 §7.2 and §7.3 leave validity periods and status to the
> application, and so does this library.

- [The Three Parameters](#the-three-parameters)
- [RFC9162_SHA256](#rfc9162_sha256)
- [What Follows from the RFC](#what-follows-from-the-rfc)

## The Three Parameters

A receipt (RFC 9942 §3) is a `COSE_Sign1` whose payload is the Merkle Tree Hash of a log and whose headers carry the
proofs relating an entry, or an older tree, to that tree head. Three header parameters carry the pieces:

| Name | Label | Type | Reference | Accessor |
|---|---|---|---|---|
| `receipts` | 394 (`CoseHeaders::LABEL_RECEIPTS`) | `[+ bstr .cbor Receipt]` | [RFC 9942 §2](https://www.rfc-editor.org/rfc/rfc9942#section-2) | `getReceipts(): list<CoseSign1Tag>` |
| `vds` | 395 (`CoseHeaders::LABEL_VDS`) | `int` | [RFC 9942 §2](https://www.rfc-editor.org/rfc/rfc9942#section-2) | `getVds(): ?int` |
| `vdp` | 396 (`CoseHeaders::LABEL_VDP`) | `map` | [RFC 9942 §2](https://www.rfc-editor.org/rfc/rfc9942#section-2) | `getVdp(): ?MapObject` |

- **`getReceipts()`** returns the receipts a message carries, in the order they are carried, as
  `CBOR\Tag\CoseSign1Tag` instances, or an empty list when there are none. The parameter is looked up in the
  protected bucket first, then in the unprotected one (§4.3 registers it "in the protected and unprotected headers";
  the example of the RFC puts it in the unprotected bucket of a statement signed before any receipt existed). Each
  entry is a byte string wrapping exactly one CBOR data item — trailing bytes make it malformed — and "Receipts MUST
  be tagged as COSE_Sign1" (§4.3): an entry that decodes to anything but a tag 18 is rejected. A receipt decoded by a
  decoder that does not register the class, as a `GenericTag` 18, is rebuilt as the typed message.
- **`getVds()`** reads the identifier of the verifiable data structure from the **protected bucket only**, where
  §5.2.1 and §5.3.1 require it ("The VDS in the protected header is necessary to understand the inclusion proof
  structure"). The value is handed back as carried; whether it is registered is checked where the proofs are read.
- **`getVdp()`** returns the proof map as it travels, its keys checked to be labels, nothing read into the proofs.
  The CDDL of §5 places it in the unprotected header of the receipt — a proof gains nothing from the signature, since
  the tree head it leads to is what the signature covers — and a protected one is read too, first.

## RFC9162_SHA256

The one structure the IANA "COSE Verifiable Data Structure Algorithms" registry lists is **`RFC9162_SHA256`**
(`vds` = 1): the SHA-256 binary Merkle Tree of [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1),
with two proof types in the "COSE Verifiable Data Structure Proofs" registry, inclusion (`vdp` label -1) and
consistency (label -2). The classes live in `Cose\Structure\VerifiableDataStructure`:

- **`Rfc9162Sha256`** is the structure: `leafHash()` (`HASH(0x00 ‖ entry)`), `nodeHash()` (`HASH(0x01 ‖ left ‖ right)`),
  `emptyTreeHash()` and `treeHash(...$entries)`, the Merkle Tree Hash of a whole list of entries by the stack
  algorithm of RFC 9162 §2.1.2; and `inclusionProofs($receiptHeaders)` / `consistencyProofs($receiptHeaders)`, which
  check that the receipt names this structure and that every key of its `vdp` is a registered label before decoding
  the proofs — RFC 9942 §4.3: "the verifier MUST confirm that the associated VDS and VDPs match entries present in the
  registries". An unregistered `vds` or proof label is an error, never skipped.
- **`Rfc9162Sha256InclusionProof`** is `inclusion-proof-content = [ tree-size: uint, leaf-index: uint, inclusion-path:
  [ + bstr ] ]` (§5.2), wrapped in a byte string. `root($entry)` applies the proof to the bytes of a candidate entry
  and returns the tree head it leads to — the payload of the receipt — or `null` when it leads nowhere: a `leaf-index`
  at or beyond `tree-size` ("then fail the proof verification", RFC 9162 §2.1.3.2 step 1), a path that does not fit
  the shape of the tree. `verify($entry, $root)` compares with a tree head you hold, with `hash_equals()`;
  `rootFromLeafHash()` and `verifyLeafHash()` take the leaf hash instead of the entry. Every node is checked to be 32
  bytes on decode.
- **`Rfc9162Sha256ConsistencyProof`** is `consistency-proof-content = [ tree-size-1: uint, tree-size-2: uint,
  consistency-path: [ + bstr ] ]` (§5.3). `newerRoot($olderRoot)` applies RFC 9162 §2.1.4.2 to the older tree head and
  returns the newer one the proof binds it to — the payload of a receipt of consistency — or `null`;
  `verify($olderRoot, $newerRoot)` compares. The algorithm is defined for `0 < older < newer` and fails outside it.
- **`ReceiptVerifier`** is the two-step verification of §5.2 as one boolean, resolved through the `Manager` of the
  application so that the `alg` of the receipt cannot select a verifier the operator did not register:

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Structure\CoseHeaders;
use Cose\Structure\VerifiableDataStructure\ReceiptVerifier;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;

$verifier = ReceiptVerifier::create(Manager::create()->add(ES256::create()));

foreach (CoseHeaders::fromMessage($signedStatement)->getReceipts() as $receipt) {   // CBOR\Tag\CoseSign1Tag
    $headers = CoseHeaders::fromMessage($receipt);
    $headers->getVds();                                     // 1 — Rfc9162Sha256::IDENTIFIER
    $issuerKey = $yourKeyResolver($headers);                // by kid, by x5chain … the trust decision is yours

    // §5.2: apply the proof to the entry; the tree head it leads to becomes the payload; verify the signature over it.
    $isIncluded = $verifier->verifyInclusion($receipt, $entry, $issuerKey);

    // §5.3.1, for a receipt of consistency: the older tree head is one you hold from an earlier receipt.
    $isAppendOnly = $verifier->verifyConsistency($receipt, $olderTreeHead, $issuerKey);
}

// The pieces, when you want them apart:
$proofs = Rfc9162Sha256::inclusionProofs($headers);         // list<Rfc9162Sha256InclusionProof>
$treeHead = $proofs[0]->root($entry);                       // 32 bytes, or null when the proof leads nowhere
```

## What Follows from the RFC

Four points that follow from the RFC:

- **The payload is the tree head, and should be detached.** §4.4: "Detached payloads force verifiers to recompute
  the root from the proof and protect against implementation errors where the signature is verified but the payload
  is incompatible with the proof." `ReceiptVerifier` always verifies the signature over the tree head the proof led
  to; when the receipt does carry a payload, it has to be that tree head or the receipt fails.
- **Several proofs, one receipt.** `[ + inclusion-proof ]` allows several; the receipt verifies as soon as one of them
  leads from the entry to a tree head the signature covers. A receipt may also carry both proof types (§3).
- **The tree size is not signed.** RFC 9942 signs the tree head alone; `tree-size` steers the walk of the proof and
  is not otherwise bound. A receipt proves inclusion under the signed tree head, not the size of the log at that
  moment — the size, and what it reveals (§6.1), is the issuer's word.
- **An empty inclusion path is accepted.** The CDDL of §5.2 writes `[ + bstr ]`, while RFC 9162 §2.1.3.1, which §5.2
  points to for "a complete description of this VDS Proof Type", defines the proof of the only leaf of a one-entry
  tree as empty. The decoder follows RFC 9162; the verification then succeeds for a tree of size one and nothing
  else. A consistency path, by contrast, is never empty (RFC 9162 §2.1.4.2 step 1).

What the library does not do: it produces no proof (a transparency service written in PHP would need `PATH` and
`PROOF` of RFC 9162 §2.1.3.1 and §2.1.4.1, which the test suite implements for its own checks), it fetches nothing,
and it decides nothing about `crit` (RFC 9052 §3.1), the validity period (§7.2) or the status (§7.3) of a receipt.

The verification is checked against the 186 inclusion and consistency probes of the Certificate Transparency
implementation [transparency-dev/merkle](https://github.com/transparency-dev/merkle), vendored under
[`tests/fixtures/rfc9162/`](../tests/fixtures/rfc9162/), and against proofs generated from the definitions of RFC
9162 for every leaf of every tree size up to 40. [`examples/17-receipts.php`](../examples/17-receipts.php) issues and
verifies a receipt of inclusion and a receipt of consistency over the eight-leaf CT test tree.
