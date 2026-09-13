# Countersignatures

[← Documentation index](README.md)

- [Countersigning](#countersigning)
- [Verifying](#verifying)
- [What Is Signed](#what-is-signed)

[RFC 9338](https://www.rfc-editor.org/rfc/rfc9338.html) defines a second signature over a finalized COSE structure,
carried in the unprotected bucket of that structure. It is what a notary or a timestamping service adds to a document
somebody else signed, and the building block of long-term archives, where a countersignature is countersigned in
turn. Any of the structures of RFC 9052 can be countersigned: a `COSE_Sign1`, a `COSE_Sign`, a `COSE_Signature`, a
`COSE_Encrypt`, a `COSE_Encrypt0`, a `COSE_recipient`, a `COSE_Mac` or a `COSE_Mac0`.

| Name | Label | Type | Reference | Accessor |
|---|---|---|---|---|
| `Countersignature version 2` | 11 (`CoseHeaders::LABEL_COUNTERSIGNATURE_V2`) | `COSE_Countersignature / [+ COSE_Countersignature]` | [RFC 9338 §2](https://www.rfc-editor.org/rfc/rfc9338#section-2) | `getCountersignatures(): CoseSignature[]` |
| `Countersignature0 version 2` | 12 (`CoseHeaders::LABEL_COUNTERSIGNATURE0_V2`) | `COSE_Countersignature0` (`bstr`) | [RFC 9338 §2](https://www.rfc-editor.org/rfc/rfc9338#section-2) | `getCountersignature0(): ?string` |

The **full form** (label 11) is a `COSE_Countersignature`, which is a `COSE_Signature` (§3.1): a `[protected,
unprotected, signature]` entry with headers of its own — its algorithm, its key identifier — carried bare or under
the CBOR tag 19. The value of the parameter is one of them or an array of one or more; `getCountersignatures()`
reads both into a list of `CoseSignature`. The **abbreviated form** (label 12) is the bare signature value: no
headers, "the parameters for computing or verifying the abbreviated countersignature are provided by the same
context used to describe the encryption, signature, or MAC processing" (§3.2).

## Countersigning

```php
use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\Countersigner;
use Cose\Signature\CountersignTarget;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

// The target: a finalized message. Its signature, tag or ciphertext is already computed.
$target = CountersignTarget::of($coseSign1);

// The countersigner's own headers: the algorithm in the protected bucket, as RFC 9052 §3.1 asks, and a key id.
$notaryHeaders = CoseHeaders::of(
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
    ])),
    MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('notary'))]),
);

$countersignature = Countersigner::sign($target, ES256::create(), $notaryPrivateKey, $notaryHeaders); // CoseSignature

// Into the unprotected bucket of the target, under label 11. The bucket is modified in place -- it is the one the
// message carries -- and the target's own signature does not cover it, so nothing else changes.
Countersigner::attach($coseSign1->getUnprotectedHeader(), $countersignature);
```

`attach()` writes the first countersignature on its own, turns the value into an array with the second, and appends
the following ones; `attach($bucket, $countersignature, tagged: true)` writes it under tag 19
(`Countersigner::tagged()` builds that on its own). `sign()` checks that an `alg` the headers carry is the algorithm
given. The abbreviated form is `sign0()`, which returns the bare value, and `attach0()`, which writes it under label
12:

```php
Countersigner::attach0($coseMac0->getUnprotectedHeader(), Countersigner::sign0($target, ES256::create(), $notaryPrivateKey));
```

## Verifying

```php
$target = CountersignTarget::of($decoded);                  // the same derivation, from the decoded message
foreach ($target->getCountersignatures() as $countersignature) {
    $alg = $manager->get((int) $countersignature->headers()->getHeaderParameter(1)->normalize());
    $kid = $countersignature->headers()->getHeaderParameter(4)?->normalize();
    $isValid = Countersigner::verify($target, $countersignature, $alg, $keyOf($kid));
}

$countersignature0 = $target->getCountersignature0();       // label 12, or null
$isValid = Countersigner::verify0($target, $countersignature0, $algorithmOfTheContext, $keyOfTheContext);
```

Both take the optional `external_aad` of RFC 9052 §4.4 as their last argument. `verify()` refuses a countersignature
whose `alg` differs from the algorithm given, and yields `false` for what does not verify; after it, RFC 9338 §3.3
leaves to the application the check "that the key is correctly paired with the signing identity and that the signing
identity is authorized" — the `kid` is a hint, not a proof.

## What Is Signed

The `Countersign_structure` of §3.3 depends on the target, and `CountersignTarget` encodes that rule once: the
second byte string of the target takes the `payload` slot, every later byte string goes into `other_fields`, and the
context string says whether `other_fields` is present:

| Target | payload | other_fields | Full context | Abbreviated context |
|---|---|---|---|---|
| `COSE_Sign1` | payload | `[signature]` | `CounterSignatureV2` | `CounterSignature0V2` |
| `COSE_Sign` | payload | — | `CounterSignature` | `CounterSignature0` |
| `COSE_Signature` (a countersignature too) | signature | — | `CounterSignature` | `CounterSignature0` |
| `COSE_Encrypt` | ciphertext | — | `CounterSignature` | `CounterSignature0` |
| `COSE_Encrypt0` | ciphertext | — | `CounterSignature` | `CounterSignature0` |
| `COSE_recipient` | ciphertext | — | `CounterSignature` | `CounterSignature0` |
| `COSE_Mac` | payload | `[tag]` | `CounterSignatureV2` | `CounterSignature0V2` |
| `COSE_Mac0` | payload | `[tag]` | `CounterSignatureV2` | `CounterSignature0V2` |

A detached payload or ciphertext is supplied by the application, `CountersignTarget::of($message, $detached)`, as
for the other structures. The abbreviated structure has no `sign_protected` field at all (§3.3: "This field is
omitted for the Countersignature0V2 attribute"), and the four context strings keep the forms apart: "the converted
structure will fail signature validation" (§3). For a target with two byte string fields the version 2 value is the
one an RFC 8152 countersigner produced — RFC 9338 §1 designed it so — which the `countersign/` fixtures of
cose-wg/Examples confirm; for the three-field targets the two differ, which is the point of the new version. The
to-be-signed bytes use the deterministic encoding RFC 9052 §9 narrows, as §4 requires, through the same
`CoseStructure` base as `Signature1`.

> [!IMPORTANT]
> Both labels are read from the **unprotected bucket only**, as §2 places them: a countersignature is applied after
> the target is finalized, so it cannot be under the target's own signature or tag. A message carrying label 11 or
> 12 in the protected bucket is rejected by the accessors. The RFC 8152 countersignatures (labels 7 and 9) are
> Deprecated at IANA and are not read; the `countersign/` and `countersign1/` fixtures of cose-wg/Examples, written
> for them, are reported as skipped by the test suite.

> [!WARNING]
> A countersignature over a `COSE_Mac`, `COSE_Mac0`, `COSE_Encrypt` or `COSE_Encrypt0` attests to the tag or the
> ciphertext, not to the plaintext (§3: "there is a distinction between attesting to the encrypted data as opposed to
> attesting to the unencrypted data"), and gives no more integrity than the tag has. RFC 9338 §6: "To provide 128-bit
> security against collision attacks, the tag length MUST be at least 256 bits. A countersignature of a COSE_Mac with
> AES-MAC (using a 128-bit key or larger) provides at most 64 bits of integrity protection. Similarly, a
> countersignature of a COSE_Encrypt with AES-CCM-16-64-128 provides at most 32 bits of integrity protection."
> Nothing in this library checks the tag length of the target: HMAC 256/256 and the AES-GCM algorithms qualify, the
> truncated HMAC 256/64, every AES-CBC-MAC and the 64-bit AES-CCM variants do not.

Only a signature algorithm *with appendix* can countersign (§3.1), the target having to be processed without the
countersignature; every signature algorithm of this library is one. The six examples of RFC 9338 Appendix A are
verified by `tests/CoseWg/Rfc9338FixtureTest.php`, and [`examples/15-countersignatures.php`](../examples/15-countersignatures.php)
runs the whole of this: a notary countersigning a `COSE_Sign1`, an archive countersigning the countersignature, an
abbreviated countersignature on a `COSE_Mac0`.
