# Signing and Verifying

[← Documentation index](README.md)

- [COSE_Sign1 (Single Signer)](#cose_sign1-single-signer)
  - [Creating a COSE_Sign1 Message](#creating-a-cose_sign1-message)
  - [Decoding and Verifying a COSE_Sign1 Message](#decoding-and-verifying-a-cose_sign1-message)
  - [What the application must check](#what-the-application-must-check)
- [COSE_Sign (Multiple Signers)](#cose_sign-multiple-signers)
- [Signature Verification Contract](#signature-verification-contract)
- [Verifying a Signature Made by a Certificate](#verifying-a-signature-made-by-a-certificate)

The signature algorithms themselves — ECDSA, EdDSA, RSA, the fully-specified identifiers of RFC 9864, ML-DSA — are listed
in [Algorithms](Algorithms.md#signature-algorithms); the keys they take in [Keys](Keys.md).

## COSE_Sign1 (Single Signer)

The `COSE_Sign1` structure is used when a message has a single signer.

### Creating a COSE_Sign1 Message

```php
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\HeaderMapHelper;

$algorithm = ES256::create();
$key = Ec2Key::create($yourPrivateCoseKey);

// Define headers
$protectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(1),                  // alg
        NegativeIntegerObject::create(ES256::identifier()) // ES256 (-7)
    ),
]);
$unprotectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(4),                  // kid
        ByteStringObject::create('my-key-id')
    ),
]);
$payload = ByteStringObject::create('Message to sign');

// The signature covers the Sig_structure, never the payload on its own. Encode the protected bucket once, so the
// bytes that are signed are the bytes the message carries. HeaderMapHelper applies RFC 9052 §3 on the way out: an
// empty map becomes h'' rather than h'a0', and the labels are checked (§1.5, §9).
$protectedHeaderAsBytes = HeaderMapHelper::encodeProtected($protectedHeader);
$toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);
$signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $key));

// Assemble the message around those exact bytes
$coseSign1 = CoseSign1Tag::create(ListObject::create([
    $protectedHeaderAsBytes,
    $unprotectedHeader,
    $payload,
    $signature,
]));

// Encode to CBOR
$encoded = (string) $coseSign1;
```

> [!NOTE]
> `CoseSign1Tag::createFromComponents($protectedHeader, $unprotectedHeader, $payload, $signature)` takes the protected
> header as a **map** and encodes it itself, which is shorter but re-encodes what you already signed. Use it when the
> signature is computed after the message, and `create()` — as above — when the bytes have to travel verbatim.
> [`examples/01-sign1.php`](../examples/01-sign1.php) is the whole round trip, key generation included, and runs as it
> stands.

### Decoding and Verifying a COSE_Sign1 Message

```php
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;

// The key of the signer you trust, and the algorithm you expect it to be used with.
$key = Ec2Key::create($theCoseKeyYouPinned);
$algorithm = ES256::create();
// The protected header labels this application knows how to process (1 = alg, 2 = crit).
$understoodLabels = [1, 2];

// cbor-php 3.4.0 registers the six COSE tags in the default decoder: tag 18 resolves on its own.
$coseSign1 = Decoder::create()->decode(new StringStream($encodedData));
if (! $coseSign1 instanceof CoseSign1Tag) {
    throw new RuntimeException('Not a COSE_Sign1 message');
}

// cbor-php carries the header buckets; this library reads them the way RFC 9052 defines them.
$headers = CoseHeaders::fromMessage($coseSign1);

// RFC 9052 §3.1: bind the signature to the algorithm the protected header declares.
// The label is matched by type as well as by value, so the text string "1" — a different label under §1.5 —
// never answers a lookup for the integer label 1.
$alg = $headers->getProtectedHeaderParameter(1);
if ($alg === null || (int) $alg->normalize() !== $algorithm::identifier()) {
    throw new RuntimeException('Unexpected or missing "alg" in the protected header');
}

// RFC 9052 §3.1: every parameter listed in "crit" must be processed, or the message must be rejected.
$crit = $headers->getProtectedHeaderParameter(2);
if ($crit !== null) {
    if (! $crit instanceof ListObject) {
        throw new RuntimeException('"crit" is not an array');
    }
    foreach ($crit as $label) {
        if (! in_array((int) $label->normalize(), $understoodLabels, true)) {
            throw new RuntimeException('Unsupported critical header parameter');
        }
    }
}

// RFC 9052 §4.2: a nil payload is detached and the application supplies the content itself.
$payload = $coseSign1->getPayload();
if ($payload instanceof NullObject) {
    throw new RuntimeException('The payload is detached; supply it from the application');
}

// Verify the Sig_structure the signature covers
$sigStructure = Signature1::create($coseSign1->getProtectedHeader(), $payload);
$isValid = $algorithm->verify((string) $sigStructure, $key, $coseSign1->getSignature()->getValue());
```

`tests/Signature/DocumentedVerifierTest.php` runs exactly this code, against a genuine ES256 message and against
messages crafted to exercise each check.

The other accessors of the message and of its headers:

```php
$protectedHeader = $coseSign1->getProtectedHeader();     // ByteStringObject: what the signature covers verbatim
$unprotectedHeader = $coseSign1->getUnprotectedHeader(); // MapObject
$signature = $coseSign1->getSignature();                 // ByteStringObject

$protectedHeaderMap = $headers->getProtectedHeaderAsMap(); // MapObject, checked
$kid = $headers->getHeaderParameter(4);                    // ?CBORObject, protected bucket first
```

### What the application must check

> [!IMPORTANT]
> The library verifies signatures; it does not decide what a message is allowed to say. Two checks
> [RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1) requires are therefore the caller's, and
> both are in the snippet above:
>
> - **`alg` (label 1)** — "This header parameter MUST be authenticated where the ability to do so exists". Read it
>   from the *protected* header, which the signature covers, and compare it with the algorithm you decided to accept
>   for that key. A verifier that hard-codes its algorithm and ignores the header still accepts a message that
>   announces a different one.
> - **`crit` (label 2)** — it lists the protected header parameters a recipient is *required* to understand. Any
>   label in that list your application does not process makes the message unusable: reject it instead of verifying
>   it.

When the algorithm is chosen from the message rather than pinned — `Manager::get()` on the `alg` read from the
header — a key that carries its own `alg` and `key_ops` can refuse a downgrade on its own, see
[Key Restrictions](Keys.md#key-restrictions-alg-and-key_ops).

## COSE_Sign (Multiple Signers)

The `COSE_Sign` structure supports multiple signatures from different signers.

```php
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\Tag\CoseSignTag;
use Cose\Signature\CoseSignature;

$protectedHeader = MapObject::create();
$unprotectedHeader = MapObject::create();
$payload = ByteStringObject::create('Document to be signed');

// Create signature structures for each signer
$signatures = ListObject::create([
    ListObject::create([
        ByteStringObject::create(''), // signature protected header
        MapObject::create([/* signer 1 unprotected header */]),
        ByteStringObject::create($signature1Bytes)
    ]),
    ListObject::create([
        ByteStringObject::create(''),
        MapObject::create([/* signer 2 unprotected header */]),
        ByteStringObject::create($signature2Bytes)
    ]),
]);

$coseSign = CoseSignTag::createFromComponents(
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $signatures
);

// Reading them back as checked views rather than raw lists
foreach (CoseSignature::all($coseSign->getSignatures()) as $signer) {
    $signerProtectedHeader = $signer->getProtectedHeader();   // ByteStringObject
    $kid = $signer->getUnprotectedHeaderParameter(4);         // ?CBORObject
    $signatureValue = $signer->getSignature();                // ByteStringObject
}
```

> [!IMPORTANT]
> Each signature of a `COSE_Sign` covers the `Signature` structure of
> [RFC 9052 §4.4](https://datatracker.ietf.org/doc/html/rfc9052#section-4.4), which carries the protected bucket of the
> message **and** the one of the signer's own entry — not the `Signature1` structure a `COSE_Sign1` uses:
>
> ```php
> use Cose\Signature\Signature;
>
> $toBeSigned = Signature::create(
>     $coseSign->getProtectedHeader(),   // body_protected
>     $signer->getProtectedHeader(),     // sign_protected
>     $coseSign->getPayload(),
> );
> $isValid = $algorithm->verify((string) $toBeSigned, $key, $signer->getSignature()->getValue());
> ```
>
> RFC 9052 §4.1 writes the list as `[+ COSE_Signature]`: at least one entry, each a `[bstr, map, bstr]` array. The CBOR
> layer only checks that the item is a list, so `CoseSignature::all()` is where that rule is applied — it rejects an
> empty list and any entry of another shape.

[`examples/02-sign-multiple-signers.php`](../examples/02-sign-multiple-signers.php) signs with two signers and shows
why `Signature` carries `sign_protected`.

A signature added *after* a message is finalized — a notary's, a timestamping service's — is a countersignature, not
another signer: it lives in the unprotected bucket and is computed over a different structure. See
[Countersignatures](Countersignatures.md). A signature over the digest of a payload kept elsewhere is a
[hash envelope](HashEnvelope.md).

## Signature Verification Contract

`Cose\Algorithm\Signature\Signature::verify()` is total for every condition the governing specifications define as an
"invalid signature" outcome. A malformed, truncated, over-long or out-of-range signature, and key material that the
crypto layer cannot decode — a point that is not on the named curve, a public key that is not a valid group element —
all return `false`. No PHP warning is raised on the way.

It throws an `InvalidArgumentException` when the key cannot be used with the algorithm at all: its key type or its
curve does not match, or — when the algorithm was asked to enforce them, see
[Key Restrictions](Keys.md#key-restrictions-alg-and-key_ops) — the key itself forbids the algorithm or the operation.
Structurally invalid key components — an empty or zero RSA modulus, an `x`, `y` or `d` whose length does not fit the
curve — are rejected earlier, by the `Key` constructors, so the exception is raised when the key is first seen rather
than at every verification.

```php
use Cose\Key\Key;
use InvalidArgumentException;

try {
    // Throws only when $key is an RSA key, an EC key on another curve, …
    $key = Key::createFromData($credentialPublicKey);
} catch (InvalidArgumentException $e) {
    // The credential cannot be used with this algorithm: reject it at registration.
}

// From here on, verification is a plain boolean, whatever the client sent.
$isValid = $algorithm->verify($data, $key, $signature);
```

`sign()` throws an `InvalidArgumentException` when the key is public, when the crypto layer cannot load it, or when the
signature operation itself fails, for instance for an RSA modulus too short for the digest.

## Verifying a Signature Made by a Certificate

WebAuthn Level 3 §8.2 to §8.4 ask a relying party to verify a packed (`x5c`), TPM or android-key attestation statement
"with the algorithm specified in `alg`", against the key of the attestation certificate. Going through
`Algorithms::getOpensslAlgorithmFor()` and `openssl_verify()` only reaches the algorithms an `OPENSSL_ALGO_*` digest
can describe — ECDSA and RSASSA-PKCS1-v1_5 — because that digest implies PKCS #1 v1.5 padding; RSASSA-PSS, EdDSA,
Ed25519 and Ed448 cannot be expressed that way at all. That is the documented scope of `Algorithms::COSE_ALGORITHM_MAP`
and of the accessor that reads it.

`Cose\Algorithm\Signature\CertificateSignatureVerifier` takes the other route: the key of the certificate becomes a
`Cose\Key\Key`, and the `Signature` class registered for the identifier verifies with it.

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\CertificateSignatureVerifier;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;
use Cose\Algorithm\Signature\RSA\PS256;

$manager = Manager::create()->add(ES256::create(), ES256K::create(), PS256::create(), Ed25519::create());
$verifier = CertificateSignatureVerifier::create($manager);

$isValid = $verifier->verify($alg, $certificatePem, $data, $signature);
```

The set of acceptable algorithms is the `Manager` the operator built, not a constant of this library: an `alg` that
comes from the wire cannot select a verifier that was never registered. `RS1` in particular is only reachable when an
`RS1` instance was registered, which can only be built by acknowledging what SHA-1 is.

The verifier configures nothing of its own, so every policy a registered algorithm carries applies unchanged: it is
that very instance which verifies, and the minimum modulus length an RSA algorithm was created with — see
[Validating RSA Keys](Keys.md#validating-rsa-keys) — is the one enforced against the key of the certificate.

```php
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\RsaKeyValidator;

// This RS256 refuses a certificate whose modulus is shorter than 3072 bits, through the verifier as anywhere else.
$manager = Manager::create()->add(RS256::create(RsaKeyValidator::create(minimumModulusLength: 3072)));
```

`verify()` returns `false` for every signature the algorithm rejects, and throws an `InvalidArgumentException` when the
certificate cannot be read, when no signature algorithm is registered for the identifier, or when the key of the
certificate cannot be used with that algorithm — the same contract as `Signature::verify()`.

When the certificate travels in the message, `verifyWithX5Chain()` takes the `x5chain` header parameter
([RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html)) as `CoseHeaders::getX5Chain()` returns it and verifies with
its end-entity certificate — see [X.509 Header Parameters](X509.md), and in particular what it says about validating
the rest of the chain.

When the certificate itself is not at hand, `verifySubjectPublicKeyInfo()` takes a SubjectPublicKeyInfo instead, and
`Cose\Key\PublicKeyLoader` exposes the conversion on its own, see
[Loading a Key from a Certificate](Keys.md#loading-a-key-from-a-certificate).
