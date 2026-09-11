# How to Use COSE Library

This library implements COSE (CBOR Object Signing and Encryption) as defined in [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) and [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053): the COSE key types, the signature and MAC algorithms, the cryptographic structures a signature or a MAC is computed over, and the header rules that decide what a message says. It also implements the algorithms and the key type that [RFC 8230](https://datatracker.ietf.org/doc/html/rfc8230) (RSASSA-PSS, RSA keys), [RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) (RSASSA-PKCS1-v1_5, secp256k1) and [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) (fully-specified identifiers) add to COSE, and the header parameters of [RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html) (`typ`) and [RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html) (CWT Claims). Every algorithm and key type table of this guide carries a *Reference* column naming the RFC and the section that define the row.

The six COSE message types themselves come from [spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0 or later, as `CBOR\Tag\CoseSign1Tag` and its siblings. The `Cose\...Tag` classes this library used to ship are deprecated since 4.8.0 and removed in 5.0.0 — see [Upgrading from the Cose\...Tag classes](#upgrading-from-the-cosetag-classes).

Content encryption itself is not implemented: the encryption tags carry a ciphertext the application produced, and `Enc_structure` gives that application the additional authenticated data to feed its AEAD.

## Table of Contents

- [Installation](#installation)
- [COSE Tags](#cose-tags)
- [Cryptographic Structures](#cryptographic-structures)
- [Reading Headers](#reading-headers)
  - [`typ` and `CWT Claims`](#typ-and-cwt-claims)
- [Signature Operations](#signature-operations)
  - [COSE_Sign1 (Single Signer)](#cose_sign1-single-signer)
  - [COSE_Sign (Multiple Signers)](#cose_sign-multiple-signers)
- [Encryption Operations](#encryption-operations)
  - [COSE_Encrypt0 (Single Recipient)](#cose_encrypt0-single-recipient)
  - [COSE_Encrypt (Multiple Recipients)](#cose_encrypt-multiple-recipients)
- [MAC Operations](#mac-operations)
  - [COSE_Mac0 (Without Recipients)](#cose_mac0-without-recipients)
  - [COSE_Mac (With Recipients)](#cose_mac-with-recipients)
- [CBOR Web Tokens (CWT)](#cbor-web-tokens-cwt)
- [Detached Content](#detached-content)
- [External Additional Authenticated Data](#external-additional-authenticated-data)
- [Upgrading from the Cose\...Tag classes](#upgrading-from-the-cosetag-classes)
- [Supported Algorithms](#supported-algorithms)
  - [Fully-Specified Algorithms](#fully-specified-algorithms)
  - [Signature Verification Contract](#signature-verification-contract)
  - [Key Restrictions (alg and key_ops)](#key-restrictions-alg-and-key_ops)
  - [Key Types](#key-types)
  - [Ed25519 Private Keys](#ed25519-private-keys)
  - [Key Parameter Forms](#key-parameter-forms)
  - [Validating RSA Keys](#validating-rsa-keys)
  - [Registering Algorithms](#registering-algorithms)
  - [Verifying a Signature Made by a Certificate](#verifying-a-signature-made-by-a-certificate)
  - [Validating Symmetric Keys](#validating-symmetric-keys)

## Installation

```bash
composer require web-auth/cose-lib
```

For COSE tag support, you also need:

```bash
composer require "spomky-labs/cbor-php:^3.3.4"
```

3.3.4 is the floor this library declares (`conflict: <3.3.4`). The CBOR decoder is what enforces the header-map rules
of RFC 9052: [§3](https://datatracker.ietf.org/doc/html/rfc9052#section-3) and
[§9](https://datatracker.ietf.org/doc/html/rfc9052#section-9) make a message malformed when a label appears twice in a
map, and the decoder bounds the nesting depth so that a crafted header cannot exhaust the memory of the process.
Nothing in this library re-checks either rule.

Every Ed25519 algorithm needs `ext-sodium`, which ships with PHP and is enabled by default; see
[Signature Algorithms](#signature-algorithms) for what happens on a build without it.

## COSE Tags

COSE defines six main tags for different cryptographic operations:

| Tag | Value | Class (cbor-php 3.4.0+) | Description |
|-----|-------|--------------------------|-------------|
| COSE_Encrypt0 | 16 | `CBOR\Tag\CoseEncrypt0Tag` | Single recipient encrypted message |
| COSE_Mac0 | 17 | `CBOR\Tag\CoseMac0Tag` | MAC without recipients |
| COSE_Sign1 | 18 | `CBOR\Tag\CoseSign1Tag` | Single signature structure |
| CWT | 61 | `CBOR\Tag\CwtTag` | CBOR Web Token ([RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392)) |
| COSE_Encrypt | 96 | `CBOR\Tag\CoseEncryptTag` | Multiple recipients encrypted message |
| COSE_Mac | 97 | `CBOR\Tag\CoseMacTag` | MAC with recipients |
| COSE_Sign | 98 | `CBOR\Tag\CoseSignTag` | Multiple signatures structure |

All seven are registered in the default decoder, so `Decoder::create()` resolves them without any `TagManager`
configuration.

## Cryptographic Structures

A COSE signature or MAC never covers the payload on its own. It covers a **structure** that also binds the protected
header and the message type, so a tag computed for a `COSE_Mac0` cannot be replayed on a `COSE_Mac`, and a signature
made for one signer of a `COSE_Sign` cannot be lifted into a `COSE_Sign1`. These structures are what this library
builds; casting one to string yields the CBOR bytes to hand to the algorithm.

| RFC 9052 | Class | Context | Fields after the context |
|---|---|---|---|
| §4.4 `Sig_structure` | `Cose\Signature\Signature1` | `"Signature1"` | body_protected, external_aad, payload |
| §4.4 `Sig_structure` | `Cose\Signature\Signature` | `"Signature"` | body_protected, **sign_protected**, external_aad, payload |
| §6.3 `MAC_structure` | `Cose\Mac\Mac0Structure` | `"MAC0"` | protected, external_aad, payload |
| §6.3 `MAC_structure` | `Cose\Mac\MacStructure` | `"MAC"` | protected, external_aad, payload |
| §5.3 `Enc_structure` | `Cose\Encryption\Encrypt0Structure` | `"Encrypt0"` | protected, external_aad |
| §5.3 `Enc_structure` | `Cose\Encryption\EncryptStructure` | `"Encrypt"` | protected, external_aad |
| §5.3 `Enc_structure` | `RecipientStructure::forEncryptRecipient()` | `"Enc_Recipient"` | protected, external_aad |
| §5.3 `Enc_structure` | `RecipientStructure::forMacRecipient()` | `"Mac_Recipient"` | protected, external_aad |
| §5.3 `Enc_structure` | `RecipientStructure::forNestedRecipient()` | `"Rec_Recipient"` | protected, external_aad |

```php
use Cose\Mac\Mac0Structure;
use Cose\Signature\Signature1;

// Signing and verifying a COSE_Sign1
$toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);
$signature = $algorithm->sign((string) $toBeSigned, $privateKey);
$isValid = $algorithm->verify((string) $toBeSigned, $publicKey, $signature);

// Authenticating a COSE_Mac0 — the same shape, a different context string
$toBeMaced = Mac0Structure::create($protectedHeaderAsBytes, $payload);
$macTag = $macAlgorithm->hash((string) $toBeMaced, $symmetricKey);
```

> [!WARNING]
> `Cose\Algorithm\Mac\Mac::hash()` and `verify()` authenticate exactly the bytes they are given. Passing
> `getPayload()->getValue()` straight to them produces a tag bound to no header, no algorithm and no message type,
> which no other implementation will accept.

The protected header is passed as the **byte string the message carries**, not as a map: the structure has to embed
it verbatim, or the signature no longer verifies. `HeaderMapHelper::encodeProtected()` produces those bytes from a
map, applying the RFC 9052 §3 rules on the way out.

There is one exception, and the structures apply it themselves. §3 lets a sender write an empty protected bucket
either as the zero-length byte string `h''` or as an empty map wrapped in a byte string, `h'a0'`, and requires
recipients to accept both; §§4.4, 5.3 and 6.3 then define the protected field of every structure with "If there are
no protected attributes, a zero-length byte string is used". A message carrying `h'a0'` is therefore verified over
`h''` — the bytes its sender computed — whichever form travels on the wire. `CoseStructure::emptyOrSerializedMap()`
is that rule, and only `h'a0'` is affected: a non-empty bucket is never re-encoded.

Every structure takes the optional `external_aad` of §4.4 as its last argument, defaulting to the zero-length byte
string the RFC prescribes:

```php
$toBeSigned = Signature1::create(
    $protectedHeaderAsBytes,
    $payload,
    ByteStringObject::create($applicationSuppliedData),
);
```

## Reading Headers

cbor-php carries the two header buckets; RFC 9052 decides what they mean. `Cose\Structure\CoseHeaders` applies the
second part to any COSE message:

```php
use Cose\Structure\CoseHeaders;

$headers = CoseHeaders::fromMessage($coseSign1);   // any CBOR\Tag\Cose*Tag

$headers->getProtectedHeaderParameter(1);          // ?CBORObject — protected bucket only
$headers->getUnprotectedHeaderParameter(4);        // ?CBORObject — unprotected bucket only
$headers->getHeaderParameter(1);                   // ?CBORObject — protected first, then unprotected
$headers->getProtectedHeaderAsMap();               // MapObject, decoded and checked
```

What it enforces, and why the raw `MapObject` accessors are not enough:

- **A label is an integer *or* a text string** ([§1.5](https://datatracker.ietf.org/doc/html/rfc9052#section-1.5)),
  and the two are different labels. cbor-php normalizes the integer `1`, the text string `"1"` and the byte string
  `h'31'` to the same map offset, so `$map->has(1)` answers `true` for all three. `getProtectedHeaderParameter(1)`
  matches the type as well, and only the integer `1` is the algorithm parameter.
- **A byte-string key is not a label at all** and makes the header malformed.
- **The zero-length protected header is accepted** ([§3](https://datatracker.ietf.org/doc/html/rfc9052#section-3):
  "Recipients MUST accept both a zero-length byte string and a zero-length map encoded in a byte string"), and
  **trailing bytes inside the protected bucket are not** — the CDDL `bstr .cbor header_map` holds exactly one item.
- **The protected bucket wins a combined lookup**, because that is the value the signature or the MAC commits to.

For a per-signer or per-recipient bucket, `CoseSignature` and `CoseRecipient` expose the same lookups; for a header
map you assembled yourself, use `CoseHeaders::of($protectedBytes, $unprotectedMap)`.

The protected header is decoded with a decoder bounded to `CoseHeaders::DEFAULT_PROTECTED_HEADER_MAX_DEPTH` (32)
levels of nesting. Pass your own `Decoder` when a header carries custom CBOR tags, or a different `$maxDepth`:

```php
$headers = CoseHeaders::fromMessage($coseSign1, $customDecoder);
```

### `typ` and `CWT Claims`

Two header parameters have a typed accessor, because each comes with a rule of its own that a raw lookup cannot
apply:

| Name | Label | Type | Reference | Accessor |
|---|---|---|---|---|
| `typ` (type) | 16 (`CoseHeaders::LABEL_TYP`) | `uint / tstr` | [RFC 9596 §2](https://www.rfc-editor.org/rfc/rfc9596#section-2) | `getTyp(): int\|string\|null` |
| `CWT Claims` | 15 (`CoseHeaders::LABEL_CWT_CLAIMS`) | `map` | [RFC 9597 §2](https://www.rfc-editor.org/rfc/rfc9597#section-2) | `getCwtClaims(): ?MapObject` |

```php
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

$headers = CoseHeaders::fromMessage($coseSign1);

$typ = $headers->getTyp();                 // "application/cwt", 61, or null — protected bucket only
$claims = $headers->getCwtClaims();        // MapObject or null — protected bucket first
$issuer = $claims === null ? null : HeaderMapHelper::findLabel($claims, 1)?->normalize();
```

**`typ`** names the whole COSE object, as opposed to `content type` (label 3), which names its payload. An unsigned
integer is a CoAP Content-Format identifier (0–65535, [RFC 7252 §12.3](https://www.rfc-editor.org/rfc/rfc7252#section-12.3));
a text string is a media type name, `<type-name>/<subtype-name>` per
[RFC 6838 §4.2](https://www.rfc-editor.org/rfc/rfc6838#section-4.2) with no leading or trailing whitespace — the
syntax of `content type` in [RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1), which
[RFC 9596 §2](https://www.rfc-editor.org/rfc/rfc9596#section-2) adopts — and "MAY include media type parameters".
`"application/cwt"` and `61` both say CWT; a bare `"cwt"` is rejected, because unlike JOSE, RFC 9596 defines no
`application/` shorthand to expand it with.

RFC 9596 §2: "The 'typ' parameter MUST NOT be present in unprotected headers." `getTyp()` reads the protected bucket
only and throws when the label is found in the unprotected one, whatever the protected bucket says. The raw
`getProtectedHeaderParameter(CoseHeaders::LABEL_TYP)` is the lenient form: it never looks at the unprotected bucket
and hands the value back unchecked. What to do with the value — typically, compare it with the media type the
application expects and refuse anything else — is left to the application by the RFC.

**`CWT Claims`** carries CWT claims ([RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392)) in the header, so
that they can be read without decoding the payload, or when there is no payload to carry them in. The accessor hands
back the map as it travels, with every key checked to be a `Claim-Label` (`int / text`, the same rule as a header
label) and nothing read into the claims themselves. It looks in the protected bucket first, then in the unprotected
one — [RFC 9597 §2](https://www.rfc-editor.org/rfc/rfc9597#section-2) only *recommends* the protected bucket, "to
avoid the contents being malleable" — and throws when the parameter appears in both: "The header parameter MUST only
occur once in either the protected or unprotected header of a COSE structure."

> [!IMPORTANT]
> RFC 9597 §2: when a claim is present both in the header and in the payload, "an application receiving such a
> structure MUST verify that their values are identical". The library cannot do this for you — the payload is opaque
> to it — so the comparison is yours to make once the signature has been verified;
> [`examples/08-cwt.php`](../examples/08-cwt.php) shows it claim by claim.

## Signature Operations

### COSE_Sign1 (Single Signer)

The `COSE_Sign1` structure is used when a message has a single signer.

#### Creating a COSE_Sign1 Message

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
> [`examples/01-sign1.php`](examples/01-sign1.php) is the whole round trip, key generation included, and runs as it
> stands.

#### Decoding and Verifying a COSE_Sign1 Message

```php
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;

// Decode CBOR data — the COSE tags are in the default decoder since cbor-php 3.4.0
$stream = new StringStream($encodedData);
$coseSign1 = Decoder::create()->decode($stream);

// Access components
$protectedHeader = $coseSign1->getProtectedHeader(); // ByteStringObject: what the signature covers verbatim
$unprotectedHeader = $coseSign1->getUnprotectedHeader(); // MapObject
$payload = $coseSign1->getPayload(); // ByteStringObject, or NullObject when detached
$signature = $coseSign1->getSignature(); // ByteStringObject

// The headers, read the way RFC 9052 defines them
$headers = CoseHeaders::fromMessage($coseSign1);
$protectedHeaderMap = $headers->getProtectedHeaderAsMap(); // MapObject, checked
$alg = $headers->getProtectedHeaderParameter(1);           // ?CBORObject
$kid = $headers->getHeaderParameter(4);                    // ?CBORObject, protected bucket first

// The key of the signer you trust, and the algorithm you expect it to be used with
$key = Ec2Key::create($theCoseKeyYouPinned);
$algorithm = ES256::create();
// The protected header labels this application knows how to process (1 = alg, 2 = crit)
$understoodLabels = [1, 2];

// RFC 9052 §3.1: bind the signature to the algorithm the protected header declares
// The label is matched by type as well as by value, so the text string "1" — a different label under §1.5 —
// never answers a lookup for the integer label 1.
$alg = $headers->getProtectedHeaderParameter(1);
if ($alg === null || (int) $alg->normalize() !== $algorithm::identifier()) {
    throw new RuntimeException('Unexpected or missing "alg" in the protected header');
}

// RFC 9052 §3.1: every parameter listed in "crit" must be processed, or the message must be rejected
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

// Create Sig_structure and verify the signature it covers
$sigStructure = Signature1::create($coseSign1->getProtectedHeader(), $coseSign1->getPayload());
$isValid = $algorithm->verify((string) $sigStructure, $key, $coseSign1->getSignature()->getValue());
```

`tests/Signature/DocumentedVerifierTest.php` runs exactly this code, against a genuine ES256 message and against
messages crafted to exercise each check.

##### What the application must check

The library verifies signatures; it does not decide what a message is allowed to say. Two checks
[RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1) requires are therefore the caller's, and
both are in the snippet above:

- **`alg` (label 1)** — "This header parameter MUST be authenticated where the ability to do so exists". Read it from
  the *protected* header, which the signature covers, and compare it with the algorithm you decided to accept for
  that key. A verifier that hard-codes its algorithm and ignores the header still accepts a message that announces a
  different one.
- **`crit` (label 2)** — it lists the protected header parameters a recipient is *required* to understand. Any label
  in that list your application does not process makes the message unusable: reject it instead of verifying it.

The protected header is decoded with a decoder bounded to `CoseHeaders::DEFAULT_PROTECTED_HEADER_MAX_DEPTH` (32)
levels of nesting. Pass your own `Decoder` when a header carries custom CBOR tags, or a different `$maxDepth` when 32
is not the right bound:

```php
// Use a custom decoder for the protected header (e.g. with custom CBOR tags)
$customDecoder = Decoder::create(
    TagManager::create()->add(MyCustomTag::class),
    OtherObjectManager::create(),
    32
);
$headers = CoseHeaders::fromMessage($coseSign1, $customDecoder);
```

### COSE_Sign (Multiple Signers)

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

## Encryption Operations

### COSE_Encrypt0 (Single Recipient)

```php
use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\Tag\CoseEncrypt0Tag;

$protectedHeader = MapObject::create([/* algorithm, etc. */]);
$unprotectedHeader = MapObject::create([/* IV, kid, etc. */]);
$ciphertext = ByteStringObject::create($encryptedData);

$coseEncrypt0 = CoseEncrypt0Tag::createFromComponents(
    $protectedHeader,
    $unprotectedHeader,
    $ciphertext
);
```

### COSE_Encrypt (Multiple Recipients)

```php
use CBOR\ListObject;
use CBOR\Tag\CoseEncryptTag;
use Cose\Structure\CoseRecipient;

$recipients = ListObject::create([
    ListObject::create([/* recipient 1 structure */]),
    ListObject::create([/* recipient 2 structure */]),
]);

$coseEncrypt = CoseEncryptTag::createFromComponents(
    $protectedHeader,
    $unprotectedHeader,
    $ciphertext,
    $recipients
);

// Reading them back as checked views; a recipient may carry recipients of its own
foreach (CoseRecipient::all($coseEncrypt->getRecipients()) as $recipient) {
    $kid = $recipient->getUnprotectedHeaderParameter(4);
    $wrappedKey = $recipient->hasDetachedCiphertext() ? null : $recipient->getCiphertext();
    $nested = $recipient->getRecipients(); // list<CoseRecipient>
}
```

> [!IMPORTANT]
> The additional authenticated data of the content encryption is the `Enc_structure` of
> [RFC 9052 §5.3](https://datatracker.ietf.org/doc/html/rfc9052#section-5.3), not the protected header on its own:
>
> ```php
> use Cose\Encryption\Encrypt0Structure;
> use Cose\Encryption\EncryptStructure;
> use Cose\Encryption\RecipientStructure;
>
> $aad = (string) EncryptStructure::create($coseEncrypt->getProtectedHeader());               // "Encrypt"
> $aad = (string) Encrypt0Structure::create($coseEncrypt0->getProtectedHeader());             // "Encrypt0"
> $aad = (string) RecipientStructure::forEncryptRecipient($recipient->getProtectedHeader());  // "Enc_Recipient"
> ```
>
> RFC 9052 §5.1 writes the list as `[+COSE_recipient]`: at least one entry, each a
> `[bstr, map, bstr / nil, ? [+ COSE_recipient]]` array. `CoseRecipient::all()` applies that rule, nested levels
> included.

## MAC Operations

### COSE_Mac0 (Without Recipients)

```php
use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\Tag\CoseMac0Tag;

$protectedHeader = MapObject::create([/* algorithm */]);
$unprotectedHeader = MapObject::create();
$payload = ByteStringObject::create('Data to authenticate');
$tag = ByteStringObject::create($macTag);

$coseMac0 = CoseMac0Tag::createFromComponents(
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $tag
);
```

### COSE_Mac (With Recipients)

```php
use CBOR\ListObject;
use CBOR\Tag\CoseMacTag;

$recipients = ListObject::create([/* recipient structures */]);

$coseMac = CoseMacTag::createFromComponents(
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $tag,
    $recipients
);
```

> [!IMPORTANT]
> The `$macTag` of both examples above is **not** a MAC of the payload. It is computed over the `MAC_structure` of
> [RFC 9052 §6.3](https://datatracker.ietf.org/doc/html/rfc9052#section-6.3), which binds the tag to the protected
> header and to the message type:
>
> ```php
> use Cose\Mac\Mac0Structure;
> use Cose\Mac\MacStructure;
>
> // COSE_Mac0: context "MAC0"
> $toBeMaced = Mac0Structure::create($coseMac0->getProtectedHeader(), $coseMac0->getPayload());
> $macTag = $algorithm->hash((string) $toBeMaced, $key);
>
> // COSE_Mac: context "MAC" — the same header and payload give a different tag
> $toBeMaced = MacStructure::create($coseMac->getProtectedHeader(), $coseMac->getPayload());
> $isValid = $algorithm->verify((string) $toBeMaced, $key, $coseMac->getTag()->getValue());
> ```
>
> `Cose\Algorithm\Mac\Mac::hash()` and `verify()` authenticate exactly the bytes they are given, so passing
> `getPayload()->getValue()` straight to them produces a tag bound to nothing and interoperable with no other
> implementation.

## CBOR Web Tokens (CWT)

A CWT ([RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392)) is a claims map carried as the payload of a COSE
message — most often a `COSE_Sign1`. cbor-php 3.4.0 also ships `CBOR\Tag\CwtTag` for the optional tag 61 that marks
the whole thing as a CWT.

Nothing about the verification changes: the payload is opaque bytes to COSE, and the claims are decoded once the
signature checks out.

```php
use CBOR\Decoder;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CwtTag;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;

$decoded = Decoder::create()->decode(StringStream::create($encoded));

// Tag 61 is optional; the message underneath is the COSE structure
$message = $decoded instanceof CwtTag ? $decoded->getValue() : $decoded;
assert($message instanceof CoseSign1Tag);

// Verify first
$toBeVerified = Signature1::create($message->getProtectedHeader(), $message->getPayload());
if (! $algorithm->verify((string) $toBeVerified, $key, $message->getSignature()->getValue())) {
    throw new RuntimeException('Invalid signature');
}

// Then read the claims (RFC 8392 §3.1: 1 = iss, 2 = sub, 3 = aud, 4 = exp, 5 = nbf, 6 = iat, 7 = cti)
$claims = Decoder::create()
    ->decode(StringStream::create($message->getPayload()->getValue()))
    ->normalize();

// ['1' => 'coap://as.example.com', '6' => '1443944944'] — cbor-php normalizes CBOR integers to numeric strings,
// so cast the timestamps before comparing them.
$expiresAt = isset($claims[4]) ? (int) $claims[4] : null;
```

> [!IMPORTANT]
> Verify before you read. A claims map decoded from an unverified payload is attacker-controlled input, and `exp` or
> `iss` read from it means nothing.

A token can also name itself and repeat claims in its protected header — `typ` ([RFC 9596](https://www.rfc-editor.org/rfc/rfc9596))
and `CWT Claims` ([RFC 9597](https://www.rfc-editor.org/rfc/rfc9597)), read through `getTyp()` and
`getCwtClaims()`; see [`typ` and `CWT Claims`](#typ-and-cwt-claims). Header claims are readable before the signature
is checked, which is what they are for (routing to the right key, say), but they are no more trustworthy than the
payload until it is; and a claim carried in both places has to be verified identical by the application.

```php
$headers = CoseHeaders::fromMessage($message);
if ($headers->getTyp() !== 'application/cwt') {
    throw new RuntimeException('Not a CWT');
}
$headerClaims = $headers->getCwtClaims(); // ?MapObject, protected bucket first

// ... verify the signature, decode the payload claims, then:
foreach ($headerClaims ?? [] as $claim) {
    // RFC 9597 §2: a claim in both the header and the payload MUST have identical values
}
```

## Detached Content

[RFC 9052 §4.1](https://datatracker.ietf.org/doc/html/rfc9052#section-4.1) lets the payload — or the ciphertext of an
encrypted message — travel outside the message, as a `nil` in its place:

```php
use CBOR\OtherObject\NullObject;

// Sending
$coseSign1 = CoseSign1Tag::createFromComponents(
    $protectedHeader,
    $unprotectedHeader,
    NullObject::create(),
    $signature
);

// Receiving: the application supplies the content it transported separately
$payload = $coseSign1->getPayload();
if ($payload instanceof NullObject) {
    $payload = ByteStringObject::create($contentYouTransportedSeparately);
}

$toBeSigned = Signature1::create($coseSign1->getProtectedHeader(), $payload);
```

## External Additional Authenticated Data

Every structure takes the optional `external_aad` of
[RFC 9052 §4.4](https://datatracker.ietf.org/doc/html/rfc9052#section-4.4) as its last argument. It defaults to the
zero-length byte string the RFC prescribes:

```php
$toBeSigned = Signature1::create(
    $coseSign1->getProtectedHeader(),
    $payload,
    ByteStringObject::create($applicationSuppliedData),
);
```

## Upgrading from the `Cose\...Tag` classes

The six COSE message classes were ported into
[spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0, which is where they belong: they describe the
shape of a CBOR structure and nothing more. The `Cose\...Tag` classes of this library are **deprecated since 4.8.0**,
raise an `E_USER_DEPRECATED` on construction, and are **removed in 5.0.0**.

| Deprecated | Replacement |
|---|---|
| `Cose\Signature\CoseSign1Tag` | `CBOR\Tag\CoseSign1Tag` |
| `Cose\Signature\CoseSignTag` | `CBOR\Tag\CoseSignTag` |
| `Cose\Mac\CoseMac0Tag` | `CBOR\Tag\CoseMac0Tag` |
| `Cose\Mac\CoseMacTag` | `CBOR\Tag\CoseMacTag` |
| `Cose\Encryption\CoseEncrypt0Tag` | `CBOR\Tag\CoseEncrypt0Tag` |
| `Cose\Encryption\CoseEncryptTag` | `CBOR\Tag\CoseEncryptTag` |
| — | `CBOR\Tag\CwtTag` (tag 61, new) |

Nothing else changes: the wire format is identical, so a message written by a deprecated class is read by its
replacement and the reverse. What the migration has to handle:

- **`create()` becomes `createFromComponents()`.** This is the one point where renaming the class is not enough:
  upstream `create()` also exists, and takes the whole `ListObject` instead of the four parts. A leftover
  four-argument `create()` call raises an `ArgumentCountError` rather than misbehaving quietly.
- **Registering the tags is no longer needed.** `Decoder::create()` resolves all seven on its own;
  `TagManager::create()->add(...)` was only ever needed because the classes lived here.
- **`getPayload()` can return `NullObject`.** Detached content is representable now, so the return type is
  `ByteStringObject|IndefiniteLengthByteStringObject|NullObject`.
- **The accessors also return the `IndefiniteLength...` variants**, which the deprecated classes rejected outright.
- **The header accessors move to `CoseHeaders`.** `getProtectedHeaderAsMap()` exists upstream but applies only the
  CBOR rules; the RFC 9052 ones — label typing, trailing data, the protected-first lookup — stay here:

  ```php
  // before
  $map = $coseSign1->getProtectedHeaderAsMap();
  $alg = $map->has(1) ? $map->get(1) : null;

  // after
  $alg = CoseHeaders::fromMessage($coseSign1)->getProtectedHeaderParameter(1);
  ```

- **`getSignatures()` and `getRecipients()` still return raw lists.** Wrap them in `CoseSignature::all()` or
  `CoseRecipient::all()` to get the `[+ ...]` rule of RFC 9052 and typed entries.

`Signature1` and the other structure builders are **not** superseded and need no change.

## Supported Algorithms

### Signature Algorithms

The *Reference* column names the section of the RFC that defines the identifier; every value was checked against
the IANA [COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) registry.

**ECDSA** (`Cose\Algorithm\Signature\ECDSA`)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| ES256 | -7 | ECDSA with SHA-256 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES384 | -35 | ECDSA with SHA-384 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES512 | -36 | ECDSA with SHA-512 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES256K | -47 | ECDSA with the secp256k1 curve and SHA-256 | [RFC 8812 §3.2](https://www.rfc-editor.org/rfc/rfc8812#section-3.2) |

**EdDSA** (`Cose\Algorithm\Signature\EdDSA`) — Ed25519 keys only, whatever the class

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| EdDSA | -8 | Edwards-curve Digital Signature Algorithm | [RFC 9053 §2.2](https://www.rfc-editor.org/rfc/rfc9053#section-2.2) |
| Ed25519 | -8 | The same algorithm under its own class name; identical signatures, identical identifier | [RFC 9053 §2.2](https://www.rfc-editor.org/rfc/rfc9053#section-2.2) |
| Ed256 | -260 | Ed25519 over a SHA-256 digest — **non-standard**, see below | — |
| Ed512 | -261 | Ed25519 over a SHA-512 digest — **non-standard**, see below | — |

The IANA registry marks -8 *Deprecated* in favour of the fully-specified Ed25519 (-19) and Ed448 (-53) of
[RFC 9864](#fully-specified-algorithms), as it does ES256, ES384 and ES512. All four stay first-class here, without
any acknowledgement: WebAuthn still requires ES256 and EdDSA.

Ed256 and Ed512 sign a SHA-256 or SHA-512 digest of the message with Ed25519. They are not EdDSA identifiers and are
registered nowhere — IANA assigns -260 to WalnutDSA and -261 to TurboSHAKE128 — hence the empty reference, and
neither of them supports Curve448. Kept for the authenticators that already produce them, and only against an
explicit acknowledgement (see below); EdDSA with Curve448 is `FullySpecified\Ed448` (-53).

**RSA** (`Cose\Algorithm\Signature\RSA`)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| PS256 | -37 | RSASSA-PSS with SHA-256 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| PS384 | -38 | RSASSA-PSS with SHA-384 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| PS512 | -39 | RSASSA-PSS with SHA-512 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| RS1 | -65535 | RSASSA-PKCS1-v1_5 with SHA-1 — **not secure**, kept only for legacy authenticators | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |

PS256, PS384 and PS512 sign with a private key, so the exponentiation is a side-channel target. A two-prime key
carrying the full CRT quintuple — the shape almost every key store produces — is exponentiated by OpenSSL, which
blinds the base and runs `BN_mod_exp_mont_consttime`. Its CRT parameters are checked against the modulus first, so an
inconsistent key is reported rather than silently repaired. Multi-prime keys ([RFC 8230 section 4](https://www.rfc-editor.org/rfc/rfc8230#section-4))
and keys reduced to `(n, e, d)` have no PEM representation and keep the in-process exponentiation; their base is
blinded, which hides it from an observer, but `gmp_powm()`, `bcpowmod()` and the native brick/math loop are not
constant-time, so prefer a full two-prime key when signing with a long-lived key on a shared host.

RS1 relies on SHA-1, which is no longer acceptable for digital signatures (see
[RFC 6194](https://datatracker.ietf.org/doc/html/rfc6194) and NIST SP 800-131A). Creating the algorithm emits an
`E_USER_WARNING` unless the risk is explicitly acknowledged:

```php
use Cose\Algorithm\Signature\RSA\RS1;

$algorithm = RS1::create(acknowledgeInsecureAlgorithm: true);
```

As of the next major version, omitting that acknowledgement will throw an exception instead of warning. The same
acknowledgement applies to `Algorithms::getOpensslAlgorithmFor()` and `Algorithms::getHashAlgorithmFor()`, which hand
out the very same primitive without any object being created:

```php
use Cose\Algorithms;

$digest = Algorithms::getOpensslAlgorithmFor(Algorithms::COSE_ALGORITHM_RS1, acknowledgeInsecureAlgorithm: true);
```

`Ed256` (-260) and `Ed512` (-261) are defined by no specification: both hash the payload and sign the digest with pure
Ed25519, without the `dom2` prefix that would make it the Ed25519ph of
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) section 5.1 — whose section 8.5 says prehashed variants
"SHOULD NOT be used" anyway. Their identifiers are not theirs either: IANA has since assigned -260 to WalnutDSA
([RFC 9021](https://www.rfc-editor.org/rfc/rfc9021)) and -261 to TurboSHAKE128
([RFC 9861](https://www.rfc-editor.org/rfc/rfc9861)), so a conforming implementation reads objects produced by these
classes as those algorithms. Despite its name, `Ed512` is not Ed448 and rejects an Ed448 key.

No authenticator emits these identifiers; prefer `Ed25519`. Creating either class emits an `E_USER_WARNING` unless the
construction is explicitly acknowledged:

```php
use Cose\Algorithm\Signature\EdDSA\Ed256;

$algorithm = Ed256::create(acknowledgeNonStandardAlgorithm: true);
```

As of the next major version, omitting that acknowledgement will throw an exception, and the identifiers will move out
of the range IANA administers.

### Fully-Specified Algorithms

[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) registers identifiers that determine the curve and the hash on
their own, instead of leaving them to the other parameters of the key. WebAuthn Level 3 has adopted them, so a relying
party may receive a credential whose `alg` carries one of these values. They live in the
`Cose\Algorithm\Signature\FullySpecified` namespace.

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| ESP256 | -9 | ECDSA with the P-256 curve and SHA-256 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESP384 | -51 | ECDSA with the P-384 curve and SHA-384 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESP512 | -52 | ECDSA with the P-521 curve and SHA-512 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB256 | -265 | ECDSA with the brainpoolP256r1 curve and SHA-256 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB320 | -266 | ECDSA with the brainpoolP320r1 curve and SHA-384 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB384 | -267 | ECDSA with the brainpoolP384r1 curve and SHA-384 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB512 | -268 | ECDSA with the brainpoolP512r1 curve and SHA-512 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| Ed25519 | -19 | EdDSA with the Ed25519 parameter set | [RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864#section-2.2) |
| Ed448 | -53 | EdDSA with the Ed448 parameter set — requires PHP 8.4 or later | [RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864#section-2.2) |

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;

$manager = Manager::create()
    ->add(ESP256::create())
    ->add(Ed25519::create());
```

`Cose\Algorithm\Signature\FullySpecified\Ed25519` (-19) and `Cose\Algorithm\Signature\EdDSA\Ed25519` (-8)
compute the same signatures; only the algorithm identifier differs.

Ed448 is not covered by the sodium extension and goes through OpenSSL, which PHP only wires up for Edwards curves as of
PHP 8.4. Call `Ed448::isSupported()` when the platform is not known in advance; the algorithm throws a
`RuntimeException` on older versions.

Every Ed25519 algorithm — `EdDSA` (-8), `Ed25519` (-8 and -19), `Ed256` (-260) and `Ed512` (-261) — is computed with
the sodium extension. Sodium ships with PHP and is enabled by default, but a build can leave it out, so it is a
suggestion of this package rather than a hard requirement: everything else works without it. Creating one of these
algorithms on a host where sodium is not loaded throws a `RuntimeException`; call `EdDSA::isSupported()` when the
platform is not known in advance.

The brainpool curves are also available on `Cose\Key\Ec2Key` as `CURVE_BP256`, `CURVE_BP320`, `CURVE_BP384` and
`CURVE_BP512` (values 256 to 259 of the COSE Elliptic Curves registry).

### Signature Verification Contract

`Cose\Algorithm\Signature\Signature::verify()` is total for every condition the governing specifications define as an
"invalid signature" outcome. A malformed, truncated, over-long or out-of-range signature, and key material that the
crypto layer cannot decode — a point that is not on the named curve, a public key that is not a valid group element —
all return `false`. No PHP warning is raised on the way.

It throws an `InvalidArgumentException` when the key cannot be used with the algorithm at all: its key type or its
curve does not match, or - when the algorithm was asked to enforce them, see
[Key Restrictions](#key-restrictions-alg-and-key_ops) - the key itself forbids the algorithm or the operation.
Structurally invalid key components — an empty or zero RSA modulus, an `x`, `y`
or `d` whose length does not fit the curve — are rejected earlier, by the `Key` constructors, so the exception is
raised when the key is first seen rather than at every verification.

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

### Key Restrictions (`alg` and `key_ops`)

A COSE key may restrict itself. [RFC 9052, section 7.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1) gives
it two parameters for that: `alg` (label 3) pins it to one algorithm — "If the algorithms do not match, then this key
object MUST NOT be used to perform the cryptographic operation" — and `key_ops` (label 4) pins it to a set of
operations, whose values are those of Table 5: `sign` (1), `verify` (2), `MAC create` (9) and `MAC verify` (10) for
the algorithms this library implements. [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1) repeats
both as a per-algorithm requirement for ECDSA (§2.1), EdDSA (§2.2), HMAC (§3.1) and AES-CBC-MAC (§3.2).

Enforcing them is **opt-in**, so that a key which used to work keeps working. Ask an algorithm — or a whole
`Manager` — to enforce the restrictions, and it refuses the key with an `InvalidArgumentException` whenever the key
forbids what is being done with it:

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;

$algorithm = ES256::create()->withKeyRestrictionsEnforced();

// …or for every algorithm of a manager at once
$manager = Manager::create()
    ->add(ES256::create(), RS256::create())
    ->withKeyRestrictionsEnforced();

// The key says "alg": -7 and "key_ops": [2], i.e. ES256, verification only
$isValid = $algorithm->verify($data, $key, $signature); // fine
$signature = $algorithm->sign($data, $key);             // InvalidArgumentException: the key does not allow "sign"
```

`withKeyRestrictionsEnforced()` returns a new algorithm and leaves the one it is called on untouched, so a manager
that enforces the restrictions can live next to one that does not. `enforcesKeyRestrictions()` says which one you are
holding, and `withKeyRestrictionsEnforced(false)` turns it off again.

This matters when the algorithm is chosen from the message rather than from the key. A verifier that reads `alg` from
the protected header and looks it up with `Manager::get()` has, without enforcement, no reason to refuse an RS1
(RSASSA-PKCS1-v1_5 with SHA-1) signature made under a key that says it is for RS256, nor a 64 bit HMAC tag under a key
that says it is for HMAC 256/256. With enforcement, the key itself rejects the downgrade.

The restrictions can also be read and applied without going through an algorithm:

```php
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Key;

$key->alg();    // -7; throws when "alg" is absent or is not an algorithm identifier
$key->keyOps(); // [2] or ['verify'], null when the key carries no "key_ops"

// Throws an InvalidArgumentException naming the restriction that is not satisfied
$key->assertUsableWith(ES256::ID, Key::OP_VERIFY);

// …or ask without the exception
$isUsable = $key->isUsableWith(ES256::ID, Key::OP_SIGN);
```

Two details are worth knowing:

- **Identifiers are compared as they are.** A key with `alg` = `ES256` (-7) is refused by `ESP256` (-9), and one with
  `alg` = `EdDSA` (-8) is refused by the fully-specified `Ed25519` (-19), even though the cryptography is the same.
  [RFC 9864, section 7](https://www.rfc-editor.org/rfc/rfc9864.html#section-7) asks for it: "A cryptographic key MUST
  be used with only a single algorithm unless the use of the same key with different algorithms is proven secure."
  A key meant to serve both carries no `alg` at all.
- **`key_ops` accepts both spellings.** COSE writes the operations as the integers of Table 5; a key converted from a
  JWK may carry the text names JOSE uses (`"sign"`, `"verify"`, `"MAC create"`, `"MAC verify"`). Both are recognised.

`Key::alg()` is strict about the value it reads: an `alg` that is not an integer — the text `'RS256'`, for instance —
throws instead of being cast to `0`, an identifier no algorithm is registered under. An integer written as a string
(`'-7'`) is accepted, as the key constructors do for `kty` and `crv`.

### Key Types

The `Cose\Key` classes cover the four key types of the IANA
[COSE Key Types](https://www.iana.org/assignments/cose/cose.xhtml#key-type) registry that the algorithms above use.
`Key::createFromData()` picks the class from `kty` (label 1), and the parameter labels are the `DATA_*` constants of
each class — `Ec2Key::DATA_X` is -2, `RsaKey::DATA_N` is -1, and so on.

| Key type | `kty` | Class | Parameters | Reference |
|----------|-------|-------|------------|-----------|
| OKP | 1 | `Cose\Key\OkpKey` | `crv` (-1), `x` (-2), `d` (-4) | [RFC 9053 §7.2](https://www.rfc-editor.org/rfc/rfc9053#section-7.2) |
| EC2 | 2 | `Cose\Key\Ec2Key` | `crv` (-1), `x` (-2), `y` (-3), `d` (-4) | [RFC 9053 §7.1.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1.1) |
| RSA | 3 | `Cose\Key\RsaKey` | `n` (-1), `e` (-2), `d` (-3), `p` (-4), `q` (-5), `dP` (-6), `dQ` (-7), `qInv` (-8), `other` (-9), `r_i` (-10), `d_i` (-11), `t_i` (-12) | [RFC 8230 §4](https://www.rfc-editor.org/rfc/rfc8230#section-4) |
| Symmetric | 4 | `Cose\Key\SymmetricKey` | `k` (-1) | [RFC 9053 §7.3](https://www.rfc-editor.org/rfc/rfc9053#section-7.3) |

The curves an `OkpKey` or an `Ec2Key` may carry in `crv`, with the `CURVE_*` constant naming each value:

| Curve | `crv` | Key type | Constant | Reference |
|-------|-------|----------|----------|-----------|
| P-256 | 1 | EC2 | `Ec2Key::CURVE_P256` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| P-384 | 2 | EC2 | `Ec2Key::CURVE_P384` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| P-521 | 3 | EC2 | `Ec2Key::CURVE_P521` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| X25519 | 4 | OKP | `OkpKey::CURVE_X25519` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| X448 | 5 | OKP | `OkpKey::CURVE_X448` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| Ed25519 | 6 | OKP | `OkpKey::CURVE_ED25519` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| Ed448 | 7 | OKP | `OkpKey::CURVE_ED448` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| secp256k1 | 8 | EC2 | `Ec2Key::CURVE_P256K` | [RFC 8812 §4.2](https://www.rfc-editor.org/rfc/rfc8812#section-4.2) |
| brainpoolP256r1 | 256 | EC2 | `Ec2Key::CURVE_BP256` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |
| brainpoolP320r1 | 257 | EC2 | `Ec2Key::CURVE_BP320` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |
| brainpoolP384r1 | 258 | EC2 | `Ec2Key::CURVE_BP384` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |
| brainpoolP512r1 | 259 | EC2 | `Ec2Key::CURVE_BP512` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |

X25519 and X448 are registered "for use w/ ECDH only": an `OkpKey` accepts them, but no algorithm of this library
uses them yet. The brainpool curves are registered at IANA by ISO/IEC 18013-5 rather than by an RFC; the link goes
to the registry entry. The names a key may carry instead of these numbers are listed under
[Key Parameter Forms](#key-parameter-forms).

### Ed25519 Private Keys

[RFC 8032, section 5.1.5](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5) defines the Ed25519 public key `A` as a
function of the private seed, and [section 5.1.6](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6) puts that `A`
into the challenge the signature is built on. `sign()` therefore always recomputes the key pair from `d` and never
signs under a public key handed to it: a `-2` (`x`) that contradicts `d` is refused with an
`InvalidArgumentException`, because signing under two different `x` values for one seed discloses the private key.

[RFC 9053, section 7.2](https://www.rfc-editor.org/rfc/rfc9053#section-7.2) makes `x` RECOMMENDED, not REQUIRED, for a
private key — "it can be recomputed from the required elements" — so an `OkpKey` may carry `crv` and `d` alone. That is
the safest way to build a signing key, since nothing can then hand it an `x` inconsistent with the seed:

```php
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Key\OkpKey;

$key = OkpKey::create([
    OkpKey::TYPE => OkpKey::TYPE_OKP,
    OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
    OkpKey::DATA_D => $seed, // 32 bytes, RFC 8032 section 5.1.5
]);

$signature = Ed25519::create()->sign($data, $key);
$publicKey = $key->x();          // recomputed from $seed
$publicCoseKey = $key->toPublic(); // carries the recomputed x, without d
```

`x()` recomputes the public key for the curves sodium covers, Ed25519 and X25519. Ed448 and X448 have no derivation
primitive in PHP, so a key on those curves still has to carry its `x`.

### Key Parameter Forms

RFC 9052 and RFC 9053 type `kty` and `crv` as `tstr / int`, so the same key reaches this library under several
shapes. The `Key` classes settle them all at construction time:

- a key type or a curve given as the numeric string spomky-labs/cbor-php produces when it decodes a CBOR integer
  (`'2'`, `'-1'`) is stored as the integer it denotes, so `Key::type()` always compares equal to `Key::TYPE_EC2` and
  friends, whether the key was decoded from CBOR or built by hand;
- a key type may also be given by name — the names of the IANA
  [COSE Key Types](https://www.iana.org/assignments/cose/cose.xhtml#key-type) registry, `OKP`, `EC2`, `RSA` and
  `Symmetric`, or the JOSE spellings `EC` and `oct` a key converted from a JWK carries. `Key::typeIs(Key::TYPE_EC2)`
  answers for every form, while `type()` keeps returning the form supplied;
- a curve may be given by name — `P-256`, `P-384`, `P-521`, `secp256k1`, `brainpoolP256r1` and so on. `curve()`
  returns the form the key carries, and `Ec2Key::curveId()` / `OkpKey::curveId()` return the value of the IANA
  [COSE Elliptic Curves](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) registry whatever that
  form is. The algorithm classes compare the latter, so a key that names its curve signs and verifies exactly like
  the same key that numbers it.

```php
use Cose\Key\Ec2Key;

$key = Ec2Key::create([
    Ec2Key::TYPE => Ec2Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_NAME_SECP256K1, // or Ec2Key::CURVE_P256K
    Ec2Key::DATA_X => $x,
    Ec2Key::DATA_Y => $y,
]);

$key->curve();   // 'secp256k1', as supplied
$key->curveId(); // 8, the registry value
```

Curve 8 is named `secp256k1` by [RFC 8812, section 4.2](https://datatracker.ietf.org/doc/html/rfc8812#section-4.2).
`Ec2Key::CURVE_NAME_P256K` (`'P-256K'`), the spelling of a draft that was renamed before its first revision, is
deprecated but still accepted.

Anything else — a float, a numeric string that is not an integer, a name no registry defines, an `x` that is not a
byte string — is refused by the constructor with an `InvalidArgumentException`, before any of it is used.

### Validating RSA Keys

[RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) defers to
[RFC 8230, section 6.1](https://www.rfc-editor.org/rfc/rfc8230#section-6.1), which requires a modulus of 2048 bits or
larger and expects implementations to handle up to 16K bits.

The upper bounds are applied automatically: every RSA algorithm rejects a key whose modulus is longer than
`RsaKeyValidator::MAXIMUM_MODULUS_LENGTH` (16384) bits or whose public exponent is longer than
`RsaKeyValidator::MAXIMUM_EXPONENT_LENGTH` (256) bits, before it computes anything with it. `verify()` returns `false`
for such a key and `sign()` throws an `InvalidArgumentException`. The cost of an RSA operation grows with the size of
the key it is given, and a verifier takes that key from whoever produced the message.

The **minimum** modulus length is applied automatically too, with `RsaKeyValidator::create()`. Because legacy
authenticators holding 1024 bit keys still exist, a key below `RsaKeyValidator::MINIMUM_MODULUS_LENGTH` (2048) bits
only emits an `E_USER_WARNING` — `RsaKeyValidator::WEAK_KEY_MESSAGE`, filled in with the reason — and the operation
goes through. As of the next major version, that warning becomes an `InvalidArgumentException` on `sign()` and a
`false` on `verify()`.

A caller that has to accept weaker keys passes the algorithm a validator carrying the bound it accepts. That bound is
enforced at once, with an exception, since the caller chose it; only the implicit default is on the warn-then-throw
schedule.

```php
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\RsaKeyValidator;

// Legacy authenticators: 1024 bit keys accepted silently, anything below still rejected
$algorithm = RS256::create(RsaKeyValidator::create(minimumModulusLength: 1024));
$algorithm = PS256::create(RsaKeyValidator::create(minimumModulusLength: 1024));

// RS1 keeps its acknowledgement flag first
$algorithm = RS1::create(true, RsaKeyValidator::create(minimumModulusLength: 1024));

// A policy stricter than the RFC, enforced now rather than in the next major version
$algorithm = RS256::create(RsaKeyValidator::create(minimumModulusLength: 3072, maximumModulusLength: 8192));
```

The validator can also be run on its own, on a key you are about to store:

```php
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;

$key = RsaKey::create($data);

// Throws an InvalidArgumentException when the key does not comply
RsaKeyValidator::create()->check($key);

// …or ask without the exception
$isAcceptable = RsaKeyValidator::create()->isValid($key);

// The modulus and exponent lengths, in bits, are available on their own
$modulusLength = RsaKeyValidator::modulusLength($key);
$exponentLength = RsaKeyValidator::exponentLength($key);

// The bounds the algorithms apply on their own, should you want to run them earlier
RsaKeyValidator::checkLengthBounds($key);
```

The validator also enforces the public exponent constraints of
[RFC 8017, section 3.1](https://datatracker.ietf.org/doc/html/rfc8017#section-3.1): an odd integer between 3 and
`n - 1`.

Every check is performed on the octet strings of the key, so rejecting an oversized key costs no more than reading it.

### Registering Algorithms

`Cose\Algorithm\Manager` registers each algorithm under the identifier it declares, and
`Cose\Algorithm\ManagerFactory` registers algorithms under aliases so that a `Manager` can be generated from a subset
of them.

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\ManagerFactory;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;

$manager = Manager::create()->add(ES256::create(), RS256::create());

$factory = ManagerFactory::create()
    ->add('ES256', ES256::create())
    ->add('RS256', RS256::create());
$manager = $factory->generate('ES256');
```

A later registration for an identifier — or, on the factory, for an alias — that is already taken replaces the earlier
one. When the replacement is an instance of **another** class, that is a misconfiguration rather than an intent:
`list()` keeps reporting a single entry, and which verifier answers for the identifier is decided by registration order
alone, which in a Symfony application means by the service container. Such a replacement therefore emits an
`E_USER_WARNING`. Registering the same class twice stays silent, so a container that autoconfigures an algorithm more
than once keeps working.

As of the next major version, a duplicate bound to a different class will throw an `InvalidArgumentException`, and an
explicit `replace()` will be the way to override a registration on purpose.

### Verifying a Signature Made by a Certificate

WebAuthn Level 3 sections 8.2 to 8.4 ask a relying party to verify a packed (`x5c`), TPM or android-key attestation
statement "with the algorithm specified in `alg`", against the key of the attestation certificate. Going through
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
[Validating RSA Keys](#validating-rsa-keys) — is the one enforced against the key of the certificate.

```php
use Cose\Key\RsaKeyValidator;

// This RS256 refuses a certificate whose modulus is shorter than 3072 bits, through the verifier as anywhere else.
$manager = Manager::create()->add(RS256::create(RsaKeyValidator::create(minimumModulusLength: 3072)));
```

`verify()` returns `false` for every signature the algorithm rejects, and throws an `InvalidArgumentException` when the
certificate cannot be read, when no signature algorithm is registered for the identifier, or when the key of the
certificate cannot be used with that algorithm — the same contract as `Signature::verify()`.

When the certificate itself is not at hand, `verifySubjectPublicKeyInfo()` takes a SubjectPublicKeyInfo instead, and
`Cose\Key\PublicKeyLoader` exposes the conversion on its own. Both accept PEM or DER, and both cover RSA (including
RSASSA-PSS keys), the elliptic curves this library names — P-256, secp256k1, P-384, P-521 and the four brainpool
curves — and the RFC 8410 curves.

```php
use Cose\Key\PublicKeyLoader;

$key = PublicKeyLoader::fromCertificate($certificatePem);
$key = PublicKeyLoader::fromSubjectPublicKeyInfo($spkiDer);
```

### MAC Algorithms

**HMAC** (`Cose\Algorithm\Mac`)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| HS256 | 5 | HMAC with SHA-256 (IANA name `HMAC 256/256`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS384 | 6 | HMAC with SHA-384 (`HMAC 384/384`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS512 | 7 | HMAC with SHA-512 (`HMAC 512/512`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS256/64 | 4 | HMAC with SHA-256 truncated to 64 bits (`HMAC 256/64`), class `HS256Truncated64` | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |

**AES-CBC-MAC** (`Cose\Algorithm\Mac\AESMAC128_64` and siblings)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| AES-MAC 128/64 | 14 | AES-128 in CBC mode, 64-bit tag — class `AESMAC128_64` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 256/64 | 15 | AES-256 in CBC mode, 64-bit tag — class `AESMAC256_64` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 128/128 | 25 | AES-128 in CBC mode, 128-bit tag — class `AESMAC128_128` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 256/128 | 26 | AES-256 in CBC mode, 128-bit tag — class `AESMAC256_128` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |

Every MAC algorithm implements `Cose\Algorithm\Mac\Mac`: `hash()` computes the tag, `verify()` compares it with
`hash_equals()`, and both take a symmetric `Key`.

```php
use Cose\Algorithm\Mac\AESMAC128_64;
use Cose\Key\SymmetricKey;
use Cose\Mac\Mac0Structure;

$key = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => random_bytes(16), // exactly 16 bytes for the 128-bit identifiers, 32 for the 256-bit ones
]);
$algorithm = AESMAC128_64::create();

$toBeMaced = Mac0Structure::create($protectedHeaderAsBytes, $payload);
$tag = $algorithm->hash((string) $toBeMaced, $key);                  // 8 bytes
$isValid = $algorithm->verify((string) $toBeMaced, $key, $tag);
```

> [!WARNING]
> AES-CBC-MAC comes with two conditions of its own, stated by
> [RFC 9053 §3.2.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.2.1), that no class can check for you:
>
> - **A key must only authenticate messages of a fixed or known length.** With messages of varying length, two
>   message/tag pairs let an attacker forge a third. The `MAC_structure` is the mitigation: it is CBOR, so it
>   encodes the length of every field, and a tag computed over a `Mac0Structure` or `MacStructure` is not exposed.
>   A tag computed over the bare payload is.
> - **CBC encryption and CBC-MAC must use different keys.** With a shared key, the last ciphertext block of an
>   encryption is a valid tag.
>
> The construction is the CBC-MAC of ISO/IEC 9797-1 with AES, an all-zero IV, padding method 1 (zero bytes up to
> the block boundary, none when the message is already a multiple of 16 bytes — what the cose-wg/Examples vectors
> use) and the last block truncated to the tag length. It is not AES-CMAC (RFC 4493).

### Validating Symmetric Keys

[RFC 9053, section 3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) requires implementations "creating and
validating MAC values" to validate the key type, the key length and the algorithm. The first two constraints admit no
exception and are applied by the MAC algorithms themselves: `hash()` and `verify()` throw an
`InvalidArgumentException` when the key is not symmetric, or when its `k` is missing, is not a PHP string or is empty.
The AES-CBC-MAC algorithms add the length: RFC 9053 §3.2 ties it to the identifier, so a `k` that is not exactly
16 bytes (AES-MAC 128/64 and 128/128) or 32 bytes (AES-MAC 256/64 and 256/128) is refused the same way, before
OpenSSL is reached.
`SymmetricKey` applies the same contract at construction time, where the mistake is easiest to attribute. A value
decoded from CBOR has to be normalized first — a `CBOR\ByteStringObject` is not a byte string.

```php
use Cose\Key\SymmetricKey;

// Throws an InvalidArgumentException: "k" is typed as a bstr by RFC 9053, section 7.3
SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => ByteStringObject::create($secret), // use ->getValue() instead
]);
```

The **minimum** key length is a policy decision and stays opt-in, as it does for RSA moduli: a key shorter than the
output of the hash function (32 bytes for HS256 and HS256/64, 48 for HS384, 64 for HS512) is only "strongly
discouraged" by [RFC 2104, section 3](https://www.rfc-editor.org/rfc/rfc2104#section-3), and deployments do key HS384
and HS512 with 32 bytes. Such a key emits an `E_USER_WARNING` at every `hash()`/`verify()` call unless the algorithm
is created with `acknowledgeShortKey: true`; the next major version will throw instead.

```php
use Cose\Algorithm\Mac\HS512;
use Cose\Key\SymmetricKeyValidator;

// No warning: the risk is acknowledged
$algorithm = HS512::create(acknowledgeShortKey: true);

// The length RFC 2104 does not discourage for this algorithm, in bytes (32, 48 or 64)
$minimumKeyLength = $algorithm->minimumKeyLength();

// Throws an InvalidArgumentException when the key is shorter
SymmetricKeyValidator::create($minimumKeyLength)->check($key);

// …or ask without the exception
$isAcceptable = SymmetricKeyValidator::create()->isValid($key);

// The key length, in bytes, on its own
$keyLength = SymmetricKeyValidator::keyLength($key);

// The checks the algorithms apply on their own, should you want to run them earlier
SymmetricKeyValidator::checkKeyValue($key);
```

`SymmetricKeyValidator` accepts any `Key`, not only a `SymmetricKey`: `Key::create()` and `Key::createFromData()` with
an integer `kty` build a generic `Key` that never goes through the `SymmetricKey` constructor.

## Common Header Parameters

The following header parameters are commonly used in COSE structures:

| Label | Name | Type | Description |
|-------|------|------|-------------|
| 1 | alg | int | Cryptographic algorithm |
| 2 | crit | [+label] | Critical headers |
| 3 | content type | tstr / uint | Content type of payload |
| 4 | kid | bstr | Key identifier |
| 5 | IV | bstr | Initialization Vector |
| 6 | Partial IV | bstr | Partial Initialization Vector |

## Examples

The [`examples/`](../examples) directory holds a runnable program per topic. Each prints what it does and fails
loudly if a check does not hold, and `tests/ExamplesTest.php` runs all of them on each build:

```bash
composer install
php examples/01-sign1.php
```

| File | Topic |
|---|---|
| `examples/01-sign1.php` | COSE_Sign1: sign, encode, decode, verify |
| `examples/02-sign-multiple-signers.php` | COSE_Sign, and why `Signature` carries `sign_protected` |
| `examples/03-mac0.php` | COSE_Mac0 over the MAC_structure, with HMAC and AES-CBC-MAC |
| `examples/04-encrypt0.php` | COSE_Encrypt0 with `Enc_structure` as the AEAD's AAD |
| `examples/05-encrypt-recipients.php` | COSE_Encrypt: key wrapping, nested recipients, detached ciphertext |
| `examples/06-headers.php` | The header rules, against what the raw CBOR map answers |
| `examples/07-detached-and-external-aad.php` | Detached content and `external_aad` |
| `examples/08-cwt.php` | CBOR Web Tokens |
| `examples/09-migration.php` | Moving off the deprecated `Cose\...Tag` classes |

The test suite is the rest of the examples, and every one of them is executed on each build:

| File | Shows |
|---|---|
| `tests/Signature/DocumentedVerifierTest.php` | The verifier documented above, run exactly as written |
| `tests/Structure/CoseStructureTest.php` | The structures against the RFC 9052 Appendix C vectors |
| `tests/Structure/CoseHeadersTest.php` | The header rules, on all six message types |
| `tests/Structure/CoseSignatureTest.php` | Per-signer views of a `COSE_Sign` |
| `tests/Structure/CoseRecipientTest.php` | Per-recipient views, nested recipients and detached ciphertext |
| `tests/Signature/CoseSign1CreateAndVerifyTest.php` | EU digital COVID certificate verification |
| `tests/Structure/DeprecatedTagClassesTest.php` | The deprecation and the upstream replacements |

## References

- [RFC 9052 - CBOR Object Signing and Encryption (COSE): Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC 9053 - CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)
- [RFC 8230 - Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages](https://datatracker.ietf.org/doc/html/rfc8230)
- [RFC 8812 - CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms](https://datatracker.ietf.org/doc/html/rfc8812)
- [RFC 9864 - Fully-Specified Algorithms for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9864.html)
- [RFC 9596 - CBOR Object Signing and Encryption (COSE) "typ" (type) Header Parameter](https://www.rfc-editor.org/rfc/rfc9596.html)
- [RFC 9597 - CBOR Web Token (CWT) Claims in COSE Headers](https://www.rfc-editor.org/rfc/rfc9597.html)
- [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml)
