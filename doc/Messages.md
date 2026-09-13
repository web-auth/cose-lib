# Messages, Structures and Headers

[← Documentation index](README.md)

What RFC 9052 defines above the CBOR: the six message types, the structures a signature, a MAC or an encryption is
computed over, and the rules that decide what a header says.

- [COSE Tags](#cose-tags)
- [Cryptographic Structures](#cryptographic-structures)
- [Reading Headers](#reading-headers)
- [Common Header Parameters](#common-header-parameters)
- [Detached Content](#detached-content)
- [External Additional Authenticated Data](#external-additional-authenticated-data)

## COSE Tags

COSE defines six message types, each a CBOR tag. The classes come from
[spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0 or later; the `Cose\...Tag` classes this
library used to ship are deprecated, see [Upgrading](Upgrading.md).

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
configuration:

```php
use CBOR\Decoder;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;

$message = Decoder::create()->decode(new StringStream($encodedData));
if (! $message instanceof CoseSign1Tag) {
    throw new RuntimeException('Not a COSE_Sign1 message');
}
```

## Cryptographic Structures

A COSE signature or MAC never covers the payload on its own. It covers a **structure** that also binds the protected
header and the message type, so a tag computed for a `COSE_Mac0` cannot be replayed on a `COSE_Mac`, and a signature
made for one signer of a `COSE_Sign` cannot be lifted into a `COSE_Sign1`. An encryption likewise authenticates a
structure rather than the bare protected header. These structures are what this library builds; casting one to
string yields the CBOR bytes to hand to the algorithm.

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
| RFC 9338 §3.3 `Countersign_structure` | `Cose\Signature\Countersign::full()` | `"CounterSignature"` / `"CounterSignatureV2"` | body_protected, **sign_protected**, external_aad, payload, ? other_fields |
| RFC 9338 §3.3 `Countersign_structure` | `Cose\Signature\Countersign::abbreviated()` | `"CounterSignature0"` / `"CounterSignature0V2"` | body_protected, external_aad, payload, ? other_fields |

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
map, applying the RFC 9052 §3 rules on the way out — an empty map becomes `h''` rather than `h'a0'`, and the labels
are checked (§1.5, §9).

There is one exception, and the structures apply it themselves. §3 lets a sender write an empty protected bucket
either as the zero-length byte string `h''` or as an empty map wrapped in a byte string, `h'a0'`, and requires
recipients to accept both; §§4.4, 5.3 and 6.3 then define the protected field of every structure with "If there are
no protected attributes, a zero-length byte string is used". A message carrying `h'a0'` is therefore verified over
`h''` — the bytes its sender computed — whichever form travels on the wire. `CoseStructure::emptyOrSerializedMap()`
is that rule, and only `h'a0'` is affected: a non-empty bucket is never re-encoded.

Every structure takes the optional `external_aad` as its last argument, see
[External Additional Authenticated Data](#external-additional-authenticated-data). The `Countersign_structure` is
computed over a finalized message rather than by it; see [Countersignatures](Countersignatures.md).

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

For a per-signer or per-recipient bucket, `CoseSignature` and `CoseRecipient` expose the same lookups — see
[Signing](Signing.md#cose_sign-multiple-signers) and [Encryption](Encryption.md#cose_encrypt-multiple-recipients);
for a header map you assembled yourself, use `CoseHeaders::of($protectedBytes, $unprotectedMap)`.
`Cose\Structure\HeaderMapHelper` holds the same rules as static functions, including `encodeProtected()` and
`assertTagNumber()`.

The protected header is decoded with a decoder bounded to `CoseHeaders::DEFAULT_PROTECTED_HEADER_MAX_DEPTH` (32)
levels of nesting. Pass your own `Decoder` when a header carries custom CBOR tags, or a different `$maxDepth` when 32
is not the right bound:

```php
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagManager;

$customDecoder = Decoder::create(
    TagManager::create()->add(MyCustomTag::class),
    OtherObjectManager::create(),
    32
);
$headers = CoseHeaders::fromMessage($coseSign1, $customDecoder);
```

Some header parameters come with a rule of their own that a raw lookup cannot apply, and have a typed accessor:
`typ` and `CWT Claims` are described with [CBOR Web Tokens](Cwt.md#typ-and-cwt-claims), the X.509 parameters in
[X.509 Header Parameters](X509.md), the hash envelope parameters in [Hash Envelope](HashEnvelope.md), the
countersignature labels in [Countersignatures](Countersignatures.md), the `receipts`, `vds` and `vdp` parameters in
[COSE Receipts](Receipts.md), and the ECDH and HKDF parameters of a `COSE_recipient` in
[Key Management](KeyManagement.md).

## Common Header Parameters

| Label | Name | Type | Description |
|-------|------|------|-------------|
| 1 | alg | int | Cryptographic algorithm |
| 2 | crit | [+label] | Critical headers |
| 3 | content type | tstr / uint | Content type of payload |
| 4 | kid | bstr | Key identifier |
| 5 | IV | bstr | Initialization Vector, see [The Nonce](Encryption.md#the-nonce-iv-and-partial-iv) |
| 6 | Partial IV | bstr | Partial Initialization Vector |
| 15 | CWT Claims | map | CWT claims in the header (RFC 9597), `getCwtClaims()` |
| 16 | typ | tstr / uint | Type of the COSE object (RFC 9596), `getTyp()` |
| 11 | Countersignature version 2 | COSE_Countersignature / [+ COSE_Countersignature] | Full countersignatures, unprotected only (RFC 9338), `getCountersignatures()` |
| 12 | Countersignature0 version 2 | bstr | Abbreviated countersignature, unprotected only (RFC 9338), `getCountersignature0()` |
| 32 | x5bag | COSE_X509 | Unordered bag of X.509 certificates (RFC 9360), `getX5Bag()` |
| 33 | x5chain | COSE_X509 | Ordered chain of X.509 certificates, end-entity first (RFC 9360), `getX5Chain()` |
| 34 | x5t | COSE_CertHash | Thumbprint of the end-entity certificate (RFC 9360), `getX5T()` |
| 35 | x5u | uri | URI of an X.509 certificate, never fetched by this library (RFC 9360), `getX5U()` |
| 258 | payload-hash-alg | int | Hash algorithm of the payload of a hash envelope, protected only (RFC 9995), `getPayloadHashAlg()` |
| 259 | preimage-content-type | uint / tstr | Content type of the hashed bytes, protected only (RFC 9995), `getPreimageContentType()` |
| 260 | payload-location | tstr | Where the hashed bytes can be retrieved, never fetched by this library (RFC 9995), `getPayloadLocation()` |
| 394 | receipts | [+ bstr .cbor Receipt] | COSE receipts, each a tagged COSE_Sign1 (RFC 9942), `getReceipts()` |
| 395 | vds | int | Verifiable data structure of a receipt, protected bucket only (RFC 9942), `getVds()` |
| 396 | vdp | map | Verifiable data structure proofs of a receipt, keyed by proof type (RFC 9942), `getVdp()` |

The header *algorithm* parameters of the key management algorithms, read from a `COSE_recipient` by the same
accessors:

| Label | Name | Type | Description |
|-------|------|------|-------------|
| -1 | ephemeral key | COSE_Key | Sender's ephemeral public key, ECDH-ES (RFC 9053 §6.3.1), `getEphemeralKey()` |
| -2 | static key | COSE_Key | Sender's static public key, ECDH-SS (RFC 9053 §6.3.1), `getStaticKey()` |
| -3 | static key id | bstr | Identifier of the sender's static key, ECDH-SS (RFC 9053 §6.3.1), `getStaticKeyId()` |
| -20 | salt | bstr | Salt of the HKDF extract step (RFC 9053 §5.1), `getSalt()` |
| -21 | PartyU identity | bstr | PartyUInfo of the COSE_KDF_Context (RFC 9053 §5.2), `getPartyUIdentity()` |
| -22 | PartyU nonce | bstr / int | `getPartyUNonce()` |
| -23 | PartyU other | bstr | `getPartyUOther()` |
| -24 | PartyV identity | bstr | PartyVInfo of the COSE_KDF_Context (RFC 9053 §5.2), `getPartyVIdentity()` |
| -25 | PartyV nonce | bstr / int | `getPartyVNonce()` |
| -26 | PartyV other | bstr | `getPartyVOther()` |
| -27 | x5t-sender | COSE_CertHash | Thumbprint of the sender's key exchange certificate, ECDH-SS (RFC 9360 §3), `getX5TSender()` |
| -28 | x5u-sender | uri | URI of the sender's key exchange certificate, never fetched (RFC 9360 §3), `getX5USender()` |
| -29 | x5chain-sender | COSE_X509 | Chain of the sender's key exchange certificate, ECDH-SS (RFC 9360 §3), `getX5ChainSender()` |

## Detached Content

[RFC 9052 §4.1](https://datatracker.ietf.org/doc/html/rfc9052#section-4.1) lets the payload — or the ciphertext of an
encrypted message — travel outside the message, as a `nil` in its place:

```php
use CBOR\ByteStringObject;
use CBOR\OtherObject\NullObject;
use CBOR\Tag\CoseSign1Tag;
use Cose\Signature\Signature1;

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
[RFC 9052 §4.4](https://datatracker.ietf.org/doc/html/rfc9052#section-4.4) as its last argument: data the application
supplies on both sides and that never travels in the message, yet is bound to the signature, the MAC or the
encryption. It defaults to the zero-length byte string the RFC prescribes:

```php
use CBOR\ByteStringObject;
use Cose\Signature\Signature1;

$toBeSigned = Signature1::create(
    $coseSign1->getProtectedHeader(),
    $payload,
    ByteStringObject::create($applicationSuppliedData),
);
```

[`examples/07-detached-and-external-aad.php`](../examples/07-detached-and-external-aad.php) shows both.
