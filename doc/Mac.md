# Message Authentication Codes

[← Documentation index](README.md)

- [COSE_Mac0 (Without Recipients)](#cose_mac0-without-recipients)
- [COSE_Mac (With Recipients)](#cose_mac-with-recipients)
- [The Tag Covers the MAC_structure](#the-tag-covers-the-mac_structure)

The MAC algorithms — HMAC and AES-CBC-MAC — are listed in [Algorithms](Algorithms.md#mac-algorithms), with the
conditions AES-CBC-MAC comes with; the key they take, and what is checked about it, in
[Validating Symmetric Keys](Keys.md#validating-symmetric-keys).

## COSE_Mac0 (Without Recipients)

```php
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\Tag\CoseMac0Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Mac\HS256;
use Cose\Key\SymmetricKey;
use Cose\Mac\Mac0Structure;
use Cose\Structure\HeaderMapHelper;

$algorithm = HS256::create();
$key = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => $sharedSecret, // 32 bytes for HS256
]);

// Encode the protected bucket once: the bytes the tag covers are the bytes the message carries
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($algorithm::identifier())),
]));
$payload = ByteStringObject::create('Data to authenticate');

// The tag covers the MAC_structure ["MAC0", protected, external_aad, payload], never the payload alone
$toBeMaced = Mac0Structure::create($protectedHeader, $payload);
$tag = ByteStringObject::create($algorithm->hash((string) $toBeMaced, $key));

$coseMac0 = CoseMac0Tag::create(ListObject::create([
    $protectedHeader,
    MapObject::create(),
    $payload,
    $tag,
]));
```

Verifying rebuilds the structure from the bytes the message carries:

```php
$toBeMaced = Mac0Structure::create($coseMac0->getProtectedHeader(), $coseMac0->getPayload());
$isValid = $algorithm->verify((string) $toBeMaced, $key, $coseMac0->getTag()->getValue()); // compared with hash_equals()
```

[`examples/03-mac0.php`](../examples/03-mac0.php) runs the whole of it, with HMAC and then with AES-CBC-MAC.

## COSE_Mac (With Recipients)

The `COSE_Mac` structure carries the MAC key to its recipients the way `COSE_Encrypt` carries a content encryption
key: one `COSE_recipient` per recipient, filled by a [key management algorithm](KeyManagement.md).

```php
use CBOR\ListObject;
use CBOR\Tag\CoseMacTag;
use Cose\Mac\MacStructure;
use Cose\Structure\CoseRecipient;

// Context "MAC" — the same header and payload give a different tag than under "MAC0"
$toBeMaced = MacStructure::create($protectedHeader, $payload);
$tag = ByteStringObject::create($algorithm->hash((string) $toBeMaced, $macKey));

$recipients = ListObject::create([
    ListObject::create([/* recipient 1: protected, unprotected, wrapped MAC key */]),
]);

$coseMac = CoseMacTag::create(ListObject::create([
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $tag,
    $recipients,
]));

// Reading the recipients back as checked views rather than raw lists
foreach (CoseRecipient::all($coseMac->getRecipients()) as $recipient) {
    $kid = $recipient->getUnprotectedHeaderParameter(4);
}
```

The `Enc_structure` a recipient of a `COSE_Mac` is computed over is `RecipientStructure::forMacRecipient()`
(`"Mac_Recipient"`); `RecipientLayer::fromRecipient()` takes the MAC algorithm as the algorithm of the layer below,
so that the `COSE_KDF_Context` binds the derived key to it. RFC 9052 §6.1 writes the list as `[+COSE_recipient]`:
at least one entry, which `CoseRecipient::all()` enforces, nested levels included.

## The Tag Covers the MAC_structure

> [!IMPORTANT]
> The tag of a `COSE_Mac0` or `COSE_Mac` is **not** a MAC of the payload. It is computed over the `MAC_structure` of
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
> implementation. For AES-CBC-MAC the structure is also what makes the algorithm safe to use at all, see
> [MAC Algorithms](Algorithms.md#mac-algorithms).
