# Encryption

[← Documentation index](README.md)

- [COSE_Encrypt0 (Single Recipient)](#cose_encrypt0-single-recipient)
- [COSE_Encrypt (Multiple Recipients)](#cose_encrypt-multiple-recipients)
- [The Nonce: IV and Partial IV](#the-nonce-iv-and-partial-iv)

The content encryption algorithms of [RFC 9053 §4](https://datatracker.ietf.org/doc/html/rfc9053#section-4) live in
`Cose\Algorithm\ContentEncryption`: `A128GCM`, `A192GCM`, `A256GCM`, the eight AES-CCM variants and
`ChaCha20Poly1305`, see [Content Encryption Algorithms](Algorithms.md#content-encryption-algorithms). Every one of
them encrypts with a symmetric key, a nonce whose length the algorithm fixes, and the `Enc_structure` of
[RFC 9052 §5.3](https://datatracker.ietf.org/doc/html/rfc9052#section-5.3) as additional authenticated data — never
the protected header on its own. `Encrypt0Structure` and `EncryptStructure` build that structure and hand it to the
algorithm through `encrypt()` and `decrypt()`. How the content key reaches the recipients of a `COSE_Encrypt` is the
subject of [Key Management](KeyManagement.md).

## COSE_Encrypt0 (Single Recipient)

```php
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Encryption\Encrypt0Structure;
use Cose\Encryption\InitializationVector;
use Cose\Key\SymmetricKey;
use Cose\Structure\HeaderMapHelper;

$algorithm = A128GCM::create();
$key = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => $sharedSecret, // 16 bytes for A128GCM
]);
// The key and nonce pair MUST be unique for every message (RFC 9053 §4.1.1)
$nonce = random_bytes($algorithm->nonceLength());

// Encode the protected bucket once: the bytes the AEAD authenticates are the bytes the message carries
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($algorithm::identifier())),
]));
$unprotectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(InitializationVector::IV), ByteStringObject::create($nonce)),
]);

// ["Encrypt0", protected, external_aad] is the AAD; the result is the ciphertext followed by the tag
$ciphertext = Encrypt0Structure::create($protectedHeader)->encrypt($algorithm, $key, $plaintext, $nonce);

$coseEncrypt0 = CoseEncrypt0Tag::create(ListObject::create([
    $protectedHeader,
    $unprotectedHeader,
    ByteStringObject::create($ciphertext),
]));
```

Decrypting rebuilds the structure from the bytes the message carries, and resolves the nonce from its headers:

```php
use Cose\Structure\CoseHeaders;

$headers = CoseHeaders::fromMessage($coseEncrypt0);
$nonce = InitializationVector::resolve($headers, $algorithm->nonceLength(), $key);
$plaintext = Encrypt0Structure::create($coseEncrypt0->getProtectedHeader())
    ->decrypt($algorithm, $key, $coseEncrypt0->getCiphertext()->getValue(), $nonce);
```

`decrypt()` throws an `InvalidArgumentException` when the content does not authenticate. A wrong key, a wrong nonce,
a rewritten protected header, an external AAD the sender did not use, a tag that was tampered with, replaced or
truncated: the primitive cannot tell them apart, and the library reports all of them with the same message
(`Aead::DECRYPTION_FAILED`).

[`examples/04-encrypt0.php`](../examples/04-encrypt0.php) runs the whole of it, `IV` and `Partial IV` included.

## COSE_Encrypt (Multiple Recipients)

The content layer is the same, under the `"Encrypt"` context, with a content encryption key (CEK) drawn at random
and wrapped for each recipient:

```php
use CBOR\ListObject;
use CBOR\Tag\CoseEncryptTag;
use Cose\Encryption\EncryptStructure;
use Cose\Structure\CoseRecipient;

$ciphertext = EncryptStructure::create($protectedHeader)->encrypt($algorithm, $contentEncryptionKey, $plaintext, $nonce);

$recipients = ListObject::create([
    ListObject::create([/* recipient 1: protected, unprotected, wrapped CEK */]),
    ListObject::create([/* recipient 2 */]),
]);

$coseEncrypt = CoseEncryptTag::create(ListObject::create([
    $protectedHeader,
    $unprotectedHeader,
    ByteStringObject::create($ciphertext),
    $recipients,
]));

// Reading them back as checked views; a recipient may carry recipients of its own
foreach (CoseRecipient::all($coseEncrypt->getRecipients()) as $recipient) {
    $kid = $recipient->getUnprotectedHeaderParameter(4);
    $wrappedKey = $recipient->hasDetachedCiphertext() ? null : $recipient->getCiphertext();
    $nested = $recipient->getRecipients(); // list<CoseRecipient>
}
```

> [!IMPORTANT]
> The additional authenticated data of the content encryption is the `Enc_structure` of
> [RFC 9052 §5.3](https://datatracker.ietf.org/doc/html/rfc9052#section-5.3), not the protected header on its own.
> `Encrypt0Structure` and `EncryptStructure` differ by their context string only, and that difference is
> authenticated: a ciphertext produced for a `COSE_Encrypt` does not open as a `COSE_Encrypt0`. For a recipient
> layer, the structure is `RecipientStructure::forEncryptRecipient()` (`"Enc_Recipient"`):
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

The recipient entries are filled by the key management algorithms of RFC 9053 §5–6, and
`EncryptStructure::encryptFor()` runs the whole of it — draw the CEK, wrap or derive it for each recipient, encrypt
the content, assemble the message — in one call:

```php
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\KeyManagement\A256KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_A128KW;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\Recipient;

$algorithm = A128GCM::create();
$coseEncrypt = EncryptStructure::create($protectedHeader)->encryptFor($algorithm, $plaintext, random_bytes(12), [
    Recipient::create(A256KW::create(), $sharedKek, null, $kidHeader),  // a Symmetric key the parties share
    Recipient::create(ECDH_ES_A128KW::create(), $bobPublicKey),         // Bob's EC2 or OKP public key
]); // CBOR\Tag\CoseEncryptTag: the IV is in its unprotected bucket, each COSE_recipient carries its "alg"
```

Opening it is the reverse, one recipient at a time — the recipient's own key, the algorithm its headers announce,
and a `RecipientLayer` that says what the recovered key is for:

```php
use Cose\Algorithm\KeyManagement\KeyManagement;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Encryption\InitializationVector;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;

$entries = CoseRecipient::all($coseEncrypt->getRecipients());
$mine = $entries[1]; // located by "kid", by the ephemeral key, or however the application names its recipients
$keyManagement = $manager->get((int) $mine->headers()->getHeaderParameter(1)?->normalize());
assert($keyManagement instanceof KeyManagement);

$cek = $keyManagement->recoverKey(RecipientLayer::fromRecipient($mine, $algorithm, null, count($entries)), $bobPrivateKey);
$plaintext = EncryptStructure::create($coseEncrypt->getProtectedHeader())->decrypt(
    $algorithm,
    SymmetricKey::create([SymmetricKey::TYPE => SymmetricKey::TYPE_OCT, SymmetricKey::DATA_K => $cek]),
    $coseEncrypt->getCiphertext()->getValue(),
    InitializationVector::resolve(CoseHeaders::fromMessage($coseEncrypt), $algorithm->nonceLength())
);
```

See [Key Management](KeyManagement.md) for the eighteen algorithms, the rules each family enforces, and the
parameters of a static-static agreement; and
[`examples/05-encrypt-recipients.php`](../examples/05-encrypt-recipients.php) for the whole of it, nested recipients
included.

## The Nonce: IV and Partial IV

[RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1) gives a message two ways to carry its
nonce: the `IV` header parameter (label 5) holds it whole; the `Partial IV` (label 6) holds only the part that
changes from one message to the next, and the recipient completes it with the `Base IV` of the key (label 5 of the
key map, [§7.1](https://datatracker.ietf.org/doc/html/rfc9052#section-7.1)):

1. left-pad the Partial IV with zeros to the nonce length of the algorithm;
2. XOR it with the Base IV, itself a prefix of the nonce.

`InitializationVector::resolve()` does both, and rejects a layer carrying the two parameters at once — the RFC says
they "MUST NOT both be present in the same security layer" — as well as an `IV` of the wrong length:

```php
use Cose\Encryption\InitializationVector;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;

$key = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => $sharedSecret,
    SymmetricKey::BASE_IV => $baseIv, // h'89F52F65A1C58093' in RFC 9052 Appendix C.4.2
]);

// The recipient: from the message headers
$nonce = InitializationVector::resolve(CoseHeaders::fromMessage($message), $algorithm->nonceLength(), $key);

// The sender: from the counter it is about to send as Partial IV
$nonce = InitializationVector::fromPartialIv($counter, $baseIv, $algorithm->nonceLength());
```

> [!WARNING]
> **A nonce reused under the same key is catastrophic for every algorithm here.** AES-GCM and ChaCha20/Poly1305 leak
> their authentication key, after which any message under that key can be forged; AES-CCM leaks the XOR of the two
> plaintexts. Draw the nonce with `random_bytes()` for each message, or send a strictly increasing counter as the
> `Partial IV`. The 7-byte nonce of the AES-CCM-64-* variants is too short for random draws to stay unique for long
> (a collision is expected after about 2^28 messages): use a counter with those.
