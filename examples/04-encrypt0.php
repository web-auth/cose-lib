<?php

declare(strict_types=1);

/**
 * COSE_Encrypt0 (RFC 9052 section 5.2): content encrypted for a single recipient.
 *
 * This library does not implement content encryption -- that is what your AEAD is for. What it gives you is the
 * Enc_structure of RFC 9052 section 5.3, the additional authenticated data the AEAD has to cover so that the
 * ciphertext is bound to the header it travels with. Here the AEAD is AES-128-GCM through OpenSSL.
 *
 * Note that Enc_structure carries no payload: the content is what the AEAD encrypts, and the structure is what it
 * authenticates alongside it.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Encryption\Encrypt0Structure;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Encrypt0: encrypt and decrypt');

$contentEncryptionKey = random_bytes(16);
$iv = random_bytes(12);
$plaintext = 'Secret content';

// --- encrypting -------------------------------------------------------------

// A128GCM is algorithm 1 in the IANA COSE Algorithms registry. The IV (label 5) is not secret and rides in the
// unprotected bucket, as RFC 9053 section 4.1 allows.
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(1)),
]));
$unprotectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(5), ByteStringObject::create($iv)),
]);

// The additional authenticated data: ["Encrypt0", protected, external_aad]
$aad = (string) Encrypt0Structure::create($protectedHeader);
example_hex('Enc_structure', $aad);

$ciphertext = openssl_encrypt(
    $plaintext,
    'aes-128-gcm',
    $contentEncryptionKey,
    OPENSSL_RAW_DATA,
    $iv,
    $authTag,
    $aad,
    16
);
example_assert($ciphertext !== false, 'the content was encrypted');

// RFC 9053 section 4.1: the authentication tag is appended to the ciphertext.
$message = CoseEncrypt0Tag::create(ListObject::create([
    $protectedHeader,
    $unprotectedHeader,
    ByteStringObject::create($ciphertext . $authTag),
]));

$encoded = (string) $message;
example_hex('COSE_Encrypt0', $encoded);
echo PHP_EOL;

// --- decrypting -------------------------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseEncrypt0Tag, 'decoded as a COSE_Encrypt0');

$headers = CoseHeaders::fromMessage($decoded);
$alg = $headers->getProtectedHeaderParameter(1);
example_assert($alg !== null && (int) $alg->normalize() === 1, 'the protected header declares A128GCM');

$decodedIv = $headers->getUnprotectedHeaderParameter(5)?->getValue();
example_assert($decodedIv !== null, 'the IV is present');

// The AAD is rebuilt from the bytes the message carries, not from a re-encoded map.
$aad = (string) Encrypt0Structure::create($decoded->getProtectedHeader());

$carried = $decoded->getCiphertext()->getValue();
$recovered = openssl_decrypt(
    substr($carried, 0, -16),
    'aes-128-gcm',
    $contentEncryptionKey,
    OPENSSL_RAW_DATA,
    (string) $decodedIv,
    substr($carried, -16),
    $aad
);
example_assert($recovered === $plaintext, 'the content was recovered');

// --- what the AAD buys you ----------------------------------------------------

// Flip the declared algorithm in the AAD and the AEAD refuses: the ciphertext is bound to the header it shipped with.
$tamperedAad = (string) Encrypt0Structure::create(
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(3)),
    ]))
);
$shouldFail = openssl_decrypt(
    substr($carried, 0, -16),
    'aes-128-gcm',
    $contentEncryptionKey,
    OPENSSL_RAW_DATA,
    (string) $decodedIv,
    substr($carried, -16),
    $tamperedAad
);
example_assert($shouldFail === false, 'a rewritten protected header breaks decryption');
