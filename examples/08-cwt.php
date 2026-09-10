<?php

declare(strict_types=1);

/**
 * CBOR Web Token (RFC 8392): a claims set carried as the payload of a COSE message.
 *
 * A CWT is not a separate format -- it is what a COSE_Sign1 most often contains. cbor-php 3.4.0 also ships CwtTag for
 * the optional tag 61 that marks the whole thing as a CWT.
 *
 * The point to take away: verify, then read. A claims map decoded from an unverified payload is attacker-controlled
 * input, and an "exp" read from it means nothing.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CwtTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('CWT: a signed claims set');

$privateKey = example_ec_key();
$publicKey = $privateKey->toPublic();
$algorithm = ES256::create();

$issuedAt = 1443944944;
$expiresAt = $issuedAt + 3600;

// --- issuing ------------------------------------------------------------------

// RFC 8392 section 3.1: 1 = iss, 2 = sub, 3 = aud, 4 = exp, 5 = nbf, 6 = iat, 7 = cti
$claims = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), TextStringObject::create('coap://as.example.com')),
    MapItem::create(UnsignedIntegerObject::create(2), TextStringObject::create('erikw')),
    MapItem::create(UnsignedIntegerObject::create(4), UnsignedIntegerObject::create($expiresAt)),
    MapItem::create(UnsignedIntegerObject::create(6), UnsignedIntegerObject::create($issuedAt)),
]);

$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
]));

// The claims set is the payload: opaque bytes as far as COSE is concerned.
$payload = ByteStringObject::create((string) $claims);

$toBeSigned = Signature1::create($protectedHeader, $payload);
$signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $privateKey));

$message = CoseSign1Tag::create(ListObject::create([
    $protectedHeader,
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('AsymmetricECDSA256')),
    ]),
    $payload,
    $signature,
]));

// Tag 61 is optional; it says "what follows is a CWT".
$encoded = (string) CwtTag::create($message);
example_hex('CWT', $encoded);
example_assert(str_starts_with(bin2hex($encoded), 'd83d'), 'the outer head is tag 61');
echo PHP_EOL;

// --- consuming -----------------------------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));

// Accept both the tagged and the untagged form.
$token = $decoded instanceof CwtTag ? $decoded->getValue() : $decoded;
example_assert($token instanceof CoseSign1Tag, 'the token is a COSE_Sign1');

// 1. Bind the algorithm before anything else.
$headers = CoseHeaders::fromMessage($token);
$alg = $headers->getProtectedHeaderParameter(1);
example_assert(
    $alg !== null && (int) $alg->normalize() === ES256::identifier(),
    'the protected header declares the expected algorithm'
);
example_line('kid', (string) $headers->getHeaderParameter(4)?->getValue());

// 2. Verify.
$toBeVerified = Signature1::create($token->getProtectedHeader(), $token->getPayload());
example_assert(
    $algorithm->verify((string) $toBeVerified, $publicKey, $token->getSignature()->getValue()),
    'the signature verifies'
);

// 3. Only now, read the claims.
$decodedClaims = Decoder::create()
    ->decode(StringStream::create($token->getPayload()->getValue()))
    ->normalize();

example_line('iss', (string) $decodedClaims[1]);
example_line('sub', (string) $decodedClaims[2]);

// cbor-php normalizes CBOR integers to numeric strings, so cast before comparing timestamps.
example_assert(is_string($decodedClaims[4]), 'the timestamps come back as numeric strings');
$expiry = (int) $decodedClaims[4];
example_line('exp', sprintf('%d (%s)', $expiry, gmdate('Y-m-d H:i:s\Z', $expiry)));
example_assert($expiry === $expiresAt, 'the expiry round-trips once cast');
