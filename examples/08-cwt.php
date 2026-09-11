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
 *
 * Two header parameters travel with the token here: "typ" (RFC 9596), which names what the whole COSE object is, and
 * "CWT Claims" (RFC 9597), which repeats claims in the protected header so that they can be read without decoding the
 * payload. RFC 9597 section 2: when a claim appears in both, "an application receiving such a structure MUST verify
 * that their values are identical" -- the payload is opaque to the library, so that comparison is done below, by the
 * application.
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

// RFC 9596 section 2: "typ" says what the COSE object is -- "application/cwt", or its CoAP Content-Format 61. It
// MUST NOT be in the unprotected header. RFC 9597 section 2: "CWT Claims" is a map of claims, in the protected header
// by recommendation; here "iss" and "exp" are repeated so that a consumer can route on them before verifying.
$headerClaims = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), TextStringObject::create('coap://as.example.com')),
    MapItem::create(UnsignedIntegerObject::create(4), UnsignedIntegerObject::create($expiresAt)),
]);
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), TextStringObject::create('application/cwt')),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), $headerClaims),
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

// The type: an application expecting a CWT refuses anything else (RFC 9596 section 2 leaves that check to it).
// getTyp() reads the protected bucket only and rejects a message carrying "typ" in the unprotected one.
$typ = $headers->getTyp();
example_line('typ', (string) $typ);
example_assert($typ === 'application/cwt' || $typ === 61, 'the token says it is a CWT');

// The header claims are readable now, before the signature is checked: enough to pick the issuer's key, not
// enough to trust. getCwtClaims() rejects the parameter when it appears in both buckets (RFC 9597 section 2).
$claimsInHeader = $headers->getCwtClaims();
example_assert($claimsInHeader !== null, 'the protected header carries CWT Claims');
example_line('iss (header)', (string) HeaderMapHelper::findLabel($claimsInHeader, 1)?->normalize());

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

// 4. RFC 9597 section 2: a claim present in both the header and the payload MUST have identical values. The library
// cannot do this for you -- it never decodes the payload -- so compare the encoded values claim by claim.
$payloadClaims = Decoder::create()
    ->decode(StringStream::create($token->getPayload()->getValue()));
example_assert($payloadClaims instanceof MapObject, 'the payload is a claims map');
foreach ($claimsInHeader as $claim) {
    $key = $claim->getKey();
    $label = $key instanceof UnsignedIntegerObject || $key instanceof NegativeIntegerObject
        ? (int) $key->normalize()
        : (string) $key->normalize();
    $inPayload = HeaderMapHelper::findLabel($payloadClaims, $label);
    example_assert(
        $inPayload !== null && (string) $inPayload === (string) $claim->getValue(),
        sprintf('header claim %s matches the payload', $label)
    );
}
