<?php

declare(strict_types=1);

/**
 * COSE_Sign1 (RFC 9052 section 4.2): one signer, the shape WebAuthn and CWT use most.
 *
 * The point to take away: the signature covers the Sig_structure, never the payload on its own. That structure binds
 * the protected header and the message type, which is what stops a signature from being lifted onto another message.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Sign1: sign and verify');

$privateKey = example_ec_key();
$publicKey = $privateKey->toPublic();
$algorithm = ES256::create();

// --- signing ---------------------------------------------------------------

// The protected bucket is authenticated; the unprotected one is not. "alg" belongs in the protected one
// (RFC 9052 section 3.1), "kid" is only a hint and can sit outside.
$protectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
]);
$unprotectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('my-key-id')),
]);
$payload = ByteStringObject::create('Message to sign');

// Encode the protected bucket once. The Sig_structure embeds these bytes verbatim, so the message has to carry the
// very same ones -- re-encoding the map afterwards is how signatures silently stop verifying.
$protectedHeaderAsBytes = HeaderMapHelper::encodeProtected($protectedHeader);

$toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);
$signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $privateKey));

$message = CoseSign1Tag::create(ListObject::create([
    $protectedHeaderAsBytes,
    $unprotectedHeader,
    $payload,
    $signature,
]));

$encoded = (string) $message;
example_hex('Sig_structure', (string) $toBeSigned);
example_hex('COSE_Sign1', $encoded);
echo PHP_EOL;

// --- verifying -------------------------------------------------------------

// cbor-php 3.4.0 registers the six COSE tags in the default decoder, so tag 18 resolves without any setup.
$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseSign1Tag, 'decoded as a COSE_Sign1');

$headers = CoseHeaders::fromMessage($decoded);

// RFC 9052 section 3.1: the algorithm the protected header declares has to be the one you accept for that key. A
// verifier that hard-codes its algorithm and ignores the header accepts a message announcing another one.
$alg = $headers->getProtectedHeaderParameter(1);
example_assert(
    $alg !== null && (int) $alg->normalize() === ES256::identifier(),
    'the protected header declares ES256'
);
example_line('kid', (string) $headers->getHeaderParameter(4)?->getValue());

$decodedPayload = $decoded->getPayload();
example_assert(! $decodedPayload instanceof NullObject, 'the payload is attached');

$toBeVerified = Signature1::create($decoded->getProtectedHeader(), $decodedPayload);
example_assert(
    $algorithm->verify((string) $toBeVerified, $publicKey, $decoded->getSignature()->getValue()),
    'the signature verifies'
);

// --- what tampering looks like ---------------------------------------------

$tampered = (string) CoseSign1Tag::create(ListObject::create([
    $decoded->getProtectedHeader(),
    $decoded->getUnprotectedHeader(),
    ByteStringObject::create('Another message'),
    $decoded->getSignature(),
]));
$tamperedMessage = Decoder::create()->decode(StringStream::create($tampered));
$toBeVerified = Signature1::create($tamperedMessage->getProtectedHeader(), $tamperedMessage->getPayload());
example_assert(
    ! $algorithm->verify((string) $toBeVerified, $publicKey, $tamperedMessage->getSignature()->getValue()),
    'a swapped payload no longer verifies'
);
