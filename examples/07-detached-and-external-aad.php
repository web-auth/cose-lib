<?php

declare(strict_types=1);

/**
 * Detached content (RFC 9052 section 4.1) and external_aad (section 4.4).
 *
 * Two things an application supplies from outside the message: the payload, when it travels separately, and any
 * context the signature should cover without being carried on the wire.
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
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('Detached content and external_aad');

$privateKey = example_ec_key();
$publicKey = $privateKey->toPublic();
$algorithm = ES256::create();

$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
]));

// --- detached content ---------------------------------------------------------

// The content travels out of band -- a large file, a body already on disk -- and a nil sits in its place.
$content = ByteStringObject::create('A payload carried outside the message');

$toBeSigned = Signature1::create($protectedHeader, $content);
$signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $privateKey));

$detached = CoseSign1Tag::create(ListObject::create([
    $protectedHeader,
    MapObject::create(),
    NullObject::create(),
    $signature,
]));

$encoded = (string) $detached;
example_hex('COSE_Sign1', $encoded);
example_line('size', sprintf('%d bytes, payload not included', strlen($encoded)));

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseSign1Tag, 'decoded as a COSE_Sign1');
example_assert($decoded->getPayload() instanceof NullObject, 'the payload is detached');

// The application puts the content back before verifying. Everything else is unchanged.
$toBeVerified = Signature1::create($decoded->getProtectedHeader(), $content);
example_assert(
    $algorithm->verify((string) $toBeVerified, $publicKey, $decoded->getSignature()->getValue()),
    'the signature verifies once the content is supplied'
);

// Supplying the wrong content fails, which is the whole point of signing it.
$wrong = Signature1::create($decoded->getProtectedHeader(), ByteStringObject::create('Something else'));
example_assert(
    ! $algorithm->verify((string) $wrong, $publicKey, $decoded->getSignature()->getValue()),
    'the wrong content does not verify'
);
echo PHP_EOL;

// --- external_aad --------------------------------------------------------------

// Context the two parties already share -- a session identifier, a transaction id -- that the signature should cover
// without being transmitted. RFC 9052 section 4.4: absent, it defaults to a zero-length byte string.
$sessionContext = ByteStringObject::create('session-42');
$payload = ByteStringObject::create('Bound to a session');

$toBeSigned = Signature1::create($protectedHeader, $payload, $sessionContext);
$signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $privateKey));

example_hex('with external_aad', (string) $toBeSigned);
example_hex('without', (string) Signature1::create($protectedHeader, $payload));

$message = CoseSign1Tag::create(ListObject::create([
    $protectedHeader,
    MapObject::create(),
    $payload,
    $signature,
]));
$decoded = Decoder::create()->decode(StringStream::create((string) $message));

// A verifier that knows the context accepts it...
$toBeVerified = Signature1::create($decoded->getProtectedHeader(), $decoded->getPayload(), $sessionContext);
example_assert(
    $algorithm->verify((string) $toBeVerified, $publicKey, $decoded->getSignature()->getValue()),
    'the signature verifies with the right external_aad'
);

// ...and one that does not, or that has the wrong context, does not. The message on the wire is identical.
$toBeVerified = Signature1::create($decoded->getProtectedHeader(), $decoded->getPayload());
example_assert(
    ! $algorithm->verify((string) $toBeVerified, $publicKey, $decoded->getSignature()->getValue()),
    'and not without it'
);
$toBeVerified = Signature1::create(
    $decoded->getProtectedHeader(),
    $decoded->getPayload(),
    ByteStringObject::create('session-43')
);
example_assert(
    ! $algorithm->verify((string) $toBeVerified, $publicKey, $decoded->getSignature()->getValue()),
    'nor with a different one'
);
