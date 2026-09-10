<?php

declare(strict_types=1);

/**
 * COSE_Mac0 (RFC 9052 section 6.2): a MAC with no recipient structure.
 *
 * The point to take away: Mac::hash() authenticates exactly the bytes it is given. Handing it the payload produces a
 * tag bound to no header, no algorithm and no message type -- and interoperable with nothing. The MAC_structure is
 * what binds them, and its context string is the only difference between a COSE_Mac0 and a COSE_Mac tag.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\Tag\CoseMac0Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Mac\HS256;
use Cose\Mac\Mac0Structure;
use Cose\Mac\MacStructure;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Mac0: authenticate and verify');

$key = example_symmetric_key();
$algorithm = HS256::create();

// --- authenticating ---------------------------------------------------------

// HMAC 256/256 is algorithm 5 in the IANA COSE Algorithms registry.
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(HS256::identifier())),
]));
$payload = ByteStringObject::create('Data to authenticate');

$toBeMaced = Mac0Structure::create($protectedHeader, $payload);
$tag = ByteStringObject::create($algorithm->hash((string) $toBeMaced, $key));

$message = CoseMac0Tag::create(ListObject::create([
    $protectedHeader,
    MapObject::create(),
    $payload,
    $tag,
]));

$encoded = (string) $message;
example_hex('MAC_structure', (string) $toBeMaced);
example_hex('COSE_Mac0', $encoded);
echo PHP_EOL;

// --- verifying ---------------------------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseMac0Tag, 'decoded as a COSE_Mac0');

$headers = CoseHeaders::fromMessage($decoded);
$alg = $headers->getProtectedHeaderParameter(1);
example_assert(
    $alg !== null && (int) $alg->normalize() === HS256::identifier(),
    'the protected header declares HMAC 256/256'
);

$toBeVerified = Mac0Structure::create($decoded->getProtectedHeader(), $decoded->getPayload());
example_assert(
    $algorithm->verify((string) $toBeVerified, $key, $decoded->getTag()->getValue()),
    'the tag verifies over the MAC_structure'
);

// --- the two mistakes the structure prevents ---------------------------------

example_assert(
    ! $algorithm->verify($decoded->getPayload()->getValue(), $key, $decoded->getTag()->getValue()),
    'the tag does not verify over the bare payload'
);

// The same header and payload under the "MAC" context -- a COSE_Mac -- give a different tag, so a tag cannot be
// moved between the two message types.
$asMac = MacStructure::create($decoded->getProtectedHeader(), $decoded->getPayload());
example_assert(
    ! $algorithm->verify((string) $asMac, $key, $decoded->getTag()->getValue()),
    'the tag is not valid under the "MAC" context'
);
example_hex('MAC0 structure', (string) $toBeVerified);
example_hex('MAC structure', (string) $asMac);
