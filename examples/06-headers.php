<?php

declare(strict_types=1);

/**
 * Reading headers the way RFC 9052 defines them.
 *
 * cbor-php carries the two buckets; it does not decide what they mean. CoseHeaders does, and each rule below exists
 * because the raw MapObject accessors answer differently -- in a way a conformant peer would not.
 */

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag\CoseSign1Tag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('Header rules');

/**
 * A COSE_Sign1 around the given protected bucket, so each rule is shown on a real message.
 */
$messageWith = static fn (string $protectedHeaderBytes, ?MapObject $unprotected = null): CoseSign1Tag
    => CoseSign1Tag::create(ListObject::create([
        ByteStringObject::create($protectedHeaderBytes),
        $unprotected ?? MapObject::create(),
        ByteStringObject::create('content'),
        ByteStringObject::create('signature'),
    ]));

// --- 1. a label is an int OR a tstr, and the two are different -----------------

// {"1": -7} -- a text-string label, not the algorithm parameter.
$textLabel = MapObject::create([
    MapItem::create(TextStringObject::create('1'), NegativeIntegerObject::create(-7)),
]);
$headers = CoseHeaders::fromMessage($messageWith((string) $textLabel));

// cbor-php keys its map by the normalized key, and PHP turns the offset "1" into 1, so both land on one slot:
example_assert($headers->getProtectedHeaderAsMap()->has(1), 'the raw map answers has(1) for a text-string key');
example_assert($headers->getProtectedHeaderParameter(1) === null, 'but the integer label 1 is absent');
example_assert(
    $headers->getProtectedHeaderParameter('1')?->normalize() === '-7',
    'and the text-string label "1" is what carries the value'
);
echo PHP_EOL;

// --- 2. a byte-string key is not a label at all --------------------------------

// {h'31': -7} normalizes to the string "1" as well, so without a type check it would answer for "alg".
$byteLabel = MapObject::create([
    MapItem::create(ByteStringObject::create('1'), NegativeIntegerObject::create(-7)),
]);
try {
    CoseHeaders::fromMessage($messageWith((string) $byteLabel))->getProtectedHeaderAsMap();
    example_assert(false, 'unreachable');
} catch (InvalidArgumentException $exception) {
    example_line('byte-string key', $exception->getMessage());
}
echo PHP_EOL;

// --- 3. the empty protected bucket, both spellings -----------------------------

// RFC 9052 section 3: "Recipients MUST accept both a zero-length byte string and a zero-length map encoded in a byte
// string." The first is the form senders are told to prefer.
foreach (['' => "h''", "\xa0" => "h'a0'"] as $bytes => $description) {
    $headers = CoseHeaders::fromMessage($messageWith($bytes));
    example_assert(count($headers->getProtectedHeaderAsMap()) === 0, $description . ' is an empty header');
}
example_line('encodeProtected([])', "h'" . bin2hex(HeaderMapHelper::encodeProtected(MapObject::create())->getValue()) . "'");
echo PHP_EOL;

// --- 4. the protected bucket holds exactly one CBOR item -----------------------

// The CDDL is "bstr .cbor header_map". Trailing bytes make the bucket malformed, and a decoder that ignores them
// disagrees with a strict one about what the message says.
try {
    CoseHeaders::fromMessage($messageWith("\xa1\x01\x26\xff\xff"))->getProtectedHeaderAsMap();
    example_assert(false, 'unreachable');
} catch (InvalidArgumentException $exception) {
    example_line('trailing bytes', $exception->getMessage());
}
echo PHP_EOL;

// --- 5. the protected bucket wins a combined lookup ----------------------------

// A message carrying a label in both buckets is malformed anyway; preferring the protected value keeps the answer on
// the side the signature covers.
$protectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
]);
$unprotectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-35)),
    MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('key-1')),
]);
$headers = CoseHeaders::fromMessage($messageWith((string) $protectedHeader, $unprotectedHeader));

example_assert($headers->getHeaderParameter(1)?->normalize() === '-7', 'getHeaderParameter reads the protected -7');
example_assert(
    $headers->getUnprotectedHeaderParameter(1)?->normalize() === '-35',
    'the unprotected -35 is still reachable explicitly'
);
example_assert($headers->getHeaderParameter(4)?->getValue() === 'key-1', 'kid falls through to the unprotected bucket');
example_assert($headers->getHeaderParameter(42) === null, 'an absent label is null, not an exception');
echo PHP_EOL;

// --- 6. duplicate labels ---------------------------------------------------------

// RFC 9052 section 9: "Applications MUST NOT generate messages with the same label used twice as a key in a single
// map." Building one is refused before it can be sent.
try {
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-35)),
    ]));
    example_assert(false, 'unreachable');
} catch (InvalidArgumentException $exception) {
    example_line('duplicate label', $exception->getMessage());
}
