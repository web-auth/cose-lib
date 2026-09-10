<?php

declare(strict_types=1);

/**
 * Migrating off the deprecated Cose\...Tag classes (issue #176).
 *
 * The six COSE message classes moved to spomky-labs/cbor-php 3.4.0. The ones this library shipped are deprecated
 * since 4.8.0 and removed in 5.0.0. The wire format is identical, so the two sides interoperate and an application
 * can migrate one at a time.
 *
 * Run with `php -d error_reporting=E_ALL examples/09-migration.php` to see the deprecation notices.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Signature\CoseSign1Tag as DeprecatedCoseSign1Tag;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('Migrating to the cbor-php COSE classes');

$protectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
]);
$unprotectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('my-key-id')),
]);
$payload = ByteStringObject::create('Message');
$signature = ByteStringObject::create('signature');

// --- before --------------------------------------------------------------------

// The deprecated four-argument factory. The notice is silenced here only so the example reads cleanly.
$before = @DeprecatedCoseSign1Tag::create($protectedHeader, $unprotectedHeader, $payload, $signature);
example_hex('before', (string) $before);

// --- after ---------------------------------------------------------------------

// create() upstream takes the whole list, so the four-argument form is createFromComponents(). This is the one point
// where renaming the class is not enough -- a leftover create($a, $b, $c, $d) raises an ArgumentCountError rather
// than misbehaving quietly.
$after = CoseSign1Tag::createFromComponents($protectedHeader, $unprotectedHeader, $payload, $signature);
example_hex('after', (string) $after);

example_assert((string) $before === (string) $after, 'both produce the same bytes');
echo PHP_EOL;

// --- the two sides interoperate --------------------------------------------------

// A message written by the deprecated class decodes as the replacement. Since cbor-php 3.4.0 the COSE tags are in
// the default decoder, so TagManager::create()->add(...) is no longer needed either.
$decoded = Decoder::create()->decode(StringStream::create((string) $before));
example_assert($decoded instanceof CoseSign1Tag, 'the old bytes decode as the new class');
example_assert((string) $decoded === (string) $before, 're-encoding is byte-identical');
echo PHP_EOL;

// --- what changed in the accessors -------------------------------------------------

// getPayload() can now return NullObject: detached content is representable, where the deprecated class rejected it.
example_line('getPayload()', $decoded->getPayload()::class);

// The header accessors move to CoseHeaders. getProtectedHeaderAsMap() exists upstream but applies only the CBOR
// rules; the RFC 9052 ones -- label typing, trailing data, the protected-first lookup -- live here.
$headers = CoseHeaders::fromMessage($decoded);
example_line('alg', (string) $headers->getProtectedHeaderParameter(1)?->normalize());
example_line('kid', (string) $headers->getHeaderParameter(4)?->getValue());
echo PHP_EOL;

// --- one behaviour worth knowing ----------------------------------------------------

// createFromComponents() encodes an empty protected map as h'a0'. RFC 9052 section 3 asks senders to prefer h'',
// which encodeProtected() emits -- pass the bytes to create() when that matters.
$viaComponents = CoseSign1Tag::createFromComponents(
    MapObject::create(),
    MapObject::create(),
    $payload,
    $signature
);
example_line('empty, components', "h'" . bin2hex($viaComponents->getProtectedHeader()->getValue()) . "'");

$viaBytes = CoseSign1Tag::create(ListObject::create([
    HeaderMapHelper::encodeProtected(MapObject::create()),
    MapObject::create(),
    $payload,
    $signature,
]));
example_line('empty, encodeProtected', "h'" . bin2hex($viaBytes->getProtectedHeader()->getValue()) . "'");
