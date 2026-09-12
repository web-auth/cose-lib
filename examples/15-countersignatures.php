<?php

declare(strict_types=1);

/**
 * Version 2 countersignatures (RFC 9338): a second party signs a finalized COSE structure.
 *
 * A countersignature is what a notary or a timestamping service puts on a document somebody else signed: it attests
 * that the signature existed, without touching it. RFC 9338 lets any of the COSE structures be countersigned, in a
 * full form -- a COSE_Signature with headers of its own, label 11 -- or an abbreviated one, the bare signature value,
 * label 12. The point to take away: the countersignature covers the Countersign_structure, whose fields depend on
 * the target, and lives in the unprotected bucket of that target.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Mac\Mac0Structure;
use Cose\Signature\Countersign;
use Cose\Signature\Countersigner;
use Cose\Signature\CountersignTarget;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('Countersignatures (RFC 9338)');

$algorithm = ES256::create();
$author = example_ec_key();
$notary = example_ec_key();
$archive = example_ec_key();

$es256Protected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
]));
$headersOf = static fn (string $kid): CoseHeaders => CoseHeaders::of(
    $es256Protected,
    MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid))])
);

// --- the author signs ----------------------------------------------------------

$payload = ByteStringObject::create('Contract, final version');
$signature = $algorithm->sign((string) Signature1::create($es256Protected, $payload), $author);
$message = CoseSign1Tag::create(ListObject::create([
    $es256Protected,
    MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('author'))]),
    $payload,
    ByteStringObject::create($signature),
]));
example_hex('COSE_Sign1', (string) $message);

// --- the notary countersigns -----------------------------------------------------

// The target says what the countersignature covers. For a COSE_Sign1 that is the protected bucket, the payload and
// -- this is what RFC 9338 adds to RFC 8152 -- the signature value, as other_fields.
$target = CountersignTarget::of($message);
$toBeSigned = Countersign::full($target, $es256Protected);
example_line('context', $toBeSigned->getContext());
example_hex('Countersign_structure', (string) $toBeSigned);

// The countersigner's headers are its own: its algorithm, its key identifier. sign() checks that an "alg" they carry
// is the algorithm in hand, and hands back the COSE_Countersignature -- a COSE_Signature.
$countersignature = Countersigner::sign($target, $algorithm, $notary, $headersOf('notary'));

// The countersignature goes into the unprotected bucket of the target, under label 11. attach() writes into the
// bucket the message carries; the author's signature does not cover it, so the message still verifies.
Countersigner::attach($message->getUnprotectedHeader(), $countersignature);
$encoded = (string) $message;
example_hex('countersigned', $encoded);
echo PHP_EOL;

// --- the receiver verifies both -------------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseSign1Tag, 'decoded as a COSE_Sign1');
$decodedPayload = $decoded->getPayload();
example_assert($decodedPayload instanceof ByteStringObject, 'the payload is attached');
example_assert(
    $algorithm->verify(
        (string) Signature1::create($decoded->getProtectedHeader(), $decodedPayload),
        $author->toPublic(),
        $decoded->getSignature()->getValue()
    ),
    "the author's signature verifies: the countersignature is not under it"
);

$target = CountersignTarget::of($decoded);
$countersignatures = $target->getCountersignatures();  // label 11, one or many, normalised to a list
example_assert(count($countersignatures) === 1, 'the message carries one countersignature');
$kid = $countersignatures[0]->getUnprotectedHeaderParameter(4)?->normalize();
example_line('countersigner kid', (string) $kid);
example_assert(
    Countersigner::verify($target, $countersignatures[0], $algorithm, $notary->toPublic()),
    "the notary's countersignature verifies"
);
example_assert(
    ! Countersigner::verify($target, $countersignatures[0], $algorithm, $archive->toPublic()),
    'another key does not verify it'
);
echo PHP_EOL;

// --- a second countersigner, and a countersignature of a countersignature --------

// RFC 9338 section 3.1: "the countersignature can itself be countersigned", which is what long-term archives do.
// The target is then the notary's COSE_Countersignature, whose signature value takes the payload slot.
$ofNotary = CountersignTarget::of($countersignatures[0]);
example_line('inner context', Countersign::full($ofNotary, $es256Protected)->getContext());
$archival = Countersigner::sign($ofNotary, $algorithm, $archive, $headersOf('archive'));
Countersigner::attach($countersignatures[0]->getUnprotectedHeader(), $archival);

// A second countersignature on the message turns label 11 into an array (section 2: "COSE_Countersignature /
// [+ COSE_Countersignature]"); attach() handles the change of shape.
$second = Countersigner::sign($target, $algorithm, $archive, $headersOf('archive'));
Countersigner::attach($decoded->getUnprotectedHeader(), $second);

$decoded = Decoder::create()->decode(StringStream::create((string) $decoded));
example_assert($decoded instanceof CoseSign1Tag, 'decoded again as a COSE_Sign1');
$target = CountersignTarget::of($decoded);
$outer = $target->getCountersignatures();
example_assert(count($outer) === 2, 'the message carries two countersignatures');
example_assert(
    Countersigner::verify($target, $outer[1], $algorithm, $archive->toPublic()),
    "the archive's countersignature of the message verifies"
);
$inner = CountersignTarget::of($outer[0])->getCountersignatures();
example_assert(count($inner) === 1, "the notary's countersignature carries one of its own");
example_assert(
    Countersigner::verify(CountersignTarget::of($outer[0]), $inner[0], $algorithm, $archive->toPublic()),
    "the archive's countersignature of the notary's countersignature verifies"
);
echo PHP_EOL;

// --- the abbreviated form, on a COSE_Mac0 -----------------------------------------

// Countersignature0 (label 12) is the bare signature value: no headers, so the algorithm and the key come from the
// context the application already has. RFC 9338 section 6 on countersigning a MAC or an encryption: the
// countersignature attests to the tag, and gives no more integrity than the tag has -- "the tag length MUST be at
// least 256 bits" for 128-bit security, which HMAC 256/256 provides and AES-CBC-MAC 128/64 would not.
$macKey = example_symmetric_key();
$hs256Protected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(HS256::identifier())),
]));
$tag = HS256::create()->hash((string) Mac0Structure::create($hs256Protected, $payload), $macKey);
$mac0 = CoseMac0Tag::create(ListObject::create([$hs256Protected, MapObject::create(), $payload, ByteStringObject::create($tag)]));

$target = CountersignTarget::of($mac0);  // payload, then [tag]
example_line('MAC0 context', Countersign::abbreviated($target)->getContext());
Countersigner::attach0($mac0->getUnprotectedHeader(), Countersigner::sign0($target, $algorithm, $notary));
example_hex('countersigned COSE_Mac0', (string) $mac0);

$decodedMac0 = Decoder::create()->decode(StringStream::create((string) $mac0));
example_assert($decodedMac0 instanceof CoseMac0Tag, 'decoded as a COSE_Mac0');
$target = CountersignTarget::of($decodedMac0);
$countersignature0 = $target->getCountersignature0();
example_assert($countersignature0 !== null, 'the message carries an abbreviated countersignature');
example_assert(
    Countersigner::verify0($target, $countersignature0, $algorithm, $notary->toPublic()),
    'it verifies with the algorithm and the key the context names'
);
example_assert(
    ! Countersigner::verify0($target, $countersignature0, $algorithm, $notary->toPublic(), 'other context'),
    'the external_aad is covered'
);
echo PHP_EOL;

// --- what the reader refuses ------------------------------------------------------

// RFC 9338 section 2 places both parameters in the unprotected bucket: a countersignature under the target's own
// signature would have to exist before the signature it attests to.
$protectedWithLabel11 = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_COUNTERSIGNATURE_V2), $countersignature->toListObject()),
]));
try {
    CoseHeaders::of($protectedWithLabel11, MapObject::create())->getCountersignatures();
    example_assert(false, 'unreachable');
} catch (InvalidArgumentException $exception) {
    example_line('label 11 protected', $exception->getMessage());
}

// The two forms are not interchangeable: the context string differs, so the same bytes verify as one and not the
// other (section 3: "the converted structure will fail signature validation").
example_assert(
    ! Countersigner::verify0(CountersignTarget::of($decoded), $outer[1]->getSignature()->getValue(), $algorithm, $archive->toPublic()),
    'a full countersignature does not verify as an abbreviated one'
);
