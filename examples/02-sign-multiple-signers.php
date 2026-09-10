<?php

declare(strict_types=1);

/**
 * COSE_Sign (RFC 9052 section 4.1): several signers over one payload.
 *
 * The point to take away: a signer of a COSE_Sign commits to two protected buckets -- the message's and its own --
 * through the "Signature" structure. Signing with "Signature1" instead would produce a signature that is also valid
 * as a COSE_Sign1, which is not what a multi-signer message means.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSignTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\CoseSignature;
use Cose\Signature\Signature;
use Cose\Signature\Signature1;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Sign: two signers over one payload');

$algorithm = ES256::create();
$signers = [
    'signer-1' => example_ec_key(),
    'signer-2' => example_ec_key(),
];

// The body protected bucket is empty here: each signer declares its own algorithm, so there is nothing the message
// as a whole has to say. RFC 9052 section 3 asks senders to encode an empty map as h'', which encodeProtected() does.
$bodyProtectedHeader = HeaderMapHelper::encodeProtected(MapObject::create());
$payload = ByteStringObject::create('Document to be signed by several parties');
example_line('body protected', "h'" . bin2hex($bodyProtectedHeader->getValue()) . "'");

// --- signing ---------------------------------------------------------------

$entries = [];
foreach ($signers as $kid => $key) {
    // Each signer's own protected bucket, carrying its algorithm.
    $signProtectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
    ]));

    $toBeSigned = Signature::create($bodyProtectedHeader, $signProtectedHeader, $payload);
    $signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $key));

    // COSE_Signature = [ protected, unprotected, signature ]
    $entries[] = ListObject::create([
        $signProtectedHeader,
        MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid)),
        ]),
        $signature,
    ]);
}

$message = CoseSignTag::create(ListObject::create([
    $bodyProtectedHeader,
    MapObject::create(),
    $payload,
    ListObject::create($entries),
]));

$encoded = (string) $message;
example_line('COSE_Sign', bin2hex($encoded));
echo PHP_EOL;

// --- verifying -------------------------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseSignTag, 'decoded as a COSE_Sign');

// getSignatures() hands back the raw list, which the CBOR layer only checked is a list. CoseSignature::all() applies
// RFC 9052 section 4.1: at least one entry, each a [bstr, map, bstr].
$entries = CoseSignature::all($decoded->getSignatures());
example_assert(count($entries) === 2, 'the message carries two well-formed signatures');

foreach ($entries as $entry) {
    $kid = (string) $entry->getUnprotectedHeaderParameter(4)?->getValue();
    $key = $signers[$kid]->toPublic();

    $toBeVerified = Signature::create(
        $decoded->getProtectedHeader(),   // body_protected
        $entry->getProtectedHeader(),     // sign_protected
        $decoded->getPayload()
    );
    example_assert(
        $algorithm->verify((string) $toBeVerified, $key, $entry->getSignature()->getValue()),
        sprintf('the signature of %s verifies', $kid)
    );
}

// --- why the context string matters ----------------------------------------

$first = $entries[0];
$asSign1 = Signature1::create($first->getProtectedHeader(), $decoded->getPayload());
example_assert(
    ! $algorithm->verify(
        (string) $asSign1,
        $signers['signer-1']->toPublic(),
        $first->getSignature()->getValue()
    ),
    'the same signature is not valid as a COSE_Sign1'
);

// --- what the CBOR layer would have let through ------------------------------

try {
    CoseSignature::all(ListObject::create([]));
    example_assert(false, 'unreachable');
} catch (InvalidArgumentException $exception) {
    // RFC 9052 writes the list as "[+ COSE_Signature]": one or more. A "reject if any signature fails" loop over an
    // empty list passes vacuously, which is the bug this turns into an exception.
    example_line('empty list', $exception->getMessage());
}
