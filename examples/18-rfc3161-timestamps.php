<?php

declare(strict_types=1);

/**
 * RFC 3161 timestamp tokens in COSE headers (RFC 9921): "3161-ttc" and "3161-ctt".
 *
 * Three points to take away:
 *
 * 1. A timestamp token proves that some bytes existed at a time a Time Stamping Authority vouches for. RFC 9921
 *    defines two places for one in a COSE_Sign1 or COSE_Sign and two meanings: "3161-ttc" (269, protected) is a
 *    token over the payload, obtained before signing, "Timestamp, Then COSE"; "3161-ctt" (270, unprotected) is a
 *    token over the signature, obtained after, "COSE, Then Timestamp". The bucket is not a choice, and the typed
 *    accessors refuse a token in the other one.
 * 2. What the TSA hashes is exact: the payload bytes without their CBOR head for TTC; the CBOR-encoded signature
 *    field, head included, or the CBOR-encoded signatures array for CTT. MessageImprint produces those bytes and the
 *    MessageImprint structure of a TimeStampReq; TimestampBinding recomputes them on the receiving side and compares
 *    with the imprint inside the token, which is the check RFC 9921 section 4 requires.
 * 3. The library never talks to a TSA and never validates a token: the TSA's CMS signature, its certificate and its
 *    policy are the application's to check with a CMS implementation. The tokens used here are the two of RFC 9921
 *    Appendix A, issued by freetsa.org, plus an unsigned stand-in where the RFC has none to offer.
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
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\Timestamp\MessageImprint;
use Cose\Structure\Timestamp\TimeStampToken;
use Cose\Structure\Timestamp\TimestampBinding;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9921: RFC 3161 timestamp tokens, 3161-ttc and 3161-ctt');

$privateKey = example_ec_key();
$publicKey = $privateKey->toPublic();
$algorithm = ES256::create();
$hash = SHA256::create();
$binding = TimestampBinding::create(Manager::create()->add($hash));
$fixtures = __DIR__ . '/../tests/fixtures/rfc9921';
$read = static function (string $name) use ($fixtures): string {
    $bytes = file_get_contents($fixtures . '/' . $name);
    if ($bytes === false) {
        throw new RuntimeException('Unable to read ' . $name);
    }

    return $bytes;
};

// A TimeStampReq (RFC 3161 section 2.4.1) around an imprint: version 1, the imprint, certReq TRUE, no nonce; the
// shape the requests behind the tokens of RFC 9921 Appendix A have. Building and sending it is the application's,
// which is why this lives in the example and not in the library.
$timeStampReq = static fn (MessageImprint $imprint): string => Sequence::create(
    Integer::create(1),
    $imprint->toASN1(),
    Boolean::create(true)
)->toDER();

// --- 1. Timestamp, Then COSE: a token over the payload, in the protected bucket -----------------------------------

$payload = 'This is the content.';   // the payload of RFC 9921 Appendix A.1, so that its token fits

// RFC 9921 section 3.2: the MessageImprint is the hash of the payload bytes, "This does not include the bstr wrapping".
$imprint = MessageImprint::ttc($hash, $payload);
example_hex('TTC input', MessageImprint::ttcInput($payload));
example_hex('TTC imprint', $imprint->getHashedMessage());
example_hex('TimeStampReq', $timeStampReq($imprint));
example_assert(
    bin2hex($timeStampReq($imprint)) === '30390201013031300d06096086480165030402010500042009e638d4aa95fd7271866203595303bce232f462a94d38e393773cd3aae3f6b00101ff',
    'the request is the one of RFC 9921 Appendix A.1, byte for byte'
);

// The request goes to the TSA over HTTP (RFC 3161 section 3.4, application/timestamp-query) and a TimeStampResp comes
// back; the token inside is what the header carries. Here the TSA is played by the fixture: the token freetsa.org
// returned for exactly this request on 2025-08-29, as printed in the appendix.
$ttcToken = $read('ttc-tst.der');
$token = TimeStampToken::fromDER($ttcToken);
example_line('token', sprintf('%d bytes, policy %s, serial %s, genTime %s', strlen($ttcToken), $token->getPolicy(), $token->getSerialNumber(), $token->getGenTime()->format(DATE_ATOM)));
example_assert($token->getMessageImprint()->equals($imprint), 'the TSTInfo echoes the imprint of the request (RFC 3161 section 2.4.2)');

// The token goes into the protected bucket, next to "alg", and the message is signed as any other: the signature
// covers the token, which is the point of the mode (RFC 9921 section 1.1, the transparency use case).
$protected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($algorithm::identifier())),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_3161_TTC), ByteStringObject::create($ttcToken)),
]));
$toBeSigned = Signature1::create($protected, ByteStringObject::create($payload));
$ttcMessage = CoseSign1Tag::create(ListObject::create([
    $protected,
    MapObject::create(),
    ByteStringObject::create($payload),
    ByteStringObject::create($algorithm->sign((string) $toBeSigned, $privateKey)),
]));
example_line('COSE_Sign1 (TTC)', sprintf('%d bytes, of which %d are the token', strlen((string) $ttcMessage), strlen($ttcToken)));
example_dump('COSE_Sign1 (TTC)', $ttcMessage);
echo PHP_EOL;

// --- 2. verifying a TTC message: the signature first, then the binding, then what it means -------------------------

$decoded = Decoder::create()->decode(StringStream::create((string) $ttcMessage));
if (! $decoded instanceof CoseSign1Tag) {
    throw new RuntimeException('Not a COSE_Sign1');
}
$headers = CoseHeaders::fromMessage($decoded);

// The COSE signature, exactly as in examples/01: the token changes nothing here.
$verified = $algorithm->verify((string) Signature1::create($decoded->getProtectedHeader(), $decoded->getPayload()), $publicKey, $decoded->getSignature()->getValue());
example_assert($verified, 'the COSE signature verifies, over a protected bucket that contains the token');

// The accessor reads the token from the protected bucket only, as DER bytes; nothing inside is validated.
example_assert($headers->get3161Ttc() === $ttcToken, 'get3161Ttc() hands back the DER as carried');
example_assert($headers->get3161Ctt() === null, 'no 3161-ctt: this message says nothing about when the signature was made');

// RFC 9921 section 4: "the receiver MUST make sure that the MessageImprint in the embedded timestamp token matches a
// hash of [...] the payload". The algorithm is the token's, resolved through the Manager; the comparison is hash_equals().
example_assert($binding->matches($headers, $decoded), 'the token is a token over this payload');
example_assert($binding->matchesTtc($headers, $payload), 'the same, with the payload bytes given explicitly (detached payloads)');
example_assert(! $binding->matchesTtc($headers, 'This is the content'), 'and not over a payload one byte shorter');

// What a matching TTC token proves, and what it does not (RFC 9921 section 5.1): the payload existed at genTime. The
// signature was made by whoever holds $privateKey, at some time after that, and the token says nothing about when.
example_line('proves', sprintf('the payload existed at %s, if the TSA is trusted; nothing about the signature', $token->getGenTime()->format(DATE_ATOM)));
echo PHP_EOL;

// --- 3. COSE, Then Timestamp: a token over the signature, in the unprotected bucket ---------------------------------

// The message is signed first, without any token; then the CBOR-encoded signature field is what the TSA hashes.
$protected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($algorithm::identifier())),
]));
$signature = $algorithm->sign((string) Signature1::create($protected, ByteStringObject::create($payload)), $privateKey);
$signed = CoseSign1Tag::create(ListObject::create([
    $protected,
    MapObject::create(),
    ByteStringObject::create($payload),
    ByteStringObject::create($signature),
]));

// RFC 9921 section 3.1.1: "the bstr-wrapped signature [...] (including the heading bytes 0x5840) is used as input".
$imprint = MessageImprint::ctt($hash, $signed);
example_hex('CTT input', MessageImprint::cttInput($signed));
example_assert(MessageImprint::cttInput($signed) === "\x58\x40" . $signature, 'the input is the byte string with its head, not the bare 64 bytes');
example_hex('CTT imprint', $imprint->getHashedMessage());
example_hex('TimeStampReq', $timeStampReq($imprint));

// The TSA answers with a token over that imprint. No fixture can play the TSA here: the signature is fresh on every
// run, and a genuine token over it would need a TSA on the network. The stand-in below is the TSTInfo a TSA would
// sign, inside a SignedData with no signature, which is enough for everything this library reads and checks, and
// exactly nothing for what it does not: its CMS signature would fail any validation, as it should.
$standIn = static fn (MessageImprint $imprint): string => Sequence::create(
    ObjectIdentifier::create(TimeStampToken::OID_SIGNED_DATA),
    ExplicitlyTaggedType::create(0, Sequence::create(
        Integer::create(3),
        Set::create(),
        Sequence::create(
            ObjectIdentifier::create(TimeStampToken::OID_TST_INFO),
            ExplicitlyTaggedType::create(0, OctetString::create(Sequence::create(
                Integer::create(1),
                ObjectIdentifier::create('1.2.3.4.1'),
                $imprint->toASN1(),
                Integer::create(random_int(1, PHP_INT_MAX)),
                GeneralizedTime::create(new DateTimeImmutable('now', new DateTimeZone('UTC'))),
            )->toDER()))
        ),
        Set::create()
    ))
)->toDER();
$cttToken = $standIn($imprint);

// The token goes into the unprotected bucket of the message that was signed. The signature is untouched.
$cttMessage = CoseSign1Tag::create(ListObject::create([
    $signed->getProtectedHeader(),
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_3161_CTT), ByteStringObject::create($cttToken)),
    ]),
    $signed->getPayload(),
    $signed->getSignature(),
]));
$headers = CoseHeaders::fromMessage($cttMessage);
example_assert($headers->get3161Ctt() === $cttToken, 'get3161Ctt() reads the token from the unprotected bucket');
example_dump('COSE_Sign1 (CTT)', $cttMessage);
example_assert($binding->matchesCtt($headers, $cttMessage), 'the token is a token over the signature field of this message');
example_assert($binding->matches($headers, $cttMessage), 'matches() runs whichever modes the message carries');
example_line('proves', 'the signature existed at genTime, if the TSA is trusted; the time of the signature, not of the payload');

// A second signature over the same payload has a different value (ECDSA is randomized), so the token does not follow it.
$resigned = CoseSign1Tag::create(ListObject::create([
    $signed->getProtectedHeader(),
    $cttMessage->getUnprotectedHeader(),
    $signed->getPayload(),
    ByteStringObject::create($algorithm->sign((string) Signature1::create($protected, ByteStringObject::create($payload)), $privateKey)),
]));
example_assert(! $binding->matchesCtt(CoseHeaders::fromMessage($resigned), $resigned), 'a fresh signature over the same payload is not what the token covers');
echo PHP_EOL;

// --- 4. what the reader and the binding refuse -------------------------------------------------------------------

// RFC 9921 section 3.2: 3161-ttc is a protected header parameter. In the unprotected bucket it could be swapped
// after signing; the accessor does not read it there, it refuses the message.
$misplaced = CoseSign1Tag::create(ListObject::create([
    $signed->getProtectedHeader(),
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_3161_TTC), ByteStringObject::create($ttcToken)),
    ]),
    $signed->getPayload(),
    $signed->getSignature(),
]));
try {
    CoseHeaders::fromMessage($misplaced)->get3161Ttc();
    throw new LogicException('unreachable');
} catch (InvalidArgumentException $exception) {
    example_assert(str_contains($exception->getMessage(), 'protected header only (RFC 9921 section 3.2)'), 'a 3161-ttc in the unprotected bucket: ' . $exception->getMessage());
}

// RFC 9921 section 3.1: 3161-ctt is an unprotected header parameter. Under the signature it would have to predate
// the signature it timestamps.
$misplaced = CoseSign1Tag::create(ListObject::create([
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($algorithm::identifier())),
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_3161_CTT), ByteStringObject::create($cttToken)),
    ])),
    MapObject::create(),
    $signed->getPayload(),
    $signed->getSignature(),
]));
try {
    CoseHeaders::fromMessage($misplaced)->get3161Ctt();
    throw new LogicException('unreachable');
} catch (InvalidArgumentException $exception) {
    example_assert(str_contains($exception->getMessage(), 'unprotected header only (RFC 9921 section 3.1)'), 'a 3161-ctt in the protected bucket: ' . $exception->getMessage());
}

// A token hashed with SHA-1 is refused even when SHA-1 is registered for "x5t": SHA-1 is "Filter Only" (RFC 9054
// section 2), and a timestamp stands for the bytes it was computed over. The stand-in below carries the sha1 OID.
$sha1Token = $standIn(MessageImprint::create(MessageImprint::hashAlgorithmOid(SHA1::create()), sha1($payload, true)));
$sha1Message = CoseSign1Tag::create(ListObject::create([
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($algorithm::identifier())),
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_3161_TTC), ByteStringObject::create($sha1Token)),
    ])),
    MapObject::create(),
    $signed->getPayload(),
    $signed->getSignature(),
]));
try {
    TimestampBinding::create(Manager::create()->add($hash, SHA1::create()))->matches(CoseHeaders::fromMessage($sha1Message), $sha1Message);
    throw new LogicException('unreachable');
} catch (InvalidArgumentException $exception) {
    example_assert(str_contains($exception->getMessage(), '"Filter Only" hash (RFC 9054 section 2) cannot'), 'a SHA-1 token: ' . $exception->getMessage());
}

// The token of RFC 9921 Appendix A.2 makes a different point: it is a genuine token, issued over the wrong bytes
// (the RFC's example generator hashed an error message instead of the signature, see tests/fixtures/rfc9921/README.md),
// and the binding check says so.
$appendixA2 = TimeStampToken::fromDER($read('ctt-tst.der'));
$rfc9052Sign1 = CoseSign1Tag::create(ListObject::create([
    ByteStringObject::create("\xa1\x01\x26"),
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_3161_CTT), ByteStringObject::create($appendixA2->toDER())),
        MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('11')),
    ]),
    ByteStringObject::create($payload),
    ByteStringObject::create(hex2bin('8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36')),
]));
example_hex('A.2 imprint', $appendixA2->getMessageImprint()->getHashedMessage());
example_hex('section 3.1.1', MessageImprint::ctt($hash, $rfc9052Sign1)->getHashedMessage());
example_assert(! $binding->matchesCtt(CoseHeaders::fromMessage($rfc9052Sign1), $rfc9052Sign1), 'the token of RFC 9921 Appendix A.2 is not a token over the message it sits in');
echo PHP_EOL;

// --- 5. what the library leaves to the application ---------------------------------------------------------------

// Everything above says that a token is about this message. Whether the token is genuine is another question: the
// TSTInfo is signed by the TSA inside a CMS SignedData (RFC 5652), over a certificate chain the token may carry. That
// signature, that chain and the TSA's policy are what make genTime worth anything, and RFC 9921 section 4 points to
// RFC 5652 and RFC 3161 for them. spomky-labs/pki-framework has no CMS layer, so the library hands the bytes over.
example_line('to validate', sprintf('TimeStampToken::toDER(): %d bytes for a CMS implementation; policy %s', strlen($token->toDER()), $token->getPolicy()));

// And RFC 9921 section 5.1: a TTC time is the payload's, a CTT time is the signature's. A CWT "iat" in the payload is
// a claim the signer makes about the time; a TSA's genTime is a third party's word. Keep the three apart.
example_line('semantics', 'TTC: payload existed at genTime. CTT: signature existed at genTime. iat/exp: what the signer claims.');
