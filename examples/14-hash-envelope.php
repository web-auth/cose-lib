<?php

declare(strict_types=1);

/**
 * The COSE hash envelope of RFC 9995: sign the digest of a file, not the file.
 *
 * Three points to take away:
 *
 * 1. A hash envelope is an ordinary COSE_Sign1 (or COSE_Sign, COSE_Mac, COSE_Mac0) whose payload is the digest of the
 *    content. Nothing changes in how it is signed or verified; what changes is what the payload means, and three
 *    protected header parameters say it: payload-hash-alg (258), preimage-content-type (259), payload-location (260).
 * 2. The three live in the protected bucket and nowhere else, and "content type" (3) is banned from the envelope:
 *    it would describe the digest, and 259 already describes the file. The typed accessors enforce both.
 * 3. Verifying the signature says who vouched for the digest. Confirming that the file in hand has that digest is a
 *    second, separate step -- HashEnvelope::matches() -- and it needs the file, which the library never fetches:
 *    payload-location is a hint for the application, exactly like x5u.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HashEnvelope;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9995: COSE hash envelope');

$privateKey = example_ec_key();
$publicKey = $privateKey->toPublic();
$algorithm = ES256::create();
$hash = SHA256::create();

// The content: a file of this repository, standing in for the SBOM of the RFC's example. Only its digest travels.
$file = __DIR__ . '/README.md';
$content = file_get_contents($file);
if ($content === false) {
    throw new RuntimeException('Unable to read ' . $file);
}
example_line('content', sprintf('%s (%d bytes)', basename($file), strlen($content)));

// --- signing ---------------------------------------------------------------

// The three parameters of RFC 9995 section 4, spread next to "alg" in the protected bucket. The location is a hint
// the verifier may or may not act on; here it is the path relative to the repository.
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), TextStringObject::create('application/example+cose')),
    ...HashEnvelope::protectedHeaderFor($hash, 'text/markdown', 'examples/README.md'),
]));

// The payload is the digest, and the signature covers the Sig_structure exactly as for any COSE_Sign1.
$payload = ByteStringObject::create(HashEnvelope::payloadFor($hash, $content));
$signature = $algorithm->sign((string) Signature1::create($protectedHeader, $payload), $privateKey);

$message = CoseSign1Tag::create(ListObject::create([
    $protectedHeader,
    MapObject::create(),
    $payload,
    ByteStringObject::create($signature),
]));
$encoded = (string) $message;
example_hex('payload (SHA-256)', $payload->getValue());
example_hex('COSE_Sign1', $encoded);
example_assert(strlen($encoded) < strlen($content), 'the envelope is smaller than the content it stands for');
echo PHP_EOL;

// --- verifying -------------------------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseSign1Tag, 'decoded as a COSE_Sign1');
$headers = CoseHeaders::fromMessage($decoded);

// Step 1, the signature: who vouches for the digest. Same code as for any other message.
$alg = $headers->getProtectedHeaderParameter(1);
example_assert($alg !== null && (int) $alg->normalize() === ES256::identifier(), 'the protected header declares ES256');
$carried = $decoded->getPayload();
example_assert($carried instanceof ByteStringObject, 'the payload is attached');
example_assert(
    $algorithm->verify((string) Signature1::create($decoded->getProtectedHeader(), $carried), $publicKey, $decoded->getSignature()->getValue()),
    'the signature verifies over the digest'
);

// Step 2, the headers: what the digest is. Protected bucket only, "content type" (3) banned.
example_line('payload-hash-alg', (string) $headers->getPayloadHashAlg());
example_line('preimage-content-type', (string) $headers->getPreimageContentType());
example_line('payload-location', (string) $headers->getPayloadLocation());
example_assert($headers->getPayloadHashAlg() === SHA256::identifier(), 'the payload is a SHA-256 digest');

// Step 3, the content: the application obtains the file -- from the location, from a cache, from anywhere -- and
// confirms that its digest, computed with the function the header names, is the payload (RFC 9995 section 5.3).
$manager = Manager::create()->add($algorithm, $hash);
$envelope = HashEnvelope::create($manager);
$obtained = file_get_contents(__DIR__ . '/../' . $headers->getPayloadLocation());
example_assert($obtained !== false && $envelope->matches($headers, $carried->getValue(), $obtained), 'the file has the signed digest');
example_assert(! $envelope->matches($headers, $carried->getValue(), $content . "\n"), 'a file with one more byte does not');
echo PHP_EOL;

// --- what the envelope refuses ---------------------------------------------

// A "Filter Only" hash (RFC 9054 section 2) cannot stand for the content, even when the registry knows it for x5t.
$sha1Envelope = HashEnvelope::create(Manager::create()->add(SHA1::create(), $hash));
$sha1Headers = CoseHeaders::of(
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_HASH_ALG), NegativeIntegerObject::create(SHA1::identifier())),
    ])),
    MapObject::create()
);
try {
    $sha1Envelope->matches($sha1Headers, sha1($content, true), $content);
    example_assert(false, 'SHA-1 was accepted as payload-hash-alg');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'SHA-1 is refused as payload-hash-alg: ' . substr($e->getMessage(), 0, 60) . '...');
}

// payload-hash-alg in the unprotected bucket (RFC 9995 section 4: "MUST NOT be present in the unprotected header").
$misplaced = CoseHeaders::of(
    ByteStringObject::create(''),
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_HASH_ALG), NegativeIntegerObject::create(SHA256::identifier())),
    ])
);
try {
    $misplaced->getPayloadHashAlg();
    example_assert(false, 'an unprotected payload-hash-alg was read');
} catch (InvalidArgumentException) {
    example_assert(true, 'payload-hash-alg in the unprotected bucket is rejected');
}

// "content type" (3) next to payload-hash-alg (RFC 9995 section 4: "MUST NOT be present in the protected or
// unprotected headers"): the type of the file is preimage-content-type (259), and 3 would describe the digest.
$withContentType = CoseHeaders::of(
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CONTENT_TYPE), TextStringObject::create('application/octet-stream')),
        ...HashEnvelope::protectedHeaderFor($hash, 'text/markdown'),
    ])),
    MapObject::create()
);
try {
    $withContentType->getPreimageContentType();
    example_assert(false, 'a content type was accepted in a hash envelope');
} catch (InvalidArgumentException) {
    example_assert(true, 'content type (3) alongside payload-hash-alg is rejected');
}
