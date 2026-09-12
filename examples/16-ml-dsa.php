<?php

declare(strict_types=1);

/**
 * ML-DSA for COSE (RFC 9964): post-quantum signatures over the AKP key type.
 *
 * Four points to take away:
 *
 * 1. An ML-DSA key is an AkpKey: "kty" 7, a REQUIRED "alg" naming the parameter set, "pub" holding the encoded
 *    public key of FIPS 204 and "priv" holding the 32-byte seed - the only private key form the RFC allows. The
 *    algorithm expands a seed into the key pair, which is how a key is generated and how a stored seed is rebuilt.
 * 2. The example of the RFC (Appendix A.2, all-zero seed) is reproduced exactly: the public key the seed expands
 *    to, the signature the RFC prints, and the "kid" of the key, which is its COSE Key Thumbprint over "kty",
 *    "alg" and "pub" (section 6).
 * 3. The key is checked before OpenSSL sees it: the sizes of the parameter set when the key is built, the "alg" it
 *    cannot do without, and - when both halves are present - that "pub" is what the seed expands to (section 7.4).
 * 4. ML-DSA needs OpenSSL 3.5 and PHP 8.4. The gate is a runtime one, and every class says where it stands through
 *    isSupported(); on a platform without it, create() throws a clear message and nothing else is affected.
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
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\MLDSA\MLDSA44;
use Cose\Algorithm\Signature\MLDSA\MLDSA65;
use Cose\Algorithm\Signature\MLDSA\MLDSA87;
use Cose\Key\AkpKey;
use Cose\Key\Key;
use Cose\Key\Thumbprint;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9964: ML-DSA and the AKP key type');

// --- the platform gate -------------------------------------------------------

// OpenSSL ships ML-DSA as of 3.5, and PHP signs without a digest as of 8.4. OPENSSL_VERSION_TEXT names the headers
// PHP was built against, not the library it loaded, so the check is a runtime probe; the three classes share it.
example_line('PHP', PHP_VERSION);
example_line('OpenSSL (headers)', OPENSSL_VERSION_TEXT);
example_line('ML-DSA available', MLDSA44::isSupported() ? 'yes' : 'no');

if (! MLDSA44::isSupported()) {
    // What the gate looks like from the caller's side: a message naming the missing piece, before any key is
    // touched. A registry built this way simply has no -48, -49 or -50 entry.
    try {
        MLDSA44::create();
        example_assert(false, 'MLDSA44::create() must throw on a platform without ML-DSA');
    } catch (RuntimeException $e) {
        example_assert(true, 'MLDSA44::create() refuses this platform: ' . $e->getMessage());
    }
    $manager = Manager::create();
    example_assert(! $manager->has(MLDSA44::identifier()), 'and the manager has no ML-DSA-44 entry');
    echo PHP_EOL, 'Nothing else of this example can run here.', PHP_EOL;

    return;
}

$manager = Manager::create()->add(MLDSA44::create(), MLDSA65::create(), MLDSA87::create());
example_assert($manager->has(MLDSA87::identifier()), 'the three parameter sets are registered');
echo PHP_EOL;

// --- the example of RFC 9964 Appendix A.2 ------------------------------------

// The RFC signs with the all-zero seed, and prints the public key, the COSE_Sign1 and the "kid" of the key. All
// three are reproduced here; the fixture is the appendix itself, see tests/fixtures/rfc9964/README.md.
$appendix = json_decode((string) file_get_contents(__DIR__ . '/../tests/fixtures/rfc9964/appendix-a.json'), true);
$rfcExample = $appendix[3];
example_assert(str_contains((string) $rfcExample['key_diag'], '3: -48'), 'the first COSE example is ML-DSA-44');

$mlDsa44 = $manager->get(MLDSA44::identifier());
$rfcKey = $mlDsa44->keyPairFromSeed((string) hex2bin($rfcExample['priv']));
example_hex('seed', $rfcKey->priv());
example_line('pub', strlen($rfcKey->pub()) . ' bytes, ' . bin2hex(substr($rfcKey->pub(), 0, 16)) . '…');
example_assert(
    $rfcKey->pub() === hex2bin($rfcExample['raw_public_key']),
    'the all-zero seed expands to the public key the RFC prints'
);

$rfcToBeSigned = (string) hex2bin($rfcExample['raw_to_be_signed']);
$rfcSignature = (string) hex2bin($rfcExample['raw_signature']);
example_assert(
    $mlDsa44->verify($rfcToBeSigned, $rfcKey->toPublic(), $rfcSignature),
    'the signature the RFC prints verifies over the Sig_structure it prints'
);

// The whole COSE_Sign1 of the RFC, decoded and verified like any other message.
$rfcMessage = Decoder::create()->decode(StringStream::create((string) hex2bin($rfcExample['sign1'])));
example_assert($rfcMessage instanceof CoseSign1Tag, 'the RFC message decodes as a COSE_Sign1');
$rfcHeaders = CoseHeaders::fromMessage($rfcMessage);
example_assert(
    (int) $rfcHeaders->getProtectedHeaderParameter(1)?->normalize() === MLDSA44::identifier(),
    'its protected header declares ML-DSA-44'
);
$rfcStructure = Signature1::create($rfcMessage->getProtectedHeader(), $rfcMessage->getPayload());
example_assert((string) $rfcStructure === $rfcToBeSigned, 'the Sig_structure rebuilt here is the one the RFC signed');
example_assert(
    $manager->get(MLDSA44::identifier())->verify((string) $rfcStructure, $rfcKey->toPublic(), $rfcMessage->getSignature()->getValue()),
    'and the message verifies with the public key'
);

// Section 6: the thumbprint of an AKP key covers "kty", "alg" and "pub" - "alg" included, unlike every other key
// type, because the AKP type alone does not say what the key is. The "kid" the RFC put in the key is that digest.
$thumbprint = Thumbprint::of($rfcKey);
$rfcKid = (string) $rfcHeaders->getProtectedHeaderParameter(4)?->getValue();
example_hex('thumbprint', $thumbprint->value());
example_assert($thumbprint->equals($rfcKid), 'the "kid" of the RFC message is the thumbprint of its key');
example_line('URI', $thumbprint->toUri());
echo PHP_EOL;

// --- a fresh key, and a COSE_Sign1 signed with ML-DSA-65 ----------------------

$mlDsa65 = $manager->get(MLDSA65::identifier());
$key = $mlDsa65->keyPairFromSeed(random_bytes(32));
example_assert($key instanceof AkpKey && $key->alg() === MLDSA65::identifier(), 'keyPairFromSeed() gives an AkpKey carrying "alg" -49');
example_line('pub', strlen($key->pub()) . ' bytes');

$protectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(MLDSA65::identifier())),
    MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create(Thumbprint::of($key)->value())),
]);
$protectedHeaderAsBytes = HeaderMapHelper::encodeProtected($protectedHeader);
$payload = ByteStringObject::create('hello post quantum signatures');
$toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);

$signature = $mlDsa65->sign((string) $toBeSigned, $key);
example_line('signature', strlen($signature) . ' bytes');
example_assert(strlen($signature) === MLDSA65::signatureLength(), 'an ML-DSA-65 signature is 3309 bytes');

$message = CoseSign1Tag::create(ListObject::create([
    $protectedHeaderAsBytes,
    MapObject::create(),
    $payload,
    ByteStringObject::create($signature),
]));
example_line('COSE_Sign1', strlen((string) $message) . ' bytes');

$decoded = Decoder::create()->decode(StringStream::create((string) $message));
example_assert($decoded instanceof CoseSign1Tag, 'decoded as a COSE_Sign1');
$toBeVerified = Signature1::create($decoded->getProtectedHeader(), $decoded->getPayload());
example_assert(
    $mlDsa65->verify((string) $toBeVerified, $key->toPublic(), $decoded->getSignature()->getValue()),
    'the signature verifies with the public half'
);

// FIPS 204 signs in its "hedged" (randomised) variant by default: two signatures of the same input differ, and
// both verify.
$again = $mlDsa65->sign((string) $toBeSigned, $key);
example_assert($again !== $signature, 'signing again gives another signature');
example_assert($mlDsa65->verify((string) $toBeSigned, $key->toPublic(), $again), 'which verifies too');
echo PHP_EOL;

// --- what is refused, and where ----------------------------------------------

// The sizes of the parameter set are checked when the key is built (sections 4, 5 and 7.3): a "priv" that is not
// the 32-byte seed - the expanded private key of FIPS 204, for instance - never reaches OpenSSL.
try {
    AkpKey::create([
        Key::TYPE => Key::TYPE_AKP,
        Key::ALG => MLDSA65::ID,
        AkpKey::DATA_PUB => $key->pub(),
        AkpKey::DATA_PRIV => random_bytes(4032),
    ]);
    example_assert(false, 'an expanded private key must be refused');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'AkpKey refuses a 4032-byte "priv": ' . $e->getMessage());
}

// "alg" is REQUIRED on an AKP key (section 3): without it, nothing says which parameter set "pub" belongs to.
$withoutAlg = AkpKey::create([
    Key::TYPE => Key::TYPE_AKP,
    AkpKey::DATA_PUB => $key->pub(),
]);
try {
    $mlDsa65->verify((string) $toBeSigned, $withoutAlg, $signature);
    example_assert(false, 'a key without "alg" must be refused');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'the algorithm refuses a key without "alg": ' . $e->getMessage());
}

// And an ML-DSA-65 key is not an ML-DSA-44 key, whether or not the key restrictions are enforced.
try {
    $mlDsa44->verify((string) $toBeSigned, $key->toPublic(), $signature);
    example_assert(false, 'ML-DSA-44 must refuse an ML-DSA-65 key');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'ML-DSA-44 refuses the ML-DSA-65 key: ' . $e->getMessage());
}

// Section 7.4: a "pub" that is not what the seed expands to is a mismatched pair, refused before it signs anything.
$mismatched = AkpKey::create([
    Key::TYPE => Key::TYPE_AKP,
    Key::ALG => MLDSA65::ID,
    AkpKey::DATA_PUB => $mlDsa65->keyPairFromSeed(random_bytes(32))->pub(),
    AkpKey::DATA_PRIV => $key->priv(),
]);
try {
    $mlDsa65->sign((string) $toBeSigned, $mismatched);
    example_assert(false, 'a mismatched key pair must be refused');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'a "pub" that does not match the seed is refused: ' . $e->getMessage());
}

// A signature of another length is invalid - a verification outcome, decided before OpenSSL is called.
example_assert(
    ! $mlDsa65->verify((string) $toBeSigned, $key->toPublic(), substr($signature, 0, -1)),
    'a 3308-byte signature is invalid'
);
