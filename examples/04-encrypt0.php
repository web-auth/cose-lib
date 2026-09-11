<?php

declare(strict_types=1);

/**
 * COSE_Encrypt0 (RFC 9052 section 5.2): content encrypted for a single recipient.
 *
 * The content encryption algorithms of RFC 9053 section 4 -- AES-GCM, AES-CCM and ChaCha20/Poly1305 -- live in
 * Cose\Algorithm\ContentEncryption. The additional authenticated data they cover is the Enc_structure of RFC 9052
 * section 5.3, which binds the ciphertext to the protected header it travels with; Encrypt0Structure builds it and
 * feeds it to the algorithm through encrypt() and decrypt().
 *
 * Note that Enc_structure carries no payload: the content is what the AEAD encrypts, and the structure is what it
 * authenticates alongside it.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\Manager;
use Cose\Encryption\Encrypt0Structure;
use Cose\Encryption\InitializationVector;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Encrypt0: encrypt and decrypt');

$algorithm = A128GCM::create();
$key = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => random_bytes($algorithm->keyLength()),
]);
// The key and nonce pair MUST be unique for every message (RFC 9053 section 4.1.1): a fresh random nonce per message,
// or a strictly increasing counter sent as a Partial IV -- never a value that can repeat under the same key.
$nonce = random_bytes($algorithm->nonceLength());
$plaintext = 'Secret content';

// --- encrypting -------------------------------------------------------------

// A128GCM is algorithm 1 in the IANA COSE Algorithms registry. The IV (label 5) is not secret and rides in the
// unprotected bucket, as RFC 9053 section 4.1 allows.
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($algorithm::identifier())),
]));
$unprotectedHeader = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(InitializationVector::IV), ByteStringObject::create($nonce)),
]);

// The additional authenticated data: ["Encrypt0", protected, external_aad]
$structure = Encrypt0Structure::create($protectedHeader);
example_hex('Enc_structure', (string) $structure);

// RFC 9053 section 4.1: the ciphertext is followed by the 16-byte authentication tag.
$ciphertext = $structure->encrypt($algorithm, $key, $plaintext, $nonce);
example_assert(strlen($ciphertext) === strlen($plaintext) + $algorithm->tagLength(), 'the content was encrypted');

$message = CoseEncrypt0Tag::create(ListObject::create([
    $protectedHeader,
    $unprotectedHeader,
    ByteStringObject::create($ciphertext),
]));

$encoded = (string) $message;
example_hex('COSE_Encrypt0', $encoded);
echo PHP_EOL;

// --- decrypting -------------------------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseEncrypt0Tag, 'decoded as a COSE_Encrypt0');

// The algorithm is chosen from the protected header, through a manager holding those the application accepts.
$manager = Manager::create()->add(A128GCM::create());
$headers = CoseHeaders::fromMessage($decoded);
$alg = $headers->getProtectedHeaderParameter(1);
example_assert($alg !== null, 'the protected header declares an algorithm');
$algorithm = $manager->get((int) $alg->normalize());
example_assert($algorithm instanceof A128GCM, 'the algorithm is A128GCM');

// RFC 9052 section 3.1: the nonce is the "IV" as it is, or a "Partial IV" completed with the Base IV of the key.
$decodedNonce = InitializationVector::resolve($headers, $algorithm->nonceLength(), $key);
example_assert($decodedNonce === $nonce, 'the IV is the one sent');

// The AAD is rebuilt from the bytes the message carries, not from a re-encoded map.
$recovered = Encrypt0Structure::create($decoded->getProtectedHeader())
    ->decrypt($algorithm, $key, $decoded->getCiphertext()->getValue(), $decodedNonce);
example_assert($recovered === $plaintext, 'the content was recovered');

// --- what the AAD buys you ----------------------------------------------------

// Rewrite the declared algorithm in the protected header and the AEAD refuses: the ciphertext is bound to the header
// it shipped with. A wrong key, a wrong nonce or a tampered tag fail the same way, with the same message.
$tampered = Encrypt0Structure::create(HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(3)), // A256GCM
])));
try {
    $tampered->decrypt($algorithm, $key, $decoded->getCiphertext()->getValue(), $decodedNonce);
    example_assert(false, 'a rewritten protected header breaks decryption');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'a rewritten protected header breaks decryption');
    example_line('message', $e->getMessage());
}

// --- a Partial IV instead of the IV ------------------------------------------

// A key may carry a Base IV (label 5 of the key map); the message then sends only the part that changes -- a counter
// -- as the Partial IV (label 6). RFC 9052 section 3.1: left-pad the Partial IV to the nonce length, XOR with the
// Base IV. The two header parameters MUST NOT both be present in the same layer.
$keyWithBaseIv = SymmetricKey::create($key->getData() + [
    SymmetricKey::BASE_IV => random_bytes(8),
]);
$counter = "\x00\x01";
$nonce = InitializationVector::fromPartialIv($counter, $keyWithBaseIv->get(SymmetricKey::BASE_IV), $algorithm->nonceLength());
$ciphertext = $structure->encrypt($algorithm, $keyWithBaseIv, $plaintext, $nonce);
$message = CoseEncrypt0Tag::create(ListObject::create([
    $protectedHeader,
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(InitializationVector::PARTIAL_IV), ByteStringObject::create($counter)),
    ]),
    ByteStringObject::create($ciphertext),
]));
example_hex('with a Partial IV', (string) $message);

$decoded = Decoder::create()->decode(StringStream::create((string) $message));
example_assert($decoded instanceof CoseEncrypt0Tag, 'decoded as a COSE_Encrypt0');
$decodedNonce = InitializationVector::resolve(CoseHeaders::fromMessage($decoded), $algorithm->nonceLength(), $keyWithBaseIv);
example_assert($decodedNonce === $nonce, 'the nonce is resolved from the Partial IV and the Base IV');
$recovered = Encrypt0Structure::create($decoded->getProtectedHeader())
    ->decrypt($algorithm, $keyWithBaseIv, $decoded->getCiphertext()->getValue(), $decodedNonce);
example_assert($recovered === $plaintext, 'the content was recovered');
