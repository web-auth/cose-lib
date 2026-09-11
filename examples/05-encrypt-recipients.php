<?php

declare(strict_types=1);

/**
 * COSE_Encrypt (RFC 9052 section 5.1): one ciphertext, several recipients.
 *
 * The content is encrypted once, with a random content encryption key (CEK) and one of the algorithms of RFC 9053
 * section 4 -- here A128GCM through EncryptStructure, whose context is "Encrypt" rather than "Encrypt0". Each
 * recipient then carries the CEK wrapped for itself, and may carry recipients of its own -- which is how RFC 9052
 * expresses key layering. CoseRecipient is the checked view over that list: the CBOR layer only verifies the item is
 * a list, so an empty list or a list of integers decodes without complaint.
 *
 * The key wrap algorithms of RFC 9053 section 6.2 (A128KW, -3) are not in the library yet; see issue #201. Until
 * they land, this example wraps the CEK with AES Key Wrap (RFC 3394) written out by hand at the bottom of the file,
 * and checks that code against the test vector of the RFC before using it.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseEncryptTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\InitializationVector;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Encrypt: several recipients');

$algorithm = A128GCM::create();
$contentEncryptionKey = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => random_bytes($algorithm->keyLength()),
]);
$nonce = random_bytes($algorithm->nonceLength());
$plaintext = 'Secret shared with two parties';

// Each recipient has a key-encryption key it already shares with the sender.
$keyEncryptionKeys = [
    'alice' => random_bytes(16),
    'bob' => random_bytes(16),
];

// --- encrypting the content ---------------------------------------------------

$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($algorithm::identifier())),
]));
$structure = EncryptStructure::create($protectedHeader);
example_hex('Enc_structure', (string) $structure);
$ciphertext = $structure->encrypt($algorithm, $contentEncryptionKey, $plaintext, $nonce);
example_assert(strlen($ciphertext) === strlen($plaintext) + $algorithm->tagLength(), 'the content was encrypted');

// --- wrapping the key for each recipient ---------------------------------------

// The AES Key Wrap below is checked against RFC 3394 section 4.1 (128 bits of key data, 128-bit KEK) before use.
example_assert(
    example_aes_key_wrap(hex2bin('000102030405060708090A0B0C0D0E0F'), hex2bin('00112233445566778899AABBCCDDEEFF'))
        === hex2bin('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'),
    'the hand-written AES Key Wrap matches RFC 3394 section 4.1'
);

$recipients = [];
foreach ($keyEncryptionKeys as $kid => $kek) {
    // A128KW is algorithm -3. RFC 9052 section 8.5.2: for an AE key wrap algorithm the protected bucket MUST be
    // empty, and the unprotected one carries "alg" and, here, the identifier of the shared secret.
    // COSE_recipient = [ protected, unprotected, ciphertext / nil, ? recipients ]
    $recipients[] = ListObject::create([
        ByteStringObject::create(''),
        MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-3)),
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid)),
        ]),
        ByteStringObject::create(example_aes_key_wrap($kek, $contentEncryptionKey->k())),
    ]);
}

$message = CoseEncryptTag::create(ListObject::create([
    $protectedHeader,
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(InitializationVector::IV), ByteStringObject::create($nonce)),
    ]),
    ByteStringObject::create($ciphertext),
    ListObject::create($recipients),
]));

$encoded = (string) $message;
example_hex('COSE_Encrypt', $encoded);
echo PHP_EOL;

// --- a recipient opens the message ---------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseEncryptTag, 'decoded as a COSE_Encrypt');

$entries = CoseRecipient::all($decoded->getRecipients());
example_assert(count($entries) === 2, 'the message carries two well-formed recipients');

// The nonce and the AAD of the content layer come from the message; the CEK from the recipient entry.
$decodedNonce = InitializationVector::resolve(CoseHeaders::fromMessage($decoded), $algorithm->nonceLength());
$contentStructure = EncryptStructure::create($decoded->getProtectedHeader());

foreach ($entries as $entry) {
    $kid = (string) $entry->getUnprotectedHeaderParameter(4)?->getValue();
    $kek = $keyEncryptionKeys[$kid];

    example_assert(! $entry->hasDetachedCiphertext(), sprintf('%s carries a wrapped key', $kid));
    example_assert((string) $entry->getUnprotectedHeaderParameter(1)?->normalize() === '-3', sprintf('%s is wrapped with A128KW', $kid));
    $cek = example_aes_key_unwrap($kek, $entry->getCiphertext()->getValue());
    example_assert($cek === $contentEncryptionKey->k(), sprintf('%s unwrapped the content key', $kid));

    // With the content key in hand, the content itself
    $recovered = $contentStructure->decrypt(
        $algorithm,
        SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => $cek,
        ]),
        $decoded->getCiphertext()->getValue(),
        $decodedNonce
    );
    example_assert($recovered === $plaintext, sprintf('%s read the content', $kid));
}

// --- nested recipients and detached ciphertext ---------------------------------

// The CDDL allows a fourth item -- recipients of the recipient -- and a nil ciphertext.
$layered = CoseRecipient::create(ListObject::create([
    ByteStringObject::create(''),
    MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('outer'))]),
    NullObject::create(),
    ListObject::create([
        ListObject::create([
            ByteStringObject::create(''),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('inner'))]),
            ByteStringObject::create('wrapped'),
        ]),
    ]),
]));
example_assert($layered->hasDetachedCiphertext(), 'the outer recipient has a detached ciphertext');
example_assert(count($layered->getRecipients()) === 1, 'it carries one nested recipient');
example_line(
    'nested kid',
    (string) $layered->getRecipients()[0]->getUnprotectedHeaderParameter(4)?->getValue()
);

// --- AES Key Wrap, RFC 3394, until issue #201 lands it in the library -----------

/**
 * RFC 3394 section 2.2.1: six rounds of AES over the 64-bit blocks of the key, chained through the register A.
 */
function example_aes_key_wrap(string $kek, string $key): string
{
    $a = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";
    $r = str_split($key, 8);
    $n = count($r);
    for ($j = 0; $j <= 5; ++$j) {
        for ($i = 0; $i < $n; ++$i) {
            $b = openssl_encrypt($a . $r[$i], 'aes-128-ecb', $kek, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            $a = substr((string) $b, 0, 8) ^ str_pad(pack('J', $n * $j + $i + 1), 8, "\0", STR_PAD_LEFT);
            $r[$i] = substr((string) $b, 8);
        }
    }

    return $a . implode('', $r);
}

/**
 * RFC 3394 section 2.2.2, the rounds run backwards; the register must come back to the initial value.
 */
function example_aes_key_unwrap(string $kek, string $wrapped): string
{
    $blocks = str_split($wrapped, 8);
    $a = array_shift($blocks);
    $r = $blocks;
    $n = count($r);
    for ($j = 5; $j >= 0; --$j) {
        for ($i = $n - 1; $i >= 0; --$i) {
            $a ^= str_pad(pack('J', $n * $j + $i + 1), 8, "\0", STR_PAD_LEFT);
            $b = openssl_decrypt($a . $r[$i], 'aes-128-ecb', $kek, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            $a = substr((string) $b, 0, 8);
            $r[$i] = substr((string) $b, 8);
        }
    }
    if (! hash_equals("\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6", $a)) {
        throw new RuntimeException('The wrapped key does not unwrap with this key-encryption key');
    }

    return implode('', $r);
}
