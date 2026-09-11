<?php

declare(strict_types=1);

/**
 * COSE_Encrypt (RFC 9052 section 5.1): one ciphertext, several recipients, and the key management algorithms of
 * RFC 9053 sections 5 and 6 that fill each recipient.
 *
 * The content is encrypted once, with a random content encryption key (CEK) and one of the AEADs of RFC 9053
 * section 4 -- A128GCM here, through EncryptStructure, whose context is "Encrypt" rather than "Encrypt0". Each
 * recipient then carries the CEK protected for itself, by the algorithm of its choice: wrapped under a key the two
 * parties share (A256KW), wrapped under a key agreed with the recipient's public key and a fresh ephemeral key
 * (ECDH-ES + A128KW), or wrapped under a key agreed between two static keys (ECDH-SS + A128KW, whose recipient then
 * has to carry a nonce). EncryptStructure::encryptFor() runs the whole of it in one call.
 *
 * Then the other kind of recipient: a direct one, whose algorithm decides the CEK instead of transporting it and
 * which RFC 9052 section 8.5 makes the only recipient of its message. And finally the layering of RFC 9052
 * Appendix B: a recipient whose key-encryption key comes from a recipient of its own.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseEncryptTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\KeyManagement\A128KW;
use Cose\Algorithm\KeyManagement\A256KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_A128KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_HKDF256;
use Cose\Algorithm\KeyManagement\ECDH_SS_A128KW;
use Cose\Algorithm\KeyManagement\EllipticCurveDiffieHellman;
use Cose\Algorithm\KeyManagement\KeyManagement;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Algorithm\Manager;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\InitializationVector;
use Cose\Encryption\Recipient;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Encrypt: several recipients');

$algorithm = A128GCM::create();
$manager = Manager::create()->add(
    $algorithm,
    A128KW::create(),
    A256KW::create(),
    ECDH_ES_A128KW::create(),
    ECDH_SS_A128KW::create(),
    ECDH_ES_HKDF256::create(),
);
$plaintext = 'Secret shared with three parties';

// The parties. Alice sends; the three recipients hold, respectively, a key shared with Alice, a P-256 key pair, and
// an X25519 key pair. Alice has a static P-256 key of her own for the static-static agreement.
$sharedKek = example_symmetric_key();
$bob = example_ec_key();
$carol = EllipticCurveDiffieHellman::generateEphemeralKey(OkpKey::create([
    Key::TYPE => Key::TYPE_OKP,
    OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
    OkpKey::DATA_X => str_repeat("\0", 32),
]));
$alice = EllipticCurveDiffieHellman::generateEphemeralKey($carol);

// --- encrypting for the three ---------------------------------------------------

$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($algorithm::identifier())),
]));
$recipients = [
    // A shared key wraps the CEK: the "alg" goes in the unprotected bucket, the protected one MUST be empty.
    Recipient::create(A256KW::create(), $sharedKek, null, example_kid('shared-kek')),
    // Bob's public key: a fresh ephemeral key is generated and written as the "ephemeral key" parameter.
    Recipient::create(ECDH_ES_A128KW::create(), $bob->toPublic(), null, example_kid('bob')),
    // Carol's public key and Alice's static private key: RFC 9053 section 6.3.1 requires a nonce or a salt.
    Recipient::create(ECDH_SS_A128KW::create(), $carol->toPublic(), null, MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('carol')),
        MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_STATIC_KEY_ID), ByteStringObject::create('alice')),
        MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_NONCE), ByteStringObject::create(random_bytes(32))),
    ]))->withSenderKey($alice),
];

$message = EncryptStructure::create($protectedHeader)
    ->encryptFor($algorithm, $plaintext, random_bytes($algorithm->nonceLength()), $recipients);
$encoded = (string) $message;
example_hex('COSE_Encrypt', $encoded);
echo PHP_EOL;

// --- each recipient opens the message ----------------------------------------------

$decoded = Decoder::create()->decode(StringStream::create($encoded));
example_assert($decoded instanceof CoseEncryptTag, 'decoded as a COSE_Encrypt');

$entries = CoseRecipient::all($decoded->getRecipients());
example_assert(count($entries) === 3, 'the message carries three well-formed recipients');

// The nonce and the AAD of the content layer come from the message; the CEK from the recipient entry.
$nonce = InitializationVector::resolve(CoseHeaders::fromMessage($decoded), $algorithm->nonceLength());
$contentStructure = EncryptStructure::create($decoded->getProtectedHeader());

/**
 * What a recipient does: find its own entry, hand it to the algorithm the entry announces with its own key, and
 * decrypt the content with the key that comes back.
 *
 * @param list<CoseRecipient> $entries
 */
function example_open(array $entries, string $kid, Key $ownKey, Manager $manager, ?Key $senderKey = null): string
{
    global $algorithm, $contentStructure, $decoded, $nonce;
    foreach ($entries as $entry) {
        if ($entry->getUnprotectedHeaderParameter(4)?->normalize() !== $kid) {
            continue;
        }
        $keyManagement = $manager->get((int) $entry->headers()->getHeaderParameter(1)?->normalize());
        example_assert($keyManagement instanceof KeyManagement, sprintf('%s: the recipient announces a key management algorithm', $kid));
        $layer = RecipientLayer::fromRecipient($entry, $algorithm, null, count($entries))
            ->withSenderKey($senderKey);
        $cek = $keyManagement->recoverKey($layer, $ownKey);

        return $contentStructure->decrypt(
            $algorithm,
            SymmetricKey::create([
                SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
                SymmetricKey::DATA_K => $cek,
            ]),
            $decoded->getCiphertext()->getValue(),
            $nonce
        );
    }
    throw new RuntimeException(sprintf('No recipient "%s"', $kid));
}

example_assert(example_open($entries, 'shared-kek', $sharedKek, $manager) === $plaintext, 'the holder of the shared key read the content');
example_assert(example_open($entries, 'bob', $bob, $manager) === $plaintext, 'Bob read the content with his private key and the ephemeral key of the message');
// Carol resolves "alice" (the static key id) out of the keys she trusts, and hands Alice's public key over.
example_assert(example_open($entries, 'carol', $carol, $manager, $alice->toPublic()) === $plaintext, 'Carol read the content with her private key and Alice\'s static public key');
example_line('recipient 0 alg', 'A256KW, in the unprotected bucket (RFC 9053 section 6.2.1: the protected one MUST be empty)');
example_line('recipient 1 epk', bin2hex((string) $entries[1]->headers()->getEphemeralKey()?->x()));
example_line('recipient 2 static kid', (string) $entries[2]->headers()->getStaticKeyId());

// A second message for Bob carries a different ephemeral key: RFC 9053 section 6.3.1, a new one per operation.
$again = EncryptStructure::create($protectedHeader)->encryptFor($algorithm, $plaintext, random_bytes(12), [$recipients[1]]);
example_assert(
    CoseRecipient::all($again->getRecipients())[0]->headers()->getEphemeralKey()?->x() !== $entries[1]->headers()->getEphemeralKey()?->x(),
    'two encryptions for Bob use two ephemeral keys'
);
echo PHP_EOL;

// --- a direct recipient decides the CEK ----------------------------------------------

// ECDH-ES + HKDF-256 is direct key agreement: the derived key *is* the CEK, nothing is wrapped, and RFC 9052
// section 8.5.4 makes such a recipient the only one of its message. encryptFor() derives the CEK from it.
$direct = EncryptStructure::create($protectedHeader)->encryptFor($algorithm, $plaintext, random_bytes(12), [
    Recipient::create(ECDH_ES_HKDF256::create(), $bob->toPublic(), null, example_kid('bob')),
]);
$directEntries = CoseRecipient::all($direct->getRecipients());
example_assert($directEntries[0]->getCiphertext()->getValue() === '', 'a direct recipient carries an empty ciphertext');
$decoded = $direct;
$nonce = InitializationVector::resolve(CoseHeaders::fromMessage($direct), $algorithm->nonceLength());
$contentStructure = EncryptStructure::create($direct->getProtectedHeader());
example_assert(example_open($directEntries, 'bob', $bob, $manager) === $plaintext, 'Bob read the directly keyed content');

try {
    EncryptStructure::create($protectedHeader)->encryptFor($algorithm, $plaintext, random_bytes(12), [
        Recipient::create(ECDH_ES_HKDF256::create(), $bob->toPublic()),
        Recipient::create(A256KW::create(), $sharedKek),
    ]);
    example_assert(false, 'a direct recipient with a sibling must be refused');
} catch (InvalidArgumentException $e) {
    example_line('direct + sibling', 'refused: ' . $e->getMessage());
}
echo PHP_EOL;

// --- nested recipients (RFC 9052 Appendix B) ------------------------------------------

// A recipient may carry recipients of its own, which is how RFC 9052 expresses key layering: the outer recipient
// wraps the CEK under a key-encryption key (KEK), and the inner recipient delivers that KEK. Here the KEK is agreed
// with Bob's key, as in Appendix B. encryptFor() stops at one level, so the two entries are assembled by hand, from
// the inside out: the inner layer first, since a direct agreement decides the key it hands up.
//
// The inner layer protects a key "for" A128KW: the algorithm and the key length its COSE_KDF_Context binds to are
// those of the outer recipient, not of the content.
$innerProtected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ECDH_ES_HKDF256::ID)),
]));
$inner = ECDH_ES_HKDF256::create()->protectKey(
    RecipientLayer::create(CoseHeaders::of($innerProtected, MapObject::create()), A128KW::create()),
    $bob->toPublic()
);
$kek = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => $inner->key(),
]);

// The outer layer wraps the CEK under that KEK, for the content algorithm.
$cek = random_bytes($algorithm->keyLength());
$outerHeaders = CoseHeaders::of(ByteStringObject::create(''), MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(A128KW::ID)),
]));
$outer = A128KW::create()->protectKey(RecipientLayer::create($outerHeaders, $algorithm), $kek, $cek);

$innerUnprotected = MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('bob'))]);
foreach ($inner->headerParameters() as $item) {
    $innerUnprotected->set($item);
}
$layered = CoseEncryptTag::create(ListObject::create([
    $protectedHeader,
    MapObject::create([MapItem::create(UnsignedIntegerObject::create(InitializationVector::IV), ByteStringObject::create($iv = random_bytes(12)))]),
    ByteStringObject::create(EncryptStructure::create($protectedHeader)->encrypt($algorithm, SymmetricKey::create([
        SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        SymmetricKey::DATA_K => $cek,
    ]), $plaintext, $iv)),
    ListObject::create([
        ListObject::create([
            ByteStringObject::create(''),
            $outerHeaders->getUnprotectedHeader(),
            ByteStringObject::create($outer->ciphertext()),
            ListObject::create([
                ListObject::create([$innerProtected, $innerUnprotected, ByteStringObject::create($inner->ciphertext())]),
            ]),
        ]),
    ]),
]));
example_hex('layered COSE_Encrypt', (string) $layered);

// Bob opens it from the inside out: the inner recipient gives him the KEK, the outer one the CEK.
$outerEntry = CoseRecipient::all($layered->getRecipients())[0];
example_assert($outerEntry->hasRecipients(), 'the outer recipient carries a recipient of its own');
$innerEntry = $outerEntry->getRecipients()[0];
$recoveredKek = ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient($innerEntry, A128KW::create()), $bob);
$recoveredCek = A128KW::create()->recoverKey(RecipientLayer::fromRecipient($outerEntry, $algorithm), SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => $recoveredKek,
]));
example_assert($recoveredCek === $cek, 'Bob recovered the CEK through the two layers');
example_line('layers', 'A128KW under a KEK that ECDH-ES + HKDF-256 derived for A128KW');

function example_kid(string $kid): MapObject
{
    return MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid))]);
}
