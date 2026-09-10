<?php

declare(strict_types=1);

/**
 * COSE_Encrypt (RFC 9052 section 5.1): one ciphertext, several recipients.
 *
 * Each recipient carries the content encryption key wrapped for itself, and may carry recipients of its own -- which
 * is how RFC 9052 expresses key layering. CoseRecipient is the checked view over that list: the CBOR layer only
 * verifies the item is a list, so an empty list or a list of integers decodes without complaint.
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
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\RecipientStructure;
use Cose\Structure\CoseRecipient;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('COSE_Encrypt: several recipients');

$contentEncryptionKey = random_bytes(16);
$iv = random_bytes(12);
$plaintext = 'Secret shared with two parties';

// Each recipient has a key-encryption key it already shares with the sender.
$keyEncryptionKeys = [
    'alice' => random_bytes(16),
    'bob' => random_bytes(16),
];

// --- encrypting the content ---------------------------------------------------

$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(1)), // A128GCM
]));
$aad = (string) EncryptStructure::create($protectedHeader);
$ciphertext = openssl_encrypt(
    $plaintext,
    'aes-128-gcm',
    $contentEncryptionKey,
    OPENSSL_RAW_DATA,
    $iv,
    $authTag,
    $aad,
    16
);
example_assert($ciphertext !== false, 'the content was encrypted');
example_hex('Enc_structure', $aad);

// --- wrapping the key for each recipient ---------------------------------------

$recipients = [];
foreach ($keyEncryptionKeys as $kid => $kek) {
    // A128KW is algorithm -3. Its Enc_structure uses the "Enc_Recipient" context, which is what stops a wrapped key
    // from being replayed at another level of the same message.
    $recipientProtectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-3)),
    ]));
    $recipientAad = (string) RecipientStructure::forEncryptRecipient($recipientProtectedHeader);

    $wrapIv = random_bytes(12);
    $wrapped = openssl_encrypt(
        $contentEncryptionKey,
        'aes-128-gcm',
        $kek,
        OPENSSL_RAW_DATA,
        $wrapIv,
        $wrapTag,
        $recipientAad,
        16
    );

    // COSE_recipient = [ protected, unprotected, ciphertext / nil, ? recipients ]
    $recipients[] = ListObject::create([
        $recipientProtectedHeader,
        MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid)),
            MapItem::create(UnsignedIntegerObject::create(5), ByteStringObject::create($wrapIv)),
        ]),
        ByteStringObject::create($wrapped . $wrapTag),
    ]);
}

$message = CoseEncryptTag::create(ListObject::create([
    $protectedHeader,
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(5), ByteStringObject::create($iv)),
    ]),
    ByteStringObject::create($ciphertext . $authTag),
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

foreach ($entries as $entry) {
    $kid = (string) $entry->getUnprotectedHeaderParameter(4)?->getValue();
    $kek = $keyEncryptionKeys[$kid];

    example_assert(! $entry->hasDetachedCiphertext(), sprintf('%s carries a wrapped key', $kid));
    $wrapped = $entry->getCiphertext()->getValue();
    $wrapIv = (string) $entry->getUnprotectedHeaderParameter(5)?->getValue();
    $recipientAad = (string) RecipientStructure::forEncryptRecipient($entry->getProtectedHeader());

    $cek = openssl_decrypt(
        substr($wrapped, 0, -16),
        'aes-128-gcm',
        $kek,
        OPENSSL_RAW_DATA,
        $wrapIv,
        substr($wrapped, -16),
        $recipientAad
    );
    example_assert($cek === $contentEncryptionKey, sprintf('%s unwrapped the content key', $kid));

    // With the content key in hand, the content itself
    $carried = $decoded->getCiphertext()->getValue();
    $recovered = openssl_decrypt(
        substr($carried, 0, -16),
        'aes-128-gcm',
        (string) $cek,
        OPENSSL_RAW_DATA,
        (string) HeaderMapHelper::findLabel($decoded->getUnprotectedHeader(), 5)?->getValue(),
        substr($carried, -16),
        (string) EncryptStructure::create($decoded->getProtectedHeader())
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
