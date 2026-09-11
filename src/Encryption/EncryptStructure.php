<?php

declare(strict_types=1);

namespace Cose\Encryption;

use CBOR\ByteStringObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\Tag\CoseEncryptTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Algorithm\KeyManagement\ProtectedKey;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseStructure;
use Cose\Structure\HeaderMapHelper;
use function count;
use InvalidArgumentException;
use function max;
use function random_bytes;
use function sprintf;

/**
 * The Enc_structure of a COSE_Encrypt (RFC 9052 section 5.3).
 *
 * Enc_structure = [ "Encrypt", protected : empty_or_serialized_map, external_aad : bstr ]
 *
 * This is the additional authenticated data of the content encryption. Unlike the signature and MAC structures it
 * carries no payload: the content itself is what the AEAD encrypts, and this structure is what it authenticates
 * alongside it.
 *
 *
 * The fields a decoded message supplies are typed to accept the indefinite-length byte strings the cbor-php
 * accessors can hand back, and are kept as they were given: a cryptographic structure has to embed the protected
 * bucket byte for byte, or the signature the sender computed over it no longer verifies. The one exception is the
 * empty map wrapped in a byte string (h'a0'), which RFC 9052 section 3 allows on the wire but which the structures
 * of sections 4.4, 5.3 and 6.3 write as a zero-length byte string, see {@see CoseStructure::emptyOrSerializedMap()}.
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-5.3
 * @see \Cose\Tests\Structure\CoseStructureTest
 */
final class EncryptStructure extends CoseStructure
{
    private readonly ByteStringObject $externalAad;

    public function __construct(
        private readonly ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader,
        ?ByteStringObject $externalAad = null
    ) {
        $this->externalAad = $externalAad ?? self::emptyExternalAad();
    }

    public static function create(
        ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader,
        ?ByteStringObject $externalAad = null
    ): self {
        return new self($protectedHeader, $externalAad);
    }

    public function getProtectedHeader(): ByteStringObject|IndefiniteLengthByteStringObject
    {
        return $this->protectedHeader;
    }

    public function getExternalAad(): ByteStringObject
    {
        return $this->externalAad;
    }

    /**
     * Encrypts the content with this structure as the additional authenticated data (RFC 9052 section 5.3): what
     * the ciphertext field of the COSE_Encrypt carries.
     *
     * @param string $nonce the "IV" of the message, or the nonce a "Partial IV" resolves to, see
     *                      {@see InitializationVector}; a key and nonce pair MUST be unique for every message
     *
     * @throws InvalidArgumentException when the key or the nonce cannot be used with the algorithm
     * @return string the ciphertext followed by the authentication tag
     */
    public function encrypt(ContentEncryption $algorithm, SymmetricKey $key, string $plaintext, string $nonce): string
    {
        return $algorithm->encrypt($key, $plaintext, $nonce, (string) $this);
    }

    /**
     * Decrypts the ciphertext field of a COSE_Encrypt with this structure as the additional authenticated data.
     *
     * Build the structure from the protected header the message carries, byte for byte, and from the external AAD
     * the application agreed on: a protected header that was re-encoded, or an external AAD that differs, is a
     * message that does not authenticate.
     *
     * @throws InvalidArgumentException when the key or the nonce cannot be used with the algorithm, or when the
     *                                  content does not authenticate
     */
    public function decrypt(ContentEncryption $algorithm, SymmetricKey $key, string $ciphertext, string $nonce): string
    {
        return $algorithm->decrypt($key, $ciphertext, $nonce, (string) $this);
    }

    /**
     * Encrypts the content for one or more recipients and builds the COSE_Encrypt: the "encrypt for N recipients"
     * convenience of RFC 9052 section 5.1, with the key management of RFC 9053 sections 5 and 6.
     *
     * The content encryption key is decided as the recipient algorithms dictate. A direct algorithm -- "direct",
     * "direct+HKDF-*", "ECDH-ES + HKDF-*", "ECDH-SS + HKDF-*" -- derives it from the recipient's key, and RFC 9052
     * sections 8.5.1 and 8.5.4 make such a recipient the only one of the message: a second recipient next to it is
     * refused. Otherwise the CEK is drawn at random, keyLength() bytes of it, and each recipient wraps it -- AES Key
     * Wrap under the shared secret, or under the key an ECDH agreement derived. Each COSE_recipient is then the
     * protected bucket the recipient chose, its unprotected bucket with the parameters the algorithm produced
     * merged in (the "ephemeral key" of ECDH-ES), and the ciphertext the algorithm returned.
     *
     * The "IV" header parameter is added to the unprotected bucket of the message unless a bucket already carries
     * an "IV" or a "Partial IV": a sender that uses a Partial IV (RFC 9052 section 3.1) sets it in the headers and
     * hands over the nonce it resolves to, as for encrypt().
     *
     * @param string $nonce exactly nonceLength() bytes of the content encryption algorithm; the key and nonce pair
     *                      MUST be unique for every message, and the CEK being fresh whenever it is drawn here, a
     *                      random nonce is the simplest way to be sure of it
     * @param iterable<Recipient> $recipients at least one
     * @param MapObject|null $unprotectedHeader the unprotected bucket of the message, empty by default
     *
     * @throws InvalidArgumentException when no recipient is given, when a direct recipient has siblings, when a
     *                                  recipient's key cannot be used with its algorithm or its headers lack what
     *                                  the algorithm needs, or when the nonce is not of the length the algorithm
     *                                  fixes
     * @return CoseEncryptTag the message, ready to be serialized
     */
    public function encryptFor(
        ContentEncryption $algorithm,
        string $plaintext,
        string $nonce,
        iterable $recipients,
        ?MapObject $unprotectedHeader = null
    ): CoseEncryptTag {
        $recipients = [...$recipients];
        $count = count($recipients);
        if ($count === 0) {
            throw new InvalidArgumentException(
                'A COSE_Encrypt carries at least one recipient (RFC 9052 section 5.1); none was given.'
            );
        }
        $direct = null;
        foreach ($recipients as $index => $recipient) {
            if ($recipient->algorithm()->isDirect()) {
                if ($count > 1) {
                    throw new InvalidArgumentException(sprintf(
                        'Recipient %d uses %s, which decides the content encryption key and MUST be the only recipient of the message (RFC 9052 sections 8.5.1 and 8.5.4); %d recipients were given.',
                        $index,
                        $recipient->algorithm()::class,
                        $count
                    ));
                }
                $direct = $recipient;
            }
        }

        $entries = [];
        if ($direct !== null) {
            $protected = $direct->algorithm()
                ->protectKey($direct->toLayer($algorithm, null, $count), $direct->key());
            $cek = $protected->key();
            $entries[] = self::recipientEntry($direct, $protected);
        } else {
            $cek = random_bytes(max(1, $algorithm->keyLength()));
            foreach ($recipients as $recipient) {
                $protected = $recipient->algorithm()
                    ->protectKey($recipient->toLayer($algorithm, null, $count), $recipient->key(), $cek);
                $entries[] = self::recipientEntry($recipient, $protected);
            }
        }

        $key = SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $cek,
        ]);
        $ciphertext = $this->encrypt($algorithm, $key, $plaintext, $nonce);

        $unprotected = $unprotectedHeader ?? MapObject::create();
        $headers = CoseHeaders::of($this->protectedHeader, $unprotected);
        if ($headers->getHeaderParameter(InitializationVector::IV) === null
            && $headers->getHeaderParameter(InitializationVector::PARTIAL_IV) === null) {
            $unprotected = self::withItem(
                $unprotected,
                MapItem::create(UnsignedIntegerObject::create(InitializationVector::IV), ByteStringObject::create($nonce))
            );
        }

        return CoseEncryptTag::create(ListObject::create([
            $this->protectedHeader,
            $unprotected,
            ByteStringObject::create($ciphertext),
            ListObject::create($entries),
        ]));
    }

    protected function context(): string
    {
        return 'Encrypt';
    }

    /**
     * COSE_recipient = [ protected, unprotected, ciphertext ]: the recipient's own headers, the parameters the
     * algorithm produced merged into the unprotected bucket, and the ciphertext the algorithm returned.
     */
    private static function recipientEntry(Recipient $recipient, ProtectedKey $protected): ListObject
    {
        $unprotected = $recipient->unprotectedHeader();
        foreach ($protected->headerParameters() as $item) {
            $unprotected = self::withItem($unprotected, $item);
        }

        return ListObject::create([
            HeaderMapHelper::encodeProtected($recipient->protectedHeader()),
            $unprotected,
            ByteStringObject::create($protected->ciphertext()),
        ]);
    }

    /**
     * A copy of the map with the item added: the maps a caller hands over are never written to.
     */
    private static function withItem(MapObject $map, MapItem $item): MapObject
    {
        $items = [];
        foreach ($map as $existing) {
            $items[] = $existing;
        }
        $items[] = $item;

        return MapObject::create($items);
    }

    protected function items(): array
    {
        return [self::emptyOrSerializedMap($this->protectedHeader), $this->externalAad];
    }
}
