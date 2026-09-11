<?php

declare(strict_types=1);

namespace Cose\Encryption;

use CBOR\ByteStringObject;
use CBOR\IndefiniteLengthByteStringObject;
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseStructure;
use InvalidArgumentException;

/**
 * The Enc_structure of a COSE_Encrypt0 (RFC 9052 section 5.3).
 *
 * Enc_structure = [ "Encrypt0", protected : empty_or_serialized_map, external_aad : bstr ]
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
final class Encrypt0Structure extends CoseStructure
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
     * the ciphertext field of the COSE_Encrypt0 carries.
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
     * Decrypts the ciphertext field of a COSE_Encrypt0 with this structure as the additional authenticated data.
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

    protected function context(): string
    {
        return 'Encrypt0';
    }

    protected function items(): array
    {
        return [self::emptyOrSerializedMap($this->protectedHeader), $this->externalAad];
    }
}
