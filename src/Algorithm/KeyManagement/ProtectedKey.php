<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use CBOR\MapObject;

/**
 * What the sending side of a key management algorithm produces for one COSE_recipient: the key of the layer below,
 * the header parameters the recipient must carry for the receiving side to redo the computation, and the
 * "ciphertext" field of the recipient.
 *
 * - For the direct encryption and direct key agreement families the key is the one the algorithm derived, the
 *   ciphertext is the zero-length byte string RFC 9052 section 8.5.1 requires, and the header parameters carry the
 *   sender's ephemeral key when there is one.
 * - For the key wrap families the key is the one the caller gave, wrapped into the ciphertext.
 *
 * The header parameters belong in the unprotected bucket of the recipient: RFC 9053 section 5.2 designs the
 * context parameters for it, and an ephemeral key is authenticated by the agreement it is an input of, not by any
 * bucket. {@see \Cose\Encryption\EncryptStructure::encryptFor()} merges them there.
 */
final class ProtectedKey
{
    private function __construct(
        private readonly string $key,
        private readonly MapObject $headerParameters,
        private readonly string $ciphertext
    ) {
    }

    public static function create(string $key, MapObject $headerParameters, string $ciphertext): self
    {
        return new self($key, $headerParameters, $ciphertext);
    }

    /**
     * The key of the layer below, as raw bytes: the one to encrypt or MAC the content with, or the KEK of the
     * recipient above when recipients are nested.
     */
    public function key(): string
    {
        return $this->key;
    }

    /**
     * The header parameters to add to the unprotected bucket of the recipient, empty when the algorithm needs none.
     */
    public function headerParameters(): MapObject
    {
        return $this->headerParameters;
    }

    /**
     * The "ciphertext" field of the COSE_recipient: the wrapped key, or the zero-length byte string of the direct
     * families.
     */
    public function ciphertext(): string
    {
        return $this->ciphertext;
    }
}
