<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\KeyRestrictionEnforcement;
use Cose\Algorithm\Signature\OpenSslError;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use function hash_equals;
use function intdiv;
use InvalidArgumentException;
use function is_string;
use function openssl_encrypt;
use const OPENSSL_RAW_DATA;
use const OPENSSL_ZERO_PADDING;
use RuntimeException;
use function sprintf;
use function str_repeat;
use function strlen;
use function substr;

/**
 * AES Message Authentication Codes (RFC 9053, section 3.2).
 *
 * "AES-CBC-MAC is defined in [MAC]" (ISO/IEC 9797-1) and is "the instantiation of the CBC-MAC construction […] using
 * AES as the block cipher", "with the IV fixed to all zeros" - it is not AES-CMAC (RFC 4493), the section says so.
 * The message is encrypted with AES in CBC mode under a zero IV and the last ciphertext block, truncated to the
 * length of the identifier, is the tag. RFC 9053 delegates the padding to ISO/IEC 9797-1 and does not restate the
 * method; the vectors of cose-wg/Examples, which are what interoperates, use padding method 1: the message is
 * right-padded with zero bytes up to the block boundary, and left alone when it is already a multiple of 16 bytes.
 *
 * RFC 9053, section 3.2.1 lists the weaknesses of the construction, and both are the caller's to handle:
 *
 * - "A single key must only be used for messages of a fixed or known length. If this is not the case, then an
 *   attacker will be able to generate a message with a valid tag given two message and tag pairs." The COSE
 *   MAC_structure is the mitigation: it encodes the lengths of every field it holds, so a tag computed over a
 *   Cose\Mac\MacStructure or Cose\Mac\Mac0Structure is not exposed. A tag computed over arbitrary bytes is.
 * - "Cipher Block Chaining (CBC) encryption and CBC-MAC MUST use different keys." A key that also encrypts anything
 *   in CBC mode lets the last ciphertext block stand in for the tag.
 *
 * Section 3.2 requires that "implementations creating and validating MAC values MUST validate that the key type, key
 * length, and algorithm are correct and appropriate for the entities involved": the key has to be symmetric, with a
 * `k` that is a byte string of exactly the length of the identifier - 16 bytes for the 128-bit variants, 32 for the
 * 256-bit ones - which is checked before OpenSSL is reached. The "alg" and "key_ops" restrictions of the key are
 * enforced through KeyRestrictionAware.
 *
 * The 64-bit tag variants (14 and 15) are the ones constrained devices use, and IANA marks all four identifiers as
 * recommended: none of them needs an acknowledgement to be created.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-3.2
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-3.2.1
 * @see \Cose\Tests\Algorithm\Mac\AesCbcMacTest
 */
abstract class AesCbcMac implements Mac, KeyRestrictionAware
{
    use KeyRestrictionEnforcement;

    /**
     * The AES block size, in bytes: the size of the IV, of the padding boundary and of the untruncated tag.
     */
    public const BLOCK_SIZE = 16;

    public function hash(string $data, Key $key): string
    {
        // RFC 9053, section 3.2: "If the 'key_ops' field is present, it MUST include 'MAC create' when creating an
        // AES-MAC authentication tag."
        return $this->compute($data, $this->checkKey($key, Key::OP_MAC_CREATE));
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        // ... and it MUST include 'MAC verify' when verifying one, so the two operations cannot share a code path.
        return hash_equals($this->compute($data, $this->checkKey($key, Key::OP_MAC_VERIFY)), $signature);
    }

    /**
     * The exact length, in bytes, of the key this algorithm accepts: 16 for AES-128, 32 for AES-256.
     */
    public function keyLength(): int
    {
        return intdiv($this->getKeyLength(), 8);
    }

    /**
     * The length, in bytes, of the tag this algorithm produces: 8 or 16.
     */
    public function tagLength(): int
    {
        return intdiv($this->getTagLength(), 8);
    }

    /**
     * The IANA name of the algorithm, for error messages: "AES-MAC 128/64" and its siblings.
     */
    public function name(): string
    {
        return sprintf('AES-MAC %d/%d', $this->getKeyLength(), $this->getTagLength());
    }

    /**
     * The key length, in bits: 128 or 256.
     */
    abstract protected function getKeyLength(): int;

    /**
     * The tag length, in bits: 64 or 128.
     */
    abstract protected function getTagLength(): int;

    private function compute(string $data, string $k): string
    {
        // ISO/IEC 9797-1 padding method 1: as few zero bytes as needed to reach a positive multiple of the block
        // size, so that the empty message becomes one zero block and a full block is left alone.
        $remainder = strlen($data) % self::BLOCK_SIZE;
        if ($remainder !== 0 || $data === '') {
            $data .= str_repeat("\0", self::BLOCK_SIZE - $remainder);
        }

        // OPENSSL_ZERO_PADDING is OpenSSL's "no padding": the message is already aligned, and PKCS#7 would append a
        // block the construction does not have.
        OpenSslError::clear();
        $ciphertext = openssl_encrypt(
            $data,
            sprintf('aes-%d-cbc', $this->getKeyLength()),
            $k,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            str_repeat("\0", self::BLOCK_SIZE)
        );
        if ($ciphertext === false) {
            throw new RuntimeException('Unable to compute the AES-CBC-MAC tag: ' . OpenSslError::lastMessage());
        }

        return substr($ciphertext, -self::BLOCK_SIZE, $this->tagLength());
    }

    /**
     * @param int $operation the Key::OP_* constant of the operation the key is about to be used for
     *
     * @throws InvalidArgumentException when the key cannot be used with this algorithm
     */
    private function checkKey(Key $key, int $operation): string
    {
        if (! $key->typeIs(Key::TYPE_OCT)) {
            throw new InvalidArgumentException('Invalid key. Must be of type symmetric');
        }

        if (! $key->has(SymmetricKey::DATA_K)) {
            throw new InvalidArgumentException('Invalid key. The value of the key is missing');
        }

        $k = $key->get(SymmetricKey::DATA_K);
        if (! is_string($k)) {
            throw new InvalidArgumentException(
                'Invalid key. The value of the key must be a byte string (CBOR objects shall be normalized first)'
            );
        }
        if ($k === '') {
            throw new InvalidArgumentException('Invalid key. The value of the key is empty');
        }

        // RFC 9053, section 3.2: the key length is part of the identifier, so a key of any other length is the
        // wrong key rather than a weak one. It is refused before OpenSSL is given anything.
        if (strlen($k) !== $this->keyLength()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key. %s requires a %d-byte key, %d bytes given',
                $this->name(),
                $this->keyLength(),
                strlen($k)
            ));
        }

        $this->checkKeyRestrictions($key, $operation);

        return $k;
    }
}
