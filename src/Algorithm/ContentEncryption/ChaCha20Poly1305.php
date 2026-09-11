<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

use function function_exists;
use function sodium_crypto_aead_chacha20poly1305_ietf_decrypt;
use function sodium_crypto_aead_chacha20poly1305_ietf_encrypt;
use SodiumException;

/**
 * ChaCha20/Poly1305 (RFC 9053, section 4.3): the AEAD construction of RFC 8439, 256-bit key, 96-bit nonce, 128-bit
 * tag.
 *
 * "The ChaCha20/Poly1305 AEAD construction defined in [RFC8439] has no parameterization": there is one identifier
 * and nothing to choose. The computation goes through the sodium extension when it is loaded - its
 * `_ietf_` functions are the RFC 8439 construction with the 96-bit nonce - and through OpenSSL's
 * "chacha20-poly1305" otherwise; the two produce the same bytes.
 *
 * RFC 9053 section 4.3.1: the key and nonce pair MUST be unique for every invocation, and no more than 2^64 messages
 * should be encrypted under one key. A reused nonce leaks the Poly1305 key, after which every message under that key
 * can be forged, and the XOR of the two plaintexts. Draw the nonce with random_bytes(12) for each message, or from a
 * strictly increasing counter.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-4.3
 * @see https://www.rfc-editor.org/rfc/rfc8439
 */
final class ChaCha20Poly1305 extends Aead
{
    public const ID = 24;

    private const OPENSSL_CIPHER = 'chacha20-poly1305';

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    /**
     * Whether this platform can compute the algorithm: through the sodium extension, or through an OpenSSL build
     * that implements the cipher.
     */
    public static function isSupported(): bool
    {
        return self::hasSodium() || self::isOpensslCipherAvailable(self::OPENSSL_CIPHER);
    }

    public function keyLength(): int
    {
        return 32;
    }

    public function nonceLength(): int
    {
        return 12;
    }

    public function tagLength(): int
    {
        return 16;
    }

    protected function doEncrypt(string $k, string $plaintext, string $nonce, string $aad): string
    {
        if (self::hasSodium()) {
            // Ciphertext followed by the tag, the layout RFC 8439 section 2.8 and COSE share.
            return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $k);
        }

        return $this->opensslEncrypt(self::OPENSSL_CIPHER, $k, $plaintext, $nonce, $aad);
    }

    protected function doDecrypt(string $k, string $ciphertext, string $tag, string $nonce, string $aad): ?string
    {
        if (self::hasSodium()) {
            try {
                $plaintext = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext . $tag, $aad, $nonce, $k);
            } catch (SodiumException) {
                // The key and the nonce have been checked; what sodium refuses here is the content itself.
                return null;
            }

            return $plaintext === false ? null : $plaintext;
        }

        return $this->opensslDecrypt(self::OPENSSL_CIPHER, $k, $ciphertext, $tag, $nonce, $aad);
    }

    private static function hasSodium(): bool
    {
        return function_exists('sodium_crypto_aead_chacha20poly1305_ietf_encrypt');
    }
}
