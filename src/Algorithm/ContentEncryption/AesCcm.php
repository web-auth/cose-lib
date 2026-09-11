<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

use function intdiv;
use function sprintf;

/**
 * AES-CCM (RFC 9053, section 4.2): AES in Counter with CBC-MAC mode, RFC 3610.
 *
 * CCM is parameterized by the key size, the tag size and L, the size of the length field, which in turn fixes the
 * nonce size: 15 - L bytes. RFC 9053 section 4.2, Table 6 registers eight combinations, named AES-CCM-L-M-K for L in
 * bits (16 or 64), the tag M in bits (64 or 128) and the key K in bits (128 or 256):
 *
 * - L = 16 bits (2 bytes) leaves a 13-byte nonce and limits a message to 2^16 - 1 = 65535 bytes;
 * - L = 64 bits (8 bytes) leaves a 7-byte nonce and lifts that limit, at the price of 2^56 possible nonces only.
 *
 * The nonce length is part of the identifier and a nonce of any other length is refused before OpenSSL sees it:
 * OpenSSL accepts any nonce between 7 and 13 bytes and derives L from it, so a 12-byte nonce handed to
 * AES-CCM-16-64-128 would be encrypted with L = 3 and no conforming recipient could open the result.
 *
 * RFC 9053 section 4.2.1: the key and nonce pair MUST be unique for every message, and the number of AES block
 * operations under one key MUST NOT exceed 2^61. A reused nonce leaks the XOR of the two plaintexts. With the
 * 7-byte nonce of the L = 64 variants, a random nonce collides after roughly 2^28 messages, so those variants call
 * for a counter (as a "Partial IV") rather than random_bytes().
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-4.2
 * @see https://www.rfc-editor.org/rfc/rfc3610
 */
abstract class AesCcm extends Aead
{
    /**
     * Whether the OpenSSL build behind this process implements AES-CCM: some builds leave it out, and PHP only
     * exposes the tag length argument openssl_encrypt() needs for it since 7.1.
     */
    public static function isSupported(): bool
    {
        return self::isOpensslCipherAvailable(sprintf('aes-%d-ccm', static::keyLengthInBits()));
    }

    public function keyLength(): int
    {
        return intdiv(static::keyLengthInBits(), 8);
    }

    /**
     * 15 - L bytes (RFC 3610 section 2.2): 13 for a 16-bit length field, 7 for a 64-bit one.
     */
    public function nonceLength(): int
    {
        return 15 - intdiv(static::lengthFieldInBits(), 8);
    }

    public function tagLength(): int
    {
        return intdiv(static::tagLengthInBits(), 8);
    }

    abstract protected static function keyLengthInBits(): int;

    /**
     * L, the size of the length field, in bits: 16 or 64.
     */
    abstract protected static function lengthFieldInBits(): int;

    abstract protected static function tagLengthInBits(): int;

    protected function doEncrypt(string $k, string $plaintext, string $nonce, string $aad): string
    {
        return $this->opensslEncrypt($this->cipher(), $k, $plaintext, $nonce, $aad);
    }

    protected function doDecrypt(string $k, string $ciphertext, string $tag, string $nonce, string $aad): ?string
    {
        return $this->opensslDecrypt($this->cipher(), $k, $ciphertext, $tag, $nonce, $aad);
    }

    private function cipher(): string
    {
        return sprintf('aes-%d-ccm', static::keyLengthInBits());
    }
}
