<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

use function intdiv;
use function sprintf;

/**
 * AES-GCM (RFC 9053, section 4.1): AES in Galois/Counter Mode, 96-bit nonce, 128-bit tag.
 *
 * "This document fixes the size of the nonce at 96 bits" and "the size of the authentication tag is fixed at 128
 * bits": both are enforced here, a nonce of any other length being refused before OpenSSL sees it.
 *
 * RFC 9053 section 4.1.1 bounds the use of one key: the key and nonce pair MUST be unique for every message, and
 * the number of messages encrypted under one key MUST NOT exceed 2^32 - 2^24.5 following the TLS 1.3 analysis. A
 * nonce reused under the same key leaks the GHASH authentication key, after which every message under that key can
 * be forged. Draw it with random_bytes(12) for each message, or from a strictly increasing counter.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-4.1
 */
abstract class AesGcm extends Aead
{
    public static function isSupported(): bool
    {
        return self::isOpensslCipherAvailable(sprintf('aes-%d-gcm', static::keyLengthInBits()));
    }

    public function keyLength(): int
    {
        return intdiv(static::keyLengthInBits(), 8);
    }

    public function nonceLength(): int
    {
        return 12;
    }

    public function tagLength(): int
    {
        return 16;
    }

    abstract protected static function keyLengthInBits(): int;

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
        return sprintf('aes-%d-gcm', static::keyLengthInBits());
    }
}
