<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

/**
 * AES-CCM-16-64-256 (RFC 9053, section 4.2, Table 6): AES-CCM with a 256-bit key, a 64-bit tag and a 16-bit length
 * field, hence a 13-byte nonce.
 */
final class A256CCM_16_64 extends AesCcm
{
    public const ID = 11;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    protected static function keyLengthInBits(): int
    {
        return 256;
    }

    protected static function lengthFieldInBits(): int
    {
        return 16;
    }

    protected static function tagLengthInBits(): int
    {
        return 64;
    }
}
