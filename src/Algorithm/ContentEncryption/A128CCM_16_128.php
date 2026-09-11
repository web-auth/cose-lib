<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

/**
 * AES-CCM-16-128-128 (RFC 9053, section 4.2, Table 6): AES-CCM with a 128-bit key, a 128-bit tag and a 16-bit length
 * field, hence a 13-byte nonce.
 */
final class A128CCM_16_128 extends AesCcm
{
    public const ID = 30;

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
        return 128;
    }

    protected static function lengthFieldInBits(): int
    {
        return 16;
    }

    protected static function tagLengthInBits(): int
    {
        return 128;
    }
}
