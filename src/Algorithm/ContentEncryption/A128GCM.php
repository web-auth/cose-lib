<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

/**
 * AES-GCM with a 128-bit key and a 128-bit tag (RFC 9053, section 4.1, Table 5).
 */
final class A128GCM extends AesGcm
{
    public const ID = 1;

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
}
