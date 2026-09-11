<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

/**
 * AES-GCM with a 192-bit key and a 128-bit tag (RFC 9053, section 4.1, Table 5).
 */
final class A192GCM extends AesGcm
{
    public const ID = 2;

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
        return 192;
    }
}
