<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * A128KW: AES Key Wrap with a 128-bit key (RFC 9053, section 6.2.1, table 13).
 */
final class A128KW extends AesKeyWrap
{
    public const ID = -3;

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
