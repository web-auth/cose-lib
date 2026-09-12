<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * A192KW: AES Key Wrap with a 192-bit key (RFC 9053, section 6.2.1, table 13).
 */
final class A192KW extends AesKeyWrap
{
    public const ID = -4;

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
