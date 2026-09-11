<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * A256KW: AES Key Wrap with a 256-bit key (RFC 9053, section 6.2.1, table 13).
 */
final class A256KW extends AesKeyWrap
{
    public const ID = -5;

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
}
