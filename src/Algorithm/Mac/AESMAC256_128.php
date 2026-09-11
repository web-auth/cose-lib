<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

/**
 * AES-MAC 256/128: AES-CBC-MAC with a 256-bit key and a 128-bit tag (RFC 9053, section 3.2).
 */
final class AESMAC256_128 extends AesCbcMac
{
    public const ID = 26;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    protected function getKeyLength(): int
    {
        return 256;
    }

    protected function getTagLength(): int
    {
        return 128;
    }
}
