<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

/**
 * AES-MAC 128/64: AES-CBC-MAC with a 128-bit key and a 64-bit tag (RFC 9053, section 3.2).
 */
final class AESMAC128_64 extends AesCbcMac
{
    public const ID = 14;

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
        return 128;
    }

    protected function getTagLength(): int
    {
        return 64;
    }
}
