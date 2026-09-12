<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * direct+HKDF-AES-256 (RFC 9053, section 6.1.2, table 12): AES-CBC-MAC with a 256-bit key as the PRF, expand step only -- the shared secret is the PRK and must be 32 bytes long.
 */
final class DirectHKDF_AES256 extends DirectHkdf
{
    public const ID = -13;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    public function name(): string
    {
        return 'direct+HKDF-AES-256';
    }

    public function hkdf(): Hkdf
    {
        return Hkdf::aesCbcMac(256);
    }
}
