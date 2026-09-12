<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * ECDH-SS + A128KW (RFC 9053, section 6.4.1, table 16): Static-Static ECDH, the shared secret run through HKDF SHA-256 into a 128-bit AES Key Wrap key.
 */
final class ECDH_SS_A128KW extends Ecdh
{
    public const ID = -32;

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
        return 'ECDH-SS + A128KW';
    }

    public function isEphemeralStatic(): bool
    {
        return false;
    }

    public function hkdf(): Hkdf
    {
        return Hkdf::hmac('sha256');
    }

    public function keyWrap(): KeyWrap
    {
        return A128KW::create();
    }
}
