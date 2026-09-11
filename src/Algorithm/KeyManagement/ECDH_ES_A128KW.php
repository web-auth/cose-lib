<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * ECDH-ES + A128KW (RFC 9053, section 6.4.1, table 16): Ephemeral-Static ECDH, the shared secret run through HKDF SHA-256 into a 128-bit AES Key Wrap key.
 */
final class ECDH_ES_A128KW extends Ecdh
{
    public const ID = -29;

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
        return 'ECDH-ES + A128KW';
    }

    public function isEphemeralStatic(): bool
    {
        return true;
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
