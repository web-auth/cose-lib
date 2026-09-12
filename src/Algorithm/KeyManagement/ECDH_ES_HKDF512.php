<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * ECDH-ES + HKDF-512 (RFC 9053, section 6.3.1, table 14): Ephemeral-Static ECDH, the shared secret run through HKDF SHA-512 into the key of the layer below.
 */
final class ECDH_ES_HKDF512 extends Ecdh
{
    public const ID = -26;

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
        return 'ECDH-ES + HKDF-512';
    }

    public function isEphemeralStatic(): bool
    {
        return true;
    }

    public function hkdf(): Hkdf
    {
        return Hkdf::hmac('sha512');
    }
}
