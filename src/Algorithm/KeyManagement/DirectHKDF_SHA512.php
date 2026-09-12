<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * direct+HKDF-SHA-512 (RFC 9053, section 6.1.2, table 12): HMAC with SHA-512 as the PRF, extract and expand.
 */
final class DirectHKDF_SHA512 extends DirectHkdf
{
    public const ID = -11;

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
        return 'direct+HKDF-SHA-512';
    }

    public function hkdf(): Hkdf
    {
        return Hkdf::hmac('sha512');
    }
}
