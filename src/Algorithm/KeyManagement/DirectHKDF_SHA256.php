<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * direct+HKDF-SHA-256 (RFC 9053, section 6.1.2, table 12): HMAC with SHA-256 as the PRF, extract and expand.
 */
final class DirectHKDF_SHA256 extends DirectHkdf
{
    public const ID = -10;

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
        return 'direct+HKDF-SHA-256';
    }

    public function hkdf(): Hkdf
    {
        return Hkdf::hmac('sha256');
    }
}
