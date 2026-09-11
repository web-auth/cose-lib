<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

use function hash;

/**
 * SHA-512 (RFC 9054, section 3.2).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3.2
 */
final class SHA512 implements Hash
{
    public const ID = -44;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    public function hash(string $data): string
    {
        return hash('sha512', $data, true);
    }

    public function length(): int
    {
        return 64;
    }
}
