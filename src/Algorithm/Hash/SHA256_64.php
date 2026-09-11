<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

use function hash;
use function substr;

/**
 * SHA-256/64 (RFC 9054, section 3.2): SHA-256 truncated to its first 64 bits, a Filter Only hash.
 *
 * The truncation buys a smaller transmission size at the price of a proportionally higher chance of collision,
 * which is why IANA marks it Filter Only: RFC 9054 has it in mind for selecting among candidate certificates,
 * each of which is then tested with its public key. This class does not implement {@see Hash}.
 *
 * The truncation is defined by RFC 9054 itself; it is not a SHA-2 variant with its own initial values, unlike
 * SHA-512/256 ({@see SHA512_256}).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3.2
 */
final class SHA256_64 implements FilterOnlyHash
{
    public const ID = -15;

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
        return substr(hash('sha256', $data, true), 0, 8);
    }

    public function length(): int
    {
        return 8;
    }
}
