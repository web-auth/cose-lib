<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

use function hash;

/**
 * SHA-512/256 (RFC 9054, section 3.2): the SHA-2 function of FIPS 180-4, section 5.3.6 that runs the SHA-512
 * compression on 64-bit words with initial values of its own and keeps 256 bits of the result.
 *
 * It is not SHA-512 cut to 32 bytes - the initial hash values differ, so the two digests share nothing - which is
 * why the computation goes through the primitive PHP spells "sha512/256" rather than through a substr() of SHA-512.
 * (SHA-256/64, {@see SHA256_64}, is the truncation.)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3.2
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf section 5.3.6
 */
final class SHA512_256 implements Hash
{
    public const ID = -17;

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
        return hash('sha512/256', $data, true);
    }

    public function length(): int
    {
        return 32;
    }
}
