<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

/**
 * SHAKE256 with a 512-bit output (RFC 9054, section 3.3).
 *
 * SHAKE256 is an extendable-output function (FIPS 202, section 6.2): it has no output length of its own. RFC 9054
 * fixes the one COSE stores at 512 bits, and registers no identifier for any other length, so this class always
 * returns 64 bytes.
 *
 * PHP has no SHAKE primitive, see {@see SHAKE128}; the computation is the Keccak sponge of {@see Keccak}, which
 * needs 64-bit integers - isSupported() says whether this build has them.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3.3
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf section 6.2
 */
final class SHAKE256 implements Hash
{
    public const ID = -45;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    /**
     * Whether this PHP build can compute the sponge, i.e. whether its integers are 64 bits wide.
     */
    public static function isSupported(): bool
    {
        return Keccak::isSupported();
    }

    public function hash(string $data): string
    {
        return Keccak::shake256($data, $this->length());
    }

    public function length(): int
    {
        return 64;
    }
}
