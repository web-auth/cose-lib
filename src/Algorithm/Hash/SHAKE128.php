<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

/**
 * SHAKE128 with a 256-bit output (RFC 9054, section 3.3).
 *
 * SHAKE128 is an extendable-output function (FIPS 202, section 6.2): it has no output length of its own. RFC 9054
 * fixes the one COSE stores at 256 bits, and registers no identifier for any other length, so this class always
 * returns 32 bytes.
 *
 * PHP has no SHAKE primitive - hash_algos() lists the sha3-* fixed-length functions only, and openssl_digest() can
 * neither set an output length nor, on the OpenSSL 3 builds checked, produce one at all - so the computation is the
 * Keccak sponge of {@see Keccak}. It needs 64-bit integers; isSupported() says whether this build has them.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3.3
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf section 6.2
 */
final class SHAKE128 implements Hash
{
    public const ID = -18;

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
        return Keccak::shake128($data, $this->length());
    }

    public function length(): int
    {
        return 32;
    }
}
