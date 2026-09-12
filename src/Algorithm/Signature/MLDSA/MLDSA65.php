<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\MLDSA;

/**
 * ML-DSA-65 (RFC 9964, section 5): ML-DSA with the parameter set of FIPS 204 table 1 that targets NIST security
 * category 3. A 1952-byte public key, a 3309-byte signature, a 32-byte seed as the private key.
 *
 * Requires PHP 8.4 or later and an OpenSSL runtime of 3.5 or later: call `isSupported()` before use when the
 * platform is not known in advance.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9964.html#section-5
 */
final class MLDSA65 extends MLDSA
{
    public const ID = -49;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    public static function publicKeyLength(): int
    {
        return 1952;
    }

    public static function signatureLength(): int
    {
        return 3309;
    }

    protected static function algorithmName(): string
    {
        return 'ML-DSA-65';
    }
}
