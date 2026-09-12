<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\MLDSA;

/**
 * ML-DSA-87 (RFC 9964, section 5): ML-DSA with the parameter set of FIPS 204 table 1 that targets NIST security
 * category 5. A 2592-byte public key, a 4627-byte signature, a 32-byte seed as the private key.
 *
 * Requires PHP 8.4 or later and an OpenSSL runtime of 3.5 or later: call `isSupported()` before use when the
 * platform is not known in advance.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9964.html#section-5
 */
final class MLDSA87 extends MLDSA
{
    public const ID = -50;

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
        return 2592;
    }

    public static function signatureLength(): int
    {
        return 4627;
    }

    protected static function algorithmName(): string
    {
        return 'ML-DSA-87';
    }
}
