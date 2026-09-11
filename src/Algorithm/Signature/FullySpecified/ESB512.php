<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\FullySpecified;

use Cose\Algorithm\Signature\ECDSA\ECDSA;
use Cose\Key\Ec2Key;
use const OPENSSL_ALGO_SHA512;

/**
 * ECDSA using the brainpoolP512r1 curve and SHA-512.
 *
 * The brainpoolP512r1 curve is not in every OpenSSL build: call `isSupported()` before use when the platform is not
 * known in advance; create() throws a RuntimeException on a build without it.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1
 */
final class ESB512 extends ECDSA
{
    use RequiresAnOpenSslCurve;

    public const ID = -268;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }

    protected function getCurve(): int
    {
        return Ec2Key::CURVE_BP512;
    }

    protected function getSignaturePartLength(): int
    {
        return 128;
    }

    protected static function curveName(): string
    {
        return Ec2Key::CURVE_NAME_BP512;
    }

    protected static function algorithmName(): string
    {
        return 'ESB512';
    }
}
