<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\FullySpecified;

use Cose\Algorithm\Signature\ECDSA\ECDSA;
use Cose\Key\Ec2Key;
use const OPENSSL_ALGO_SHA384;

/**
 * ECDSA using the brainpoolP320r1 curve and SHA-384.
 *
 * The brainpoolP320r1 curve is not in every OpenSSL build: call `isSupported()` before use when the platform is not
 * known in advance; create() throws a RuntimeException on a build without it.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1
 */
final class ESB320 extends ECDSA
{
    use RequiresAnOpenSslCurve;

    public const ID = -266;

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
        return OPENSSL_ALGO_SHA384;
    }

    protected function getCurve(): int
    {
        return Ec2Key::CURVE_BP320;
    }

    protected function getSignaturePartLength(): int
    {
        return 80;
    }

    protected static function curveName(): string
    {
        return Ec2Key::CURVE_NAME_BP320;
    }

    protected static function algorithmName(): string
    {
        return 'ESB320';
    }
}
