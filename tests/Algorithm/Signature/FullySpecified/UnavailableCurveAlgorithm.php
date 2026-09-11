<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\FullySpecified;

use Cose\Algorithm\Signature\ECDSA\ECDSA;
use Cose\Algorithm\Signature\FullySpecified\RequiresAnOpenSslCurve;
use Cose\Key\Ec2Key;
use const OPENSSL_ALGO_SHA256;

/**
 * An ECDSA algorithm on a curve that does not exist: what an ESB* algorithm is on a build without its curve.
 */
final class UnavailableCurveAlgorithm extends ECDSA
{
    use RequiresAnOpenSslCurve;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return -65000;
    }

    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function getCurve(): int
    {
        return Ec2Key::CURVE_BP256;
    }

    protected function getSignaturePartLength(): int
    {
        return 64;
    }

    protected static function curveName(): string
    {
        return 'brainpoolP000r1';
    }

    protected static function algorithmName(): string
    {
        return 'ESX000';
    }
}
