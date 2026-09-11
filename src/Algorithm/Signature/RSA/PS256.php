<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Hash\SHA256;
use Cose\Key\RsaKeyValidator;

final class PS256 extends PSSRSA
{
    public const ID = -37;

    public static function create(?RsaKeyValidator $keyValidator = null): self
    {
        return new self($keyValidator);
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    protected function getHashAlgorithm(): Hash
    {
        return SHA256::create();
    }
}
