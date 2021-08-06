<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use Assert\Assertion;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use function Safe\openssl_sign;

abstract class RSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key);
        Assertion::true($key->isPrivate(), 'The key is not private');

        openssl_sign($data, $signature, $key->asPem(), $this->getHashAlgorithm());

        return $signature;
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);

        return 1 === openssl_verify($data, $signature, $key->asPem(), $this->getHashAlgorithm());
    }

    abstract protected function getHashAlgorithm(): int;

    private function handleKey(Key $key): RsaKey
    {
        return RsaKey::create($key->getData());
    }
}
