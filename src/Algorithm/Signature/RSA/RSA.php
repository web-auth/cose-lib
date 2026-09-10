<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use Cose\Algorithm\Signature\OpenSslError;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use InvalidArgumentException;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

/**
 * @see \Cose\Tests\Algorithm\Signature\RSA\RSATest
 */
abstract class RSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key);
        if (! $key->isPrivate()) {
            throw new InvalidArgumentException('The key is not private.');
        }
        $privateKey = openssl_pkey_get_private($key->asPem());
        if ($privateKey === false) {
            throw new InvalidArgumentException('Unable to load the RSA private key');
        }
        OpenSslError::clear();
        // openssl_sign() reports failure with a boolean and never throws: a modulus too short for the digest would
        // otherwise leave $signature null and raise a TypeError on the way out.
        if (! openssl_sign($data, $signature, $privateKey, $this->getHashAlgorithm())) {
            throw new InvalidArgumentException('Unable to sign the data: ' . OpenSslError::lastMessage());
        }

        return $signature;
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);
        // The key is loaded before use so that key material OpenSSL cannot decode yields false instead of an
        // E_WARNING raised from inside openssl_verify().
        $publicKey = openssl_pkey_get_public($key->toPublic()->asPem());
        if ($publicKey === false) {
            return false;
        }

        return openssl_verify($data, $signature, $publicKey, $this->getHashAlgorithm()) === 1;
    }

    abstract protected function getHashAlgorithm(): int;

    private function handleKey(Key $key): RsaKey
    {
        return RsaKey::create($key->getData());
    }
}
