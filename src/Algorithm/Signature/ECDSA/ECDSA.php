<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\ECDSA;

use Cose\Algorithm\Signature\Signature;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use InvalidArgumentException;
use function openssl_sign;
use function openssl_verify;
use function strlen;

/**
 * @see \Cose\Tests\Algorithm\Signature\ECDSA\ECDSATest
 */
abstract class ECDSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key);
        openssl_sign($data, $signature, $key->asPEM(), $this->getHashAlgorithm());

        return ECSignature::fromAsn1($signature, $this->getSignaturePartLength());
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);
        $publicKey = $key->toPublic();
        $length = $this->getSignaturePartLength();
        if (strlen($signature) !== $length) {
            // A signature of the wrong size is a caller error, not attacker input: the exception is kept.
            throw new InvalidArgumentException('Invalid signature length.');
        }

        try {
            $signature = ECSignature::toAsn1($signature, $length);
        } catch (InvalidArgumentException) {
            // A well-formed but invalid signature (e.g. R = 0) is a verification failure, not an error.
            return false;
        }

        return openssl_verify($data, $signature, $publicKey->asPEM(), $this->getHashAlgorithm()) === 1;
    }

    abstract protected function getCurve(): int;

    abstract protected function getHashAlgorithm(): int;

    abstract protected function getSignaturePartLength(): int;

    private function handleKey(Key $key): Ec2Key
    {
        $key = Ec2Key::create($key->getData());
        if ($key->curve() !== $this->getCurve()) {
            throw new InvalidArgumentException('This key cannot be used with this algorithm');
        }

        return $key;
    }
}
