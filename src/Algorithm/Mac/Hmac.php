<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use function hash_equals;
use function hash_hmac;
use function intdiv;
use InvalidArgumentException;
use function substr;
use Throwable;

/**
 * @see \Cose\Tests\Algorithm\Mac\HmacTest
 */
abstract class Hmac implements Mac
{
    public function hash(string $data, Key $key): string
    {
        // The key is rebuilt as a SymmetricKey so that the sole definition of what a usable symmetric key is lives
        // in that class, as it does for the ECDSA, EdDSA and RSA algorithms. RFC 9052 section 7.1: "Implementations
        // MUST verify that the key type is appropriate for the algorithm being processed."
        $key = $this->handleKey($key);
        $signature = hash_hmac($this->getHashAlgorithm(), $data, $key->k(), true);

        return substr($signature, 0, intdiv($this->getSignatureLength(), 8));
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        return hash_equals($this->hash($data, $key), $signature);
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getSignatureLength(): int;

    private function handleKey(Key $key): SymmetricKey
    {
        try {
            return SymmetricKey::create($key->getData());
        } catch (InvalidArgumentException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidArgumentException('Invalid symmetric key', 0, $e);
        }
    }
}
