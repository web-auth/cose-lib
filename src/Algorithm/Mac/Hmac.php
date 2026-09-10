<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\KeyRestrictionEnforcement;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use InvalidArgumentException;

/**
 * @see \Cose\Tests\Algorithm\Mac\HmacTest
 */
abstract class Hmac implements Mac, KeyRestrictionAware
{
    use KeyRestrictionEnforcement;

    public function hash(string $data, Key $key): string
    {
        // RFC 9053, section 3.1: "If the 'key_ops' field is present, it MUST include 'MAC create' when creating an
        // HMAC authentication tag."
        $this->checkKey($key, Key::OP_MAC_CREATE);

        return $this->compute($data, $key);
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        // ... and it MUST include 'MAC verify' when verifying one, so the two operations cannot share a code path.
        $this->checkKey($key, Key::OP_MAC_VERIFY);

        return hash_equals($this->compute($data, $key), $signature);
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getSignatureLength(): int;

    private function compute(string $data, Key $key): string
    {
        $signature = hash_hmac($this->getHashAlgorithm(), $data, (string) $key->get(SymmetricKey::DATA_K), true);

        return substr($signature, 0, intdiv($this->getSignatureLength(), 8));
    }

    private function checkKey(Key $key, int $operation): void
    {
        if ($key->type() !== Key::TYPE_OCT && $key->type() !== Key::TYPE_NAME_OCT) {
            throw new InvalidArgumentException('Invalid key. Must be of type symmetric');
        }

        if (! $key->has(SymmetricKey::DATA_K)) {
            throw new InvalidArgumentException('Invalid key. The value of the key is missing');
        }

        $this->checkKeyRestrictions($key, $operation);
    }
}
