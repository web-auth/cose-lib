<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\EdDSA;

use Cose\Key\Key;

/**
 * Ed25519 over the SHA-256 digest of the message. Neither this pre-hash variant nor the identifier -260 belongs to
 * EdDSA — the IANA COSE Algorithms registry assigns -260 to WalnutDSA — and the class is kept for the authenticators
 * that already produce it. The fully-specified EdDSA identifiers are
 * {@see \Cose\Algorithm\Signature\FullySpecified\Ed25519} (-19) and
 * {@see \Cose\Algorithm\Signature\FullySpecified\Ed448} (-53).
 */
final class Ed256 extends EdDSA
{
    public const ID = -260;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    public function sign(string $data, Key $key): string
    {
        $hashedData = hash('sha256', $data, true);

        return parent::sign($hashedData, $key);
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $hashedData = hash('sha256', $data, true);

        return parent::verify($hashedData, $key, $signature);
    }
}
