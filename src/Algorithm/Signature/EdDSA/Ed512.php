<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\EdDSA;

use Cose\Key\Key;

/**
 * Ed25519 over the SHA-512 digest of the message, not EdDSA with Curve448: the signature is computed by
 * {@see EdDSA}, which accepts Ed25519 keys only. Neither this pre-hash variant nor the identifier -261 belongs to
 * EdDSA — the IANA COSE Algorithms registry assigns -261 to TurboSHAKE128 — and the class is kept for the
 * authenticators that already produce it. EdDSA with Curve448 is
 * {@see \Cose\Algorithm\Signature\FullySpecified\Ed448} (-53).
 */
final class Ed512 extends EdDSA
{
    public const ID = -261;

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
        $hashedData = hash('sha512', $data, true);

        return parent::sign($hashedData, $key);
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $hashedData = hash('sha512', $data, true);

        return parent::verify($hashedData, $key, $signature);
    }
}
