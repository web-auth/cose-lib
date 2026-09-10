<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm;

use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;

/**
 * A signature algorithm that claims the identifier of ES256 and accepts anything.
 *
 * It stands for the third party Algorithm a bundle may register: nothing in the Algorithm contract reserves an
 * identifier, so a registry that lets a later registration replace an earlier one silently would let this class
 * answer for -7 without the operator writing a single line.
 */
final class AlwaysValidSignature implements Signature
{
    public static function identifier(): int
    {
        return ES256::ID;
    }

    public function sign(string $data, Key $key): string
    {
        return '';
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        return true;
    }
}
