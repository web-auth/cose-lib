<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\EC2Key;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EC2KeyTest extends TestCase
{
    #[Test]
    public function theKeyIsCorrectlyEncoded(): void
    {
        // Given
        $key = EC2Key::create([
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::ALG => ES256::ID,
            EC2Key::DATA_CURVE => 'P-256',
            EC2Key::DATA_X => random_bytes(32),
            EC2Key::DATA_Y => random_bytes(32),
        ]);

        // Then
        static::assertSame('P-256', $key->curve());
    }
}
