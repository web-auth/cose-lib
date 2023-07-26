<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Key\OkpKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class OkpKeyTest extends TestCase
{
    #[Test]
    public function theKeyIsCorrectlyEncoded(): void
    {
        // Given
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::ALG => Ed25519::ID,
            OkpKey::DATA_CURVE => 'Ed25519',
            OkpKey::DATA_X => bin2hex('98C91448E657A3366C3C04551DAFD92A8BB2BA35138B4ACB94CA1E79D2627BAE'),
        ]);

        // Then
        static::assertSame('Ed25519', $key->curve());
    }
}
