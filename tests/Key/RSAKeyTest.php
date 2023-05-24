<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\RsaKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RSAKeyTest extends TestCase
{
    #[Test]
    public function theKeyIsCorrectlyEncoded(): void
    {
        // Given
        $key = RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::ALG => RS256::ID,
            RsaKey::DATA_N => base64_decode(
                'sWCJwDvzAQ2ssuX7GIQJn5VO4cOGi4MJe6A0mzwA+/YdZlCw5tJaOZcSeLiFunECdJtuI9ldcQasF8ZsGqLSr98O25WdGHiD3R+z4v0KW8pkJaDVAL2hZSkFlyUJ2y6Vfvndpe0oe2aCsIXdEmHSO0k4da4bGWNCBNWGuzCV9Uf++t3rzLBi9kOtnSrlTfEpnxArWuhySQwJDeQLhBKdmugULQugVfTnpISK23Wq3hkOfz7XyLmAgLIRhE4rwsiDtC0cYRA7r9iip3Vc8h2xAV5y0+1g4+uN5KFV4zDxqBy98V43h5sZJ6UBcJH36t6ysdD5ux92SrpPeazcSTCqEw',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
        ]);
        $expected = trim(file_get_contents(__DIR__ . '/RSA-Public.pem'));

        // When
        $pem = $key->toPublic()
            ->asPem();

        // Then
        static::assertSame($expected, $pem);
    }
}
