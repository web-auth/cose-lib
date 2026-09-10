<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\RsaKey;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

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

    /**
     * A structurally invalid modulus or exponent used to survive the constructor and surface much later as a
     * Brick\Math exception or a TypeError, from inside verify().
     */
    #[Test]
    #[DataProvider('getInvalidKeys')]
    public function aStructurallyInvalidKeyIsRejected(mixed $modulus, mixed $exponent, string $expectedMessage): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedMessage);

        // When
        RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => $modulus,
            RsaKey::DATA_E => $exponent,
        ]);
    }

    #[Test]
    public function aNonStringPrivateParameterIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid RSA key. The private parameters shall be byte strings');

        // When
        RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => str_repeat("\xff", 256),
            RsaKey::DATA_E => "\x01\x00\x01",
            RsaKey::DATA_D => 12345,
        ]);
    }

    /**
     * @return iterable<string, array{mixed, mixed, string}>
     */
    public static function getInvalidKeys(): iterable
    {
        $message = 'Invalid RSA key. The modulus and the exponent shall be non-empty byte strings';

        yield 'an empty modulus' => ['', "\x01\x00\x01", $message];
        yield 'an empty exponent' => [str_repeat("\xff", 256), '', $message];
        yield 'an integer modulus' => [12345, "\x01\x00\x01", $message];
        yield 'an integer exponent' => [str_repeat("\xff", 256), 65537, $message];
        yield 'a zero modulus' => ["\x00", "\x01\x00\x01", 'Invalid RSA key. The modulus shall not be zero'];
        yield 'an all-zero modulus' => [
            str_repeat("\x00", 256),
            "\x01\x00\x01",
            'Invalid RSA key. The modulus shall not be zero',
        ];
    }
}
