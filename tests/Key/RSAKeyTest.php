<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\RsaKey;
use InvalidArgumentException;
use function ltrim;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function substr;

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
     * The DER of a key is built from its octet strings directly, so the encoding of an ASN.1 INTEGER is this
     * library's business now: leading zero octets are not part of the value and are dropped, and a value whose first
     * bit is set gains a 0x00 octet so that it is not read as a negative number (X.690, section 8.3).
     *
     * @see https://github.com/web-auth/cose-lib/security/advisories/GHSA-9v8c-2mgr-qvx3
     */
    #[Test]
    #[DataProvider('getKeysWithTheSameValue')]
    public function theEncodingOfAnIntegerFollowsX690(string $modulus, string $exponent): void
    {
        // Given
        $key = RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => $modulus,
            RsaKey::DATA_E => $exponent,
        ]);

        // When
        $pem = $key->asPem();
        $details = openssl_pkey_get_details(openssl_pkey_get_public($pem));

        // Then
        static::assertSame(ltrim($modulus, "\x00"), $details['rsa']['n']);
        static::assertSame(ltrim($exponent, "\x00"), $details['rsa']['e']);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function getKeysWithTheSameValue(): iterable
    {
        $modulus = "\xc7" . str_repeat("\x11", 254) . "\x01";

        yield 'the first bit of the modulus is set' => [$modulus, "\x01\x00\x01"];
        yield 'the modulus is padded' => ["\x00\x00" . $modulus, "\x01\x00\x01"];
        yield 'the first bit of the modulus is clear' => ["\x47" . substr($modulus, 1), "\x01\x00\x01"];
        yield 'the first bit of the exponent is set' => [$modulus, "\xff\xff\xff"];
        yield 'the exponent is padded' => [$modulus, "\x00\x00\x01\x00\x01"];
        yield 'the exponent is a single octet' => [$modulus, "\x03"];
        // 127 octets of content are the last that the short form of a DER length can hold (X.690, section 8.1.3.4).
        yield 'a modulus at the DER length boundary' => ["\x7f" . str_repeat("\x11", 125) . "\x01", "\x01\x00\x01"];
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
