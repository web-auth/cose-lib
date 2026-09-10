<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use function base64_decode;
use function bin2hex;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\EC2Key;
use Cose\Tests\RaisesNoPhpError;
use const INF;
use InvalidArgumentException;
use const NAN;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function random_bytes;
use stdClass;

final class EC2KeyTest extends TestCase
{
    use RaisesNoPhpError;

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

    /**
     * The Brainpool curves of the COSE Elliptic Curves registry, used by the RFC 9864 ESB* algorithms.
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
     */
    #[Test]
    #[DataProvider('getBrainpoolCurves')]
    public function aBrainpoolKeyCarriesTheExpectedCurveIdentifier(
        int $curve,
        string $name,
        int $coordinateLength,
        string $oid
    ): void {
        // Given
        $data = [
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::DATA_X => random_bytes($coordinateLength),
            EC2Key::DATA_Y => random_bytes($coordinateLength),
        ];

        // When
        $byValue = EC2Key::create($data + [
            EC2Key::DATA_CURVE => $curve,
        ]);
        $byName = EC2Key::create($data + [
            EC2Key::DATA_CURVE => $name,
        ]);

        // Then
        static::assertSame($curve, $byValue->curve());
        static::assertSame($name, $byName->curve());
        static::assertStringStartsWith("-----BEGIN PUBLIC KEY-----\n", $byValue->asPEM());
        static::assertStringContainsString($oid, self::derOf($byValue->asPEM()));
        static::assertSame(self::derOf($byValue->asPEM()), self::derOf($byName->asPEM()));
    }

    #[Test]
    #[DataProvider('getBrainpoolCoordinateLengths')]
    public function aBrainpoolKeyWithAnInvalidCoordinateLengthIsRejected(int $curve, int $coordinateLength): void
    {
        // Then
        $this->expectExceptionMessage('Invalid length for x coordinate');

        // When
        EC2Key::create([
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::DATA_CURVE => $curve,
            EC2Key::DATA_X => random_bytes($coordinateLength - 1),
            EC2Key::DATA_Y => random_bytes($coordinateLength),
        ]);
    }

    /**
     * RFC 5915 section 3 fixes the length of the private key, but only x and y used to be checked. A degenerate d
     * produced signatures that the key's own public point rejected, with nothing failing at signing time.
     */
    #[Test]
    #[DataProvider('getInvalidPrivateKeyLengths')]
    public function aPrivateKeyOfTheWrongLengthIsRejected(mixed $d): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid length for d');

        // When
        EC2Key::create([
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::DATA_CURVE => EC2Key::CURVE_P256,
            EC2Key::DATA_X => random_bytes(32),
            EC2Key::DATA_Y => random_bytes(32),
            EC2Key::DATA_D => $d,
        ]);
    }

    #[Test]
    public function anUnsupportedCurveIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve is not supported');

        // When
        EC2Key::create([
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::DATA_CURVE => 4242,
            EC2Key::DATA_X => random_bytes(32),
            EC2Key::DATA_Y => random_bytes(32),
        ]);
    }

    /**
     * RFC 8812, sections 3.1 and 4.2 register the name "secp256k1" for the curve of identifier 8; the only name the
     * library used to accept was "P-256K", the spelling of a draft that was renamed before its first revision.
     */
    #[Test]
    public function theRegisteredNameOfCurve8IsAccepted(): void
    {
        // When
        $key = EC2Key::create([
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::DATA_CURVE => EC2Key::CURVE_NAME_SECP256K1,
            EC2Key::DATA_X => random_bytes(32),
            EC2Key::DATA_Y => random_bytes(32),
        ]);

        // Then
        static::assertSame('secp256k1', $key->curve());
        static::assertSame(EC2Key::CURVE_P256K, $key->curveId());
        // The DER of the object identifier 1.3.132.0.10 (SEC 2, section 2.4.1).
        static::assertStringContainsString('06052b8104000a', self::derOf($key->asPEM()));
    }

    /**
     * RFC 9053, section 7.1, table 19 types "crv" as "int / tstr", so the same curve reaches the library under two
     * forms. curveId() is what the algorithm classes compare, and it has to see through both.
     */
    #[Test]
    #[DataProvider('getCurveForms')]
    public function theCurveIdentifierIsTheRegistryValueWhateverFormIsUsed(
        int|string $curve,
        int $expectedId,
        int $coordinateLength
    ): void {
        // When
        $key = EC2Key::create([
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::DATA_CURVE => $curve,
            EC2Key::DATA_X => random_bytes($coordinateLength),
            EC2Key::DATA_Y => random_bytes($coordinateLength),
        ]);

        // Then
        static::assertSame($curve, $key->curve());
        static::assertSame($expectedId, $key->curveId());
    }

    /**
     * spomky-labs/cbor-php renders a CBOR integer as a numeric string, so this is the shape every key decoded from
     * CBOR has.
     */
    #[Test]
    public function theNumericStringsOfADecodedKeyBecomeIntegers(): void
    {
        // When
        $key = EC2Key::create([
            EC2Key::TYPE => '2',
            EC2Key::DATA_CURVE => '1',
            EC2Key::DATA_X => random_bytes(32),
            EC2Key::DATA_Y => random_bytes(32),
        ]);

        // Then
        static::assertSame(EC2Key::TYPE_EC2, $key->type());
        static::assertSame(EC2Key::CURVE_P256, $key->curve());
        static::assertSame(EC2Key::CURVE_P256, $key->curveId());
    }

    /**
     * The constructor used to index its own tables and cast its values before checking that the entries were there
     * and of the expected type, so a malformed key was rejected through a PHP warning, a TypeError or an Error - and
     * sometimes with a message describing the wrong problem - instead of through the documented exception.
     *
     * @param array<int|string, mixed> $data
     */
    #[Test]
    #[DataProvider('getMalformedKeys')]
    public function aMalformedKeyIsRejectedWithTheDocumentedException(array $data, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        self::withoutPhpErrors(static fn (): EC2Key => EC2Key::create($data));
    }

    /**
     * @return iterable<string, array{int|string, int, int}>
     */
    public static function getCurveForms(): iterable
    {
        yield 'P-256 by value' => [EC2Key::CURVE_P256, EC2Key::CURVE_P256, 32];
        yield 'P-256 by name' => [EC2Key::CURVE_NAME_P256, EC2Key::CURVE_P256, 32];
        yield 'P-384 by value' => [EC2Key::CURVE_P384, EC2Key::CURVE_P384, 48];
        yield 'P-384 by name' => [EC2Key::CURVE_NAME_P384, EC2Key::CURVE_P384, 48];
        yield 'P-521 by value' => [EC2Key::CURVE_P521, EC2Key::CURVE_P521, 66];
        yield 'P-521 by name' => [EC2Key::CURVE_NAME_P521, EC2Key::CURVE_P521, 66];
        yield 'secp256k1 by value' => [EC2Key::CURVE_P256K, EC2Key::CURVE_P256K, 32];
        yield 'secp256k1 by its registered name' => [EC2Key::CURVE_NAME_SECP256K1, EC2Key::CURVE_P256K, 32];
        yield 'secp256k1 by its draft name' => [EC2Key::CURVE_NAME_P256K, EC2Key::CURVE_P256K, 32];
        yield 'brainpoolP256r1 by name' => [EC2Key::CURVE_NAME_BP256, EC2Key::CURVE_BP256, 32];
        yield 'brainpoolP320r1 by name' => [EC2Key::CURVE_NAME_BP320, EC2Key::CURVE_BP320, 40];
        yield 'brainpoolP384r1 by name' => [EC2Key::CURVE_NAME_BP384, EC2Key::CURVE_BP384, 48];
        yield 'brainpoolP512r1 by name' => [EC2Key::CURVE_NAME_BP512, EC2Key::CURVE_BP512, 64];
    }

    /**
     * @return iterable<string, array{array<int|string, mixed>, string}>
     */
    public static function getMalformedKeys(): iterable
    {
        $coordinate = random_bytes(32);
        $complete = [
            EC2Key::TYPE => EC2Key::TYPE_EC2,
            EC2Key::DATA_CURVE => EC2Key::CURVE_P256,
            EC2Key::DATA_X => $coordinate,
            EC2Key::DATA_Y => $coordinate,
        ];

        $missing = 'Invalid EC2 key. The curve or the "x/y" coordinates are missing';
        $unsupported = 'The curve is not supported';
        $wrongType = 'Invalid EC2 key. The key type does not correspond to an EC2 key';

        $without = static function (int $index) use ($complete): array {
            unset($complete[$index]);

            return $complete;
        };
        $with = static fn (int $index, mixed $value): array => [
            $index => $value,
        ] + $complete;

        yield 'no key type' => [$without(EC2Key::TYPE), 'Invalid key: the type is not defined'];
        yield 'no curve' => [$without(EC2Key::DATA_CURVE), $missing];
        yield 'no x coordinate' => [$without(EC2Key::DATA_X), $missing];
        yield 'no y coordinate' => [$without(EC2Key::DATA_Y), $missing];

        yield 'an OKP key type' => [$with(EC2Key::TYPE, EC2Key::TYPE_OKP), $wrongType];
        yield 'the OKP key type name' => [$with(EC2Key::TYPE, EC2Key::TYPE_NAME_OKP), $wrongType];
        yield 'a truncatable key type' => [$with(EC2Key::TYPE, '2.9'), $wrongType];
        yield 'a key type with a trailing suffix' => [$with(EC2Key::TYPE, '2abc'), $wrongType];
        yield 'a key type given as an array' => [$with(EC2Key::TYPE, []), $wrongType];

        // The identifier of an OKP curve, of an unassigned value, and every shape a CBOR "crv" can normalise to.
        yield 'the identifier of an X25519 curve' => [$with(EC2Key::DATA_CURVE, 4), $unsupported];
        yield 'an unassigned curve identifier' => [$with(EC2Key::DATA_CURVE, 999), $unsupported];
        yield 'a negative curve identifier' => [$with(EC2Key::DATA_CURVE, -1), $unsupported];
        yield 'a curve given as an array' => [$with(EC2Key::DATA_CURVE, []), $unsupported];
        yield 'a curve given as a float' => [$with(EC2Key::DATA_CURVE, 1.0), $unsupported];
        yield 'a curve given as NAN' => [$with(EC2Key::DATA_CURVE, NAN), $unsupported];
        yield 'a curve given as INF' => [$with(EC2Key::DATA_CURVE, INF), $unsupported];
        yield 'a curve given as a boolean' => [$with(EC2Key::DATA_CURVE, true), $unsupported];
        yield 'a curve given as an object' => [$with(EC2Key::DATA_CURVE, new stdClass()), $unsupported];
        yield 'a truncatable curve' => [$with(EC2Key::DATA_CURVE, '1.5'), $unsupported];
        yield 'a padded curve' => [$with(EC2Key::DATA_CURVE, ' 1'), $unsupported];
        yield 'an unknown curve name' => [$with(EC2Key::DATA_CURVE, 'P-255'), $unsupported];
        yield 'the JWK name of an Edwards curve' => [$with(EC2Key::DATA_CURVE, 'Ed25519'), $unsupported];

        yield 'x given as an array' => [$with(EC2Key::DATA_X, []), 'Invalid type for x coordinate'];
        yield 'x given as an object' => [$with(EC2Key::DATA_X, new stdClass()), 'Invalid type for x coordinate'];
        yield 'x given as an integer' => [$with(EC2Key::DATA_X, 42), 'Invalid type for x coordinate'];
        yield 'y given as an array' => [$with(EC2Key::DATA_Y, []), 'Invalid type for y coordinate'];
        yield 'y given as an integer' => [$with(EC2Key::DATA_Y, 42), 'Invalid type for y coordinate'];

        yield 'x too short' => [$with(EC2Key::DATA_X, random_bytes(31)), 'Invalid length for x coordinate'];
        yield 'x too long' => [$with(EC2Key::DATA_X, random_bytes(33)), 'Invalid length for x coordinate'];
        yield 'y too short' => [$with(EC2Key::DATA_Y, random_bytes(31)), 'Invalid length for y coordinate'];
        // The coordinates of a P-256 point under the identifier of the wider P-521 curve.
        yield 'coordinates of another curve' => [
            $with(EC2Key::DATA_CURVE, EC2Key::CURVE_P521),
            'Invalid length for x coordinate',
        ];
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function getInvalidPrivateKeyLengths(): iterable
    {
        yield 'empty' => [''];
        yield 'a single byte' => ["\x00"];
        yield 'too short' => [random_bytes(31)];
        yield 'too long' => [random_bytes(40)];
        yield 'an integer' => [42];
    }

    /**
     * @return iterable<string, array{int, string, int, string}>
     */
    public static function getBrainpoolCurves(): iterable
    {
        // The values are the DER encoded object identifiers of RFC 5639, section 4.
        yield 'brainpoolP256r1' => [EC2Key::CURVE_BP256, EC2Key::CURVE_NAME_BP256, 32, '06092b2403030208010107'];
        yield 'brainpoolP320r1' => [EC2Key::CURVE_BP320, EC2Key::CURVE_NAME_BP320, 40, '06092b2403030208010109'];
        yield 'brainpoolP384r1' => [EC2Key::CURVE_BP384, EC2Key::CURVE_NAME_BP384, 48, '06092b240303020801010b'];
        yield 'brainpoolP512r1' => [EC2Key::CURVE_BP512, EC2Key::CURVE_NAME_BP512, 64, '06092b240303020801010d'];
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function getBrainpoolCoordinateLengths(): iterable
    {
        yield 'brainpoolP256r1' => [EC2Key::CURVE_BP256, 32];
        yield 'brainpoolP320r1' => [EC2Key::CURVE_BP320, 40];
        yield 'brainpoolP384r1' => [EC2Key::CURVE_BP384, 48];
        yield 'brainpoolP512r1' => [EC2Key::CURVE_BP512, 64];
    }

    private static function derOf(string $pem): string
    {
        return bin2hex(base64_decode((string) preg_replace('#-----[^-]+-----|\s#', '', $pem), true));
    }
}
