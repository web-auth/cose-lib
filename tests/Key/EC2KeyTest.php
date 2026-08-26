<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use function base64_decode;
use function bin2hex;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\EC2Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function random_bytes;

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
