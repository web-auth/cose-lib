<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use function base64_decode;
use function chr;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use function hex2bin;
use InvalidArgumentException;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strtr;
use function substr;

/**
 * Ec2Key::isOnCurve() and assertOnCurve(): the point validation of RFC 9053 section 6.3.1.1, which the constructor
 * deliberately does not run.
 */
final class Ec2KeyPointValidationTest extends TestCase
{
    /**
     * The keys of cose-wg/Examples, one per NIST curve, and a compressed one.
     *
     * @return iterable<string, array{Ec2Key}>
     */
    public static function pointsOnTheirCurve(): iterable
    {
        yield 'P-256 (Meriadoc)' => [Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => self::base64url('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            Ec2Key::DATA_Y => self::base64url('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ])];
        yield 'P-384 (ecdsa-02)' => [Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P384,
            Ec2Key::DATA_X => self::base64url('kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc'),
            Ec2Key::DATA_Y => self::base64url('mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s'),
        ])];
        yield 'P-521 (Bilbo)' => [Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P521,
            Ec2Key::DATA_X => self::base64url('AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt'),
            Ec2Key::DATA_Y => self::base64url('AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1'),
        ])];
        yield 'P-256 compressed (Appendix B ephemeral key)' => [Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin('B2ADD44368EA6D641F9CA9AF308B4079AEB519F11E9B8A55A600B21233E86E68'),
            Ec2Key::DATA_Y => false,
        ])];
    }

    #[Test]
    #[DataProvider('pointsOnTheirCurve')]
    public function aRealKeyIsOnItsCurve(Ec2Key $key): void
    {
        static::assertTrue($key->isOnCurve());
        $key->assertOnCurve();
        $this->addToAssertionCount(1);
    }

    /**
     * The constructor accepts any bytes of the right length, as it always has; the check is a separate step.
     */
    #[Test]
    public function arbitraryBytesLoadButAreNotOnTheCurve(): void
    {
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => str_repeat("\x42", 32),
            Ec2Key::DATA_Y => str_repeat("\x43", 32),
        ]);

        static::assertFalse($key->isOnCurve());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid EC2 key. The x and y coordinates do not form a point on the curve (RFC 9053 section 6.3.1.1).');

        $key->assertOnCurve();
    }

    /**
     * A coordinate that is not a field element -- x = p -- is not a point, whatever y says.
     */
    #[Test]
    public function aCoordinateBeyondTheFieldIsNotOnTheCurve(): void
    {
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
            Ec2Key::DATA_Y => str_repeat("\0", 32),
        ]);

        static::assertFalse($key->isOnCurve());
    }

    /**
     * A point on the quadratic twist of P-256 (y^2 = x^3 + 9a x + 27b), the kind of key an invalid-curve attack
     * sends: it has the right length and the right shape, and it is not on P-256.
     */
    #[Test]
    public function aPointOnTheTwistIsNotOnTheCurve(): void
    {
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin('0000000000000000000000000000000000000000000000000000000000000001'),
            Ec2Key::DATA_Y => (string) hex2bin('19491ba72f2b43b6db85214a07d0a7235de3da4aa93c8eb6bb778de0b2c0b9c4'),
        ]);

        static::assertFalse($key->isOnCurve());
    }

    /**
     * Flipping one bit of y of a point on the curve takes it off the curve.
     */
    #[Test]
    public function aTamperedCoordinateIsNotOnTheCurve(): void
    {
        $y = self::base64url('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw');
        $y = substr($y, 0, 31) . chr(ord($y[31]) ^ 1);
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => self::base64url('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            Ec2Key::DATA_Y => $y,
        ]);

        static::assertFalse($key->isOnCurve());
    }

    private static function base64url(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
