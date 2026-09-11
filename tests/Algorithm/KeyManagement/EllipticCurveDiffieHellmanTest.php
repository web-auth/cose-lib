<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use Brick\Math\BigInteger;
use function base64_decode;
use function bin2hex;
use Cose\Algorithm\KeyManagement\EllipticCurveDiffieHellman;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use function strtr;

/**
 * The ECDH primitive of RFC 9053 section 6.3.1: the shared secrets of cose-wg/Examples, the agreement on every
 * curve the platform provides, and the checks of section 6.3.1.1 -- the point validation of an EC2 public key, run
 * before any scalar multiplication, and the all-zero output of a low-order OKP key.
 */
final class EllipticCurveDiffieHellmanTest extends TestCase
{
    /**
     * Meriadoc's P-256 key of cose-wg/Examples and the ephemeral key of ecdh-direct-examples/p256-hkdf-256-01,
     * whose Secret_hex the fixture records.
     */
    #[Test]
    public function theSharedSecretOfTheP256FixtureIsReproduced(): void
    {
        $meriadoc = self::meriadoc();
        $ephemeral = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
            Ec2Key::DATA_Y => (string) hex2bin('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB'),
        ]);

        static::assertSame(
            '4b31712e096e5f20b4ecf9790fd8cc7c8b7e2c8ad90bda81cb224f62c0e7b9a6',
            bin2hex(EllipticCurveDiffieHellman::sharedSecret($meriadoc, $ephemeral))
        );
    }

    /**
     * X25519-tests/x25519-ss-hkdf-256-direct: Bob's private key and Alice's static public key, RFC 7748 section 6.1
     * test vectors.
     */
    #[Test]
    public function theSharedSecretOfTheX25519FixtureIsReproduced(): void
    {
        $bob = OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => (string) hex2bin('DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F'),
            OkpKey::DATA_D => (string) hex2bin('58AB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E06B'),
        ]);
        $alice = OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => (string) hex2bin('8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A'),
        ]);

        static::assertSame(
            '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
            bin2hex(EllipticCurveDiffieHellman::sharedSecret($bob, $alice))
        );
    }

    /**
     * @return iterable<string, array{Ec2Key|OkpKey, int}>
     */
    public static function curves(): iterable
    {
        yield 'P-256' => [self::ec2Template(Ec2Key::CURVE_P256, 32), 32];
        yield 'P-384' => [self::ec2Template(Ec2Key::CURVE_P384, 48), 48];
        yield 'P-521' => [self::ec2Template(Ec2Key::CURVE_P521, 66), 66];
        yield 'X25519' => [self::okpTemplate(OkpKey::CURVE_X25519, 32), 32];
        yield 'X448' => [self::okpTemplate(OkpKey::CURVE_X448, 56), 56];
        yield 'brainpoolP256r1' => [self::ec2Template(Ec2Key::CURVE_BP256, 32), 32];
        yield 'brainpoolP320r1' => [self::ec2Template(Ec2Key::CURVE_BP320, 40), 40];
        yield 'brainpoolP384r1' => [self::ec2Template(Ec2Key::CURVE_BP384, 48), 48];
        yield 'brainpoolP512r1' => [self::ec2Template(Ec2Key::CURVE_BP512, 64), 64];
    }

    /**
     * Two fresh key pairs on the curve agree on the same secret, of the length of the field, and the generated keys
     * carry every coordinate at full length.
     */
    #[Test]
    #[DataProvider('curves')]
    public function twoGeneratedKeysAgreeOnEveryCurve(Ec2Key|OkpKey $template, int $length): void
    {
        if (! EllipticCurveDiffieHellman::isCurveSupported($template)) {
            static::markTestSkipped('This OpenSSL build does not provide the curve.');
        }

        // When
        $alice = EllipticCurveDiffieHellman::generateEphemeralKey($template);
        $bob = EllipticCurveDiffieHellman::generateEphemeralKey($template);
        $fromAlice = EllipticCurveDiffieHellman::sharedSecret($alice, $bob->toPublic());
        $fromBob = EllipticCurveDiffieHellman::sharedSecret($bob, $alice->toPublic());

        // Then
        static::assertSame(bin2hex($fromAlice), bin2hex($fromBob));
        static::assertSame($length, strlen($fromAlice));
        static::assertTrue($alice->isPrivate());
        static::assertSame($template->curveId(), $alice->curveId());
        static::assertSame($template::class, $alice::class);
        static::assertSame($length, strlen($alice->x()));
        static::assertSame($length, strlen($alice->d()));
        if ($alice instanceof Ec2Key) {
            static::assertSame($length, strlen($alice->y()));
            static::assertTrue($alice->isOnCurve());
        }
        // Nothing but the key material: what the "ephemeral key" header parameter carries.
        static::assertSame($alice instanceof Ec2Key ? [1, -1, -2, -3, -4] : [1, -1, -2, -4], array_keys($alice->getData()));
        static::assertNotSame(bin2hex($alice->x()), bin2hex($bob->x()));
    }

    /**
     * RFC 9053 section 6.3.1.1: "For the 'EC2' key format, this can be done by checking that the x and y values
     * form a point on the curve." The point below is on the quadratic twist of P-256 -- the curve
     * y^2 = x^3 + a*d^2*x + b*d^3 for the non-residue d = 3 -- which is what an invalid-curve attack feeds a
     * receiver: a valid-looking point whose multiplication by the private scalar happens in a group of smooth
     * order. It is refused by the library's own check, with its own message, before OpenSSL sees it.
     */
    #[Test]
    public function aPointOnTheTwistIsRejectedBeforeAnyScalarMultiplication(): void
    {
        $twist = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin('0000000000000000000000000000000000000000000000000000000000000001'),
            Ec2Key::DATA_Y => (string) hex2bin('19491ba72f2b43b6db85214a07d0a7235de3da4aa93c8eb6bb778de0b2c0b9c4'),
        ]);
        static::assertTrue(self::isOnTheTwistOfP256($twist), 'the test vector is not on the twist');
        static::assertFalse($twist->isOnCurve());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid EC2 key. The x and y coordinates do not form a point on the curve (RFC 9053 section 6.3.1.1).');

        EllipticCurveDiffieHellman::sharedSecret(self::meriadoc(), $twist);
    }

    #[Test]
    public function aPointThatIsNotOnAnyCurveIsRejected(): void
    {
        $garbage = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => str_repeat("\x42", 32),
            Ec2Key::DATA_Y => str_repeat("\x43", 32),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('do not form a point on the curve');

        EllipticCurveDiffieHellman::sharedSecret(self::meriadoc(), $garbage);
    }

    /**
     * RFC 7748 section 6.1: the all-zero output of a low-order point is not a secret. The point of order 1 (the
     * neutral element, u = 0) is the simplest such key.
     */
    #[Test]
    public function anAllZeroSharedSecretIsRejected(): void
    {
        $private = EllipticCurveDiffieHellman::generateEphemeralKey(self::okpTemplate(OkpKey::CURVE_X25519, 32));
        $lowOrder = OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => str_repeat("\0", 32),
        ]);

        $this->expectException(InvalidArgumentException::class);

        EllipticCurveDiffieHellman::sharedSecret($private, $lowOrder);
    }

    /**
     * The point of order 8 of RFC 7748 section 6.1 ("u = ... the point at infinity" and the small subgroup points)
     * on X448: u = 0 is of order 1 there too.
     */
    #[Test]
    public function anAllZeroSharedSecretIsRejectedOnX448(): void
    {
        $private = EllipticCurveDiffieHellman::generateEphemeralKey(self::okpTemplate(OkpKey::CURVE_X448, 56));
        $lowOrder = OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X448,
            OkpKey::DATA_X => str_repeat("\0", 56),
        ]);

        $this->expectException(InvalidArgumentException::class);

        EllipticCurveDiffieHellman::sharedSecret($private, $lowOrder);
    }

    #[Test]
    public function aPublicPrivateKeyIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key. The ECDH private key is not private.');

        EllipticCurveDiffieHellman::sharedSecret(self::meriadoc()->toPublic(), self::meriadoc()->toPublic());
    }

    /**
     * RFC 9053 section 6.3.1: "Implementations MUST verify that the key type and curve are correct."
     */
    #[Test]
    public function anEc2KeyForAnOkpKeyIsRejected(): void
    {
        $okp = EllipticCurveDiffieHellman::generateEphemeralKey(self::okpTemplate(OkpKey::CURVE_X25519, 32));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The private key is of type OKP and the public key of type EC2: both MUST be of the same key type (RFC 9053 section 6.3.1).');

        EllipticCurveDiffieHellman::sharedSecret($okp, self::meriadoc()->toPublic());
    }

    #[Test]
    public function aKeyOnAnotherCurveIsRejected(): void
    {
        $p384 = EllipticCurveDiffieHellman::generateEphemeralKey(self::ec2Template(Ec2Key::CURVE_P384, 48));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The private key is on curve 1 and the public key on curve 2: both MUST be on the same curve (RFC 9053 section 6.3.1).');

        EllipticCurveDiffieHellman::sharedSecret(self::meriadoc(), $p384->toPublic());
    }

    /**
     * secp256k1 is registered for ES256K (RFC 8812) and for nothing else.
     */
    #[Test]
    public function secp256k1IsNotACurveEcdhIsDefinedFor(): void
    {
        $template = self::ec2Template(Ec2Key::CURVE_P256K, 32);

        static::assertFalse(EllipticCurveDiffieHellman::isCurveSupported($template));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The EC2 curve 8 is not one ECDH is defined for');

        EllipticCurveDiffieHellman::generateEphemeralKey($template);
    }

    /**
     * Ed25519 and Ed448 sign; RFC 9053 table 18 restricts ECDH to X25519 and X448.
     */
    #[Test]
    public function theEdwardsCurvesAreNotCurvesEcdhIsDefinedFor(): void
    {
        $ed25519 = OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => str_repeat("\1", 32),
            OkpKey::DATA_D => str_repeat("\2", 32),
        ]);

        static::assertFalse(EllipticCurveDiffieHellman::isCurveSupported($ed25519));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The OKP curve 6 is not one ECDH is defined for: X25519 (4) and X448 (5) are (RFC 9053 section 6.3.1); the Edwards curves sign, they do not agree.');

        EllipticCurveDiffieHellman::sharedSecret($ed25519, $ed25519->toPublic());
    }

    /**
     * Meriadoc Brandybuck's P-256 key, used by every ECDH fixture of cose-wg/Examples.
     */
    public static function meriadoc(): Ec2Key
    {
        return Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => self::base64url('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            Ec2Key::DATA_Y => self::base64url('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            Ec2Key::DATA_D => self::base64url('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'),
        ]);
    }

    public static function ec2Template(int $curve, int $length): Ec2Key
    {
        return Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => $curve,
            Ec2Key::DATA_X => str_repeat("\0", $length),
            Ec2Key::DATA_Y => str_repeat("\0", $length),
        ]);
    }

    public static function okpTemplate(int $curve, int $length): OkpKey
    {
        return OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::DATA_X => str_repeat("\0", $length),
        ]);
    }

    /**
     * y^2 = x^3 + a'x + b' with a' = 9a and b' = 27b modulo p: the twist of P-256 by d = 3, the smallest quadratic
     * non-residue of its field.
     */
    private static function isOnTheTwistOfP256(Ec2Key $key): bool
    {
        $p = BigInteger::fromBase('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 16);
        $a = BigInteger::fromBase('ffffffff00000001000000000000000000000000fffffffffffffffffffffffc', 16)->multipliedBy(9)->mod($p);
        $b = BigInteger::fromBase('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16)->multipliedBy(27)->mod($p);
        $x = BigInteger::fromBase(bin2hex($key->x()), 16);
        $y = BigInteger::fromBase(bin2hex($key->y()), 16);

        return $y->power(2)
            ->mod($p)
            ->isEqualTo($x->power(3)->plus($a->multipliedBy($x))->plus($b)->mod($p));
    }

    private static function base64url(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
