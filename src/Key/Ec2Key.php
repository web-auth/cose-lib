<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_key_exists;
use Cose\BigInteger;
use function hex2bin;
use function in_array;
use InvalidArgumentException;
use function is_bool;
use function is_int;
use function is_string;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use function str_pad;
use const STR_PAD_LEFT;
use function strlen;

/**
 * An EC2 key (RFC 9053, section 7.1.1): a point on one of the double-coordinate curves of the COSE Elliptic Curves
 * registry, with its private scalar when the key is private.
 *
 * The "y" parameter is accepted in both forms table 19 of RFC 9053, section 7.1 allows: the coordinate as a byte
 * string, or the boolean "sign bit" of the compressed point encoding of SEC 1, section 2.3.3 - true when y is odd,
 * false when it is even. A compressed key is decompressed at construction time and y() returns the coordinate
 * whichever form the key carries; getData() keeps the boolean, so that the map round-trips unchanged.
 *
 * @final
 * @see \Cose\Tests\Key\Ec2KeyTest
 * @see \Cose\Tests\Key\Ec2KeyCompressedPointTest
 */
class Ec2Key extends Key
{
    final public const CURVE_P256 = 1;

    final public const CURVE_P256K = 8;

    final public const CURVE_P384 = 2;

    final public const CURVE_P521 = 3;

    final public const CURVE_NAME_P256 = 'P-256';

    /**
     * The registered name of COSE curve 8 (RFC 8812, sections 3.1 and 4.2) and the name OpenSSL gives it.
     */
    final public const CURVE_NAME_SECP256K1 = 'secp256k1';

    /**
     * @deprecated The draft-era spelling of curve 8, from draft-ietf-cose-webauthn-algorithms-00, renamed to
     * "secp256k1" before -01 and never registered. Still accepted; use CURVE_NAME_SECP256K1 instead.
     */
    final public const CURVE_NAME_P256K = 'P-256K';

    final public const CURVE_NAME_P384 = 'P-384';

    final public const CURVE_NAME_P521 = 'P-521';

    final public const CURVE_BP256 = 256;

    final public const CURVE_BP320 = 257;

    final public const CURVE_BP384 = 258;

    final public const CURVE_BP512 = 259;

    final public const CURVE_NAME_BP256 = 'brainpoolP256r1';

    final public const CURVE_NAME_BP320 = 'brainpoolP320r1';

    final public const CURVE_NAME_BP384 = 'brainpoolP384r1';

    final public const CURVE_NAME_BP512 = 'brainpoolP512r1';

    final public const DATA_CURVE = -1;

    final public const DATA_X = -2;

    final public const DATA_Y = -3;

    final public const DATA_D = -4;

    private const SUPPORTED_CURVES_INT = [
        self::CURVE_P256,
        self::CURVE_P256K,
        self::CURVE_P384,
        self::CURVE_P521,
        self::CURVE_BP256,
        self::CURVE_BP320,
        self::CURVE_BP384,
        self::CURVE_BP512,
    ];

    /**
     * RFC 9053, section 7.1, table 19 types "crv" as "int / tstr": a curve may be named instead of numbered. Each of
     * these names maps to the identifier of the "COSE Elliptic Curves" registry that curveId() exposes.
     *
     * @var array<string, int>
     */
    private const CURVE_NAME_TO_ID = [
        self::CURVE_NAME_P256 => self::CURVE_P256,
        self::CURVE_NAME_SECP256K1 => self::CURVE_P256K,
        // The deprecated alias is listed on purpose: it is what keeps the draft-era name working.
        // @phpstan-ignore classConstant.deprecated
        self::CURVE_NAME_P256K => self::CURVE_P256K,
        self::CURVE_NAME_P384 => self::CURVE_P384,
        self::CURVE_NAME_P521 => self::CURVE_P521,
        self::CURVE_NAME_BP256 => self::CURVE_BP256,
        self::CURVE_NAME_BP320 => self::CURVE_BP320,
        self::CURVE_NAME_BP384 => self::CURVE_BP384,
        self::CURVE_NAME_BP512 => self::CURVE_BP512,
    ];

    private const NAMED_CURVE_OID = [
        self::CURVE_P256 => '1.2.840.10045.3.1.7',
        // NIST P-256 / secp256r1
        self::CURVE_P256K => '1.3.132.0.10',
        // SECG secp256k1 (RFC 8812)
        self::CURVE_P384 => '1.3.132.0.34',
        // NIST P-384 / secp384r1
        self::CURVE_P521 => '1.3.132.0.35',
        // NIST P-521 / secp521r1
        self::CURVE_BP256 => '1.3.36.3.3.2.8.1.1.7',
        // brainpoolP256r1
        self::CURVE_BP320 => '1.3.36.3.3.2.8.1.1.9',
        // brainpoolP320r1
        self::CURVE_BP384 => '1.3.36.3.3.2.8.1.1.11',
        // brainpoolP384r1
        self::CURVE_BP512 => '1.3.36.3.3.2.8.1.1.13',
        // brainpoolP512r1
    ];

    private const CURVE_KEY_LENGTH = [
        self::CURVE_P256 => 32,
        self::CURVE_P256K => 32,
        self::CURVE_P384 => 48,
        self::CURVE_P521 => 66,
        self::CURVE_BP256 => 32,
        self::CURVE_BP320 => 40,
        self::CURVE_BP384 => 48,
        self::CURVE_BP512 => 64,
    ];

    /**
     * The field prime p and the coefficients a and b of the short Weierstrass equation y^2 = x^3 + a*x + b of each
     * curve, as hexadecimal, from SEC 2 section 2.4 (secp256k1) and 2.7 (P-256 is secp256r1), FIPS 186-4 appendix
     * D.1.2 (P-384, P-521) and RFC 5639 section 3 (the Brainpool curves). They are what decompressing a point takes.
     *
     * Every one of these primes is congruent to 3 modulo 4, which is what makes the square root of decompressY()
     * a single modular exponentiation; a curve added here must satisfy that too, or bring its own root.
     *
     * @var array<int, array{string, string, string}>
     */
    private const CURVE_PARAMETERS = [
        self::CURVE_P256 => [
            'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
            'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
            '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
        ],
        self::CURVE_P256K => [
            'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
            '00',
            '07',
        ],
        self::CURVE_P384 => [
            'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
            'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
            'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
        ],
        self::CURVE_P521 => [
            '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc',
            '0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
        ],
        self::CURVE_BP256 => [
            'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
            '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
            '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
        ],
        self::CURVE_BP320 => [
            'd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27',
            '3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4',
            '520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6',
        ],
        self::CURVE_BP384 => [
            '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
            '7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826',
            '04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11',
        ],
        self::CURVE_BP512 => [
            'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3',
            '7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca',
            '3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723',
        ],
    ];

    /**
     * The y-coordinate as a byte string: the one the key carries, or the one decompressed from its sign bit.
     */
    private readonly string $y;

    /**
     * @param array<int|string, mixed> $data
     */
    public function __construct(array $data)
    {
        // Everything below is read from attacker-supplied CBOR: each entry is checked to be present and of the
        // expected PHP type before it is used, so that a malformed key always leaves through the
        // InvalidArgumentException this library documents rather than through a warning, a TypeError or an Error.
        $data = self::normalizeIntegerEntries($data, self::DATA_CURVE, self::TYPE);
        parent::__construct($data);
        if (! $this->typeIs(self::TYPE_EC2)) {
            throw new InvalidArgumentException('Invalid EC2 key. The key type does not correspond to an EC2 key');
        }
        // RFC 9053 section 7.1.1: "For public keys, it is REQUIRED that 'crv', 'x', and 'y' be present".
        if (! isset($data[self::DATA_CURVE], $data[self::DATA_X], $data[self::DATA_Y])) {
            throw new InvalidArgumentException('Invalid EC2 key. The curve or the "x/y" coordinates are missing');
        }
        // The curve is checked first: the coordinate lengths below are read from a table indexed by the curve.
        $curveId = self::toCurveId($data[self::DATA_CURVE]);
        if ($curveId === null) {
            throw new InvalidArgumentException('The curve is not supported');
        }
        $length = self::CURVE_KEY_LENGTH[$curveId];
        // RFC 9053 section 7.1, table 19 types "x" and "d" as byte strings, and "y" as a byte string or a boolean.
        if (! is_string($data[self::DATA_X])) {
            throw new InvalidArgumentException('Invalid type for x coordinate');
        }
        if (strlen($data[self::DATA_X]) !== $length) {
            throw new InvalidArgumentException('Invalid length for x coordinate');
        }
        if (is_bool($data[self::DATA_Y])) {
            $this->y = self::decompressY($curveId, $data[self::DATA_X], $data[self::DATA_Y]);
        } elseif (! is_string($data[self::DATA_Y])) {
            throw new InvalidArgumentException('Invalid type for y coordinate');
        } elseif (strlen($data[self::DATA_Y]) !== $length) {
            throw new InvalidArgumentException('Invalid length for y coordinate');
        } else {
            $this->y = $data[self::DATA_Y];
        }
        // RFC 5915 section 3: the private key is "an octet string of length ceiling (log2(n)/8)".
        if (array_key_exists(self::DATA_D, $data)
            && (! is_string($data[self::DATA_D]) || strlen($data[self::DATA_D]) !== $length)) {
            throw new InvalidArgumentException('Invalid length for d');
        }
    }

    /**
     * @param array<int|string, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    public function toPublic(): self
    {
        $data = $this->getData();
        unset($data[self::DATA_D]);

        return new self($data);
    }

    public function x(): string
    {
        return $this->get(self::DATA_X);
    }

    /**
     * The y-coordinate, as a byte string of the length of the curve whether the key carries it as such or as the
     * sign bit of a compressed point.
     */
    public function y(): string
    {
        return $this->y;
    }

    public function isPrivate(): bool
    {
        return array_key_exists(self::DATA_D, $this->getData());
    }

    public function d(): string
    {
        if (! $this->isPrivate()) {
            throw new InvalidArgumentException('The key is not private.');
        }
        return $this->get(self::DATA_D);
    }

    /**
     * The curve as the key carries it, which RFC 9053 section 7.1 allows to be either the identifier of the "COSE
     * Elliptic Curves" registry or a name. Use curveId() to get the identifier whatever form was supplied.
     */
    public function curve(): int|string
    {
        return $this->get(self::DATA_CURVE);
    }

    /**
     * The value of the curve in the IANA "COSE Elliptic Curves" registry, whichever of the two forms the key uses.
     */
    public function curveId(): int
    {
        $curve = $this->curve();

        return is_int($curve) ? $curve : self::CURVE_NAME_TO_ID[$curve];
    }

    public function asPEM(): string
    {
        if ($this->isPrivate()) {
            $der = Sequence::create(
                Integer::create(1),
                OctetString::create($this->d()),
                ExplicitlyTaggedType::create(0, ObjectIdentifier::create($this->getCurveOid())),
                ExplicitlyTaggedType::create(1, BitString::create($this->getUncompressedCoordinates())),
            );

            return $this->pem('EC PRIVATE KEY', $der->toDER());
        }

        $der = Sequence::create(
            Sequence::create(
                ObjectIdentifier::create('1.2.840.10045.2.1'),
                ObjectIdentifier::create($this->getCurveOid())
            ),
            BitString::create($this->getUncompressedCoordinates())
        );

        return $this->pem('PUBLIC KEY', $der->toDER());
    }

    public function getUncompressedCoordinates(): string
    {
        return "\x04" . $this->x() . $this->y();
    }

    /**
     * Whether the (x, y) the key carries is a point of its curve: both coordinates are field elements, smaller than
     * p, and satisfy y^2 = x^3 + a*x + b modulo p.
     *
     * The constructor does not check it, so that a key built from arbitrary bytes keeps loading as it always has
     * and so that the check stays cheap to skip where the coordinates are never used in arithmetic. Anything that
     * multiplies the point by a secret scalar has to check first: RFC 9053 section 6.3.1.1 names it as the point
     * validation ECDH needs, and feeding an off-curve point to a scalar multiplication is the invalid-curve attack
     * of Biehl, Meyer and Muller, which leaks the private key a few bits at a time. {@see assertOnCurve()} is the
     * throwing form, which {@see \Cose\Algorithm\KeyManagement\EllipticCurveDiffieHellman} calls before any
     * scalar multiplication.
     *
     * A compressed key is on the curve by construction: decompressY() found y as a root of the curve equation.
     */
    public function isOnCurve(): bool
    {
        [$pHex, $aHex, $bHex] = self::CURVE_PARAMETERS[$this->curveId()];
        $p = BigInteger::createFromBinaryString((string) hex2bin($pHex));
        $x = BigInteger::createFromBinaryString($this->x());
        $y = BigInteger::createFromBinaryString($this->y());
        if ($x->compare($p) >= 0 || $y->compare($p) >= 0) {
            return false;
        }
        $a = BigInteger::createFromBinaryString((string) hex2bin($aHex));
        $b = BigInteger::createFromBinaryString((string) hex2bin($bHex));
        $two = BigInteger::createFromDecimal(2);
        $left = $y->modPow($two, $p);
        $right = $x->modPow(BigInteger::createFromDecimal(3), $p)
            ->add($a->multiply($x))
            ->add($b)
            ->mod($p);

        return $left->compare($right) === 0;
    }

    /**
     * @throws InvalidArgumentException when the (x, y) the key carries is not a point of its curve
     *
     * @see isOnCurve()
     */
    public function assertOnCurve(): void
    {
        if (! $this->isOnCurve()) {
            throw new InvalidArgumentException(
                'Invalid EC2 key. The x and y coordinates do not form a point on the curve (RFC 9053 section 6.3.1.1).'
            );
        }
    }

    private function getCurveOid(): string
    {
        return self::NAMED_CURVE_OID[$this->curveId()];
    }

    /**
     * The y-coordinate of the point of the curve whose x-coordinate and sign bit are given: the Octet-String-to-
     * Elliptic-Curve-Point conversion of SEC 1, section 2.3.4, steps 2.4.1 to 2.4.4.
     *
     * The candidate is the square root of x^3 + a*x + b modulo p, computed as its ((p + 1) / 4)-th power - a formula
     * that holds because every prime of CURVE_PARAMETERS is congruent to 3 modulo 4 - and its square is compared
     * with what it should be the root of: an x that lies on no point of the curve has no root, the power is then
     * some other value, and the key is rejected instead of being loaded with a coordinate that satisfies nothing.
     * The two roots differ in parity, one being p minus the other, so the sign bit picks one of them.
     *
     * @param bool $odd the sign bit of the compressed encoding: true when y is odd, false when it is even
     *
     * @throws InvalidArgumentException when no point of the curve has that x-coordinate and that sign bit
     */
    private static function decompressY(int $curveId, string $x, bool $odd): string
    {
        [$pHex, $aHex, $bHex] = self::CURVE_PARAMETERS[$curveId];
        $p = BigInteger::createFromBinaryString((string) hex2bin($pHex));
        $a = BigInteger::createFromBinaryString((string) hex2bin($aHex));
        $b = BigInteger::createFromBinaryString((string) hex2bin($bHex));
        $one = BigInteger::createFromDecimal(1);
        $xValue = BigInteger::createFromBinaryString($x);
        // SEC 1, section 2.3.4, step 2.2: x is an element of the field, so it is smaller than p.
        if ($xValue->compare($p) >= 0) {
            throw new InvalidArgumentException('Invalid EC2 key. The x coordinate is not a field element of the curve');
        }
        // Step 2.4.1: alpha = x^3 + a*x + b mod p.
        $alpha = $xValue->modPow(BigInteger::createFromDecimal(3), $p)
            ->add($a->multiply($xValue))
            ->add($b)
            ->mod($p);
        // Step 2.4.2: beta, a square root of alpha, which exists only if alpha is a quadratic residue.
        $beta = $alpha->modPow($p->add($one)->shiftRight(2), $p);
        if ($beta->modPow(BigInteger::createFromDecimal(2), $p)->compare($alpha) !== 0) {
            throw new InvalidArgumentException('Invalid EC2 key. The compressed point is not on the curve');
        }
        // Steps 2.4.3 and 2.4.4: y is beta when the parities agree, p - beta otherwise - p being odd, the two roots
        // are of opposite parity. Except when beta is 0, whose only other root is 0 itself: a sign bit set for such
        // a point names no point at all.
        if ($beta->isOdd() !== $odd) {
            if ($beta->isZero()) {
                throw new InvalidArgumentException('Invalid EC2 key. The compressed point is not on the curve');
            }
            $beta = $p->subtract($beta);
        }

        // Leading zero octets are part of the coordinate (RFC 9053, section 7.1.1) and toBytes() strips them.
        return str_pad($beta->toBytes(), self::CURVE_KEY_LENGTH[$curveId], "\0", STR_PAD_LEFT);
    }

    /**
     * The registry value of a supported curve, or null when the value denotes no curve this class supports.
     */
    private static function toCurveId(mixed $curve): ?int
    {
        if (is_int($curve)) {
            return in_array($curve, self::SUPPORTED_CURVES_INT, true) ? $curve : null;
        }

        return is_string($curve) ? (self::CURVE_NAME_TO_ID[$curve] ?? null) : null;
    }
}
