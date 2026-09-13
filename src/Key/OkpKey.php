<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_key_exists;
use function extension_loaded;
use function in_array;
use InvalidArgumentException;
use function is_int;
use function is_string;
use RuntimeException;
use function sodium_crypto_scalarmult_base;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_seed_keypair;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use function strlen;

/**
 * @final
 * @see \Cose\Tests\Key\OkpKeyTest
 */
class OkpKey extends Key
{
    final public const CURVE_X25519 = 4;

    final public const CURVE_X448 = 5;

    final public const CURVE_ED25519 = 6;

    final public const CURVE_ED448 = 7;

    final public const CURVE_NAME_X25519 = 'X25519';

    final public const CURVE_NAME_X448 = 'X448';

    final public const CURVE_NAME_ED25519 = 'Ed25519';

    final public const CURVE_NAME_ED448 = 'Ed448';

    final public const DATA_CURVE = -1;

    final public const DATA_X = -2;

    final public const DATA_D = -4;

    private const SUPPORTED_CURVES_INT = [
        self::CURVE_X25519,
        self::CURVE_X448,
        self::CURVE_ED25519,
        self::CURVE_ED448,
    ];

    /**
     * RFC 9053, section 7.2, table 20 types "crv" as "int / tstr": a curve may be named instead of numbered. Each of
     * these names maps to the identifier of the "COSE Elliptic Curves" registry that curveId() exposes.
     *
     * @var array<string, int>
     */
    private const CURVE_NAME_TO_ID = [
        self::CURVE_NAME_X25519 => self::CURVE_X25519,
        self::CURVE_NAME_X448 => self::CURVE_X448,
        self::CURVE_NAME_ED25519 => self::CURVE_ED25519,
        self::CURVE_NAME_ED448 => self::CURVE_ED448,
    ];

    /**
     * RFC 8032 section 5.1.5 / 5.2.5 for the Edwards curves and RFC 7748 section 5 for the Montgomery ones: the
     * public key and the private scalar are byte strings of exactly this length.
     */
    private const CURVE_KEY_LENGTH = [
        self::CURVE_X25519 => 32,
        self::CURVE_X448 => 56,
        self::CURVE_ED25519 => 32,
        self::CURVE_ED448 => 57,
    ];

    /**
     * The curves whose public key the Sodium extension can recompute from the private one. Ed448 and X448 have no
     * such primitive in PHP, so a key on those curves still has to carry its "x".
     */
    private const DERIVABLE_CURVES = [
        self::CURVE_X25519,
        self::CURVE_ED25519,
    ];

    private const CURVE_OID = [
        self::CURVE_X25519 => '1.3.101.110',
        self::CURVE_X448 => '1.3.101.111',
        self::CURVE_ED25519 => '1.3.101.112',
        self::CURVE_ED448 => '1.3.101.113',
    ];

    /**
     * The curve as the key carries it: the registry value, or one of the names of CURVE_NAME_TO_ID.
     */
    private readonly int|string $curve;

    /**
     * The registry value of the curve, whichever form the key carries it under.
     */
    private readonly int $curveId;

    /**
     * The public key as the key carries it, or null when it has to be recomputed from the private one.
     *
     * @var non-empty-string|null
     */
    private readonly ?string $x;

    /**
     * The private key, or null when the key is public.
     *
     * @var non-empty-string|null
     */
    private readonly ?string $d;

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
        if (! $this->typeIs(self::TYPE_OKP)) {
            throw new InvalidArgumentException('Invalid OKP key. The key type does not correspond to an OKP key');
        }
        // RFC 9053 section 7.2: "d" is the authoritative private key material and "x" is only RECOMMENDED for a
        // private key, "it can be recomputed from the required elements". A private key carrying "crv" and "d"
        // alone is therefore valid, and is the safest way to build a signing key: nothing can hand over an "x"
        // inconsistent with the seed.
        if (! isset($data[self::DATA_CURVE]) || (! isset($data[self::DATA_X]) && ! isset($data[self::DATA_D]))) {
            throw new InvalidArgumentException('Invalid OKP key. The curve or the "x" coordinate is missing');
        }
        // The curve is checked first: the key lengths below are read from a table indexed by the curve.
        $curve = $data[self::DATA_CURVE];
        if (! is_int($curve) && ! is_string($curve)) {
            throw new InvalidArgumentException('The curve is not supported');
        }
        $curveId = self::toCurveId($curve);
        if ($curveId === null) {
            throw new InvalidArgumentException('The curve is not supported');
        }
        // RFC 8032 section 5.1.5 / 5.2.5 and RFC 7748 section 5: both halves are byte strings of this exact length.
        $length = self::CURVE_KEY_LENGTH[$curveId];
        $x = null;
        if (array_key_exists(self::DATA_X, $data)) {
            $x = $data[self::DATA_X];
            if (! is_string($x) || strlen($x) !== $length) {
                throw new InvalidArgumentException('Invalid length for x coordinate');
            }
        }
        $d = null;
        if (array_key_exists(self::DATA_D, $data)) {
            $d = $data[self::DATA_D];
            if (! is_string($d) || strlen($d) !== $length) {
                throw new InvalidArgumentException('Invalid length for d');
            }
        }
        $this->curve = $curve;
        $this->curveId = $curveId;
        $this->x = $x;
        $this->d = $d;
    }

    /**
     * @param array<int|string, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    /**
     * @return non-empty-string
     */
    public function x(): string
    {
        return $this->x ?? $this->derivePublicKey();
    }

    public function isPrivate(): bool
    {
        return $this->d !== null;
    }

    /**
     * @return non-empty-string
     */
    public function d(): string
    {
        return $this->d ?? throw new InvalidArgumentException('The key is not private.');
    }

    /**
     * The curve as the key carries it, which RFC 9053 section 7.2 allows to be either the identifier of the "COSE
     * Elliptic Curves" registry or a name. Use curveId() to get the identifier whatever form was supplied.
     */
    public function curve(): int|string
    {
        return $this->curve;
    }

    /**
     * The value of the curve in the IANA "COSE Elliptic Curves" registry, whichever of the two forms the key uses.
     */
    public function curveId(): int
    {
        return $this->curveId;
    }

    public function toPublic(): self
    {
        $data = $this->getData();
        $data[self::DATA_X] = $this->x();
        unset($data[self::DATA_D]);

        return new self($data);
    }

    /**
     * Recomputes the public key from the private one, as RFC 9053 section 7.2 allows when "x" was omitted.
     *
     * @return non-empty-string
     */
    private function derivePublicKey(): string
    {
        $curve = $this->curveId();
        if (! in_array($curve, self::DERIVABLE_CURVES, true)) {
            throw new InvalidArgumentException(
                'The "x" coordinate is missing and cannot be computed from "d" for this curve'
            );
        }
        if (! extension_loaded('sodium')) {
            throw new RuntimeException(
                'The "x" coordinate is missing and computing it from "d" requires the Sodium extension, which is not loaded.'
            );
        }
        $d = $this->d();
        // Both primitives return a public key of exactly 32 bytes (SODIUM_CRYPTO_SCALARMULT_BYTES and
        // SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES), which their PHP signatures only declare as a string.
        /** @var non-empty-string $x */
        $x = $curve === self::CURVE_X25519
            ? sodium_crypto_scalarmult_base($d)
            : sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($d));

        return $x;
    }

    /**
     * The registry value of a supported curve, or null when the value denotes no curve this class supports.
     */
    private static function toCurveId(int|string $curve): ?int
    {
        if (is_int($curve)) {
            return in_array($curve, self::SUPPORTED_CURVES_INT, true) ? $curve : null;
        }

        return self::CURVE_NAME_TO_ID[$curve] ?? null;
    }

    /**
     * Returns the key as a PEM encoded RFC 8410 OneAsymmetricKey (private) or SubjectPublicKeyInfo (public) structure.
     */
    public function asPEM(): string
    {
        $oid = ObjectIdentifier::create(self::CURVE_OID[$this->curveId()]);

        if ($this->isPrivate()) {
            $der = Sequence::create(
                Integer::create(0),
                Sequence::create($oid),
                OctetString::create(OctetString::create($this->d())->toDER())
            );

            return $this->pem('PRIVATE KEY', $der->toDER());
        }

        $der = Sequence::create(Sequence::create($oid), BitString::create($this->x()));

        return $this->pem('PUBLIC KEY', $der->toDER());
    }
}
