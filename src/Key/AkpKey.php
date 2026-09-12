<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_key_exists;
use Cose\Algorithms;
use InvalidArgumentException;
use function is_string;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use function sprintf;
use function strlen;

/**
 * The Algorithm Key Pair (AKP) key type of RFC 9964, section 3: "kty" 7, a public byte string "pub" (-1) and a
 * private byte string "priv" (-2) whose format the "alg" of the key decides.
 *
 * The type itself says nothing about the algorithm, which is why section 3 makes "alg" REQUIRED on every AKP key:
 * without it the key cannot be used, nor its thumbprint computed (section 6 puts "alg" among the required members).
 * A key that carries no "alg" is still built, so that a map read from the wire can be inspected, but every consumer
 * of the key - the signature algorithms, {@see Thumbprint}, asPEM() - refuses it.
 *
 * For the ML-DSA algorithms (-48, -49, -50), the only ones registered for the type so far, sections 4 and 5 fix the
 * sizes: "priv" is the 32-byte seed of FIPS 204 and nothing else - the expanded private key is deliberately not a
 * representation this RFC allows - and "pub" is the encoded public key of FIPS 204 section 7.2, 1312, 1952 or 2592
 * bytes. Both are checked here, when the key is built, so that a key of the wrong shape is rejected before any
 * cryptographic operation is attempted with it (section 7.3: "the seed length check MUST be performed").
 *
 * @see https://www.rfc-editor.org/rfc/rfc9964.html#section-3
 * @see \Cose\Tests\Key\AkpKeyTest
 */
final class AkpKey extends Key
{
    public const DATA_PUB = -1;

    public const DATA_PRIV = -2;

    /**
     * RFC 9964, section 4: "the priv parameter MUST be the seed and MUST have a length of 32 bytes."
     */
    public const ML_DSA_SEED_LENGTH = 32;

    /**
     * The size of the encoded public key of each ML-DSA parameter set, FIPS 204 table 2, as RFC 9964 section 5
     * repeats it.
     *
     * @var array<int, int>
     */
    private const ML_DSA_PUBLIC_KEY_LENGTH = [
        Algorithms::COSE_ALGORITHM_ML_DSA_44 => 1312,
        Algorithms::COSE_ALGORITHM_ML_DSA_65 => 1952,
        Algorithms::COSE_ALGORITHM_ML_DSA_87 => 2592,
    ];

    /**
     * id-ml-dsa-44, id-ml-dsa-65 and id-ml-dsa-87 (RFC 9881, section 3): the algorithm identifiers a
     * SubjectPublicKeyInfo or a PrivateKeyInfo names an ML-DSA key with. They take no parameters.
     *
     * @var array<int, string>
     */
    private const ML_DSA_OID = [
        Algorithms::COSE_ALGORITHM_ML_DSA_44 => '2.16.840.1.101.3.4.3.17',
        Algorithms::COSE_ALGORITHM_ML_DSA_65 => '2.16.840.1.101.3.4.3.18',
        Algorithms::COSE_ALGORITHM_ML_DSA_87 => '2.16.840.1.101.3.4.3.19',
    ];

    private readonly string $pub;

    private readonly ?string $priv;

    /**
     * @param array<int|string, mixed> $data
     */
    public function __construct(array $data)
    {
        // Everything below is read from attacker-supplied CBOR: each entry is checked to be present and of the
        // expected PHP type before it is used, so that a malformed key always leaves through the
        // InvalidArgumentException this library documents rather than through a warning, a TypeError or an Error.
        parent::__construct($data);
        if (! $this->typeIs(self::TYPE_AKP)) {
            throw new InvalidArgumentException('Invalid AKP key. The key type does not correspond to an AKP key');
        }
        // RFC 9964 section 3: "The pub parameter contains public information and is REQUIRED."
        if (! array_key_exists(self::DATA_PUB, $data)) {
            throw new InvalidArgumentException('Invalid AKP key. The "pub" parameter is missing');
        }
        $pub = $data[self::DATA_PUB];
        if (! is_string($pub) || $pub === '') {
            throw new InvalidArgumentException('Invalid AKP key. The "pub" parameter must be a non-empty byte string');
        }
        $priv = $data[self::DATA_PRIV] ?? null;
        if (array_key_exists(self::DATA_PRIV, $data) && (! is_string($priv) || $priv === '')) {
            throw new InvalidArgumentException('Invalid AKP key. The "priv" parameter must be a non-empty byte string');
        }
        $this->pub = $pub;
        $this->priv = is_string($priv) ? $priv : null;

        if (! $this->has(self::ALG)) {
            return;
        }
        // A non-integer "alg" is rejected here rather than by the first consumer: RFC 9964 section 3 makes the
        // parameter required, so a value that names no algorithm leaves the key unusable.
        $algorithm = $this->alg();
        if (! array_key_exists($algorithm, self::ML_DSA_PUBLIC_KEY_LENGTH)) {
            return;
        }
        // RFC 9964 sections 4, 5 and 7.3: the sizes of an ML-DSA key are fixed by its parameter set.
        if (strlen($pub) !== self::ML_DSA_PUBLIC_KEY_LENGTH[$algorithm]) {
            throw new InvalidArgumentException(sprintf(
                'Invalid AKP key. The "pub" parameter of an ML-DSA key with the algorithm %d must be %d bytes long',
                $algorithm,
                self::ML_DSA_PUBLIC_KEY_LENGTH[$algorithm]
            ));
        }
        if ($this->priv !== null && strlen($this->priv) !== self::ML_DSA_SEED_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'Invalid AKP key. The "priv" parameter of an ML-DSA key must be the %d-byte seed',
                self::ML_DSA_SEED_LENGTH
            ));
        }
    }

    /**
     * @param array<int|string, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    /**
     * The public information of the key, RFC 9964 section 3, label -1. For ML-DSA, the encoded public key of
     * FIPS 204 section 7.2.
     */
    public function pub(): string
    {
        return $this->pub;
    }

    public function isPrivate(): bool
    {
        return $this->priv !== null;
    }

    /**
     * The private information of the key, RFC 9964 section 3, label -2. For ML-DSA, the 32-byte seed of section 4.
     *
     * @throws InvalidArgumentException when the key is public
     */
    public function priv(): string
    {
        return $this->priv ?? throw new InvalidArgumentException('The key is not private.');
    }

    public function toPublic(): self
    {
        $data = $this->getData();
        unset($data[self::DATA_PRIV]);

        return new self($data);
    }

    /**
     * Returns the key as a PEM encoded structure of RFC 9881: a PrivateKeyInfo holding the seed - the "seed [0]"
     * choice of the ML-DSA-PrivateKey, section 6 - for a private key, a SubjectPublicKeyInfo for a public one.
     *
     * OpenSSL 3.5 loads both: it expands the seed into the private key and derives the public key on its own.
     *
     * @throws InvalidArgumentException when the key carries no "alg", or an "alg" that is not one of the ML-DSA
     *                                  algorithms, whose PEM forms are the only ones this library knows
     */
    public function asPEM(): string
    {
        if (! $this->has(self::ALG)) {
            throw new InvalidArgumentException(
                'The AKP key carries no "alg", which RFC 9964 section 3 requires: nothing says what its "pub" and "priv" hold'
            );
        }
        $algorithm = $this->alg();
        $oid = self::ML_DSA_OID[$algorithm] ?? throw new InvalidArgumentException(sprintf(
            'The AKP key names the algorithm %d, which is none of the ML-DSA algorithms: this library knows no PEM form for it',
            $algorithm
        ));
        $algorithmIdentifier = Sequence::create(ObjectIdentifier::create($oid));

        if ($this->isPrivate()) {
            $der = Sequence::create(
                Integer::create(0),
                $algorithmIdentifier,
                OctetString::create(ImplicitlyTaggedType::create(0, OctetString::create($this->priv()))->toDER())
            );

            return $this->pem('PRIVATE KEY', $der->toDER());
        }

        $der = Sequence::create($algorithmIdentifier, BitString::create($this->pub()));

        return $this->pem('PUBLIC KEY', $der->toDER());
    }
}
