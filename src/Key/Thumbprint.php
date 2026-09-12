<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_keys;
use function base64_encode;
use function chr;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use function count;
use function hash_equals;
use function implode;
use InvalidArgumentException;
use function is_int;
use function pack;
use function rtrim;
use function sprintf;
use function strcmp;
use function strlen;
use function strtr;
use function uksort;

/**
 * The COSE Key Thumbprint of RFC 9679: a digest of the key that depends on nothing but the key.
 *
 * The digest is computed over a COSE_Key built from scratch - not over the map the key was decoded from - that holds
 * the parameters section 4 of the RFC lists as required for the key type, and nothing else, in the deterministic
 * encoding of RFC 8949, section 4.2.1. "kid", "alg", "key_ops", the private parts, the spelling of "kty" and "crv"
 * (integer or name), the order of the members and the compressed or uncompressed form of an EC2 point therefore
 * make no difference: two representations of one key have one thumbprint, and a private key has the thumbprint of
 * its public half. That is what makes the value usable as a "kid", as the "ckt" confirmation method of a CWT
 * (section 5.6) and as the URI of section 5.7. The one exception is "alg" on an AKP key, which RFC 9964 section 6
 * puts among the required members because the type alone does not say what the key is.
 *
 * SHA-256, the hash section 3 requires every implementation to support, is the default; any {@see Hash} may be
 * given instead. The parameter is typed Hash rather than FilterOnlyHash on purpose: a thumbprint is an identifier
 * that stands for the key, which is the use RFC 9054 reserves the general-purpose hashes for.
 *
 * Section 7 of the RFC on symmetric keys, which the thumbprint is computed over the secret of: "Thumbprints MUST
 * NOT be used with passwords or other low-entropy secrets", and "if a developer is unable to determine whether all
 * symmetric keys used in an application have sufficient entropy, then thumbprints of symmetric keys MUST NOT be
 * used". A thumbprint of a symmetric key is a public identifier of a secret value; given enough entropy - a random
 * key of 128 bits or more - it reveals nothing, and given too little it is a hash of the secret to brute-force.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9679.html
 * @see \Cose\Tests\Key\ThumbprintTest
 */
final class Thumbprint
{
    /**
     * The prefix of a COSE Key Thumbprint URI (RFC 9679, section 5.7).
     */
    public const URI_PREFIX = 'urn:ietf:params:oauth:ckt';

    /**
     * The name each hash algorithm this class can spell a URI with has in the IANA "Named Information Hash
     * Algorithm Registry", which section 5.7 of RFC 9679 makes the only source of the hash segment of the URI.
     * SHA-512/256, SHAKE128 and SHAKE256 are absent from that registry, so a thumbprint made with one of them has
     * no URI.
     *
     * @see https://www.iana.org/assignments/named-information/named-information.xhtml
     * @var array<int, string>
     */
    private const URI_HASH_NAMES = [
        SHA256::ID => 'sha-256',
        SHA384::ID => 'sha-384',
        SHA512::ID => 'sha-512',
    ];

    private function __construct(
        private readonly string $value,
        private readonly Hash $hash
    ) {
    }

    /**
     * The thumbprint of the key with the given hash, SHA-256 by default.
     *
     * @throws InvalidArgumentException when the key is of a type RFC 9679 defines no required parameters for
     */
    public static function of(Key $key, Hash $hash = new SHA256()): self
    {
        return new self($hash->hash(self::canonicalForm($key)), $hash);
    }

    /**
     * The bytes the thumbprint is a digest of: the COSE_Key of the required parameters of the key type (RFC 9679,
     * section 4), in the deterministic encoding of RFC 8949, section 4.2.1 - integers and lengths in their shortest
     * form, the map keys sorted in the bytewise order of their encodings.
     *
     * "kty" is always the integer of the IANA "COSE Key Types" registry and "crv" the integer of the "COSE Elliptic
     * Curves" registry, whatever form the key names them under; the "y" of an EC2 key is always the coordinate,
     * uncompressed as section 4.2 of RFC 9679 demands; the "x" of an OKP private key that carries none is the
     * recomputed public key. An AKP key (RFC 9964, section 6) contributes "kty", "alg" and "pub".
     *
     * @throws InvalidArgumentException when the key is of a type RFC 9679 defines no required parameters for, or an
     *                                  AKP key without the "alg" its thumbprint is computed over
     */
    public static function canonicalForm(Key $key): string
    {
        $members = match (true) {
            $key instanceof OkpKey => [
                Key::TYPE => Key::TYPE_OKP,
                OkpKey::DATA_CURVE => $key->curveId(),
                OkpKey::DATA_X => $key->x(),
            ],
            $key instanceof Ec2Key => [
                Key::TYPE => Key::TYPE_EC2,
                Ec2Key::DATA_CURVE => $key->curveId(),
                Ec2Key::DATA_X => $key->x(),
                Ec2Key::DATA_Y => $key->y(),
            ],
            $key instanceof RsaKey => [
                Key::TYPE => Key::TYPE_RSA,
                RsaKey::DATA_N => $key->n(),
                RsaKey::DATA_E => $key->e(),
            ],
            $key instanceof SymmetricKey => [
                Key::TYPE => Key::TYPE_OCT,
                SymmetricKey::DATA_K => $key->k(),
            ],
            $key instanceof AkpKey => self::akpMembers($key),
            default => throw new InvalidArgumentException(sprintf(
                'No COSE Key Thumbprint is defined for a key of type "%s"',
                $key->type()
            )),
        };

        return self::encodeMap($members);
    }

    /**
     * RFC 9964, section 6: the required members of an AKP key are "kty", "alg" and "pub" - "alg", which no other key
     * type includes, because the AKP type says nothing about the algorithm and the same "pub" bytes under another
     * algorithm would be another key.
     *
     * @return array<int, int|string>
     */
    private static function akpMembers(AkpKey $key): array
    {
        if (! $key->has(Key::ALG)) {
            throw new InvalidArgumentException(
                'No COSE Key Thumbprint can be computed for an AKP key without "alg": RFC 9964 section 6 makes it a required member'
            );
        }

        return [
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => $key->alg(),
            AkpKey::DATA_PUB => $key->pub(),
        ];
    }

    /**
     * The digest, as raw bytes: the value of a "ckt" confirmation method member (RFC 9679, section 5.6).
     */
    public function value(): string
    {
        return $this->value;
    }

    public function hash(): Hash
    {
        return $this->hash;
    }

    /**
     * Whether the thumbprint is the given one, compared in constant time.
     *
     * @param string $thumbprint the raw bytes of the other thumbprint, as value() returns them
     */
    public function equals(string $thumbprint): bool
    {
        return hash_equals($this->value, $thumbprint);
    }

    /**
     * The COSE Key Thumbprint URI of RFC 9679, section 5.7: "urn:ietf:params:oauth:ckt:sha-256:" followed by the
     * digest in unpadded base64url.
     *
     * @throws InvalidArgumentException when the hash algorithm has no name in the IANA "Named Information Hash
     *                                  Algorithm Registry", which the RFC allows no other source of the hash
     *                                  segment than: SHA-512/256, SHAKE128 and SHAKE256 are in that case
     */
    public function toUri(): string
    {
        $identifier = $this->hash::identifier();
        $name = self::URI_HASH_NAMES[$identifier] ?? throw new InvalidArgumentException(sprintf(
            'The hash algorithm %d has no name in the IANA "Named Information Hash Algorithm Registry", so no COSE Key Thumbprint URI can name it',
            $identifier
        ));

        return sprintf('%s:%s:%s', self::URI_PREFIX, $name, rtrim(strtr(base64_encode($this->value), '+/', '-_'), '='));
    }

    /**
     * A CBOR map of integer keys and integer or byte string values, in the deterministic encoding of RFC 8949,
     * section 4.2.1: the keys are sorted in the bytewise lexicographic order of their encodings.
     *
     * @param array<int, int|string> $members
     */
    private static function encodeMap(array $members): string
    {
        $encodedKeys = [];
        foreach (array_keys($members) as $label) {
            $encodedKeys[$label] = self::encodeInteger($label);
        }
        uksort(
            $members,
            static fn (int $a, int $b): int => strcmp($encodedKeys[$a], $encodedKeys[$b])
        );

        $items = [];
        foreach ($members as $label => $value) {
            $items[] = $encodedKeys[$label] . (
                is_int($value) ? self::encodeInteger($value) : self::encodeByteString($value)
            );
        }

        return self::encodeHead(5, count($items)) . implode('', $items);
    }

    /**
     * Major type 0 for a non-negative integer, major type 1 with the argument -1 - n for a negative one (RFC 8949,
     * section 3.1).
     */
    private static function encodeInteger(int $value): string
    {
        return $value >= 0 ? self::encodeHead(0, $value) : self::encodeHead(1, -1 - $value);
    }

    private static function encodeByteString(string $value): string
    {
        return self::encodeHead(2, strlen($value)) . $value;
    }

    /**
     * The initial byte and the argument of a data item, the argument in the shortest form that holds it (RFC 8949,
     * section 4.2.1, first two rules).
     */
    private static function encodeHead(int $majorType, int $argument): string
    {
        $type = $majorType << 5;

        return match (true) {
            $argument < 24 => chr($type | $argument),
            $argument < 0x100 => chr($type | 24) . chr($argument),
            $argument < 0x10000 => chr($type | 25) . pack('n', $argument),
            $argument < 0x100000000 => chr($type | 26) . pack('N', $argument),
            default => chr($type | 27) . pack('J', $argument),
        };
    }
}
