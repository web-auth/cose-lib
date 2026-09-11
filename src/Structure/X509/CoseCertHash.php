<?php

declare(strict_types=1);

namespace Cose\Structure\X509;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\FilterOnlyHash;
use Cose\Algorithm\Manager;
use function hash_equals;
use InvalidArgumentException;
use function is_int;
use function is_string;
use function sprintf;

/**
 * The COSE_CertHash structure of RFC 9360: the thumbprint of an X.509 certificate, as "x5t" and "x5t-sender" carry
 * it.
 *
 * RFC 9360 section 2: "COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]". The first element names a hash
 * algorithm by its identifier in the IANA COSE Algorithms registry -- the RFC 9054 identifiers, which
 * {@see \Cose\Algorithm\Hash} implements -- and the second is "the hash value computed over the DER-encoded
 * certificate".
 *
 * A thumbprint selects a certificate; it does not vouch for it. Section 5: "The security of the algorithm used for
 * 'x5t' does not affect the security of the system, as this header parameter selects which certificate that is
 * already present on the system should be used, but it does not provide any trust." That is the filtering use of
 * RFC 9054 section 2, which is why {@see hashAlgorithm()} and {@see matches()} are typed {@see FilterOnlyHash}: SHA-1
 * (-14) and SHA-256/64 (-15) are legitimate here, and a match is always followed by a real check -- validating the
 * certificate and verifying the signature with its key. What every application has to accept is SHA-256 (-16):
 * section 2, "applications that use this header parameter MUST support the hash algorithm 'SHA-256'".
 *
 * The digest is taken over the bytes of the certificate as they are carried, and both compute() and matches() take
 * those bytes rather than a parsed certificate. A certificate parsed and re-encoded is not always the same byte
 * string: the certificates of cose-wg/Examples, for one, carry a BIT STRING with a spare byte that a DER encoder
 * drops, so their re-encoding has a different thumbprint from the one the "x5t" of signed-05 carries. Hashing what
 * travels is the only reading under which two implementations agree.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-2
 * @see \Cose\Tests\Structure\X509\CoseCertHashTest
 */
final class CoseCertHash
{
    private function __construct(
        private readonly int|string $hashAlg,
        private readonly string $hashValue
    ) {
    }

    /**
     * @param int|string $hashAlg the identifier of the hash algorithm, as registered by IANA
     * @param string $hashValue the digest of the DER-encoded certificate, as raw bytes
     */
    public static function create(int|string $hashAlg, string $hashValue): self
    {
        if ($hashAlg === '') {
            throw new InvalidArgumentException(
                'Invalid COSE_CertHash. The hash algorithm identifier shall not be an empty text string.'
            );
        }

        return new self($hashAlg, $hashValue);
    }

    /**
     * The thumbprint of a certificate, computed with the given algorithm over its encoding as carried.
     *
     * @param string $certificate the DER-encoded certificate, the bytes the message carries or will carry
     */
    public static function compute(FilterOnlyHash $hash, string $certificate): self
    {
        return new self($hash::identifier(), $hash->hash($certificate));
    }

    /**
     * Decode a COSE_CertHash as it is carried in a header parameter.
     *
     * @param string $parameter the name of the header parameter, for the error messages
     */
    public static function fromCBOR(CBORObject $value, string $parameter = 'COSE_CertHash'): self
    {
        if (! $value instanceof ListObject && ! $value instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. A COSE_CertHash shall be an array of two elements, [hashAlg, hashValue] (RFC 9360 section 2), got "%s".',
                $parameter,
                $value::class
            ));
        }
        if ($value->count() !== 2) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. A COSE_CertHash shall be an array of two elements, [hashAlg, hashValue] (RFC 9360 section 2), got %d element(s).',
                $parameter,
                $value->count()
            ));
        }

        $hashAlg = $value->get(0);
        if ($hashAlg instanceof UnsignedIntegerObject || $hashAlg instanceof NegativeIntegerObject) {
            $identifier = $hashAlg->normalize();
            if ((string) (int) $identifier !== $identifier) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s" header parameter. The hash algorithm identifier %s exceeds the platform integer range.',
                    $parameter,
                    $identifier
                ));
            }
            $identifier = (int) $identifier;
        } elseif ($hashAlg instanceof TextStringObject || $hashAlg instanceof IndefiniteLengthTextStringObject) {
            $identifier = $hashAlg->getValue();
            if ($identifier === '') {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s" header parameter. The hash algorithm identifier of a COSE_CertHash shall not be an empty text string.',
                    $parameter
                ));
            }
        } else {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The hash algorithm of a COSE_CertHash shall be an integer or a text string (RFC 9360 section 2), got "%s".',
                $parameter,
                $hashAlg::class
            ));
        }

        $hashValue = $value->get(1);
        if (! $hashValue instanceof ByteStringObject && ! $hashValue instanceof IndefiniteLengthByteStringObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The hash value of a COSE_CertHash shall be a byte string (RFC 9360 section 2), got "%s".',
                $parameter,
                $hashValue::class
            ));
        }

        return new self($identifier, $hashValue->getValue());
    }

    /**
     * Encode the structure as RFC 9360 section 2 writes it: [hashAlg, hashValue].
     */
    public function toCBOR(): ListObject
    {
        $hashAlg = $this->hashAlg;
        if (is_string($hashAlg)) {
            $identifier = TextStringObject::create($hashAlg);
        } elseif ($hashAlg < 0) {
            $identifier = NegativeIntegerObject::create($hashAlg);
        } else {
            $identifier = UnsignedIntegerObject::create($hashAlg);
        }

        return ListObject::create([$identifier, ByteStringObject::create($this->hashValue)]);
    }

    /**
     * The identifier of the hash algorithm, as carried: an integer for every algorithm IANA has registered so far,
     * a text string if a future registration uses one.
     */
    public function hashAlg(): int|string
    {
        return $this->hashAlg;
    }

    /**
     * The digest, as raw bytes.
     */
    public function hashValue(): string
    {
        return $this->hashValue;
    }

    /**
     * The hash algorithm the thumbprint names, resolved through the registry of the application.
     *
     * The set of acceptable algorithms is the Manager the operator built, as it is for every other identifier that
     * comes from the wire: an identifier that was never registered is refused, and so is one registered with anything
     * but a hash. Both SHA-1 and SHA-256/64 resolve when registered, because filtering is the one use RFC 9054
     * section 2 admits them for; the return type says so.
     *
     * @throws InvalidArgumentException when the identifier is a text string (the registry resolves integers only,
     * and IANA has registered no text string hash identifier), when no algorithm is registered for it, or when the
     * algorithm registered for it is not a hash
     */
    public function hashAlgorithm(Manager $manager): FilterOnlyHash
    {
        $identifier = $this->hashAlg;
        if (! is_int($identifier)) {
            throw new InvalidArgumentException(sprintf(
                'The hash algorithm "%s" of the COSE_CertHash cannot be resolved: the registry resolves integer identifiers only, and IANA has registered no text string hash algorithm identifier.',
                $identifier
            ));
        }
        if (! $manager->has($identifier)) {
            throw new InvalidArgumentException(sprintf(
                'The hash algorithm %d of the COSE_CertHash is not registered. RFC 9360 section 2 requires SHA-256 (-16) to be supported.',
                $identifier
            ));
        }
        $algorithm = $manager->get($identifier);
        if (! $algorithm instanceof FilterOnlyHash) {
            throw new InvalidArgumentException(sprintf(
                'The algorithm identifier %d of the COSE_CertHash is registered with "%s", which is not a hash algorithm.',
                $identifier,
                $algorithm::class
            ));
        }

        return $algorithm;
    }

    /**
     * Whether the thumbprint is the one of the given certificate.
     *
     * $hash is the algorithm this thumbprint names -- typically the result of {@see hashAlgorithm()} -- and is checked
     * to be: comparing a SHA-1 thumbprint with a SHA-256 digest would answer false for every certificate, which is a
     * bug to report, not a mismatch to filter on. The digests are compared with hash_equals().
     *
     * @param string $certificate the DER-encoded certificate, the bytes the message carries
     *
     * @throws InvalidArgumentException when $hash is not the algorithm the thumbprint names
     */
    public function matches(string $certificate, FilterOnlyHash $hash): bool
    {
        if ($hash::identifier() !== $this->hashAlg) {
            throw new InvalidArgumentException(sprintf(
                'The COSE_CertHash names the hash algorithm %s, not %d ("%s").',
                is_int($this->hashAlg) ? (string) $this->hashAlg : '"' . $this->hashAlg . '"',
                $hash::identifier(),
                $hash::class
            ));
        }

        return hash_equals($this->hashValue, $hash->hash($certificate));
    }
}
