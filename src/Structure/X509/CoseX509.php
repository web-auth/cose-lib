<?php

declare(strict_types=1);

namespace Cose\Structure\X509;

use ArrayIterator;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\ListObject;
use Cose\Algorithm\Hash\FilterOnlyHash;
use function count;
use Countable;
use InvalidArgumentException;
use IteratorAggregate;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use function sprintf;
use Throwable;
use Traversable;

/**
 * The COSE_X509 structure of RFC 9360: one or more DER-encoded X.509 certificates, as "x5bag", "x5chain" and
 * "x5chain-sender" carry them.
 *
 * RFC 9360 section 2 defines it as "COSE_X509 = bstr / [ 2*certs: bstr ]": a single certificate travels as one byte
 * string, two or more as an array of byte strings, one certificate per entry. An array of length one is not a
 * COSE_X509 -- the CDDL says "2*" -- so fromCBOR() rejects it and toCBOR() never produces it. "The contents of 'bstr'
 * are the bytes of a DER-encoded certificate", which is the only form the certificates are held in here: DER, as
 * carried, so that a thumbprint ("x5t", the hash "computed over the DER-encoded certificate") can be checked without
 * re-encoding anything.
 *
 * This class is the wire shape and nothing more. {@see X5Bag} and {@see X5Chain} put a name on what the certificates
 * are -- an unordered bag, or a candidate chain with the end-entity certificate first -- and hand them to
 * spomky-labs/pki-framework for whatever comes next. What comes next is the application's: this library builds no
 * path, checks no revocation, holds no trust anchor. RFC 9360 section 2: "Parties that intend to rely on the
 * assertions made by a certificate obtained from any of these methods still need to validate it."
 *
 * @implements IteratorAggregate<int, string>
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see \Cose\Tests\Structure\X509\CoseX509Test
 */
final class CoseX509 implements Countable, IteratorAggregate
{
    /**
     * @param non-empty-list<string> $certificates
     */
    private function __construct(
        private readonly array $certificates
    ) {
    }

    /**
     * @param string ...$certificates one or more DER-encoded certificates
     */
    public static function create(string ...$certificates): self
    {
        $list = [];
        foreach ($certificates as $certificate) {
            if ($certificate === '') {
                throw new InvalidArgumentException(
                    'Invalid COSE_X509. A certificate shall be the bytes of a DER-encoded certificate, got an empty byte string (RFC 9360 section 2).'
                );
            }
            $list[] = $certificate;
        }
        if ($list === []) {
            throw new InvalidArgumentException(
                'Invalid COSE_X509. The structure shall carry at least one certificate (RFC 9360 section 2).'
            );
        }

        return new self($list);
    }

    /**
     * The same, from certificates already parsed: each is re-encoded to DER.
     *
     * For a sender, which is what this is for, the re-encoding is what travels and what a peer will hash. For a
     * receiver it is a different byte string from the one carried whenever the original was not strict DER, which
     * is why a thumbprint is always checked against the bytes as carried ({@see CoseCertHash}) and never against a
     * parsed certificate.
     */
    public static function fromCertificates(Certificate ...$certificates): self
    {
        return self::create(...array_map(static fn (Certificate $certificate): string => $certificate->toDER(), $certificates));
    }

    /**
     * Decode a COSE_X509 as it is carried in a header parameter.
     *
     * A byte string is one certificate; an array is two or more, each a byte string. An array of one -- valid CBOR,
     * invalid CDDL -- is refused with a message that says why, rather than being read as the single certificate its
     * sender presumably meant: a peer that emits it does not implement RFC 9360, and the next thing it emits may not
     * mean what it seems to either.
     *
     * @param string $parameter the name of the header parameter, for the error messages
     */
    public static function fromCBOR(CBORObject $value, string $parameter = 'COSE_X509'): self
    {
        if ($value instanceof ByteStringObject || $value instanceof IndefiniteLengthByteStringObject) {
            return self::create($value->getValue());
        }
        if (! $value instanceof ListObject && ! $value instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. A COSE_X509 shall be a byte string or an array of byte strings (RFC 9360 section 2), got "%s".',
                $parameter,
                $value::class
            ));
        }
        if ($value->count() < 2) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. A COSE_X509 array shall hold two or more certificates ("[ 2*certs: bstr ]", RFC 9360 section 2), got %d; a single certificate shall be a byte string, not an array.',
                $parameter,
                $value->count()
            ));
        }
        $certificates = [];
        foreach ($value as $entry) {
            if (! $entry instanceof ByteStringObject && ! $entry instanceof IndefiniteLengthByteStringObject) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s" header parameter. Each certificate of a COSE_X509 array shall be a byte string (RFC 9360 section 2), got "%s".',
                    $parameter,
                    $entry::class
                ));
            }
            $certificates[] = $entry->getValue();
        }

        return self::create(...$certificates);
    }

    /**
     * Encode the structure as RFC 9360 section 2 writes it: a byte string for one certificate, an array of byte
     * strings for two or more. An array of one is never produced.
     */
    public function toCBOR(): ByteStringObject|ListObject
    {
        if (count($this->certificates) === 1) {
            return ByteStringObject::create($this->certificates[0]);
        }

        return ListObject::create(array_map(
            ByteStringObject::create(...),
            $this->certificates
        ));
    }

    /**
     * The certificates, DER-encoded, in the order they are carried.
     *
     * @return non-empty-list<string>
     */
    public function certificates(): array
    {
        return $this->certificates;
    }

    /**
     * The certificates, parsed.
     *
     * @throws InvalidArgumentException when an entry is not a DER-encoded X.509 certificate
     * @return non-empty-list<Certificate>
     */
    public function toCertificates(): array
    {
        $parsed = [];
        foreach ($this->certificates as $index => $certificate) {
            try {
                $parsed[] = Certificate::fromDER($certificate);
            } catch (Throwable $throwable) {
                throw new InvalidArgumentException(
                    sprintf('Invalid COSE_X509. The certificate at index %d is not a DER-encoded X.509 certificate.', $index),
                    0,
                    $throwable
                );
            }
        }

        return $parsed;
    }

    /**
     * The first certificate whose thumbprint is the given one, or null when none matches.
     *
     * This is the "x5t" lookup of RFC 9360 section 2 -- the parameter "identifies the end-entity X.509 certificate by
     * a hash value" -- as a filter over the certificates carried alongside it. $hash is the algorithm the thumbprint
     * names, resolved by the caller through {@see CoseCertHash::hashAlgorithm()}; the comparison is the constant-time
     * one of {@see CoseCertHash::matches()}. A match selects a candidate and proves nothing about it: the certificate
     * still has to be validated, and the signature verified with its key.
     */
    public function find(CoseCertHash $thumbprint, FilterOnlyHash $hash): ?string
    {
        foreach ($this->certificates as $certificate) {
            if ($thumbprint->matches($certificate, $hash)) {
                return $certificate;
            }
        }

        return null;
    }

    public function count(): int
    {
        return count($this->certificates);
    }

    /**
     * @return Traversable<int, string>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->certificates);
    }
}
