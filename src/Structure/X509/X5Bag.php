<?php

declare(strict_types=1);

namespace Cose\Structure\X509;

use ArrayIterator;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\ListObject;
use Cose\Algorithm\Hash\FilterOnlyHash;
use Countable;
use InvalidArgumentException;
use IteratorAggregate;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use Traversable;

/**
 * The "x5bag" header parameter of RFC 9360 (label 32): a COSE_X509 whose certificates are in no particular order.
 *
 * RFC 9360 section 2: "The set of certificates in this header parameter is unordered and may contain self-signed
 * certificates. Note that there could be duplicate certificates. The certificate bag can contain certificates that
 * are completely extraneous to the message." Nothing in a bag says which certificate is the end-entity one; "x5t"
 * usually does ({@see find()}), and "the party evaluating the signature will need to be capable of building the
 * certificate path as necessary."
 *
 * The bag is exposed as it is carried, and as a CertificateBundle of spomky-labs/pki-framework for the path building.
 * Both are untrusted input: "The presence of a self-signed certificate in the parameter MUST NOT cause the update of
 * the set of trust anchors without some out-of-band confirmation."
 *
 * @implements IteratorAggregate<int, string>
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see \Cose\Tests\Structure\X509\X5BagTest
 */
final class X5Bag implements Countable, IteratorAggregate
{
    private function __construct(
        private readonly CoseX509 $certificates
    ) {
    }

    /**
     * @param string ...$certificates one or more DER-encoded certificates
     */
    public static function create(string ...$certificates): self
    {
        return new self(CoseX509::create(...$certificates));
    }

    public static function fromCertificates(Certificate ...$certificates): self
    {
        return new self(CoseX509::fromCertificates(...$certificates));
    }

    /**
     * @param string $parameter the name of the header parameter, for the error messages
     */
    public static function fromCBOR(CBORObject $value, string $parameter = 'x5bag'): self
    {
        return new self(CoseX509::fromCBOR($value, $parameter));
    }

    public function toCBOR(): ByteStringObject|ListObject
    {
        return $this->certificates->toCBOR();
    }

    /**
     * The certificates, DER-encoded, in the order they happen to be carried.
     *
     * @return non-empty-list<string>
     */
    public function certificates(): array
    {
        return $this->certificates->certificates();
    }

    /**
     * The bag, parsed, for the path building of spomky-labs/pki-framework or of any other PKIX implementation.
     *
     * @throws InvalidArgumentException when an entry is not a DER-encoded X.509 certificate
     */
    public function toCertificateBundle(): CertificateBundle
    {
        return CertificateBundle::create(...$this->certificates->toCertificates());
    }

    /**
     * The first certificate of the bag whose thumbprint is the given one, or null; see {@see CoseX509::find()}.
     */
    public function find(CoseCertHash $thumbprint, FilterOnlyHash $hash): ?string
    {
        return $this->certificates->find($thumbprint, $hash);
    }

    public function count(): int
    {
        return $this->certificates->count();
    }

    /**
     * @return Traversable<int, string>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->certificates->certificates());
    }
}
