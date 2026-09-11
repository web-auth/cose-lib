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
use SpomkyLabs\Pki\X509\Certificate\CertificateChain;
use Traversable;

/**
 * The "x5chain" header parameter of RFC 9360 (label 33; "x5chain-sender", label -29, has the same structure): a
 * COSE_X509 whose certificates are ordered, the end-entity certificate first.
 *
 * RFC 9360 section 2: "The certificates are to be ordered starting with the certificate containing the end-entity
 * key followed by the certificate that signed it, and so on. There is no requirement for the entire chain to be
 * present in the element if there is reason to believe that the relying party already has, or can locate, the
 * missing certificates. This means that the relying party is still required to do path building but that a
 * candidate path is proposed in this header parameter."
 *
 * So this is a proposal, and the two things the class does with it are the two things that need no trust: name the
 * end-entity certificate, whose key verifies the signature ({@see \Cose\Algorithm\Signature\CertificateSignatureVerifier::verifyWithX5Chain()}),
 * and hand the proposed path to spomky-labs/pki-framework as a CertificateChain, which is where path validation
 * against the trust anchors of the application starts. Neither happens here: "The trust mechanism MUST process any
 * certificates in this parameter as untrusted input."
 *
 * @implements IteratorAggregate<int, string>
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-3
 * @see \Cose\Tests\Structure\X509\X5ChainTest
 */
final class X5Chain implements Countable, IteratorAggregate
{
    private function __construct(
        private readonly CoseX509 $certificates
    ) {
    }

    /**
     * @param string ...$certificates one or more DER-encoded certificates, the end-entity certificate first
     */
    public static function create(string ...$certificates): self
    {
        return new self(CoseX509::create(...$certificates));
    }

    /**
     * @param Certificate ...$certificates the end-entity certificate first
     */
    public static function fromCertificates(Certificate ...$certificates): self
    {
        return new self(CoseX509::fromCertificates(...$certificates));
    }

    public static function fromCertificateChain(CertificateChain $chain): self
    {
        return self::fromCertificates(...$chain->certificates());
    }

    /**
     * @param string $parameter the name of the header parameter, for the error messages
     */
    public static function fromCBOR(CBORObject $value, string $parameter = 'x5chain'): self
    {
        return new self(CoseX509::fromCBOR($value, $parameter));
    }

    public function toCBOR(): ByteStringObject|ListObject
    {
        return $this->certificates->toCBOR();
    }

    /**
     * The certificates, DER-encoded, end-entity first.
     *
     * @return non-empty-list<string>
     */
    public function certificates(): array
    {
        return $this->certificates->certificates();
    }

    /**
     * The first certificate of the chain, DER-encoded: the one "containing the end-entity key", whose public key
     * verifies the signature.
     */
    public function endEntityCertificate(): string
    {
        return $this->certificates->certificates()[0];
    }

    /**
     * The proposed path, parsed, for the path validation of spomky-labs/pki-framework
     * (SpomkyLabs\Pki\X509\CertificationPath\CertificationPath) or of any other PKIX implementation.
     *
     * @throws InvalidArgumentException when an entry is not a DER-encoded X.509 certificate
     */
    public function toCertificateChain(): CertificateChain
    {
        return CertificateChain::create(...$this->certificates->toCertificates());
    }

    /**
     * The first certificate of the chain whose thumbprint is the given one, or null; see {@see CoseX509::find()}.
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
