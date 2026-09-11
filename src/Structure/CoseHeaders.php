<?php

declare(strict_types=1);

namespace Cose\Structure;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\DecoderInterface;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\MapObject;
use CBOR\Tag\AbstractCoseTag;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\X5Bag;
use Cose\Structure\X509\X5Chain;
use InvalidArgumentException;
use function sprintf;

/**
 * The two header buckets of a COSE message, read the way RFC 9052 defines them.
 *
 * cbor-php 3.4.0 owns the shape of a COSE message and hands back the buckets as they were encoded. What it does not
 * do -- and what a CBOR library has no business doing -- is apply the header rules of RFC 9052 sections 1.5 and 3 on
 * top: a label is an integer or a text string and nothing else, the two are distinct even when they normalize to the
 * same map offset, a label appears at most once, and the protected bucket holds exactly one CBOR item.
 *
 * That is what this reads. It works on any COSE message: the upstream classes through fromMessage(), the deprecated
 * Cose\...Tag classes and the per-signer or per-recipient entries through of().
 *
 * ```php
 * $message = Decoder::create()->decode(StringStream::create($bytes)); // CBOR\Tag\CoseSign1Tag
 * $headers = CoseHeaders::fromMessage($message);
 *
 * $alg = $headers->getProtectedHeaderParameter(1);   // never answered by the text string "1"
 * $kid = $headers->getHeaderParameter(4);            // protected bucket first
 * $typ = $headers->getTyp();                         // RFC 9596: "application/cwt" or 61, protected bucket only
 * $claims = $headers->getCwtClaims();                // RFC 9597: the claims map, or null
 * $chain = $headers->getX5Chain();                   // RFC 9360: the certificate chain, end-entity first, or null
 * ```
 *
 * The protected bucket is decoded once, on first use.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3
 * @see https://www.rfc-editor.org/rfc/rfc9596#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9597#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://github.com/web-auth/cose-lib/issues/166
 * @see \Cose\Tests\Structure\CoseHeadersTest
 */
final class CoseHeaders
{
    public const DEFAULT_PROTECTED_HEADER_MAX_DEPTH = HeaderMapHelper::DEFAULT_PROTECTED_HEADER_MAX_DEPTH;

    /**
     * The "CWT Claims" header parameter of RFC 9597: a map of CWT claims, so that they can be read before the
     * payload is decrypted or when there is no payload to carry them in.
     */
    public const LABEL_CWT_CLAIMS = 15;

    /**
     * The "typ" (type) header parameter of RFC 9596: the type of the whole COSE object, as opposed to "content type"
     * (label 3), which is the type of its payload.
     */
    public const LABEL_TYP = 16;

    /**
     * The "x5bag" header parameter of RFC 9360: an unordered bag of X.509 certificates, a COSE_X509.
     */
    public const LABEL_X5BAG = 32;

    /**
     * The "x5chain" header parameter of RFC 9360: an ordered chain of X.509 certificates, end-entity first, a
     * COSE_X509.
     */
    public const LABEL_X5CHAIN = 33;

    /**
     * The "x5t" header parameter of RFC 9360: the thumbprint of the end-entity X.509 certificate, a COSE_CertHash.
     */
    public const LABEL_X5T = 34;

    /**
     * The "x5u" header parameter of RFC 9360: a URI pointing to an X.509 certificate.
     */
    public const LABEL_X5U = 35;

    /**
     * The "x5t-sender" header algorithm parameter of RFC 9360 section 3: the thumbprint of the sender's key exchange
     * certificate, a COSE_CertHash. Only meaningful with the ECDH-SS algorithms, hence no accessor until those exist
     * (issue #201); {@see CoseCertHash::fromCBOR()} reads the value of a raw lookup.
     */
    public const LABEL_X5T_SENDER = -27;

    /**
     * The "x5u-sender" header algorithm parameter of RFC 9360 section 3: a URI for the sender's key exchange
     * certificate. ECDH-SS only; {@see HeaderMapHelper::assertUriValue()} reads the value of a raw lookup.
     */
    public const LABEL_X5U_SENDER = -28;

    /**
     * The "x5chain-sender" header algorithm parameter of RFC 9360 section 3: the chain of the sender's key exchange
     * certificate, a COSE_X509. ECDH-SS only; {@see X5Chain::fromCBOR()} reads the value of a raw lookup.
     */
    public const LABEL_X5CHAIN_SENDER = -29;

    private ?MapObject $decodedProtectedHeader = null;

    private function __construct(
        private readonly ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader,
        private readonly MapObject|IndefiniteLengthMapObject $unprotectedHeader,
        private readonly ?DecoderInterface $decoder,
        private readonly int $maxDepth
    ) {
    }

    /**
     * The buckets of a COSE message, given as they are carried.
     *
     * This is the form to use for a per-signer COSE_Signature or a COSE_recipient -- {@see CoseSignature} and
     * {@see CoseRecipient} build it for you -- and for the deprecated Cose\...Tag classes.
     */
    public static function of(
        ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader,
        MapObject|IndefiniteLengthMapObject $unprotectedHeader,
        ?DecoderInterface $decoder = null,
        int $maxDepth = self::DEFAULT_PROTECTED_HEADER_MAX_DEPTH
    ): self {
        return new self($protectedHeader, $unprotectedHeader, $decoder, $maxDepth);
    }

    /**
     * The buckets of one of the six COSE messages of cbor-php 3.4.0 or later.
     *
     * The nesting bound only applies to the decoder built when none is given: a caller passing its own $decoder sets
     * its own bound, and $maxDepth is then ignored.
     */
    public static function fromMessage(
        AbstractCoseTag $message,
        ?DecoderInterface $decoder = null,
        int $maxDepth = self::DEFAULT_PROTECTED_HEADER_MAX_DEPTH
    ): self {
        return new self($message->getProtectedHeader(), $message->getUnprotectedHeader(), $decoder, $maxDepth);
    }

    /**
     * The protected bucket as it is carried: the byte string the cryptographic structure covers verbatim.
     */
    public function getProtectedHeader(): ByteStringObject|IndefiniteLengthByteStringObject
    {
        return $this->protectedHeader;
    }

    /**
     * The protected bucket, decoded and checked: the zero-length byte string of RFC 9052 section 3 is an empty
     * header, trailing bytes after the header map are rejected, and every key is a label.
     */
    public function getProtectedHeaderAsMap(): MapObject
    {
        return $this->decodedProtectedHeader ??= HeaderMapHelper::decodeProtected(
            $this->protectedHeader,
            $this->decoder,
            $this->maxDepth
        );
    }

    /**
     * The unprotected bucket, with its labels checked.
     */
    public function getUnprotectedHeaderAsMap(): MapObject
    {
        return HeaderMapHelper::assertValidLabels($this->unprotectedHeader);
    }

    /**
     * The unprotected bucket as it is carried.
     */
    public function getUnprotectedHeader(): MapObject|IndefiniteLengthMapObject
    {
        return $this->unprotectedHeader;
    }

    /**
     * The value of a label in the protected bucket, or null when the bucket does not carry it.
     *
     * The label is matched by type as well as by value, so the integer 1 -- the algorithm -- is never answered by
     * the text string "1" or by a byte string that happens to normalize the same way.
     */
    public function getProtectedHeaderParameter(int|string $label): ?CBORObject
    {
        return HeaderMapHelper::findLabel($this->getProtectedHeaderAsMap(), $label);
    }

    /**
     * The value of a label in the unprotected bucket, or null when the bucket does not carry it.
     */
    public function getUnprotectedHeaderParameter(int|string $label): ?CBORObject
    {
        return HeaderMapHelper::findLabel($this->unprotectedHeader, $label);
    }

    /**
     * The value of a label, looked up in the protected bucket first.
     *
     * A parameter found there is the one the signature or the MAC commits to, so it wins over an unprotected copy of
     * the same label. A message carrying a label in both buckets is malformed anyway (RFC 9052 section 3: "The same
     * label MUST NOT occur in both buckets"); preferring the protected value keeps the answer on the authenticated
     * side of that mistake.
     */
    public function getHeaderParameter(int|string $label): ?CBORObject
    {
        return $this->getProtectedHeaderParameter($label) ?? $this->getUnprotectedHeaderParameter($label);
    }

    /**
     * The "typ" header parameter (RFC 9596), or null when the message does not declare one.
     *
     * An unsigned integer is a CoAP Content-Format identifier, and a text string a media type name that "MAY include
     * media type parameters" (section 2) -- "application/cwt" or 61 both say CWT. The syntax is the one of "content
     * type" (RFC 9052 section 3.1): a text value without the "<type-name>/<subtype-name>" shape is rejected. RFC 9596
     * defines no "application/" shorthand, unlike JOSE, so a bare "cwt" is malformed rather than something to expand.
     *
     * Section 2: "The 'typ' parameter MUST NOT be present in unprotected headers." This accessor reads the protected
     * bucket only and rejects a message that carries the label in the unprotected one, wherever else it appears.
     * The raw lookup, getProtectedHeaderParameter(CoseHeaders::LABEL_TYP), is the lenient form: it never looks at
     * the unprotected bucket and hands the value back unchecked.
     *
     * What the value means is the application's business: RFC 9596 section 2 leaves any processing, such as comparing
     * it with an expected media type, to "application-specific processing rules".
     *
     * @see https://www.rfc-editor.org/rfc/rfc9596#section-2
     */
    public function getTyp(): int|string|null
    {
        $typ = $this->getProtectedHeaderParameter(self::LABEL_TYP);
        if (HeaderMapHelper::findLabel($this->unprotectedHeader, self::LABEL_TYP) !== null) {
            throw new InvalidArgumentException(
                'Invalid "typ" header parameter. It shall not be present in the unprotected header (RFC 9596 section 2).'
            );
        }

        return $typ === null ? null : HeaderMapHelper::assertContentTypeValue($typ, 'typ');
    }

    /**
     * The "CWT Claims" header parameter (RFC 9597), or null when the message does not carry one.
     *
     * The value is the claims map as it travels, "{ * Claim-Label => any }" with "Claim-Label = int / text": every
     * key is checked to be a label, nothing is read into the claims themselves. RFC 8392 defines the registered
     * ones (1 = iss, 2 = sub, 3 = aud, 4 = exp, 5 = nbf, 6 = iat, 7 = cti); what to do with them is left to the
     * application, as is the rule of RFC 9597 section 2 that a claim carried both here and in the payload "MUST" have
     * identical values -- the payload is opaque to this library.
     *
     * The parameter is looked up in the protected bucket first, then in the unprotected one; section 2 only
     * recommends the protected bucket ("RECOMMENDED ... to avoid the contents being malleable"), so neither is
     * refused. What is refused is the parameter appearing in both: "The header parameter MUST only occur once in
     * either the protected or unprotected header of a COSE structure."
     *
     * @see https://www.rfc-editor.org/rfc/rfc9597#section-2
     */
    public function getCwtClaims(): ?MapObject
    {
        $protected = $this->getProtectedHeaderParameter(self::LABEL_CWT_CLAIMS);
        $unprotected = $this->getUnprotectedHeaderParameter(self::LABEL_CWT_CLAIMS);
        if ($protected !== null && $unprotected !== null) {
            throw new InvalidArgumentException(
                'Invalid "CWT Claims" header parameter. It shall occur once, in either the protected or the unprotected header, not in both (RFC 9597 section 2).'
            );
        }

        $claims = $protected ?? $unprotected;
        if ($claims === null) {
            return null;
        }
        if (! $claims instanceof MapObject && ! $claims instanceof IndefiniteLengthMapObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "CWT Claims" header parameter. The value shall be a map of claims (RFC 9597 section 2), got "%s".',
                $claims::class
            ));
        }

        return HeaderMapHelper::assertValidClaimLabels($claims);
    }

    /**
     * The "x5bag" header parameter (RFC 9360), or null when the message does not carry one.
     *
     * The bag is looked up in the protected bucket first, then in the unprotected one: section 2 allows either ("As
     * the contents of this header parameter are untrusted input, the header parameter can be in either the protected
     * or unprotected header bucket"). Where it was found matters to the application all the same, because "The
     * end-entity certificate MUST be integrity protected by COSE" -- by this parameter being in the protected bucket,
     * by an "x5t" in the protected bucket naming the certificate, or by the certificate being in the external_aad.
     * The decode applies the shape rules of COSE_X509 and nothing more: no certificate is parsed, validated or
     * trusted here.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
     */
    public function getX5Bag(): ?X5Bag
    {
        $value = $this->getHeaderParameter(self::LABEL_X5BAG);

        return $value === null ? null : X5Bag::fromCBOR($value, 'x5bag');
    }

    /**
     * The "x5chain" header parameter (RFC 9360), or null when the message does not carry one.
     *
     * Protected bucket first, then unprotected, under the same rule and with the same caveat as {@see getX5Bag()}.
     * The chain is a candidate path proposed by the sender, end-entity certificate first; building and validating the
     * path against the trust anchors of the application is the application's work, which {@see X5Chain::toCertificateChain()}
     * hands to spomky-labs/pki-framework.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
     */
    public function getX5Chain(): ?X5Chain
    {
        $value = $this->getHeaderParameter(self::LABEL_X5CHAIN);

        return $value === null ? null : X5Chain::fromCBOR($value, 'x5chain');
    }

    /**
     * The "x5t" header parameter (RFC 9360), or null when the message does not carry one.
     *
     * Protected bucket first, then unprotected ("As this header parameter does not provide any trust, the header
     * parameter can be in either a protected or unprotected header bucket"), while "The identification of the
     * end-entity certificate MUST be integrity protected by COSE", so a thumbprint read from the unprotected bucket
     * identifies nothing an application should act on. The hash algorithm the thumbprint names is resolved by the
     * application, through {@see CoseCertHash::hashAlgorithm()} and its Manager.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
     */
    public function getX5T(): ?CoseCertHash
    {
        $value = $this->getHeaderParameter(self::LABEL_X5T);

        return $value === null ? null : CoseCertHash::fromCBOR($value, 'x5t');
    }

    /**
     * The "x5u" header parameter (RFC 9360) as a URI string, or null when the message does not carry one.
     *
     * Protected bucket first, then unprotected. The value is returned as text and nothing else: this library never
     * dereferences it. Whether to fetch it, over what, and what to make of the answer -- RFC 9360 section 2: "If a
     * retrieved certificate does not chain to an existing trust anchor, that certificate MUST NOT be trusted unless
     * the URI provides integrity protection and server authentication and the server is configured as trusted to
     * provide new trust anchors" -- is entirely the application's.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
     */
    public function getX5U(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_X5U);

        return $value === null ? null : HeaderMapHelper::assertUriValue($value, 'x5u');
    }
}
