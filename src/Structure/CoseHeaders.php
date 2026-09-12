<?php

declare(strict_types=1);

namespace Cose\Structure;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\DecoderInterface;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\X5Bag;
use Cose\Structure\X509\X5Chain;
use function get_debug_type;
use InvalidArgumentException;
use function sprintf;
use Throwable;

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
 * $epk = $recipient->headers()->getEphemeralKey();   // RFC 9053: the sender's ephemeral public key of an ECDH-ES recipient
 * $receipts = $headers->getReceipts();               // RFC 9942: the COSE receipts, each a CBOR\Tag\CoseSign1Tag
 * ```
 *
 * The protected bucket is decoded once, on first use.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3
 * @see https://www.rfc-editor.org/rfc/rfc9596#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9597#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-2
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
     * The "receipts" header parameter of RFC 9942: a "Priority ordered sequence of CBOR encoded Receipts", each a
     * tagged COSE_Sign1 carrying the proofs of a verifiable data structure.
     */
    public const LABEL_RECEIPTS = 394;

    /**
     * The "vds" header parameter of RFC 9942: the identifier of the verifiable data structure a receipt's proofs
     * belong to, in the IANA "COSE Verifiable Data Structure Algorithms" registry.
     */
    public const LABEL_VDS = 395;

    /**
     * The "vdp" header parameter of RFC 9942: the map of verifiable data structure proofs of a receipt, keyed by
     * the labels of the IANA "COSE Verifiable Data Structure Proofs" registry.
     */
    public const LABEL_VDP = 396;

    /**
     * The "x5t-sender" header algorithm parameter of RFC 9360 section 3: the thumbprint of the sender's key exchange
     * certificate, a COSE_CertHash. Only meaningful with the ECDH-SS algorithms; {@see getX5TSender()} reads it.
     */
    public const LABEL_X5T_SENDER = -27;

    /**
     * The "x5u-sender" header algorithm parameter of RFC 9360 section 3: a URI for the sender's key exchange
     * certificate. ECDH-SS only; {@see getX5USender()} reads it.
     */
    public const LABEL_X5U_SENDER = -28;

    /**
     * The "x5chain-sender" header algorithm parameter of RFC 9360 section 3: the chain of the sender's key exchange
     * certificate, a COSE_X509. ECDH-SS only; {@see getX5ChainSender()} reads it.
     */
    public const LABEL_X5CHAIN_SENDER = -29;

    /**
     * The "ephemeral key" header algorithm parameter of RFC 9053 section 6.3.1, table 15: the sender's ephemeral
     * public key of an ECDH-ES recipient, a COSE_Key.
     */
    public const LABEL_EPHEMERAL_KEY = -1;

    /**
     * The "static key" header algorithm parameter of RFC 9053 section 6.3.1, table 15: the sender's static public
     * key of an ECDH-SS recipient, a COSE_Key.
     */
    public const LABEL_STATIC_KEY = -2;

    /**
     * The "static key id" header algorithm parameter of RFC 9053 section 6.3.1, table 15: the identifier of the
     * sender's static public key of an ECDH-SS recipient, a byte string the application resolves.
     */
    public const LABEL_STATIC_KEY_ID = -3;

    /**
     * The "salt" header algorithm parameter of RFC 9053 section 5.1, table 9: the salt of the HKDF extract step,
     * a byte string.
     */
    public const LABEL_SALT = -20;

    /**
     * The "PartyU identity", "PartyU nonce" and "PartyU other" header algorithm parameters of RFC 9053 section 5.2,
     * table 10: the PartyUInfo of the COSE_KDF_Context. The identity and the other information are byte strings;
     * the nonce is a byte string or an integer.
     */
    public const LABEL_PARTY_U_IDENTITY = -21;

    public const LABEL_PARTY_U_NONCE = -22;

    public const LABEL_PARTY_U_OTHER = -23;

    /**
     * The "PartyV identity", "PartyV nonce" and "PartyV other" header algorithm parameters of RFC 9053 section 5.2,
     * table 10: the PartyVInfo of the COSE_KDF_Context, typed like the PartyU ones.
     */
    public const LABEL_PARTY_V_IDENTITY = -24;

    public const LABEL_PARTY_V_NONCE = -25;

    public const LABEL_PARTY_V_OTHER = -26;

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

    /**
     * The "x5t-sender" header algorithm parameter (RFC 9360 section 3), or null when the recipient does not carry
     * one: the thumbprint of the sender's key exchange certificate, for an ECDH-SS recipient.
     *
     * Protected bucket first, then unprotected. Which certificate it names, and whether that certificate is trusted,
     * is the application's to settle -- this library validates no chain -- before the key of that certificate is
     * handed to the algorithm through {@see \Cose\Algorithm\KeyManagement\RecipientLayer::withSenderKey()}.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9360#section-3
     */
    public function getX5TSender(): ?CoseCertHash
    {
        $value = $this->getHeaderParameter(self::LABEL_X5T_SENDER);

        return $value === null ? null : CoseCertHash::fromCBOR($value, 'x5t-sender');
    }

    /**
     * The "x5u-sender" header algorithm parameter (RFC 9360 section 3) as a URI string, or null when the recipient
     * does not carry one. Never dereferenced by this library, like {@see getX5U()}.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9360#section-3
     */
    public function getX5USender(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_X5U_SENDER);

        return $value === null ? null : HeaderMapHelper::assertUriValue($value, 'x5u-sender');
    }

    /**
     * The "x5chain-sender" header algorithm parameter (RFC 9360 section 3), or null when the recipient does not
     * carry one: the chain of the sender's key exchange certificate, end-entity first, for an ECDH-SS recipient.
     *
     * The chain is untrusted input, like "x5chain": the application validates the path, then loads the key of the
     * end-entity certificate with {@see \Cose\Key\PublicKeyLoader::fromCertificate()} and hands it to the
     * algorithm. Nothing here does either.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9360#section-3
     */
    public function getX5ChainSender(): ?X5Chain
    {
        $value = $this->getHeaderParameter(self::LABEL_X5CHAIN_SENDER);

        return $value === null ? null : X5Chain::fromCBOR($value, 'x5chain-sender');
    }

    /**
     * The "receipts" header parameter (RFC 9942), as the COSE_Sign1 messages it carries, in the order they are
     * carried -- "Priority ordered", the registry says -- or an empty list when the message carries none.
     *
     * RFC 9942 section 4.3 registers the parameter "to enable Receipts to be conveyed in the protected and unprotected
     * headers", so the lookup is the usual one, protected bucket first. A receipt is self-contained -- its own
     * signature is what makes it trustworthy, not the bucket it sits in -- which is also why the example of the RFC
     * puts them in the unprotected bucket of a message that was signed before any receipt existed. The value is
     * "[+ bstr .cbor Receipt]": an array of one or more byte strings, each wrapping exactly one CBOR data item,
     * and "Receipts MUST be tagged as COSE_Sign1" (section 4.3), so an entry that does not decode to a tag 18 is
     * rejected. Nothing inside a receipt is read here: {@see fromMessage()} on an entry gives its headers, and
     * {@see \Cose\Structure\VerifiableDataStructure\ReceiptVerifier} verifies it.
     *
     * @return list<CoseSign1Tag>
     *
     * @see https://www.rfc-editor.org/rfc/rfc9942#section-4.3
     */
    public function getReceipts(): array
    {
        $value = $this->getHeaderParameter(self::LABEL_RECEIPTS);
        if ($value === null) {
            return [];
        }
        if (! $value instanceof ListObject && ! $value instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "receipts" header parameter. The value shall be an array of one or more byte strings, each a CBOR-encoded receipt (RFC 9942 section 4.3), got "%s".',
                get_debug_type($value)
            ));
        }
        if ($value->count() === 0) {
            throw new InvalidArgumentException(
                'Invalid "receipts" header parameter. The array shall carry at least one receipt, "[+ bstr .cbor Receipt]" (RFC 9942 section 4.3).'
            );
        }

        $receipts = [];
        foreach ($value as $entry) {
            if (! $entry instanceof ByteStringObject && ! $entry instanceof IndefiniteLengthByteStringObject) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "receipts" header parameter. Each receipt shall be a byte string carrying a CBOR-encoded COSE_Sign1 (RFC 9942 section 4.3), got "%s".',
                    get_debug_type($entry)
                ));
            }
            $receipts[] = self::receiptValue(
                HeaderMapHelper::decodeEmbedded($entry, $this->decoder, $this->maxDepth, 'receipt')
            );
        }

        return $receipts;
    }

    /**
     * The "vds" header parameter (RFC 9942), or null when the message does not declare one in its protected header.
     *
     * The parameter names the verifiable data structure the proofs of a receipt belong to, and RFC 9942 sections
     * 5.2.1 and 5.3.1 require it in the protected header: "The VDS in the protected header is necessary to
     * understand the inclusion proof structure in the unprotected header." An identifier the signature does not
     * cover could redirect the proofs to another structure, so this accessor reads the protected bucket only; a
     * copy in the unprotected one is ignored, as the raw lookup getUnprotectedHeaderParameter(CoseHeaders::LABEL_VDS)
     * remains for whoever wants to see it.
     *
     * The value is handed back as carried. Whether it is registered -- 1 is RFC9162_SHA256, 0 is reserved, nothing
     * else is assigned at the time of writing -- is checked where the proofs are read, since "the verifier MUST
     * confirm that the associated VDS and VDPs match entries present in the registries" (section 4.3).
     *
     * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.2.1
     */
    public function getVds(): ?int
    {
        $value = $this->getProtectedHeaderParameter(self::LABEL_VDS);
        if ($value === null) {
            return null;
        }
        if (! $value instanceof UnsignedIntegerObject && ! $value instanceof NegativeIntegerObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "vds" header parameter. The value shall be an integer of the IANA "COSE Verifiable Data Structure Algorithms" registry (RFC 9942 section 2), got "%s".',
                get_debug_type($value)
            ));
        }
        $normalized = $value->normalize();
        if ((string) (int) $normalized !== $normalized) {
            throw new InvalidArgumentException(
                'Invalid "vds" header parameter. The integer value exceeds the platform integer range.'
            );
        }

        return (int) $normalized;
    }

    /**
     * The "vdp" header parameter (RFC 9942), or null when the message does not carry one.
     *
     * The value is the map of proofs as it travels, keyed by the labels of the IANA "COSE Verifiable Data Structure
     * Proofs" registry -- for RFC9162_SHA256, -1 for the inclusion proofs and -2 for the consistency proofs -- with
     * each key checked to be a label and unique, and nothing read into the proofs themselves:
     * {@see \Cose\Structure\VerifiableDataStructure\Rfc9162Sha256::inclusionProofs()} decodes them once the "vds"
     * has said what they are.
     *
     * The CDDL of RFC 9942 section 5 places the map in the unprotected header of a receipt, and a proof gains nothing
     * from the signature: the tree head it leads to is what the signature covers, so a tampered proof leads to a
     * root the signature does not verify over. The lookup is nonetheless the usual one, protected bucket first, so
     * that a receipt whose issuer chose to protect the map is read too.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.2.1
     */
    public function getVdp(): ?MapObject
    {
        $value = $this->getHeaderParameter(self::LABEL_VDP);
        if ($value === null) {
            return null;
        }
        if (! $value instanceof MapObject && ! $value instanceof IndefiniteLengthMapObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "vdp" header parameter. The value shall be a map of proofs keyed by proof type (RFC 9942 section 2), got "%s".',
                get_debug_type($value)
            ));
        }

        return HeaderMapHelper::assertValidLabels($value);
    }

    /**
     * The "ephemeral key" header algorithm parameter (RFC 9053 section 6.3.1), or null when the recipient does not
     * carry one: the sender's ephemeral public key of an ECDH-ES recipient, as an EC2 or an OKP key.
     *
     * Protected bucket first, then unprotected; RFC 9052 section 8.5.4 requires the parameter for the ECDH-ES
     * algorithms. The value is a COSE_Key and has to be a public one: a key that carries a private part is rejected,
     * since a sender that writes its private scalar into a header has leaked it, and nothing this library does
     * should build on that. The point is not checked to be on the curve here -- the algorithm does it, before any
     * scalar multiplication ({@see \Cose\Key\Ec2Key::assertOnCurve()}).
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1
     */
    public function getEphemeralKey(): Ec2Key|OkpKey|null
    {
        $value = $this->getHeaderParameter(self::LABEL_EPHEMERAL_KEY);

        return $value === null ? null : self::publicKeyValue($value, 'ephemeral key');
    }

    /**
     * The "static key" header algorithm parameter (RFC 9053 section 6.3.1), or null when the recipient does not
     * carry one: the sender's static public key of an ECDH-SS recipient, as an EC2 or an OKP key, with the same
     * checks as {@see getEphemeralKey()}.
     *
     * A static key carried in the message identifies the sender only as far as the application trusts it: the
     * header is not authenticated by anything but the key agreement itself.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1
     */
    public function getStaticKey(): Ec2Key|OkpKey|null
    {
        $value = $this->getHeaderParameter(self::LABEL_STATIC_KEY);

        return $value === null ? null : self::publicKeyValue($value, 'static key');
    }

    /**
     * The "static key id" header algorithm parameter (RFC 9053 section 6.3.1), or null when the recipient does not
     * carry one: the identifier of the sender's static public key of an ECDH-SS recipient, a byte string the
     * application resolves to a key it holds.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1
     */
    public function getStaticKeyId(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_STATIC_KEY_ID);

        return $value === null ? null : self::byteStringValue($value, 'static key id');
    }

    /**
     * The "salt" header algorithm parameter (RFC 9053 section 5.1), or null when the recipient does not carry one:
     * the salt of the HKDF extract step. It "does not need to be separately authenticated": it is bound to the key
     * by being an input of the derivation, which is why it may travel in the unprotected bucket.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.1
     */
    public function getSalt(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_SALT);

        return $value === null ? null : self::byteStringValue($value, 'salt');
    }

    /**
     * The "PartyU identity" header algorithm parameter (RFC 9053 section 5.2), or null when absent.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
     */
    public function getPartyUIdentity(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_PARTY_U_IDENTITY);

        return $value === null ? null : self::byteStringValue($value, 'PartyU identity');
    }

    /**
     * The "PartyU nonce" header algorithm parameter (RFC 9053 section 5.2), or null when absent: a byte string or
     * an integer, table 10 allowing both.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
     */
    public function getPartyUNonce(): string|int|null
    {
        $value = $this->getHeaderParameter(self::LABEL_PARTY_U_NONCE);

        return $value === null ? null : self::nonceValue($value, 'PartyU nonce');
    }

    /**
     * The "PartyU other" header algorithm parameter (RFC 9053 section 5.2), or null when absent.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
     */
    public function getPartyUOther(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_PARTY_U_OTHER);

        return $value === null ? null : self::byteStringValue($value, 'PartyU other');
    }

    /**
     * The "PartyV identity" header algorithm parameter (RFC 9053 section 5.2), or null when absent.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
     */
    public function getPartyVIdentity(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_PARTY_V_IDENTITY);

        return $value === null ? null : self::byteStringValue($value, 'PartyV identity');
    }

    /**
     * The "PartyV nonce" header algorithm parameter (RFC 9053 section 5.2), or null when absent: a byte string or
     * an integer.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
     */
    public function getPartyVNonce(): string|int|null
    {
        $value = $this->getHeaderParameter(self::LABEL_PARTY_V_NONCE);

        return $value === null ? null : self::nonceValue($value, 'PartyV nonce');
    }

    /**
     * The "PartyV other" header algorithm parameter (RFC 9053 section 5.2), or null when absent.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
     */
    public function getPartyVOther(): ?string
    {
        $value = $this->getHeaderParameter(self::LABEL_PARTY_V_OTHER);

        return $value === null ? null : self::byteStringValue($value, 'PartyV other');
    }

    /**
     * A COSE_Key-valued header parameter as a public EC2 or OKP key: the key types RFC 9053 section 6.3.1 allows
     * for ECDH, and the only ones a key agreement parameter can carry.
     */
    private static function publicKeyValue(CBORObject $value, string $parameter): Ec2Key|OkpKey
    {
        if (! $value instanceof MapObject && ! $value instanceof IndefiniteLengthMapObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The value shall be a COSE_Key map (RFC 9053 section 6.3.1), got "%s".',
                $parameter,
                get_debug_type($value)
            ));
        }
        try {
            $key = Key::createFromData($value->normalize());
        } catch (Throwable $e) {
            // The map comes from the wire: whatever the key constructor objects to reaches the caller as the
            // exception this library documents, never as a TypeError or an Error.
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The value is not a valid COSE_Key: %s',
                $parameter,
                $e->getMessage()
            ), 0, $e);
        }
        if (! $key instanceof Ec2Key && ! $key instanceof OkpKey) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The key type shall be EC2 or OKP (RFC 9053 section 6.3.1), got "%s".',
                $parameter,
                $key->type()
            ));
        }
        if ($key->isPrivate()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The value shall be a public key and carries a private part.',
                $parameter
            ));
        }

        return $key;
    }

    /**
     * A decoded receipt as a CBOR\Tag\CoseSign1Tag: the class the default decoder produces for tag 18, or the
     * GenericTag a decoder without that class produces for it, rebuilt as the typed message -- the bytes are the same.
     */
    private static function receiptValue(CBORObject $decoded): CoseSign1Tag
    {
        if ($decoded instanceof CoseSign1Tag) {
            return $decoded;
        }
        if ($decoded instanceof Tag
            && HeaderMapHelper::tagNumber($decoded->getAdditionalInformation(), $decoded->getData(), 'receipt') === CoseSign1Tag::getTagId()
        ) {
            $receipt = CoseSign1Tag::createFromLoadedData(
                $decoded->getAdditionalInformation(),
                $decoded->getData(),
                $decoded->getValue()
            );
            if ($receipt instanceof CoseSign1Tag) {
                return $receipt;
            }
        }

        throw new InvalidArgumentException(sprintf(
            'Invalid "receipts" header parameter. Receipts MUST be tagged as COSE_Sign1 (RFC 9942 section 4.3), got "%s".',
            get_debug_type($decoded)
        ));
    }

    private static function byteStringValue(CBORObject $value, string $parameter): string
    {
        if (! $value instanceof ByteStringObject && ! $value instanceof IndefiniteLengthByteStringObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The value shall be a byte string, got "%s".',
                $parameter,
                get_debug_type($value)
            ));
        }

        return $value->getValue();
    }

    /**
     * "nonce : bstr / int" (RFC 9053 section 5.2): the value is handed back as the type it was carried in, because
     * the two encode differently in the COSE_KDF_Context and a byte string of digits is not the integer they spell.
     */
    private static function nonceValue(CBORObject $value, string $parameter): string|int
    {
        if ($value instanceof ByteStringObject || $value instanceof IndefiniteLengthByteStringObject) {
            return $value->getValue();
        }
        if ($value instanceof UnsignedIntegerObject || $value instanceof NegativeIntegerObject) {
            $normalized = $value->normalize();
            // A 64-bit value beyond PHP_INT_MAX normalizes to a numeric string; it cannot be re-encoded as an int.
            if ((string) (int) $normalized !== $normalized) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s" header parameter. The integer value exceeds the platform integer range.',
                    $parameter
                ));
            }

            return (int) $normalized;
        }

        throw new InvalidArgumentException(sprintf(
            'Invalid "%s" header parameter. The value shall be a byte string or an integer (RFC 9053 section 5.2), got "%s".',
            $parameter,
            get_debug_type($value)
        ));
    }
}
