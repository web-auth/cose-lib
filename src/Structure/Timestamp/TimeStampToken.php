<?php

declare(strict_types=1);

namespace Cose\Structure\Timestamp;

use DateTimeImmutable;
use InvalidArgumentException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use function sprintf;
use function strlen;
use Throwable;

/**
 * An RFC 3161 TimeStampToken, read far enough to bind it to a COSE message and no further.
 *
 * A token is a CMS ContentInfo of type id-signedData (RFC 5652 section 5.1) whose encapsulated content is a TSTInfo
 * (RFC 3161 section 2.4.2):
 *
 * ```
 * TimeStampToken ::= ContentInfo                                    -- contentType is id-signedData
 * SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates?, crls?, signerInfos }
 * EncapsulatedContentInfo ::= SEQUENCE { eContentType, eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 * TSTInfo ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     policy         TSAPolicyId,
 *     messageImprint MessageImprint,
 *     serialNumber   INTEGER,
 *     genTime        GeneralizedTime,
 *     accuracy       Accuracy OPTIONAL,
 *     ordering       BOOLEAN DEFAULT FALSE,
 *     nonce          INTEGER OPTIONAL,
 *     tsa            [0] GeneralName OPTIONAL,
 *     extensions     [1] IMPLICIT Extensions OPTIONAL }
 * ```
 *
 * This class walks the outer layers by their fixed positions, checks the two content types and the TSTInfo version,
 * and reads the imprint, the policy, the serial number, the time and the nonce. It is what RFC 9921 section 4 needs:
 * "the receiver MUST make sure that the MessageImprint in the embedded timestamp token matches a hash of either the
 * payload, signature, or signature fields", which {@see TimestampBinding} does with {@see getMessageImprint()}.
 *
 * What it does not do, and what nothing in this library does: verify the TSA's signature over the TSTInfo, validate
 * the TSA's certificate, check the token against a policy, or read the accuracy, the ordering flag, the TSA name and
 * the extensions. A TSTInfo whose imprint matches is a claim by whoever signed the token, and the claim is worth
 * what the signature is worth: "[RFC5652] provides details about signature verification, and [RFC3161] provides
 * details specific to timestamp token validation" (RFC 9921 section 4). spomky-labs/pki-framework has no CMS layer;
 * the application, or a CMS implementation, takes {@see toDER()} from here. {@see getTstInfo()} is the decoded
 * structure for whoever wants the fields this class does not read.
 *
 * @see https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
 * @see https://www.rfc-editor.org/rfc/rfc5652#section-5
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-4
 * @see \Cose\Tests\Structure\Timestamp\TimeStampTokenTest
 */
final class TimeStampToken
{
    /**
     * id-signedData (RFC 5652 section 5.1): the content type of every TimeStampToken.
     */
    public const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

    /**
     * id-ct-TSTInfo (RFC 3161 section 2.4.2): "The value of eContentType MUST be id-ct-TSTInfo".
     */
    public const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

    private function __construct(
        private readonly string $der,
        private readonly Sequence $tstInfo,
        private readonly MessageImprint $messageImprint,
        private readonly string $policy,
        private readonly string $serialNumber,
        private readonly DateTimeImmutable $genTime,
        private readonly ?string $nonce
    ) {
    }

    /**
     * The token read out of its DER encoding, the bytes a "3161-ttc" or "3161-ctt" header parameter carries.
     *
     * @throws InvalidArgumentException when the bytes are not one DER element and nothing else, when the outer
     * ContentInfo is not id-signedData, when the encapsulated content is not id-ct-TSTInfo or is absent, when the
     * TSTInfo is not version 1 or does not decode
     */
    public static function fromDER(string $der): self
    {
        try {
            $offset = 0;
            $contentInfo = Element::fromDER($der, $offset);
        } catch (Throwable $e) {
            throw new InvalidArgumentException(sprintf('Invalid TimeStampToken. The bytes are not DER: %s', $e->getMessage()), 0, $e);
        }
        if ($offset !== strlen($der)) {
            throw new InvalidArgumentException('Invalid TimeStampToken. The DER encoding is followed by trailing bytes.');
        }

        try {
            $contentInfo = UnspecifiedType::fromElementBase($contentInfo)->asSequence();
            if ($contentInfo->count() !== 2) {
                throw new InvalidArgumentException(sprintf('the ContentInfo shall carry a contentType and a content, got %d elements', $contentInfo->count()));
            }
            $contentType = $contentInfo->at(0)
                ->asObjectIdentifier()
                ->oid();
            if ($contentType !== self::OID_SIGNED_DATA) {
                throw new InvalidArgumentException(sprintf('the contentType shall be id-signedData (%s), got %s', self::OID_SIGNED_DATA, $contentType));
            }
            $signedData = $contentInfo->at(1)
                ->asTagged()
                ->asExplicit(0)
                ->asSequence();
            if ($signedData->count() < 4) {
                throw new InvalidArgumentException(sprintf('the SignedData shall carry at least a version, digestAlgorithms, encapContentInfo and signerInfos, got %d elements', $signedData->count()));
            }
            $encapContentInfo = $signedData->at(2)
                ->asSequence();
            $eContentType = $encapContentInfo->at(0)
                ->asObjectIdentifier()
                ->oid();
            if ($eContentType !== self::OID_TST_INFO) {
                throw new InvalidArgumentException(sprintf('the eContentType shall be id-ct-TSTInfo (%s), got %s', self::OID_TST_INFO, $eContentType));
            }
            if ($encapContentInfo->count() !== 2) {
                throw new InvalidArgumentException('the eContent is absent, the SignedData carries no TSTInfo');
            }
            $eContent = $encapContentInfo->at(1)
                ->asTagged()
                ->asExplicit(0)
                ->asOctetString()
                ->string();
            $tstInfo = self::tstInfo($der, $eContent);
        } catch (InvalidArgumentException $e) {
            throw new InvalidArgumentException('Invalid TimeStampToken. ' . $e->getMessage() . ' (RFC 3161 section 2.4.2).', 0, $e);
        } catch (Throwable $e) {
            throw new InvalidArgumentException(sprintf('Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2): %s', $e->getMessage()), 0, $e);
        }

        return $tstInfo;
    }

    /**
     * The token as carried: the bytes to hand to a CMS implementation for the validation this library does not do.
     */
    public function toDER(): string
    {
        return $this->der;
    }

    /**
     * The MessageImprint the TSA signed: the hash the token stands for, with its algorithm.
     */
    public function getMessageImprint(): MessageImprint
    {
        return $this->messageImprint;
    }

    /**
     * The TSA policy under which the token was issued (RFC 3161 section 2.4.2, "policy"), as a dotted OID. Whether
     * the policy is acceptable is the application's decision.
     */
    public function getPolicy(): string
    {
        return $this->policy;
    }

    /**
     * The serial number of the token, "unique for each TimeStampToken issued by a given TSA" (RFC 3161 section
     * 2.4.2), as a decimal string since it "MUST" be able to reach 160 bits.
     */
    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }

    /**
     * The time the TSA asserts, "the time at which the timestamp token has been created by the TSA" (RFC 3161 section
     * 2.4.2), in UTC.
     *
     * RFC 9921 section 5.1 on what the time means: in "3161-ttc" mode it is when the payload existed, in "3161-ctt"
     * mode when the signature existed. "Validators must not interpret protected-header payload timestamps as proof of
     * signature creation time".
     */
    public function getGenTime(): DateTimeImmutable
    {
        return $this->genTime;
    }

    /**
     * The nonce the request carried, echoed back by the TSA (RFC 3161 section 2.4.2), as a decimal string, or null
     * when the request carried none. An application that sent a nonce compares it here.
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * The decoded TSTInfo, for the fields this class does not read: accuracy, ordering, tsa, extensions.
     */
    public function getTstInfo(): Sequence
    {
        return $this->tstInfo;
    }

    /**
     * The TSTInfo, by the positions of its five mandatory fields, then the optional ones by type: accuracy is a
     * SEQUENCE, ordering a BOOLEAN, nonce an INTEGER, and tsa and extensions are tagged, so the first INTEGER after
     * genTime is the nonce.
     */
    private static function tstInfo(string $der, string $eContent): self
    {
        $offset = 0;
        $element = Element::fromDER($eContent, $offset);
        if ($offset !== strlen($eContent)) {
            throw new InvalidArgumentException('the eContent is followed by trailing bytes');
        }
        $tstInfo = UnspecifiedType::fromElementBase($element)->asSequence();
        if ($tstInfo->count() < 5) {
            throw new InvalidArgumentException(sprintf('the TSTInfo shall carry at least a version, policy, messageImprint, serialNumber and genTime, got %d elements', $tstInfo->count()));
        }
        $version = $tstInfo->at(0)
            ->asInteger()
            ->number();
        if ($version !== '1') {
            throw new InvalidArgumentException(sprintf('the TSTInfo version shall be 1, got %s', $version));
        }
        $policy = $tstInfo->at(1)
            ->asObjectIdentifier()
            ->oid();
        $messageImprint = MessageImprint::fromASN1($tstInfo->at(2));
        $serialNumber = $tstInfo->at(3)
            ->asInteger()
            ->number();
        $genTime = $tstInfo->at(4)
            ->asGeneralizedTime()
            ->dateTime();

        $nonce = null;
        for ($index = 5; $index < $tstInfo->count(); $index++) {
            $optional = $tstInfo->at($index);
            if ($optional->isTagged()) {
                break;
            }
            if ($optional->isType(Element::TYPE_INTEGER)) {
                $nonce = $optional->asInteger()
                    ->number();
                break;
            }
        }

        return new self($der, $tstInfo, $messageImprint, $policy, $serialNumber, $genTime, $nonce);
    }
}
