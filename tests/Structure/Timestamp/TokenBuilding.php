<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\Timestamp;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\UnsignedIntegerObject;
use Cose\Key\Ec2Key;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\Timestamp\MessageImprint;
use Cose\Structure\Timestamp\TimeStampToken;
use DateTimeImmutable;
use function file_get_contents;
use function hex2bin;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;

/**
 * Timestamp tokens and timestamped messages, built from their parts, for the tests of the RFC 9921 classes.
 *
 * The tokens built here are unsigned: a CMS SignedData with an empty signerInfos set around a TSTInfo. That is
 * enough for what the library reads (the TSTInfo) and for what the tests check (the binding of the imprint), and it
 * is the point: the library never verifies the TSA's signature, so a test that relied on one would be testing
 * nothing this library does. The two genuine tokens of RFC 9921 Appendix A are under tests/fixtures/rfc9921/.
 *
 * The messages are those of RFC 9052 Appendix C.2.1 (COSE_Sign1) and C.1.1 (COSE_Sign), the ones RFC 9921 section
 * 3.1 computes its imprints over, signed with the P-256 key "11" of RFC 9052 Appendix C.7.1.
 */
trait TokenBuilding
{
    private const FIXTURES = __DIR__ . '/../../fixtures/rfc9921';

    /**
     * The SHA-256 OID, as RFC 9921 section 3.1.1 writes it: "OBJECT IDENTIFIER sha-256 (2 16 840 1 101 3 4 2 1)".
     */
    private const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

    /**
     * The signature of the COSE_Sign1 of RFC 9052 Appendix C.2.1, as RFC 9921 section 3.1.1 quotes it.
     */
    private const RFC9052_C_2_1_SIGNATURE = '8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36';

    /**
     * The signature of the COSE_Sign of RFC 9052 Appendix C.1.1, as RFC 9921 section 3.1.2 quotes it.
     */
    private const RFC9052_C_1_1_SIGNATURE = 'e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a';

    /**
     * The SHA-256 imprints RFC 9921 prints: section 3.1.1 (CTT, COSE_Sign1), section 3.1.2 (CTT, COSE_Sign) and
     * Appendix A.1 (TTC, the payload).
     */
    private const IMPRINT_CTT_SIGN1 = '44c2419d131d53d55584b5dd33b788c24e551c6d44b1afc8b2b85e6954763b4e';

    private const IMPRINT_CTT_SIGN = '803fada2912d6b7a833a27bd961cc05bc1cc164759b1c56f7aa771e4e21526f7';

    private const IMPRINT_TTC = '09e638d4aa95fd7271866203595303bce232f462a94d38e393773cd3aae3f6b0';

    private const PAYLOAD = 'This is the content.';

    private static function fixture(string $name): string
    {
        $bytes = file_get_contents(self::FIXTURES . '/' . $name);
        static::assertNotFalse($bytes);

        return $bytes;
    }

    /**
     * The P-256 key "11" of RFC 9052 Appendix C.7.1, public part only: the tests verify, they do not sign.
     */
    private static function key11(): Ec2Key
    {
        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => hex2bin('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff'),
            Ec2Key::DATA_Y => hex2bin('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e'),
        ]);
    }

    /**
     * A TSTInfo (RFC 3161 section 2.4.2) over the given imprint, with the optional fields the caller asks for, in
     * the order the ASN.1 module gives them: accuracy, ordering, nonce, tsa.
     */
    private static function tstInfo(
        MessageImprint $imprint,
        string $genTime = '2025-08-29T07:45:46Z',
        int|string|null $nonce = null,
        bool $accuracy = false,
        ?bool $ordering = null,
        bool $tsa = false,
        int $version = 1,
        string $policy = '1.2.3.4.1',
        string $serialNumber = '12096870'
    ): Sequence {
        $elements = [
            Integer::create($version),
            ObjectIdentifier::create($policy),
            $imprint->toASN1(),
            Integer::create($serialNumber),
            GeneralizedTime::create(new DateTimeImmutable($genTime)),
        ];
        if ($accuracy) {
            // Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER OPTIONAL, micros [1] INTEGER OPTIONAL }
            $elements[] = Sequence::create(Integer::create(1));
        }
        if ($ordering !== null) {
            $elements[] = Boolean::create($ordering);
        }
        if ($nonce !== null) {
            $elements[] = Integer::create($nonce);
        }
        if ($tsa) {
            // tsa [0] GeneralName, here a directoryName [4] of an empty Name
            $elements[] = ExplicitlyTaggedType::create(0, ExplicitlyTaggedType::create(4, Sequence::create()));
        }

        return Sequence::create(...$elements);
    }

    /**
     * An unsigned TimeStampToken: ContentInfo { id-signedData, [0] SignedData { 3, {}, { id-ct-TSTInfo, [0] eContent }, {} } }.
     */
    private static function token(
        Sequence $tstInfo,
        string $contentType = TimeStampToken::OID_SIGNED_DATA,
        string $eContentType = TimeStampToken::OID_TST_INFO,
        ?string $eContent = null
    ): string {
        $eContent ??= $tstInfo->toDER();
        $encapContentInfo = Sequence::create(
            ObjectIdentifier::create($eContentType),
            ExplicitlyTaggedType::create(0, OctetString::create($eContent))
        );

        return Sequence::create(
            ObjectIdentifier::create($contentType),
            ExplicitlyTaggedType::create(0, Sequence::create(
                Integer::create(3),
                Set::create(),
                $encapContentInfo,
                Set::create()
            ))
        )->toDER();
    }

    /**
     * An unsigned token over the given imprint, with a nonce when asked.
     */
    private static function tokenOver(MessageImprint $imprint, int|string|null $nonce = null): string
    {
        return self::token(self::tstInfo($imprint, nonce: $nonce));
    }

    /**
     * The COSE_Sign1 of RFC 9052 Appendix C.2.1, the message of RFC 9921 sections 3.1.1 and A.2: {1: -7} protected,
     * {4: '11'} unprotected, 'This is the content.', the signature of the RFC; with more entries in either bucket
     * when given.
     *
     * @param list<MapItem> $protected
     * @param list<MapItem> $unprotected
     */
    private static function sign1(array $protected = [], array $unprotected = [], ?string $signature = null): CoseSign1Tag
    {
        return CoseSign1Tag::create(ListObject::create([
            HeaderMapHelper::encodeProtected(MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
                ...$protected,
            ])),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('11')),
                ...$unprotected,
            ]),
            ByteStringObject::create(self::PAYLOAD),
            ByteStringObject::create(hex2bin($signature ?? self::RFC9052_C_2_1_SIGNATURE)),
        ]));
    }

    /**
     * The COSE_Sign of RFC 9052 Appendix C.1.1, the message of RFC 9921 section 3.1.2: h'' protected, {} unprotected,
     * 'This is the content.', one signer with {1: -7} protected, {4: '11'} unprotected and the signature of the RFC.
     *
     * @param list<MapItem> $unprotected entries of the body's unprotected bucket
     */
    private static function sign(array $unprotected = [], ?string $protected = null): CoseSignTag
    {
        return CoseSignTag::create(ListObject::create([
            ByteStringObject::create($protected ?? ''),
            MapObject::create($unprotected),
            ByteStringObject::create(self::PAYLOAD),
            ListObject::create([
                ListObject::create([
                    HeaderMapHelper::encodeProtected(MapObject::create([
                        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
                    ])),
                    MapObject::create([
                        MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('11')),
                    ]),
                    ByteStringObject::create(hex2bin(self::RFC9052_C_1_1_SIGNATURE)),
                ]),
            ]),
        ]));
    }

    /**
     * A "3161-ttc" or "3161-ctt" header entry around a DER token.
     */
    private static function tokenEntry(int $label, string $der): MapItem
    {
        return MapItem::create(UnsignedIntegerObject::create($label), ByteStringObject::create($der));
    }

    private static function ttcEntry(string $der): MapItem
    {
        return self::tokenEntry(CoseHeaders::LABEL_3161_TTC, $der);
    }

    private static function cttEntry(string $der): MapItem
    {
        return self::tokenEntry(CoseHeaders::LABEL_3161_CTT, $der);
    }
}
