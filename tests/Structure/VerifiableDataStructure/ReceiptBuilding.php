<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\VerifiableDataStructure;

use function array_map;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256ConsistencyProof;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256InclusionProof;
use function hex2bin;
use function is_int;

/**
 * Receipts as RFC 9942 shapes them, built from their parts, for the tests of the verifiable data structure classes.
 *
 * The signing key is the P-256 key of RFC 9052 Appendix C.7.1 (kid "11"), the one the cose-wg fixtures sign with,
 * so that a receipt built here can be checked against another implementation if the need arises.
 */
trait ReceiptBuilding
{
    /**
     * The "vdp" map of RFC 9942 section 5: {-1: [proofs...]} and/or {-2: [proofs...]}, from the typed proofs.
     *
     * @param list<Rfc9162Sha256InclusionProof> $inclusion
     * @param list<Rfc9162Sha256ConsistencyProof> $consistency
     */
    private static function vdp(array $inclusion = [], array $consistency = []): MapObject
    {
        $items = [];
        if ($inclusion !== []) {
            $items[] = MapItem::create(
                NegativeIntegerObject::create(Rfc9162Sha256::LABEL_INCLUSION_PROOF),
                ListObject::create(array_map(static fn (Rfc9162Sha256InclusionProof $p): ByteStringObject => $p->toCBOR(), $inclusion))
            );
        }
        if ($consistency !== []) {
            $items[] = MapItem::create(
                NegativeIntegerObject::create(Rfc9162Sha256::LABEL_CONSISTENCY_PROOF),
                ListObject::create(array_map(static fn (Rfc9162Sha256ConsistencyProof $p): ByteStringObject => $p->toCBOR(), $consistency))
            );
        }

        return MapObject::create($items);
    }

    /**
     * The protected header of a receipt, section 5.2.1: {1: alg, 395: vds}, plus whatever else is given.
     *
     * @param array<int, CBORObject> $extra
     */
    private static function receiptProtectedHeader(?int $alg = -7, int|CBORObject|null $vds = 1, array $extra = []): ByteStringObject
    {
        $items = [];
        if ($alg !== null) {
            $items[] = MapItem::create(UnsignedIntegerObject::create(1), $alg < 0 ? NegativeIntegerObject::create($alg) : UnsignedIntegerObject::create($alg));
        }
        if ($vds !== null) {
            $items[] = MapItem::create(
                UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS),
                is_int($vds) ? ($vds < 0 ? NegativeIntegerObject::create($vds) : UnsignedIntegerObject::create($vds)) : $vds
            );
        }
        foreach ($extra as $label => $value) {
            $items[] = MapItem::create($label < 0 ? NegativeIntegerObject::create($label) : UnsignedIntegerObject::create($label), $value);
        }

        return HeaderMapHelper::encodeProtected(MapObject::create($items));
    }

    /**
     * The headers of a receipt, as CoseHeaders, without a message around them.
     */
    private static function receiptHeaders(ByteStringObject $protectedHeader, ?MapObject $vdp): CoseHeaders
    {
        $unprotected = $vdp === null
            ? MapObject::create()
            : MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), $vdp)]);

        return CoseHeaders::of($protectedHeader, $unprotected);
    }

    /**
     * A receipt signed with ES256 over the given payload -- the tree head -- which is detached from the message
     * unless $attach says otherwise, as RFC 9942 section 4.4 recommends.
     */
    private static function signedReceipt(
        ByteStringObject $protectedHeader,
        MapObject $unprotectedHeader,
        string $payload,
        bool $attach = false,
        ?ByteStringObject $externalAad = null,
        ?Ec2Key $key = null
    ): CoseSign1Tag {
        $key ??= self::issuerKey();
        $structure = Signature1::create($protectedHeader, ByteStringObject::create($payload), $externalAad);
        $signature = ES256::create()->sign((string) $structure, $key);

        return self::receipt($protectedHeader, $unprotectedHeader, $attach ? ByteStringObject::create($payload) : NullObject::create(), $signature);
    }

    private static function receipt(
        ByteStringObject $protectedHeader,
        MapObject $unprotectedHeader,
        CBORObject $payload,
        string $signature
    ): CoseSign1Tag {
        return CoseSign1Tag::create(ListObject::create([
            $protectedHeader,
            $unprotectedHeader,
            $payload,
            ByteStringObject::create($signature),
        ]));
    }

    /**
     * A message carrying the given receipts in the "receipts" header parameter, as bytes decoded back, so that what
     * the accessor sees is what travels.
     *
     * @param list<CoseSign1Tag> $receipts
     */
    private static function messageWithReceipts(array $receipts, bool $protected = false): CoseSign1Tag
    {
        $list = ListObject::create(array_map(
            static fn (CoseSign1Tag $receipt): ByteStringObject => ByteStringObject::create((string) $receipt),
            $receipts
        ));
        $item = MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_RECEIPTS), $list);
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create($protected ? [$item] : []));
        $unprotectedHeader = MapObject::create($protected ? [] : [$item]);
        $message = CoseSign1Tag::create(ListObject::create([
            $protectedHeader,
            $unprotectedHeader,
            ByteStringObject::create('the signed statement'),
            ByteStringObject::create('signature'),
        ]));
        $decoded = Decoder::create()->decode(StringStream::create((string) $message));
        static::assertInstanceOf(CoseSign1Tag::class, $decoded);

        return $decoded;
    }

    /**
     * The P-256 key pair of RFC 9052 Appendix C.7.1, "11".
     */
    private static function issuerKey(): Ec2Key
    {
        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => hex2bin('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff'),
            Ec2Key::DATA_Y => hex2bin('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e'),
            Ec2Key::DATA_D => hex2bin('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'),
        ]);
    }
}
