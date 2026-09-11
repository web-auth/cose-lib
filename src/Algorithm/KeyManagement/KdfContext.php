<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use CBOR\ByteStringObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\ListObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\CoseStructure;
use InvalidArgumentException;
use Stringable;

/**
 * The COSE_KDF_Context of RFC 9053 section 5.2: the "info" of every HKDF run in COSE, which binds the derived key
 * to the algorithm it is for, its length, the two parties, and the protected header of the recipient.
 *
 * COSE_KDF_Context = [
 *     AlgorithmID : int / tstr,
 *     PartyUInfo : [ PartyInfo ],
 *     PartyVInfo : [ PartyInfo ],
 *     SuppPubInfo : [ keyDataLength : uint, protected : empty_or_serialized_map, ? other : bstr ],
 *     ? SuppPrivInfo : bstr
 * ]
 *
 * Built exactly as the CDDL says: the two PartyInfo arrays are always three items, nil where nothing is known; the
 * keyDataLength is in bits; the protected field is the serialized protected bucket of the recipient as it travels,
 * or the zero-length byte string when it is empty (in either of the two forms RFC 9052 section 3 allows, see
 * {@see CoseStructure::emptyOrSerializedMap()}); "other" and SuppPrivInfo are present only when the application
 * defines them. The AlgorithmID is "either a key wrap algorithm identifier or a content encryption algorithm
 * identifier": the key the derivation is for, never the key management algorithm running it.
 *
 * Casting an instance to string yields the CBOR encoding, which is what goes into the KDF.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
 * @see \Cose\Tests\Algorithm\KeyManagement\KdfContextTest
 */
final class KdfContext implements Stringable
{
    private function __construct(
        private readonly int $algorithm,
        private readonly int $keyDataLength,
        private readonly ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader,
        private readonly PartyInfo $partyU,
        private readonly PartyInfo $partyV,
        private readonly ?string $suppPubInfoOther,
        private readonly ?string $suppPrivInfo
    ) {
        if ($keyDataLength <= 0) {
            throw new InvalidArgumentException('The keyDataLength of a COSE_KDF_Context is a positive number of bits.');
        }
    }

    /**
     * @param int $algorithm the identifier of the algorithm the derived key is for
     * @param int $keyDataLength the length of the derived key, in bits
     * @param ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader the protected bucket of the
     *                                                                           recipient, as carried
     * @param string|null $suppPubInfoOther the "other" of SuppPubInfo, when the application defines one
     * @param string|null $suppPrivInfo the SuppPrivInfo, when the application defines one
     */
    public static function create(
        int $algorithm,
        int $keyDataLength,
        ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader,
        ?PartyInfo $partyU = null,
        ?PartyInfo $partyV = null,
        ?string $suppPubInfoOther = null,
        ?string $suppPrivInfo = null
    ): self {
        return new self(
            $algorithm,
            $keyDataLength,
            $protectedHeader,
            $partyU ?? PartyInfo::none(),
            $partyV ?? PartyInfo::none(),
            $suppPubInfoOther,
            $suppPrivInfo
        );
    }

    public function algorithm(): int
    {
        return $this->algorithm;
    }

    /**
     * In bits.
     */
    public function keyDataLength(): int
    {
        return $this->keyDataLength;
    }

    public function protectedHeader(): ByteStringObject|IndefiniteLengthByteStringObject
    {
        return $this->protectedHeader;
    }

    public function partyU(): PartyInfo
    {
        return $this->partyU;
    }

    public function partyV(): PartyInfo
    {
        return $this->partyV;
    }

    public function suppPubInfoOther(): ?string
    {
        return $this->suppPubInfoOther;
    }

    public function suppPrivInfo(): ?string
    {
        return $this->suppPrivInfo;
    }

    public function toCBOR(): ListObject
    {
        $suppPubInfo = [
            UnsignedIntegerObject::create($this->keyDataLength),
            CoseStructure::emptyOrSerializedMap($this->protectedHeader),
        ];
        if ($this->suppPubInfoOther !== null) {
            $suppPubInfo[] = ByteStringObject::create($this->suppPubInfoOther);
        }
        $items = [
            $this->algorithm < 0
                ? NegativeIntegerObject::create($this->algorithm)
                : UnsignedIntegerObject::create($this->algorithm),
            $this->partyU->toCBOR(),
            $this->partyV->toCBOR(),
            ListObject::create($suppPubInfo),
        ];
        if ($this->suppPrivInfo !== null) {
            $items[] = ByteStringObject::create($this->suppPrivInfo);
        }

        return ListObject::create($items);
    }

    public function __toString(): string
    {
        return (string) $this->toCBOR();
    }
}
