<?php

declare(strict_types=1);

namespace Cose\Encryption;

use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\KeyManagement\Direct;
use Cose\Algorithm\KeyManagement\KeyManagement;
use Cose\Algorithm\KeyManagement\KeyWrap;
use Cose\Algorithm\KeyManagement\PartyInfo;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

/**
 * One recipient a COSE_Encrypt is to be encrypted for: the key management algorithm, the recipient's key as the
 * sender holds it, and the headers the sender chooses for the COSE_recipient.
 *
 * This is the sending side's input to {@see EncryptStructure::encryptFor()}; the decoded, checked view of a
 * recipient on the wire is {@see \Cose\Structure\CoseRecipient}.
 *
 * The "alg" header parameter of the recipient is added when the headers carry none, in the bucket the algorithm
 * allows: the unprotected one for "direct" and the AES Key Wrap, whose protected bucket "MUST be empty" (RFC 9053
 * sections 6.1.1 and 6.2.1), the protected one otherwise, where it is bound into the derived key through the
 * COSE_KDF_Context. Headers given with an "alg" already are left as they are.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-5.1
 * @see \Cose\Tests\Encryption\EncryptForTest
 */
final class Recipient
{
    private function __construct(
        private readonly KeyManagement $algorithm,
        private readonly Key $key,
        private readonly MapObject $protectedHeader,
        private readonly MapObject $unprotectedHeader,
        private Ec2Key|OkpKey|null $senderKey = null,
        private ?PartyInfo $partyU = null,
        private ?PartyInfo $partyV = null,
        private ?string $suppPubInfoOther = null,
        private ?string $suppPrivInfo = null
    ) {
    }

    /**
     * @param Key $key the recipient's key as the sender holds it: the shared secret of a "direct", "direct+HKDF-*"
     *                 or AES Key Wrap recipient, the public key of an ECDH one
     * @param MapObject|null $protectedHeader the protected bucket of the recipient, empty by default
     * @param MapObject|null $unprotectedHeader the unprotected bucket of the recipient -- the "kid" of the
     *                                          recipient's key, the "salt", the PartyU and PartyV information --
     *                                          empty by default; the parameters the algorithm produces, such as the
     *                                          "ephemeral key", are added to it
     */
    public static function create(
        KeyManagement $algorithm,
        Key $key,
        ?MapObject $protectedHeader = null,
        ?MapObject $unprotectedHeader = null
    ): self {
        $protected = $protectedHeader ?? MapObject::create();
        $unprotected = $unprotectedHeader ?? MapObject::create();
        if (HeaderMapHelper::findLabel($protected, 1) === null && HeaderMapHelper::findLabel($unprotected, 1) === null) {
            $alg = MapItem::create(UnsignedIntegerObject::create(1), self::integer($algorithm::identifier()));
            if ($algorithm instanceof KeyWrap || $algorithm instanceof Direct) {
                $unprotected = self::with($unprotected, $alg);
            } else {
                $protected = self::with($protected, $alg);
            }
        }

        return new self($algorithm, $key, $protected, $unprotected);
    }

    /**
     * With the sender's static private key, which the ECDH-SS algorithms need; see
     * {@see RecipientLayer::withSenderKey()}.
     */
    public function withSenderKey(Ec2Key|OkpKey|null $senderKey): self
    {
        $clone = clone $this;
        $clone->senderKey = $senderKey;

        return $clone;
    }

    /**
     * With the PartyUInfo the protocol implies and the headers do not carry; see {@see RecipientLayer::withPartyU()}.
     */
    public function withPartyU(?PartyInfo $partyU): self
    {
        $clone = clone $this;
        $clone->partyU = $partyU;

        return $clone;
    }

    /**
     * With the PartyVInfo the protocol implies and the headers do not carry; see {@see RecipientLayer::withPartyV()}.
     */
    public function withPartyV(?PartyInfo $partyV): self
    {
        $clone = clone $this;
        $clone->partyV = $partyV;

        return $clone;
    }

    /**
     * With the "other" of the SuppPubInfo of the COSE_KDF_Context; see {@see RecipientLayer::withSuppPubInfoOther()}.
     */
    public function withSuppPubInfoOther(?string $other): self
    {
        $clone = clone $this;
        $clone->suppPubInfoOther = $other;

        return $clone;
    }

    /**
     * With the SuppPrivInfo of the COSE_KDF_Context; see {@see RecipientLayer::withSuppPrivInfo()}.
     */
    public function withSuppPrivInfo(?string $suppPrivInfo): self
    {
        $clone = clone $this;
        $clone->suppPrivInfo = $suppPrivInfo;

        return $clone;
    }

    public function algorithm(): KeyManagement
    {
        return $this->algorithm;
    }

    public function key(): Key
    {
        return $this->key;
    }

    public function protectedHeader(): MapObject
    {
        return $this->protectedHeader;
    }

    public function unprotectedHeader(): MapObject
    {
        return $this->unprotectedHeader;
    }

    public function senderKey(): Ec2Key|OkpKey|null
    {
        return $this->senderKey;
    }

    public function partyU(): ?PartyInfo
    {
        return $this->partyU;
    }

    public function partyV(): ?PartyInfo
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

    /**
     * The layer the algorithm runs against, for a key of the given algorithm, among the given number of recipients.
     *
     * @param int $recipientCount the number of recipients of the message, this one included
     */
    public function toLayer(Algorithm|int $for, ?int $keyLength = null, int $recipientCount = 1): RecipientLayer
    {
        return RecipientLayer::create(
            CoseHeaders::of(HeaderMapHelper::encodeProtected($this->protectedHeader), $this->unprotectedHeader),
            $for,
            $keyLength,
            $recipientCount
        )
            ->withSenderKey($this->senderKey)
            ->withPartyU($this->partyU)
            ->withPartyV($this->partyV)
            ->withSuppPubInfoOther($this->suppPubInfoOther)
            ->withSuppPrivInfo($this->suppPrivInfo);
    }

    /**
     * A copy of the map with the item added: the maps a caller hands over are never written to.
     */
    private static function with(MapObject $map, MapItem $item): MapObject
    {
        $items = [];
        foreach ($map as $existing) {
            $items[] = $existing;
        }
        $items[] = $item;

        return MapObject::create($items);
    }

    private static function integer(int $value): UnsignedIntegerObject|NegativeIntegerObject
    {
        return $value < 0 ? NegativeIntegerObject::create($value) : UnsignedIntegerObject::create($value);
    }
}
