<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\ListObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\CoseHeaders;
use function is_int;

/**
 * The PartyInfo of a COSE_KDF_Context (RFC 9053 section 5.2): who one of the two parties of a key derivation is.
 *
 * PartyInfo = ( identity : bstr / nil, nonce : bstr / int / nil, other : bstr / nil )
 *
 * "The identity information does not need to be specified and is set to nil in that case" -- and so for the nonce
 * and the other information: an absent element is encoded as nil, never omitted, so the array is always three
 * items long. PartyU is "the entity that is creating the message and PartyV [...] the entity that is receiving
 * the message"; forHeaders() reads either from the header parameters of table 10, which is where a sender puts
 * what it wants the recipient to see. An application that knows the identities from its protocol builds the
 * value directly.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
 */
final class PartyInfo
{
    private function __construct(
        private readonly ?string $identity,
        private readonly string|int|null $nonce,
        private readonly ?string $other
    ) {
    }

    public static function create(?string $identity = null, string|int|null $nonce = null, ?string $other = null): self
    {
        return new self($identity, $nonce, $other);
    }

    /**
     * Nothing known about the party: [nil, nil, nil].
     */
    public static function none(): self
    {
        return new self(null, null, null);
    }

    /**
     * The PartyUInfo the recipient headers carry: "PartyU identity" (-21), "PartyU nonce" (-22), "PartyU other" (-23).
     */
    public static function partyUOf(CoseHeaders $headers): self
    {
        return new self($headers->getPartyUIdentity(), $headers->getPartyUNonce(), $headers->getPartyUOther());
    }

    /**
     * The PartyVInfo the recipient headers carry: "PartyV identity" (-24), "PartyV nonce" (-25), "PartyV other" (-26).
     */
    public static function partyVOf(CoseHeaders $headers): self
    {
        return new self($headers->getPartyVIdentity(), $headers->getPartyVNonce(), $headers->getPartyVOther());
    }

    /**
     * This party information completed with another: each element this one lacks is taken from the other. The
     * headers of a recipient carry what the sender chose to send; the application fills in what "is often known as
     * part of the protocol and can thus be inferred rather than made explicit" (RFC 9053 section 5.2).
     */
    public function completedWith(self $other): self
    {
        return new self(
            $this->identity ?? $other->identity,
            $this->nonce ?? $other->nonce,
            $this->other ?? $other->other
        );
    }

    public function identity(): ?string
    {
        return $this->identity;
    }

    public function nonce(): string|int|null
    {
        return $this->nonce;
    }

    public function other(): ?string
    {
        return $this->other;
    }

    /**
     * Whether the party carries a nonce: what RFC 9053 sections 6.1.2 and 6.3.1 let stand in for the HKDF salt.
     */
    public function hasNonce(): bool
    {
        return $this->nonce !== null;
    }

    /**
     * The three-item array of the CDDL.
     */
    public function toCBOR(): ListObject
    {
        return ListObject::create([
            self::byteStringOrNil($this->identity),
            $this->nonce === null ? NullObject::create() : self::nonceObject($this->nonce),
            self::byteStringOrNil($this->other),
        ]);
    }

    private static function byteStringOrNil(?string $value): CBORObject
    {
        return $value === null ? NullObject::create() : ByteStringObject::create($value);
    }

    private static function nonceObject(string|int $nonce): CBORObject
    {
        if (! is_int($nonce)) {
            return ByteStringObject::create($nonce);
        }

        return $nonce < 0 ? NegativeIntegerObject::create($nonce) : UnsignedIntegerObject::create($nonce);
    }
}
