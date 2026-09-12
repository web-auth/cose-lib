<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use Cose\Algorithm\Algorithm;
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Algorithm\Mac\AesCbcMac;
use Cose\Algorithm\Mac\Hmac;
use Cose\Key\Ec2Key;
use Cose\Key\OkpKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use InvalidArgumentException;
use function is_int;
use function sprintf;

/**
 * One recipient layer as a key management algorithm sees it: the headers of the COSE_recipient, its ciphertext,
 * and what the algorithm needs to know about the key it protects.
 *
 * The last part is what a bare COSE_recipient does not say. RFC 9053 section 5.2 binds the derived key to "the
 * algorithm for which the key material will be used" and to its length -- "either a key wrap algorithm identifier
 * or a content encryption algorithm identifier" -- so a layer names them: the content encryption or MAC algorithm
 * of the message for a recipient of the content layer, the key wrap algorithm of the recipient above for a nested
 * one (RFC 9052 Appendix B). Two facts about the recipient list complete it, because RFC 9052 section 8.5.1 and
 * 8.5.4 forbid a direct recipient to have siblings: whether the recipient is alone at its level, and whether it
 * carries recipients of its own.
 *
 * On the receiving side, fromRecipient() reads a decoded {@see CoseRecipient}. On the sending side, create() takes
 * the headers the sender chose. Either way, the optional parts are set with the with*() methods: the sender's static
 * key of an ECDH-SS agreement (the sender's private key on one side, the sender's public key -- resolved by the
 * application from "static key id", "x5t-sender", "x5u-sender" or a validated "x5chain-sender" -- on the other), and
 * the SuppPubInfo "other" and SuppPrivInfo the application may define for the COSE_KDF_Context.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.2
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-8.5
 * @see \Cose\Tests\Algorithm\KeyManagement\RecipientLayerTest
 */
final class RecipientLayer
{
    private function __construct(
        private readonly CoseHeaders $headers,
        private readonly ?string $ciphertext,
        private readonly int $algorithm,
        private readonly int $keyLength,
        private readonly bool $onlyRecipient,
        private readonly bool $hasRecipients,
        private Ec2Key|OkpKey|null $senderKey = null,
        private ?PartyInfo $partyU = null,
        private ?PartyInfo $partyV = null,
        private ?string $suppPubInfoOther = null,
        private ?string $suppPrivInfo = null
    ) {
        if ($keyLength <= 0) {
            throw new InvalidArgumentException('The key length of a recipient layer is a positive number of bytes.');
        }
    }

    /**
     * The receiving side: the layer of a decoded COSE_recipient.
     *
     * @param Algorithm|int $for the algorithm the key this recipient protects is for -- the content encryption or
     *                           MAC algorithm of the message, or the key wrap algorithm of the recipient above --
     *                           as an instance, or as its identifier when $keyLength is given
     * @param int|null $keyLength the length of that key in bytes; resolved from the algorithm instance when null,
     *                            see keyLengthOf()
     * @param int $recipientCount the number of recipients at this level of the message, this one included
     */
    public static function fromRecipient(
        CoseRecipient $recipient,
        Algorithm|int $for,
        ?int $keyLength = null,
        int $recipientCount = 1
    ): self {
        return new self(
            $recipient->headers(),
            $recipient->hasDetachedCiphertext() ? null : $recipient->getCiphertext()
                ->getValue(),
            is_int($for) ? $for : $for::identifier(),
            $keyLength ?? self::keyLengthOf($for),
            $recipientCount === 1,
            $recipient->hasRecipients()
        );
    }

    /**
     * The sending side: the layer the sender is about to fill, from the headers it chose for the recipient.
     *
     * @param Algorithm|int $for as fromRecipient()
     * @param int $recipientCount the number of recipients the message will carry at this level, this one included
     */
    public static function create(
        CoseHeaders $headers,
        Algorithm|int $for,
        ?int $keyLength = null,
        int $recipientCount = 1
    ): self {
        return new self(
            $headers,
            null,
            is_int($for) ? $for : $for::identifier(),
            $keyLength ?? self::keyLengthOf($for),
            $recipientCount === 1,
            false
        );
    }

    /**
     * The length, in bytes, of the key an algorithm takes: what the COSE_KDF_Context calls the keyDataLength, in
     * bits there. It is the fixed key length of a content encryption, AES-CBC-MAC or key wrap algorithm, and the
     * length of the hash output for HMAC, which RFC 9053 section 3.1 says a derived HMAC key "SHOULD" have and which
     * the interoperability fixtures use.
     *
     * @throws InvalidArgumentException for an algorithm that takes no key of a fixed length: a signature algorithm,
     *                                  or a key management algorithm -- give the length explicitly then
     */
    public static function keyLengthOf(Algorithm|int $algorithm): int
    {
        return match (true) {
            $algorithm instanceof ContentEncryption, $algorithm instanceof KeyWrap, $algorithm instanceof AesCbcMac => $algorithm->keyLength(),
            $algorithm instanceof Hmac => $algorithm->minimumKeyLength(),
            default => throw new InvalidArgumentException(sprintf(
                'The key length of the algorithm %s cannot be inferred; give it explicitly.',
                is_int($algorithm) ? (string) $algorithm : $algorithm::class
            )),
        };
    }

    /**
     * With the sender's static key of an ECDH-SS agreement: the sender's private key on the sending side, the
     * sender's public key on the receiving side.
     *
     * The receiving side resolves it from whatever identifies the sender in the headers -- "static key id"
     * ({@see CoseHeaders::getStaticKeyId()}), "x5t-sender", "x5u-sender" or "x5chain-sender" -- and from what it
     * trusts. A key given here takes precedence over a "static key" (-2) the headers may carry, which is unauthenticated
     * input; when none is given, that header parameter is used.
     */
    public function withSenderKey(Ec2Key|OkpKey|null $senderKey): self
    {
        $clone = clone $this;
        $clone->senderKey = $senderKey;

        return $clone;
    }

    /**
     * With the PartyUInfo the application knows from its protocol: the identity, nonce or other information of the
     * party creating the message that the headers do not carry. What the headers do carry ("PartyU identity",
     * "PartyU nonce", "PartyU other") wins element by element, see {@see PartyInfo::completedWith()}.
     */
    public function withPartyU(?PartyInfo $partyU): self
    {
        $clone = clone $this;
        $clone->partyU = $partyU;

        return $clone;
    }

    /**
     * With the PartyVInfo the application knows from its protocol, completing the "PartyV *" header parameters the
     * same way.
     */
    public function withPartyV(?PartyInfo $partyV): self
    {
        $clone = clone $this;
        $clone->partyV = $partyV;

        return $clone;
    }

    /**
     * With the "other" of the SuppPubInfo of the COSE_KDF_Context, "free-form data defined by the application".
     */
    public function withSuppPubInfoOther(?string $other): self
    {
        $clone = clone $this;
        $clone->suppPubInfoOther = $other;

        return $clone;
    }

    /**
     * With the SuppPrivInfo of the COSE_KDF_Context, "mutually known private information" such as a pre-existing
     * shared secret.
     */
    public function withSuppPrivInfo(?string $suppPrivInfo): self
    {
        $clone = clone $this;
        $clone->suppPrivInfo = $suppPrivInfo;

        return $clone;
    }

    public function headers(): CoseHeaders
    {
        return $this->headers;
    }

    /**
     * The "ciphertext" field of the recipient as carried: the wrapped key, the zero-length byte string of a direct
     * recipient, or null when it is nil (detached) or when the layer is being built by the sender.
     */
    public function ciphertext(): ?string
    {
        return $this->ciphertext;
    }

    /**
     * The identifier of the algorithm the protected key is for.
     */
    public function algorithm(): int
    {
        return $this->algorithm;
    }

    /**
     * The length of the protected key, in bytes.
     */
    public function keyLength(): int
    {
        return $this->keyLength;
    }

    /**
     * Whether the recipient is the only one at its level of the message.
     */
    public function isOnlyRecipient(): bool
    {
        return $this->onlyRecipient;
    }

    /**
     * Whether the recipient carries recipients of its own.
     */
    public function hasRecipients(): bool
    {
        return $this->hasRecipients;
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
     * The COSE_KDF_Context of this layer for a key of the given algorithm and length: the party information comes
     * from the headers, completed with what the application supplied through withPartyU() and withPartyV(); the
     * protected bucket from the headers; the supplementary information from withSuppPubInfoOther() and
     * withSuppPrivInfo().
     *
     * The defaults are the algorithm and the length of the key the layer protects, which is what direct key
     * derivation and direct key agreement bind to. Key agreement with key wrap binds to the key wrap algorithm and
     * its key size instead (RFC 9053 section 6.4.1), and passes them.
     *
     * @param int|null $algorithm the AlgorithmID, this layer's by default
     * @param int|null $keyLength the key length in bytes, this layer's by default
     */
    public function kdfContext(?int $algorithm = null, ?int $keyLength = null): KdfContext
    {
        return KdfContext::create(
            $algorithm ?? $this->algorithm,
            ($keyLength ?? $this->keyLength) * 8,
            $this->headers->getProtectedHeader(),
            PartyInfo::partyUOf($this->headers)->completedWith($this->partyU ?? PartyInfo::none()),
            PartyInfo::partyVOf($this->headers)->completedWith($this->partyV ?? PartyInfo::none()),
            $this->suppPubInfoOther,
            $this->suppPrivInfo
        );
    }
}
