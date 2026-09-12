<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_key_exists;
use function array_map;
use function array_values;
use Cose\Algorithm\KeyManagement\PartyInfo;
use Cose\Key\Key;
use function is_array;
use function is_string;
use LogicException;
use function sprintf;

/**
 * One signer or one recipient of a cose-wg/Examples fixture: its key, its headers and the intermediate values the
 * generator recorded for it.
 *
 * A COSE_Sign1 and a COSE_Mac0 have no such list, so their single party is the message block itself, and it is
 * exposed through the same class: a test walks the parties of a fixture the same way whatever the message type.
 *
 * @see CoseWgFixture
 */
final class CoseWgParty
{
    /**
     * @param array<string, mixed> $input the "signers[i]", "recipients[i]", "sign0" or "mac0" object
     * @param array<string, mixed> $intermediates the matching entry of "intermediates", empty when there is none
     */
    private function __construct(
        private readonly string $name,
        private readonly array $input,
        private readonly array $intermediates
    ) {
    }

    /**
     * @param array<string, mixed> $input
     * @param array<string, mixed> $intermediates
     */
    public static function create(string $name, array $input, array $intermediates = []): self
    {
        return new self($name, $input, $intermediates);
    }

    /**
     * The fixture name followed by the path of this party in it, e.g. "sign-tests/ecdsa-01 signers[0]".
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * The algorithm name the generator used for this party, wherever the fixture wrote it: as an "alg" of its own,
     * only inside one of its header buckets, or -- for an abbreviated countersigner, which has no header bucket --
     * among the values it used without sending.
     */
    public function algorithmName(): ?string
    {
        $name = $this->input['alg']
            ?? $this->protectedHeader()['alg']
            ?? $this->unprotectedHeader()['alg']
            ?? $this->unsentHeader()['alg']
            ?? null;

        return is_string($name) ? $name : null;
    }

    /**
     * The identifier of that algorithm, or null when the party names none or names one the table does not know.
     */
    public function algorithmIdentifier(): ?int
    {
        $name = $this->algorithmName();

        return $name === null ? null : CoseWgAlgorithms::identifierOf($name);
    }

    public function hasKey(): bool
    {
        return array_key_exists('key', $this->input);
    }

    /**
     * The key of this party as a COSE_Key: the private key for a signer, the shared or static key for a recipient.
     */
    public function key(): Key
    {
        return CoseWgKey::toCoseKey($this->object('key'));
    }

    /**
     * The sender's static key of an ECDH-SS recipient, when the fixture carries it.
     */
    public function senderKey(): ?Key
    {
        return $this->hasSenderKey() ? CoseWgKey::toCoseKey($this->object('sender_key')) : null;
    }

    public function hasSenderKey(): bool
    {
        return array_key_exists('sender_key', $this->input);
    }

    /**
     * @return array<string, mixed> the "protected" headers as the fixture writes them, by name
     */
    public function protectedHeader(): array
    {
        return $this->object('protected');
    }

    /**
     * @return array<string, mixed> the "unprotected" headers as the fixture writes them, by name
     */
    public function unprotectedHeader(): array
    {
        return $this->object('unprotected');
    }

    /**
     * @return array<string, mixed> the headers the generator used but did not send, by name
     */
    public function unsentHeader(): array
    {
        return $this->object('unsent');
    }

    /**
     * The full IV the generator encrypted with but did not send, when the message carries a "Partial IV" (RFC 9052
     * section 3.1) instead; null when the fixture records none.
     */
    public function unsentIv(): ?string
    {
        return $this->bytesOf($this->unsentHeader(), 'IV_hex');
    }

    /**
     * The external_aad this party's structure carries, or the empty string RFC 9052 section 4.4 defaults to.
     */
    public function externalAad(): string
    {
        return $this->bytesOf($this->input, 'external') ?? '';
    }

    /**
     * Whether the generator marked this recipient as one that must fail to unwrap.
     */
    public function mustFail(): bool
    {
        return ($this->input['fail'] ?? false) === true;
    }

    /**
     * The Sig_structure the generator signed, as recorded in the intermediates; null when it recorded none.
     */
    public function toBeSigned(): ?string
    {
        return $this->bytesOf($this->intermediates, 'ToBeSign_hex');
    }

    /**
     * The COSE_KDF_Context of a recipient, when recorded.
     */
    public function kdfContext(): ?string
    {
        return $this->bytesOf($this->intermediates, 'Context_hex');
    }

    /**
     * The ECDH shared secret of a recipient, when recorded.
     */
    public function sharedSecret(): ?string
    {
        return $this->bytesOf($this->intermediates, 'Secret_hex');
    }

    /**
     * The key-encryption key of a key agreement with key wrap recipient -- the output of the KDF -- when recorded.
     */
    public function keyEncryptionKey(): ?string
    {
        return $this->bytesOf($this->intermediates, 'KEK_hex');
    }

    /**
     * The PartyUInfo the generator used without sending it ("apu_id", "apu_nonce", "apu_other" of "unsent"): what
     * the application supplies to the derivation from its protocol. Null when the fixture records none.
     */
    public function unsentPartyU(): ?PartyInfo
    {
        return $this->unsentPartyInfo('apu');
    }

    /**
     * The PartyVInfo the generator used without sending it, likewise.
     */
    public function unsentPartyV(): ?PartyInfo
    {
        return $this->unsentPartyInfo('apv');
    }

    /**
     * The SuppPubInfo "other" the generator put into the COSE_KDF_Context ("pub_other" of "unsent"), when any.
     */
    public function suppPubInfoOther(): ?string
    {
        return $this->unsentText('pub_other');
    }

    /**
     * The SuppPrivInfo the generator put into the COSE_KDF_Context ("priv_other" of "unsent"), when any.
     */
    public function suppPrivInfo(): ?string
    {
        return $this->unsentText('priv_other');
    }

    /**
     * The recipients nested under this one, for the layered key management of RFC 9052 section 5.1.
     *
     * @return list<self>
     */
    public function recipients(): array
    {
        $recipients = $this->input['recipients'] ?? [];
        $intermediates = $this->intermediates['recipients'] ?? [];
        if (! is_array($recipients) || ! is_array($intermediates)) {
            throw new LogicException(sprintf('%s: the recipients are not a list', $this->name));
        }
        /** @var array<int, array<string, mixed>|mixed> $recipients */
        /** @var array<int, array<string, mixed>|mixed> $intermediates */

        return array_values(array_map(
            fn (int $index, mixed $recipient): self => self::create(
                sprintf('%s recipients[%d]', $this->name, $index),
                is_array($recipient) ? $recipient : throw new LogicException(
                    sprintf('%s: the recipient %d is not an object', $this->name, $index)
                ),
                is_array($intermediates[$index] ?? null) ? $intermediates[$index] : []
            ),
            array_keys($recipients),
            $recipients
        ));
    }

    /**
     * The full countersigners of this party: the "countersign.signers" list of the fixture, each with its key and
     * headers, paired with the "countersigners" intermediates. Empty when the party is not countersigned.
     *
     * @return list<self>
     */
    public function countersigners(): array
    {
        return $this->countersignerParties('countersign', 'countersigners');
    }

    /**
     * The abbreviated countersigners of this party: the "countersign0.signers" list, whose algorithm is among the
     * "unsent" values, paired with the "countersign0" intermediates.
     *
     * @return list<self>
     */
    public function countersigners0(): array
    {
        return $this->countersignerParties('countersign0', 'countersign0');
    }

    /**
     * @return list<self>
     */
    private function countersignerParties(string $block, string $intermediatesList): array
    {
        $signers = $this->object($block)['signers'] ?? [];
        $intermediates = $this->intermediates[$intermediatesList] ?? [];
        if (! is_array($signers) || ! is_array($intermediates)) {
            throw new LogicException(sprintf('%s: the %s signers are not a list', $this->name, $block));
        }
        /** @var array<int, array<string, mixed>|mixed> $signers */
        /** @var array<int, array<string, mixed>|mixed> $intermediates */

        return array_values(array_map(
            fn (int $index, mixed $signer): self => self::create(
                sprintf('%s %s[%d]', $this->name, $block, $index),
                is_array($signer) ? $signer : throw new LogicException(
                    sprintf('%s: the %s signer %d is not an object', $this->name, $block, $index)
                ),
                is_array($intermediates[$index] ?? null) ? $intermediates[$index] : []
            ),
            array_keys($signers),
            $signers
        ));
    }

    private function unsentPartyInfo(string $prefix): ?PartyInfo
    {
        $identity = $this->unsentText($prefix . '_id');
        $nonce = $this->unsentText($prefix . '_nonce');
        $other = $this->unsentText($prefix . '_other');
        if ($identity === null && $nonce === null && $other === null) {
            return null;
        }

        return PartyInfo::create($identity, $nonce, $other);
    }

    /**
     * The fixtures write the unsent context values as plain text, taken as bytes.
     */
    private function unsentText(string $field): ?string
    {
        $unsent = $this->unsentHeader();
        if (! array_key_exists($field, $unsent)) {
            return null;
        }
        $value = $unsent[$field];
        if (! is_string($value)) {
            throw new LogicException(sprintf('%s: "%s" is not a string', $this->name, $field));
        }

        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    private function object(string $field): array
    {
        $value = $this->input[$field] ?? [];
        if (! is_array($value)) {
            throw new LogicException(sprintf('%s: "%s" is not an object', $this->name, $field));
        }
        /** @var array<string, mixed> $value */

        return $value;
    }

    /**
     * @param array<string, mixed> $source
     */
    private function bytesOf(array $source, string $field): ?string
    {
        if (! array_key_exists($field, $source)) {
            return null;
        }
        $value = $source[$field];
        if (! is_string($value)) {
            throw new LogicException(sprintf('%s: "%s" is not a hex string', $this->name, $field));
        }

        return CoseWgFixture::bytes($value, sprintf('%s "%s"', $this->name, $field));
    }
}
