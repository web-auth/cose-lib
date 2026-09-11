<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use CBOR\MapObject;
use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\KeyRestrictionEnforcement;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use InvalidArgumentException;
use function is_string;
use function sprintf;

/**
 * "direct+HKDF-*" (RFC 9053 section 6.1.2): "take a common shared secret between the two parties and apply the HKDF
 * function (Section 5.1), using the context structure defined in Section 5.2 to transform the shared secret into
 * the CEK".
 *
 * The four identifiers of table 12 differ by their {@see Hkdf}: HMAC with SHA-256 or SHA-512, extract and expand;
 * or AES-CBC-MAC with a 128- or 256-bit key, expand only, the shared secret being the PRK and having to be exactly
 * that long. The derived key is as long as the layer below needs; the COSE_KDF_Context names that layer's
 * algorithm and length, and embeds the protected bucket of the recipient, which "can be of nonzero length" here --
 * the fixtures of cose-wg/Examples carry "alg" in it.
 *
 * "Either the 'salt' parameter for HKDF (Table 9) or the 'PartyU nonce' parameter for the context structure
 * (Table 10) MUST be present" and "be a unique value for the shared secret in question". The sending side refuses
 * to derive without one of the two; the receiving side derives with whatever the message carries, so that a
 * message from a sender that omitted both still opens. For the AES variants the salt, even when present, "is not
 * used as part of the HKDF functionality" (section 5.1): only the nonce then makes the key differ per message.
 *
 * The key checks of section 6.1.2 are applied: the key type "MUST be 'Symmetric'", the "alg", when present, "MUST
 * match the algorithm being used", and the "key_ops", when present, "MUST include 'derive key' or 'derive bits'".
 * The last two are enforced by default, {@see KeyRestrictionAware}, these classes being new.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.1.2
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.1
 * @see \Cose\Tests\Algorithm\KeyManagement\DirectHkdfTest
 */
abstract class DirectHkdf implements DirectEncryption, KeyRestrictionAware
{
    use KeyRestrictionEnforcement;

    public function __construct()
    {
        // RFC 9053 section 6.1.2 makes the "alg" and "key_ops" checks a MUST, and these algorithms have no caller to
        // keep compatible: they enforce the restrictions unless told otherwise.
        $this->enforceKeyRestrictions = true;
    }

    public function isDirect(): bool
    {
        return true;
    }

    /**
     * The name of RFC 9053 table 12: "direct+HKDF-SHA-256", ...
     */
    abstract public function name(): string;

    /**
     * The HKDF of RFC 9053 table 8 this identifier selects.
     */
    abstract public function hkdf(): Hkdf;

    public function recoverKey(RecipientLayer $layer, Key $recipientKey): string
    {
        LayerRules::assertDirectRecipientCarriesAnEmptyCiphertext($layer, $this->name());

        return $this->derive($layer, $recipientKey);
    }

    public function protectKey(RecipientLayer $layer, Key $recipientKey, ?string $key = null): ProtectedKey
    {
        if ($key !== null) {
            throw new InvalidArgumentException(sprintf(
                '%s derives the key of the layer below from the shared secret: no key can be given to protect.',
                $this->name()
            ));
        }
        LayerRules::assertDirectRecipient($layer, $this->name());
        LayerRules::assertSaltOrPartyUNonce($layer, $this->name(), '6.1.2');

        return ProtectedKey::create($this->derive($layer, $recipientKey), MapObject::create(), '');
    }

    /**
     * The shared secret run through the HKDF with the salt of the headers and the COSE_KDF_Context of the layer.
     */
    private function derive(RecipientLayer $layer, Key $key): string
    {
        $secret = $this->secretOf($key);

        return $this->hkdf()
            ->derive($secret, $layer->headers()->getSalt(), (string) $layer->kdfContext(), $layer->keyLength());
    }

    private function secretOf(Key $key): string
    {
        if (! $key->typeIs(Key::TYPE_OCT)) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key. The key type of a %s key MUST be "Symmetric" (RFC 9053 section 6.1.2), got "%s".',
                $this->name(),
                $key->type()
            ));
        }
        if (! $key->has(SymmetricKey::DATA_K)) {
            throw new InvalidArgumentException('Invalid key. The value of the key is missing');
        }
        $k = $key->get(SymmetricKey::DATA_K);
        if (! is_string($k)) {
            throw new InvalidArgumentException(
                'Invalid key. The value of the key must be a byte string (CBOR objects shall be normalized first)'
            );
        }
        if ($k === '') {
            throw new InvalidArgumentException('Invalid key. The value of the key is empty');
        }
        // RFC 9053 section 6.1.2: "If the 'key_ops' field is present, it MUST include 'derive key' or 'derive bits'."
        $this->checkKeyRestrictions($key, Key::OP_DERIVE_KEY, Key::OP_DERIVE_BITS);

        return $k;
    }
}
