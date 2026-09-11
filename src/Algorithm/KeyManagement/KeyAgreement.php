<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use Cose\Key\Ec2Key;
use Cose\Key\OkpKey;
use InvalidArgumentException;

/**
 * The key agreement classes of RFC 9052 sections 8.5.4 and 8.5.5: a Diffie-Hellman agreement between the sender's
 * key -- ephemeral (ES) or static (SS) -- and the recipient's static key, whose shared secret a KDF turns into the
 * key of the layer below (direct key agreement, RFC 9053 section 6.3), or into the key that wraps it (key agreement
 * with key wrap, section 6.4).
 *
 * The twelve ECDH algorithms of RFC 9053 tables 14 and 16 implement it: "ECDH-ES + HKDF-256" and its siblings.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-8.5.4
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-8.5.5
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.4
 */
interface KeyAgreement extends KeyManagement
{
    /**
     * Whether the sender's key is a fresh one for every message (Ephemeral-Static, carried in the "ephemeral key"
     * header parameter) rather than a static one (Static-Static, identified by "static key", "static key id" or
     * the "*-sender" parameters of RFC 9360 section 3).
     */
    public function isEphemeralStatic(): bool;

    /**
     * The key wrap the agreed key feeds, or null for direct key agreement, where the agreed key is the key of the
     * layer below itself. isDirect() is the negation.
     */
    public function keyWrap(): ?KeyWrap;

    /**
     * The key the agreement and the KDF produce, with the given pair of keys: the key of the layer below for direct
     * key agreement, the KEK for key agreement with key wrap. This is the step both sides share; recoverKey() and
     * protectKey() are the two ways of coming by the keys.
     *
     * @param Ec2Key|OkpKey $privateKey one party's private key
     * @param Ec2Key|OkpKey $publicKey the other party's public key, on the same curve; an EC2 point is checked to be
     *                                 on the curve before anything is computed with it (RFC 9053 section 6.3.1.1)
     *
     * @throws InvalidArgumentException when the keys are not a usable pair: not both private and public, of
     *                                  different types or curves, on a curve ECDH is not defined for, a point that
     *                                  is not on the curve, or an OKP agreement whose shared secret is all zeros
     *                                  (RFC 7748 section 6.1)
     */
    public function agree(RecipientLayer $layer, Ec2Key|OkpKey $privateKey, Ec2Key|OkpKey $publicKey): string;
}
