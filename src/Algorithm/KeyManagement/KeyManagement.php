<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use Cose\Algorithm\Algorithm;
use Cose\Key\Key;
use InvalidArgumentException;

/**
 * A content key distribution method, RFC 9052 section 8.5: what fills a COSE_recipient on the sender side and
 * what reads one on the receiving side, in both cases to hand the layer below its key.
 *
 * The layer below is the content layer -- the AEAD of a COSE_Encrypt, the MAC of a COSE_Mac -- or, when recipients
 * are nested, the recipient above (RFC 9052 section 5.1, Appendix B). Whatever it is, its key is what this
 * interface produces: the CEK, the MAC key, or the KEK of the next layer up.
 *
 * Three families implement it, one interface each: {@see DirectEncryption} (RFC 9052 section 8.5.1: "direct" and
 * "direct+HKDF-*"), {@see KeyWrap} (section 8.5.2: A128KW, A192KW, A256KW) and {@see KeyAgreement} (sections 8.5.4
 * and 8.5.5: ECDH-ES and ECDH-SS, with or without a key wrap). What they share is here.
 *
 * Every recipient is processed against a {@see RecipientLayer}: the headers of the COSE_recipient, its ciphertext,
 * and what the derivation needs to know about the key it protects -- the algorithm that key is for and its length,
 * which RFC 9053 section 5.2 binds into the derived key through the COSE_KDF_Context.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-8.5
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6
 */
interface KeyManagement extends Algorithm
{
    /**
     * Whether the algorithm decides the key of the layer below instead of transporting one the sender chose: the
     * direct encryption class (RFC 9052 section 8.5.1) and the direct key agreement class (section 8.5.4).
     *
     * Such a recipient "MUST be the only mode used on the message" (section 8.5.1) and "there MUST be only one
     * recipient in the message" (section 8.5.4): the key is created by the recipient, so a second recipient could
     * not be handed the same one. {@see \Cose\Encryption\EncryptStructure::encryptFor()} enforces it on the sender
     * side, recoverKey() on the receiving side.
     */
    public function isDirect(): bool;

    /**
     * The receiving side: recovers the key the COSE_recipient carries for the layer below.
     *
     * @param Key $recipientKey the recipient's own key: the shared secret (a symmetric key) for the direct
     *                          encryption and key wrap families, the recipient's private EC2 or OKP key for the
     *                          key agreement family
     *
     * @throws InvalidArgumentException when the key cannot be used with this algorithm (wrong type, wrong length,
     *                                  wrong curve, or -- when the algorithm enforces them -- an "alg" or a
     *                                  "key_ops" that forbids the operation), when the recipient layer is not laid
     *                                  out as RFC 9052 section 8.5 requires for the family, when a header parameter
     *                                  the algorithm needs is missing or malformed, or when the wrapped key does not
     *                                  unwrap
     * @return string the key of the layer below, as raw bytes
     */
    public function recoverKey(RecipientLayer $layer, Key $recipientKey): string;

    /**
     * The sending side: protects the key of the layer below for the recipient, or derives it.
     *
     * @param Key $recipientKey the recipient's key as the sender holds it: the shared secret for the direct
     *                          encryption and key wrap families, the recipient's public EC2 or OKP key for the key
     *                          agreement family (a private key is accepted and its public half used)
     * @param string|null $key the key of the layer below, when the sender chose it -- the key wrap and key agreement
     *                         with key wrap families require one; the direct families refuse one, since they derive
     *                         it: {@see ProtectedKey::key()} is then the key the layer below must be keyed with
     *
     * @throws InvalidArgumentException as recoverKey(), and when $key is given to a direct algorithm or withheld
     *                                  from a wrapping one, or when the layer lacks what the RFC requires the sender
     *                                  to include (the salt or PartyU nonce of RFC 9053 sections 6.1.2 and 6.3.1)
     */
    public function protectKey(RecipientLayer $layer, Key $recipientKey, ?string $key = null): ProtectedKey;
}
