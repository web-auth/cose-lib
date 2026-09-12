<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use Cose\Structure\CoseStructure;
use InvalidArgumentException;
use function sprintf;

/**
 * The rules RFC 9052 section 8.5 lays down for the shape of a COSE_recipient, per class of algorithm, checked on
 * the receiving side before any key material is touched and on the sending side before any is produced.
 *
 * @internal
 */
final class LayerRules
{
    /**
     * A direct recipient (RFC 9052 sections 8.5.1 and 8.5.4): its "ciphertext" "MUST be a zero-length byte string",
     * its "recipients" "MUST be absent", and it "MUST be the only mode used on the message" -- "there MUST be only
     * one recipient in the message".
     *
     * The ciphertext rule is only applicable on the receiving side, where the recipient exists; a layer being built
     * by the sender has none yet.
     *
     * @param string $name the name of the algorithm, for the message
     */
    public static function assertDirectRecipient(RecipientLayer $layer, string $name): void
    {
        if (! $layer->isOnlyRecipient()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid recipient. %s decides the key of the layer below and MUST be the only recipient of the message (RFC 9052 section 8.5.1 and 8.5.4).',
                $name
            ));
        }
        if ($layer->hasRecipients()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid recipient. The "recipients" field of a %s recipient MUST be absent (RFC 9052 section 8.5.1).',
                $name
            ));
        }
        if ($layer->ciphertext() !== null && $layer->ciphertext() !== '') {
            throw new InvalidArgumentException(sprintf(
                'Invalid recipient. The "ciphertext" field of a %s recipient MUST be a zero-length byte string (RFC 9052 section 8.5.1).',
                $name
            ));
        }
    }

    /**
     * On the receiving side, the ciphertext of a direct recipient has to be there, and empty: a nil ciphertext
     * (detached content, RFC 9052 section 5.1) is not "a zero-length byte string".
     */
    public static function assertDirectRecipientCarriesAnEmptyCiphertext(RecipientLayer $layer, string $name): void
    {
        self::assertDirectRecipient($layer, $name);
        if ($layer->ciphertext() === null) {
            throw new InvalidArgumentException(sprintf(
                'Invalid recipient. The "ciphertext" field of a %s recipient MUST be a zero-length byte string, not nil (RFC 9052 section 8.5.1).',
                $name
            ));
        }
    }

    /**
     * An empty protected bucket, as RFC 9053 section 6.1.1 requires of "direct" and section 6.2.1 of the AES Key Wrap
     * ("The protected header bucket MUST be empty"), in either of the two encodings of an empty bucket RFC 9052
     * section 3 tells recipients to accept.
     *
     * @param string $reference the RFC 9053 section that states the rule, for the message
     */
    public static function assertEmptyProtectedHeader(RecipientLayer $layer, string $name, string $reference): void
    {
        $protected = CoseStructure::emptyOrSerializedMap($layer->headers()->getProtectedHeader());
        if ($protected->getValue() !== '') {
            throw new InvalidArgumentException(sprintf(
                'Invalid recipient. The protected header bucket of a %s recipient MUST be empty (RFC 9053 section %s).',
                $name,
                $reference
            ));
        }
    }

    /**
     * The wrapped key a key wrap recipient carries. RFC 9052 section 5.1 lets the ciphertext of any recipient be
     * nil, but a key that travels outside the message has to be supplied by the application, which is not what a
     * recipient layer resolves.
     */
    public static function wrappedKeyOf(RecipientLayer $layer, string $name): string
    {
        $ciphertext = $layer->ciphertext();
        if ($ciphertext === null) {
            throw new InvalidArgumentException(sprintf(
                'Invalid recipient. The "ciphertext" field of a %s recipient is nil: the wrapped key travels outside the message and has to be supplied.',
                $name
            ));
        }

        return $ciphertext;
    }

    /**
     * RFC 9053 section 6.1.2 (direct key with KDF) and section 6.3.1 (Static-Static ECDH): "either the 'salt'
     * parameter for HKDF (Table 9) or the 'PartyU nonce' parameter for the context structure (Table 10) MUST be
     * present". The sender is the one that has to include one; the receiving side derives with what it is given, so
     * that a message from a sender that omitted both -- the interoperability fixtures include some -- still opens.
     *
     * @param string $reference the RFC 9053 section that states the rule, for the message
     */
    public static function assertSaltOrPartyUNonce(RecipientLayer $layer, string $name, string $reference): void
    {
        $headers = $layer->headers();
        if ($headers->getSalt() === null && $headers->getPartyUNonce() === null) {
            throw new InvalidArgumentException(sprintf(
                'Invalid recipient. A %s recipient MUST carry a "salt" (-20) or a "PartyU nonce" (-22) header parameter, unique for the pair of keys (RFC 9053 section %s).',
                $name,
                $reference
            ));
        }
    }
}
