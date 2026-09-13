<?php

declare(strict_types=1);

namespace Cose\Structure\Timestamp;

use CBOR\OtherObject\NullObject;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Manager;
use Cose\Structure\CoseHeaders;
use function hash_equals;
use InvalidArgumentException;
use function sprintf;

/**
 * The binding check of RFC 9921 section 4: is the RFC 3161 timestamp token a COSE message carries a token over
 * this message?
 *
 * "As part of the signature verification, the receiver MUST make sure that the MessageImprint in the embedded
 * timestamp token matches a hash of either the payload, signature, or signature fields, depending on the mode of use
 * and type of COSE structure." The mode is which header parameter carries the token, "3161-ttc" (269, protected,
 * over the payload) or "3161-ctt" (270, unprotected, over the signature or signatures field); the structure is
 * COSE_Sign1 or COSE_Sign; and {@see MessageImprint} knows the bytes each combination hashes. This class recomputes
 * the digest of those bytes with the algorithm the token names and compares with hash_equals().
 *
 * The algorithm is resolved the way every identifier that comes from the wire is: the OID in the token's
 * MessageImprint is mapped to its RFC 9054 identifier, the identifier is looked up in the Manager of the
 * application, and the result has to be a {@see Hash}. A token hashed with SHA-1 (-14) therefore fails the check
 * even when the Manager registers SHA-1 for "x5t": the imprint stands for the payload or for the signature, which is
 * the integrity use RFC 9054 section 2 reserves to the general-purpose algorithms, and a SHA-1 timestamp proves
 * existence of something with the same SHA-1, which since 2017 need not be the same thing.
 *
 * A true answer means the token is about this message. It does not mean the token is genuine: nothing here verifies
 * the TSA's CMS signature, validates the TSA's certificate or checks the policy, and RFC 9921 section 4 points to
 * RFC 5652 and RFC 3161 for that. The application, or a CMS implementation, validates {@see TimeStampToken::toDER()}
 * ; this class answers the one question in between, so that a valid token over some other bytes is not taken for
 * a timestamp of this message. Nor does a true answer say anything about the COSE signature itself, which the
 * application verifies first, as for a hash envelope or a receipt.
 *
 * The two modes do not say the same thing, and section 5.1 requires a validator to keep them apart: a "3161-ttc"
 * token proves that the payload existed at genTime, a "3161-ctt" token that the signature did. "Validators must not
 * interpret protected-header payload timestamps as proof of signature creation time". {@see matchesTtc()} and
 * {@see matchesCtt()} are therefore separate; {@see matches()} runs whichever the message carries and requires each
 * to hold, and the application reads back which ones through the accessors of CoseHeaders.
 *
 * ```php
 * $binding = TimestampBinding::create(Manager::create()->add(SHA256::create()));
 * $headers = CoseHeaders::fromMessage($message);
 *
 * // once the COSE signature has been verified:
 * if ($headers->get3161Ctt() !== null && $binding->matchesCtt($headers, $message)) {
 *     $token = TimeStampToken::fromDER($headers->get3161Ctt());
 *     // the signature existed at $token->getGenTime(), if the TSA's own signature on $token->toDER() checks out
 * }
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-4
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-5.1
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-2
 * @see \Cose\Tests\Structure\Timestamp\TimestampBindingTest
 */
final class TimestampBinding
{
    private function __construct(
        private readonly Manager $manager
    ) {
    }

    /**
     * @param Manager $manager the registry the token's hash algorithm resolves through; it has to register the hash
     * algorithms the application accepts in a MessageImprint, SHA-256 (-16) being the one RFC 9921 exemplifies
     */
    public static function create(Manager $manager): self
    {
        return new self($manager);
    }

    /**
     * The hash algorithm a MessageImprint names, resolved through the registry.
     *
     * @throws InvalidArgumentException when the OID is not one of RFC 9054, when the identifier is not registered,
     * and when it is registered with something that is not a {@see Hash}: SHA-1 (-14) is "Filter Only" (RFC 9054
     * section 2), and a timestamp is not a filter
     */
    public function imprintHashAlgorithm(MessageImprint $imprint): Hash
    {
        $identifier = $imprint->getHashAlgorithmIdentifier();
        if ($identifier === null) {
            throw new InvalidArgumentException(sprintf(
                'The hash algorithm %s of the MessageImprint is not one of the RFC 9054 hash algorithms.',
                $imprint->getHashAlgorithmOid()
            ));
        }
        if (! $this->manager->has($identifier)) {
            throw new InvalidArgumentException(sprintf(
                'The hash algorithm %s (%d) of the MessageImprint is not registered.',
                $imprint->getHashAlgorithmOid(),
                $identifier
            ));
        }
        $algorithm = $this->manager->get($identifier);
        if (! $algorithm instanceof Hash) {
            throw new InvalidArgumentException(sprintf(
                'The hash algorithm %s (%d) of the MessageImprint is registered with "%s", which is not a hash algorithm usable as an integrity primitive: a timestamp token stands for the bytes it was computed over, and a "Filter Only" hash (RFC 9054 section 2) cannot.',
                $imprint->getHashAlgorithmOid(),
                $identifier,
                $algorithm::class
            ));
        }

        return $algorithm;
    }

    /**
     * Whether the MessageImprint of a token is the digest of the given bytes, computed with the algorithm the token
     * names.
     *
     * The lowest-level form, for a token and an input the application already holds. {@see matchesTtc()} and
     * {@see matchesCtt()} pick both out of the message.
     *
     * @param string $input the bytes the TSA was asked to timestamp: {@see MessageImprint::ttcInput()} or
     * {@see MessageImprint::cttInput()}
     *
     * @throws InvalidArgumentException when the token names a hash algorithm the registry does not resolve to a
     * {@see Hash}
     */
    public function tokenMatches(TimeStampToken $token, string $input): bool
    {
        $imprint = $token->getMessageImprint();
        $hash = $this->imprintHashAlgorithm($imprint);

        return hash_equals($hash->hash($input), $imprint->getHashedMessage());
    }

    /**
     * Whether the "3161-ttc" token of the message is a token over the payload (RFC 9921 section 3.2).
     *
     * @param string $payload the payload bytes, as carried in the message or, when the payload is detached, as the
     * application holds them; without the byte string head
     *
     * @throws InvalidArgumentException when the message carries no "3161-ttc", carries it in the wrong bucket, or
     * carries a token that does not decode or names a hash algorithm the registry does not resolve to a {@see Hash}
     */
    public function matchesTtc(CoseHeaders $headers, string $payload): bool
    {
        $der = $headers->get3161Ttc();
        if ($der === null) {
            throw new InvalidArgumentException(
                'Not a timestamped message. The "3161-ttc" header parameter (label 269) is not present in the protected header (RFC 9921 section 3.2).'
            );
        }

        return $this->tokenMatches(TimeStampToken::fromDER($der), MessageImprint::ttcInput($payload));
    }

    /**
     * Whether the "3161-ctt" token of the message is a token over the CBOR-encoded "signature" field of the
     * COSE_Sign1, or the CBOR-encoded "signatures" field of the COSE_Sign (RFC 9921 section 3.1).
     *
     * @param CoseHeaders $headers the body headers of $message, or of another message when the application has a
     * reason to bind the token to this one
     *
     * @throws InvalidArgumentException when the message carries no "3161-ctt", carries it in the wrong bucket, or
     * carries a token that does not decode or names a hash algorithm the registry does not resolve to a {@see Hash}
     */
    public function matchesCtt(CoseHeaders $headers, CoseSign1Tag|CoseSignTag $message): bool
    {
        $der = $headers->get3161Ctt();
        if ($der === null) {
            throw new InvalidArgumentException(
                'Not a timestamped message. The "3161-ctt" header parameter (label 270) is not present in the unprotected header (RFC 9921 section 3.1).'
            );
        }

        return $this->tokenMatches(TimeStampToken::fromDER($der), MessageImprint::cttInput($message));
    }

    /**
     * Whether every RFC 3161 token the message carries is a token over this message: the "3161-ttc" one over the
     * payload, the "3161-ctt" one over the signature or signatures field, each under its own rule.
     *
     * A message may carry both, one timestamp of the payload taken before signing and one of the signature taken
     * after, and both have to hold. Which ones it carries, and so what a true answer proves, is what
     * {@see CoseHeaders::get3161Ttc()} and {@see CoseHeaders::get3161Ctt()} say; RFC 9921 section 5.1 requires the
     * application to tell the two apart.
     *
     * @param string|null $detachedPayload the payload bytes when the message carries nil in their place (RFC 9052
     * section 4.1, detached content); ignored when the message carries its payload
     *
     * @throws InvalidArgumentException when the message carries neither parameter, when a "3161-ttc" is to be checked
     * against a detached payload the caller did not supply, and in the cases of {@see matchesTtc()} and
     * {@see matchesCtt()}
     */
    public function matches(CoseHeaders $headers, CoseSign1Tag|CoseSignTag $message, ?string $detachedPayload = null): bool
    {
        $ttc = $headers->get3161Ttc();
        $ctt = $headers->get3161Ctt();
        if ($ttc === null && $ctt === null) {
            throw new InvalidArgumentException(
                'Not a timestamped message. Neither the "3161-ttc" header parameter (label 269, protected) nor the "3161-ctt" one (label 270, unprotected) is present (RFC 9921 section 3).'
            );
        }
        if ($ttc !== null) {
            $payload = $message->getPayload();
            if ($payload instanceof NullObject) {
                if ($detachedPayload === null) {
                    throw new InvalidArgumentException(
                        'The payload of the message is detached and was not supplied; the "3161-ttc" token cannot be checked without the payload bytes (RFC 9921 section 3.2).'
                    );
                }
                $payload = $detachedPayload;
            } else {
                $payload = $payload->getValue();
            }
            if (! $this->matchesTtc($headers, $payload)) {
                return false;
            }
        }
        if ($ctt !== null && ! $this->matchesCtt($headers, $message)) {
            return false;
        }

        return true;
    }
}
