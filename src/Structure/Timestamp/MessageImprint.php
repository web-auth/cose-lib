<?php

declare(strict_types=1);

namespace Cose\Structure\Timestamp;

use function array_search;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use Cose\Algorithm\Hash\FilterOnlyHash;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Hash\SHA512_256;
use Cose\Algorithm\Hash\SHAKE128;
use Cose\Algorithm\Hash\SHAKE256;
use function hash_equals;
use function in_array;
use InvalidArgumentException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use function sprintf;
use function strlen;
use Throwable;

/**
 * The MessageImprint of RFC 3161 section 2.4.1: the hash a Time Stamping Authority signs, with the algorithm that
 * produced it.
 *
 * ```
 * MessageImprint ::= SEQUENCE {
 *     hashAlgorithm   AlgorithmIdentifier,
 *     hashedMessage   OCTET STRING }
 * ```
 *
 * It is the one thing a TimeStampReq carries about the data being timestamped, and the one thing the TSTInfo of the
 * returned token echoes back (RFC 3161 section 2.4.2: "The message imprint MUST have the same value as the similar
 * field in TimeStampReq"). Binding a token to a COSE message is therefore a matter of recomputing the imprint and
 * comparing, and RFC 9921 says what the input is in each of its two modes:
 *
 * - "3161-ttc" (Timestamp, Then COSE), section 3.2: "the hash of the payload of the COSE Signed Message. This does
 *   not include the bstr wrapping -- only the payload bytes." {@see ttcInput()} is the identity on the payload bytes
 *   and exists so that the rule has a name; {@see ttc()} computes the imprint.
 * - "3161-ctt" (COSE, Then Timestamp), section 3.1: "the hash of the CBOR-encoded signature field of the COSE_Sign1
 *   message, or the hash of the CBOR-encoded signatures field of the COSE_Sign message." CBOR-encoded, which for
 *   the signature of a COSE_Sign1 means the byte string with its head -- section 3.1.1 spells it out, "the
 *   bstr-wrapped signature [...] (including the heading bytes 0x5840) is used as input" -- and for the signatures of
 *   a COSE_Sign the whole array, each entry with its two header buckets (section 3.1.2). {@see cttInput()} returns
 *   those bytes, as the message carries them; {@see ctt()} computes the imprint.
 *
 * The hash algorithm is named by an object identifier on the wire and by an integer in COSE; this class maps the
 * RFC 9054 algorithms to their OIDs and back ({@see hashAlgorithmOid()}, {@see hashAlgorithmIdentifier()}). The
 * senders' constructors take a {@see Hash} and not a FilterOnlyHash on purpose: the imprint stands for the data,
 * which is the integrity use of RFC 9054 section 2, and SHA-1 has no OID here that a sender can pick. SHA-256/64
 * (-15) has no OID at all.
 *
 * {@see toASN1()} and {@see toDER()} produce the structure for a TimeStampReq the application builds and sends;
 * {@see fromASN1()} and {@see fromDER()} read it back out of a token. This library does neither the building nor the
 * sending: what a request carries besides the imprint (a nonce, a policy, "certReq") is the application's, and so
 * is the transport.
 *
 * @see https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-3
 * @see \Cose\Tests\Structure\Timestamp\MessageImprintTest
 */
final class MessageImprint
{
    /**
     * The hash algorithms of RFC 9054 that have an object identifier, COSE identifier => OID.
     *
     * The SHA-2 OIDs are those of RFC 5754 section 2 (NIST's hashAlgs arc); id-shake128 and id-shake256 are those of
     * RFC 8702 section 3.1, whose fixed output lengths, 256 and 512 bits, are the ones RFC 9054 section 3.3 assigns to
     * SHAKE128 (-18) and SHAKE256 (-45). SHA-1 is id-sha1 of RFC 3370 section 2.1, listed so that a token hashed
     * with it is recognized and refused for what it is, rather than as an unknown algorithm.
     */
    private const OIDS = [
        SHA256::ID => '2.16.840.1.101.3.4.2.1',
        SHA384::ID => '2.16.840.1.101.3.4.2.2',
        SHA512::ID => '2.16.840.1.101.3.4.2.3',
        SHA512_256::ID => '2.16.840.1.101.3.4.2.6',
        SHAKE128::ID => '2.16.840.1.101.3.4.2.11',
        SHAKE256::ID => '2.16.840.1.101.3.4.2.12',
        SHA1::ID => '1.3.14.3.2.26',
    ];

    /**
     * The SHA-2 AlgorithmIdentifiers carry a NULL parameter or none (RFC 5754 section 2: "Implementations MUST
     * accept SHA2 AlgorithmIdentifiers with absent parameters" and "with NULL parameters"); RFC 8702 section 3.1
     * requires the SHAKE ones to carry none. The encoder follows: NULL for the SHA family, as the examples of RFC
     * 9921 write it, nothing for SHAKE.
     */
    private const PARAMETERLESS = [SHAKE128::ID, SHAKE256::ID];

    private function __construct(
        private readonly string $hashAlgorithmOid,
        private readonly string $hashedMessage
    ) {
    }

    /**
     * An imprint from its two fields, as read from a token or computed elsewhere.
     *
     * @param string $hashAlgorithmOid the object identifier of the hash algorithm, in dotted form
     * @param string $hashedMessage the digest, as raw bytes
     */
    public static function create(string $hashAlgorithmOid, string $hashedMessage): self
    {
        if ($hashedMessage === '') {
            throw new InvalidArgumentException('Invalid MessageImprint. The hashedMessage shall not be empty (RFC 3161 section 2.4.1).');
        }

        return new self($hashAlgorithmOid, $hashedMessage);
    }

    /**
     * The imprint of the "3161-ttc" mode: the hash of the payload bytes (RFC 9921 section 3.2).
     *
     * @param string $payload the payload of the COSE_Sign or COSE_Sign1, as raw bytes, without the byte string head
     */
    public static function ttc(Hash $hash, string $payload): self
    {
        return new self(self::hashAlgorithmOid($hash), $hash->hash(self::ttcInput($payload)));
    }

    /**
     * The imprint of the "3161-ctt" mode: the hash of the CBOR-encoded "signature" field of a COSE_Sign1, or of the
     * CBOR-encoded "signatures" field of a COSE_Sign (RFC 9921 section 3.1).
     */
    public static function ctt(Hash $hash, CoseSign1Tag|CoseSignTag $message): self
    {
        return new self(self::hashAlgorithmOid($hash), $hash->hash(self::cttInput($message)));
    }

    /**
     * The bytes a TSA request hashes in the "3161-ttc" mode: the payload, and nothing else.
     *
     * RFC 9921 section 3.2: "the hash of the payload of the COSE Signed Message. This does not include the bstr
     * wrapping -- only the payload bytes." The function is the identity; it exists so that the two modes read the
     * same at the call site, and so that the rule is stated once.
     *
     * @param string $payload the payload of the COSE_Sign or COSE_Sign1, as raw bytes
     */
    public static function ttcInput(string $payload): string
    {
        return $payload;
    }

    /**
     * The bytes a TSA request hashes in the "3161-ctt" mode: the CBOR encoding of the "signature" field of a
     * COSE_Sign1, or of the "signatures" field of a COSE_Sign, as the message carries it.
     *
     * For a COSE_Sign1 that is the byte string with its head: RFC 9921 section 3.1.1, "the bstr-wrapped signature
     * [...] (including the heading bytes 0x5840) is used as input for computing the MessageImprint". For a
     * COSE_Sign it is the array of COSE_Signature entries, head, protected buckets, unprotected buckets and
     * signatures included (section 3.1.2). The bytes are the encoding the message holds, so a signature carried as
     * an indefinite-length byte string hashes as such, and a message decoded from the wire yields the wire bytes.
     */
    public static function cttInput(CoseSign1Tag|CoseSignTag $message): string
    {
        return $message instanceof CoseSign1Tag ? (string) $message->getSignature() : (string) $message->getSignatures();
    }

    /**
     * The object identifier of a hash algorithm of RFC 9054, in dotted form.
     *
     * @throws InvalidArgumentException for SHA-256/64 (-15), which has none
     */
    public static function hashAlgorithmOid(FilterOnlyHash $hash): string
    {
        $identifier = $hash::identifier();
        if (! isset(self::OIDS[$identifier])) {
            throw new InvalidArgumentException(sprintf(
                'The hash algorithm %d (%s) has no object identifier and cannot name a MessageImprint hash.',
                $identifier,
                $hash::class
            ));
        }

        return self::OIDS[$identifier];
    }

    /**
     * The COSE Algorithms identifier of the hash algorithm an object identifier names, or null when the OID is not
     * one of the RFC 9054 algorithms: SHA-256 (-16), SHA-384 (-43), SHA-512 (-44), SHA-512/256 (-17), SHAKE128
     * (-18), SHAKE256 (-45), and SHA-1 (-14).
     */
    public static function hashAlgorithmIdentifier(string $oid): ?int
    {
        $identifier = array_search($oid, self::OIDS, true);

        return $identifier === false ? null : $identifier;
    }

    /**
     * The imprint read out of a DER-encoded MessageImprint.
     *
     * @throws InvalidArgumentException when the bytes are not one MessageImprint and nothing else
     */
    public static function fromDER(string $der): self
    {
        try {
            $offset = 0;
            $sequence = Element::fromDER($der, $offset);
        } catch (Throwable $e) {
            throw new InvalidArgumentException(sprintf('Invalid MessageImprint. The bytes are not DER: %s', $e->getMessage()), 0, $e);
        }
        if ($offset !== strlen($der)) {
            throw new InvalidArgumentException('Invalid MessageImprint. The DER encoding is followed by trailing bytes.');
        }

        return self::fromASN1(UnspecifiedType::fromElementBase($sequence));
    }

    /**
     * The imprint read out of a decoded MessageImprint: a SEQUENCE of an AlgorithmIdentifier, whose parameters are
     * absent or NULL, and an OCTET STRING.
     *
     * @throws InvalidArgumentException when the element has another shape
     */
    public static function fromASN1(UnspecifiedType $element): self
    {
        try {
            $sequence = $element->asSequence();
            if ($sequence->count() !== 2) {
                throw new InvalidArgumentException(sprintf('a SEQUENCE of two elements was expected, got %d', $sequence->count()));
            }
            $algorithm = $sequence->at(0)
                ->asSequence();
            if ($algorithm->count() < 1 || $algorithm->count() > 2) {
                throw new InvalidArgumentException(sprintf('the hashAlgorithm shall be an AlgorithmIdentifier of one or two elements, got %d', $algorithm->count()));
            }
            $oid = $algorithm->at(0)
                ->asObjectIdentifier()
                ->oid();
            if ($algorithm->count() === 2 && ! $algorithm->at(1)->isType(Element::TYPE_NULL)) {
                throw new InvalidArgumentException('the parameters of the hashAlgorithm shall be absent or NULL (RFC 5754 section 2)');
            }
            $hashedMessage = $sequence->at(1)
                ->asOctetString()
                ->string();
        } catch (InvalidArgumentException $e) {
            throw new InvalidArgumentException('Invalid MessageImprint. ' . $e->getMessage() . ' (RFC 3161 section 2.4.1).', 0, $e);
        } catch (Throwable $e) {
            throw new InvalidArgumentException(sprintf('Invalid MessageImprint. The element is not a MessageImprint (RFC 3161 section 2.4.1): %s', $e->getMessage()), 0, $e);
        }

        return self::create($oid, $hashedMessage);
    }

    /**
     * The object identifier of the hash algorithm, in dotted form.
     */
    public function getHashAlgorithmOid(): string
    {
        return $this->hashAlgorithmOid;
    }

    /**
     * The COSE Algorithms identifier of the hash algorithm, or null when the OID is not one of RFC 9054.
     */
    public function getHashAlgorithmIdentifier(): ?int
    {
        return self::hashAlgorithmIdentifier($this->hashAlgorithmOid);
    }

    /**
     * The digest, as raw bytes.
     */
    public function getHashedMessage(): string
    {
        return $this->hashedMessage;
    }

    /**
     * Whether the two imprints name the same algorithm and carry the same digest, the digest compared with
     * hash_equals().
     */
    public function equals(self $other): bool
    {
        return $this->hashAlgorithmOid === $other->hashAlgorithmOid
            && hash_equals($this->hashedMessage, $other->hashedMessage);
    }

    /**
     * The MessageImprint as an ASN.1 SEQUENCE, to be placed in a TimeStampReq (RFC 3161 section 2.4.1).
     *
     * The AlgorithmIdentifier carries a NULL parameter for the SHA family and none for SHAKE, see PARAMETERLESS. An
     * imprint created from an OID the class does not know is encoded with a NULL parameter, the more common form.
     */
    public function toASN1(): Sequence
    {
        $identifier = $this->getHashAlgorithmIdentifier();
        $algorithm = $identifier !== null && in_array($identifier, self::PARAMETERLESS, true)
            ? Sequence::create(ObjectIdentifier::create($this->hashAlgorithmOid))
            : Sequence::create(ObjectIdentifier::create($this->hashAlgorithmOid), NullType::create());

        return Sequence::create($algorithm, OctetString::create($this->hashedMessage));
    }

    /**
     * The DER encoding of {@see toASN1()}.
     */
    public function toDER(): string
    {
        return $this->toASN1()
            ->toDER();
    }
}
