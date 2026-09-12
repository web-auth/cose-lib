<?php

declare(strict_types=1);

namespace Cose\Structure\VerifiableDataStructure;

use CBOR\ByteStringObject;
use CBOR\DecoderInterface;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use function get_debug_type;
use function hash_equals;
use InvalidArgumentException;
use function sprintf;

/**
 * Verifies a COSE receipt of RFC 9942: the proof it carries, then the signature over the tree head the proof leads
 * to, as one boolean.
 *
 * A receipt is a COSE_Sign1 whose payload is a Merkle Tree Hash and whose headers carry the proofs that relate an
 * entry, or an older tree, to that tree head. RFC 9942 section 4.4 recommends the payload be detached, "to protect
 * against implementation errors where the signature is verified but the payload is incompatible with the proof":
 * the verifier is then forced to recompute the tree head from the proof and can only ever verify the signature
 * over what the proof led to. This class does that whether or not the payload travels: when it does, it has to be
 * the tree head the proof leads to, or the receipt is inconsistent and fails.
 *
 * Receipt of inclusion (section 5.2): the proof is applied to the bytes of the candidate entry; the root it leads to
 * becomes the payload; the signature is verified over the Sig_structure built with it. Receipt of consistency
 * (section 5.3.1): the proof is applied to the older tree head the verifier holds -- from a receipt of inclusion it
 * verified earlier -- and the newer tree head it leads to becomes the payload. The RFC orders the two steps
 * differently for the two proof types; with a detached payload, the signature cannot be checked before the proof
 * has produced what it covers, and "It is recommended that implementations return a single boolean result for
 * Receipt-verification operations", which is what both methods do.
 *
 * What the receipt says about the structure is checked against the IANA registries before anything is verified, as
 * section 4.3 requires: a "vds" other than 1 (RFC9162_SHA256, the only registered structure) and a proof label other
 * than -1 and -2 are errors, not things to skip. The signature algorithm is the one the receipt's protected header
 * names, resolved through the Manager the operator built, so that "alg" -- which comes from the wire -- cannot
 * select a verifier the operator did not register, and the policies of the registered instance apply unchanged.
 *
 * What a true result means is exactly this: the entry is a leaf of a tree whose head the holder of the given key
 * signed (or: the older tree is a prefix of a tree whose head that key signed). Who the key belongs to, whether the
 * transparency service behind it is honest, whether the receipt is still valid (section 7.2), what to make of the
 * "crit" header parameter (RFC 9052 section 3.1) and which entry to apply the proof to are the application's, before
 * and after this call. No trust is established here.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.2
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.3.1
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-4.3
 * @see \Cose\Tests\Structure\VerifiableDataStructure\ReceiptVerifierTest
 */
final class ReceiptVerifier
{
    private function __construct(
        private readonly Manager $manager,
        private readonly ?DecoderInterface $decoder
    ) {
    }

    /**
     * @param Manager $manager the signature algorithms the verifier may use, under their identifiers
     * @param DecoderInterface|null $decoder the decoder for the protected header and the proofs, when the default
     *     one -- bounded as {@see CoseHeaders::DEFAULT_PROTECTED_HEADER_MAX_DEPTH} says -- is not wanted
     */
    public static function create(Manager $manager, ?DecoderInterface $decoder = null): self
    {
        return new self($manager, $decoder);
    }

    /**
     * Whether the receipt proves that the entry is included in a tree whose head the key signed.
     *
     * A receipt may carry several inclusion proofs ("[ + inclusion-proof ]"); each is applied to the entry in turn
     * and the receipt verifies as soon as one leads to a tree head the signature verifies over. A proof that does
     * not lead to a root -- a leaf index beyond the tree size, a path that does not fit -- is skipped, as is one that
     * leads to a root the signature does not cover.
     *
     * @param CoseSign1Tag $receipt the receipt, as {@see CoseHeaders::getReceipts()} hands it back
     * @param string $entry the candidate entry, as raw bytes: the leaf the proof is applied to
     * @param Key $key the public key of the receipt issuer, which the application has resolved and trusts
     * @param ByteStringObject|null $externalAad the external_aad of the Sig_structure, if the profile uses one
     *
     * @throws InvalidArgumentException when the receipt is not a receipt of inclusion for a registered structure:
     * no "vds", a "vds" other than RFC9162_SHA256, no "vdp", an unregistered proof label, a proof that does not
     * decode, no inclusion proof at all, no "alg", or an "alg" that is not registered with a signature algorithm
     */
    public function verifyInclusion(
        CoseSign1Tag $receipt,
        string $entry,
        Key $key,
        ?ByteStringObject $externalAad = null
    ): bool {
        $headers = CoseHeaders::fromMessage($receipt, $this->decoder);
        $proofs = Rfc9162Sha256::inclusionProofs($headers, $this->decoder);
        if ($proofs === []) {
            throw new InvalidArgumentException(
                'Invalid receipt. A receipt of inclusion shall carry at least one inclusion proof under the label -1 of the "vdp" header parameter (RFC 9942 section 5.2.1).'
            );
        }
        $algorithm = $this->signatureAlgorithm($headers);
        $carried = self::carriedPayload($receipt);

        foreach ($proofs as $proof) {
            $root = $proof->root($entry);
            if ($root === null) {
                continue;
            }
            if ($carried !== null && ! hash_equals($carried, $root)) {
                // Section 4.4: a payload the proof does not lead to is the very error a detached payload prevents.
                continue;
            }
            if ($this->verifySignature($receipt, $algorithm, $key, $root, $externalAad)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the receipt proves that the tree the given head stands for is a prefix of a newer tree whose head the
     * key signed: the append-only property of RFC 9162 section 2.1.4, for the log the receipt issuer runs.
     *
     * The older tree head is one the application holds from earlier -- typically the tree head a receipt of
     * inclusion led to, which is why section 5.3.1 speaks of "applying a previous inclusion proof to the consistency
     * proof". Several consistency proofs are tried in turn, as the inclusion proofs are.
     *
     * @param string $olderRoot the tree head of the older tree, 32 bytes
     * @param Key $key the public key of the receipt issuer
     *
     * @throws InvalidArgumentException under the conditions of {@see verifyInclusion()}, for a receipt of consistency
     */
    public function verifyConsistency(
        CoseSign1Tag $receipt,
        string $olderRoot,
        Key $key,
        ?ByteStringObject $externalAad = null
    ): bool {
        $headers = CoseHeaders::fromMessage($receipt, $this->decoder);
        $proofs = Rfc9162Sha256::consistencyProofs($headers, $this->decoder);
        if ($proofs === []) {
            throw new InvalidArgumentException(
                'Invalid receipt. A receipt of consistency shall carry at least one consistency proof under the label -2 of the "vdp" header parameter (RFC 9942 section 5.3.1).'
            );
        }
        $algorithm = $this->signatureAlgorithm($headers);
        $carried = self::carriedPayload($receipt);

        foreach ($proofs as $proof) {
            $newerRoot = $proof->newerRoot($olderRoot);
            if ($newerRoot === null) {
                continue;
            }
            if ($carried !== null && ! hash_equals($carried, $newerRoot)) {
                continue;
            }
            if ($this->verifySignature($receipt, $algorithm, $key, $newerRoot, $externalAad)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The signature algorithm the receipt names: "alg" is REQUIRED in the protected header (RFC 9942 sections
     * 5.2.1 and 5.3.1), an integer, and has to be registered with a Signature in the Manager.
     */
    private function signatureAlgorithm(CoseHeaders $headers): Signature
    {
        $alg = $headers->getProtectedHeaderParameter(1);
        if ($alg === null) {
            throw new InvalidArgumentException(
                'Invalid receipt. The "alg" header parameter is required in the protected header (RFC 9942 section 5.2.1).'
            );
        }
        if (! $alg instanceof UnsignedIntegerObject && ! $alg instanceof NegativeIntegerObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid receipt. The "alg" header parameter shall be an integer (RFC 9942 section 5.2.1), got "%s".',
                get_debug_type($alg)
            ));
        }
        $normalized = $alg->normalize();
        if ((string) (int) $normalized !== $normalized) {
            throw new InvalidArgumentException(
                'Invalid receipt. The "alg" header parameter exceeds the platform integer range.'
            );
        }
        $algorithm = $this->manager->get((int) $normalized);
        if (! $algorithm instanceof Signature) {
            throw new InvalidArgumentException(sprintf(
                'The algorithm identifier %d of the receipt is not registered with a signature algorithm.',
                (int) $normalized
            ));
        }

        return $algorithm;
    }

    /**
     * The payload the receipt carries, or null when it is detached (nil), as section 4.4 recommends. The upstream
     * class allows nothing else in that position.
     */
    private static function carriedPayload(CoseSign1Tag $receipt): ?string
    {
        $payload = $receipt->getPayload();
        if ($payload instanceof ByteStringObject || $payload instanceof IndefiniteLengthByteStringObject) {
            return $payload->getValue();
        }

        return null;
    }

    /**
     * Step 2 of section 5.2: the COSE_Sign1 signature over the Sig_structure of RFC 9052 section 4.4, the tree head
     * the proof led to standing as the payload.
     */
    private function verifySignature(
        CoseSign1Tag $receipt,
        Signature $algorithm,
        Key $key,
        string $payload,
        ?ByteStringObject $externalAad
    ): bool {
        $structure = Signature1::create(
            $receipt->getProtectedHeader(),
            ByteStringObject::create($payload),
            $externalAad
        );

        return $algorithm->verify((string) $structure, $key, $receipt->getSignature()->getValue());
    }
}
