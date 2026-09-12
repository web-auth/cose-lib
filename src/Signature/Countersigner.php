<?php

declare(strict_types=1);

namespace Cose\Signature;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag;
use CBOR\Tag\GenericTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\Signature as SignatureAlgorithm;
use Cose\Key\Key;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use InvalidArgumentException;
use function sprintf;

/**
 * The signing and verification process of RFC 9338 section 3.3, for both forms of a version 2 countersignature.
 *
 * A countersignature is a second signature over a finalized COSE structure -- "The target structure of the
 * countersignature needs to have all of its cryptographic functions finalized before computing the signature" --
 * and lives in the unprotected bucket of that structure. The full form (label 11) is a COSE_Signature of its own,
 * with headers naming its algorithm and key; the abbreviated form (label 12) is the bare signature value, and the
 * parameters that computed it are the application's context. Neither can be verified as the other: the context
 * string of the {@see Countersign} structure differs.
 *
 * ```php
 * $target = CountersignTarget::of($coseSign1);
 * $countersignature = Countersigner::sign($target, ES256::create(), $notaryKey, CoseHeaders::of($protected, $unprotected));
 * Countersigner::attach($coseSign1->getUnprotectedHeader(), $countersignature);
 *
 * foreach (CountersignTarget::of($received)->getCountersignatures() as $countersignature) {
 *     $isValid = Countersigner::verify($target, $countersignature, $algorithm, $notaryKey->toPublic());
 * }
 * ```
 *
 * Only a signature algorithm with appendix can countersign (section 3.1): the target has to be usable without the
 * countersignature, which a scheme with message recovery would forbid. Every {@see SignatureAlgorithm} of this
 * library -- ECDSA, EdDSA, RSASSA-PKCS1-v1_5, RSASSA-PSS, the fully-specified forms -- is one.
 *
 * A countersignature over a COSE_Encrypt or a COSE_Mac attests to the ciphertext or to the MAC tag, not to the
 * plaintext (section 3), and only as far as the tag reaches: section 6, "To provide 128-bit security against
 * collision attacks, the tag length MUST be at least 256 bits. A countersignature of a COSE_Mac with AES-MAC [...]
 * provides at most 64 bits of integrity protection [...] a COSE_Encrypt with AES-CCM-16-64-128 provides at most 32
 * bits". Nothing here checks the tag length: the algorithm of the target is the application's choice.
 *
 * Verification is total in the sense of {@see SignatureAlgorithm::verify()}: what does not verify yields false, a
 * key or an algorithm that cannot be used at all throws. After it, "the application performs the appropriate
 * checks to ensure that the key is correctly paired with the signing identity and that the signing identity is
 * authorized" (section 3.3): the key identifier of a countersignature is a hint, not a proof.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9338#section-3.3
 * @see \Cose\Tests\Signature\CountersignerTest
 */
final class Countersigner
{
    /**
     * Computes a full countersignature (label 11) of the target: a COSE_Countersignature whose headers are the ones
     * given and whose signature covers the Countersign_structure with their protected bucket as sign_protected.
     *
     * The headers are the countersigner's: RFC 9052 section 3.1 asks for the algorithm there, in the protected
     * bucket, and applications usually add a key identifier. An "alg" they carry has to be the algorithm given.
     *
     * @param string $externalAad the external_aad of the Countersign_structure, the zero-length byte string by
     *                            default (RFC 9052 section 4.4)
     *
     * @throws InvalidArgumentException when the key cannot sign with the algorithm, or the headers announce
     *                                  another algorithm
     */
    public static function sign(
        CountersignTarget $target,
        SignatureAlgorithm $algorithm,
        Key $key,
        CoseHeaders $countersignerHeaders,
        string $externalAad = ''
    ): CoseSignature {
        self::assertAlgorithmMatches($countersignerHeaders, $algorithm);
        $toBeSigned = Countersign::full(
            $target,
            $countersignerHeaders->getProtectedHeader(),
            ByteStringObject::create($externalAad)
        );
        $signature = $algorithm->sign((string) $toBeSigned, $key);

        return CoseSignature::create(ListObject::create([
            $countersignerHeaders->getProtectedHeader(),
            $countersignerHeaders->getUnprotectedHeader(),
            ByteStringObject::create($signature),
        ]));
    }

    /**
     * Verifies a full countersignature (label 11) of the target: the signature it carries, over the
     * Countersign_structure with its own protected bucket as sign_protected.
     *
     * @param string $externalAad the external_aad the countersigner used
     *
     * @throws InvalidArgumentException when the key cannot be used with the algorithm, or the countersignature
     *                                  announces another algorithm than the one given
     */
    public static function verify(
        CountersignTarget $target,
        CoseSignature $countersignature,
        SignatureAlgorithm $algorithm,
        Key $key,
        string $externalAad = ''
    ): bool {
        self::assertAlgorithmMatches($countersignature->headers(), $algorithm);
        $toBeSigned = Countersign::full(
            $target,
            $countersignature->getProtectedHeader(),
            ByteStringObject::create($externalAad)
        );

        return $algorithm->verify((string) $toBeSigned, $key, $countersignature->getSignature()->getValue());
    }

    /**
     * Computes an abbreviated countersignature (label 12) of the target: the bare signature value over the
     * Countersign_structure without sign_protected (RFC 9338 section 3.2).
     *
     * @throws InvalidArgumentException when the key cannot sign with the algorithm
     */
    public static function sign0(
        CountersignTarget $target,
        SignatureAlgorithm $algorithm,
        Key $key,
        string $externalAad = ''
    ): string {
        $toBeSigned = Countersign::abbreviated($target, ByteStringObject::create($externalAad));

        return $algorithm->sign((string) $toBeSigned, $key);
    }

    /**
     * Verifies an abbreviated countersignature (label 12) of the target with the algorithm and the key the
     * application's context names.
     *
     * @throws InvalidArgumentException when the key cannot be used with the algorithm
     */
    public static function verify0(
        CountersignTarget $target,
        string $countersignature0,
        SignatureAlgorithm $algorithm,
        Key $key,
        string $externalAad = ''
    ): bool {
        $toBeSigned = Countersign::abbreviated($target, ByteStringObject::create($externalAad));

        return $algorithm->verify((string) $toBeSigned, $key, $countersignature0);
    }

    /**
     * Places a full countersignature in the unprotected bucket of its target, under label 11.
     *
     * RFC 9338 section 2 types the value as "COSE_Countersignature / [+ COSE_Countersignature]": the first
     * countersignature is written on its own, a second one turns the value into an array of the two, and later ones
     * are appended. What the bucket already carries is kept as it is, tagged or not; the new entry is written bare,
     * or under the CBOR tag 19 when asked ({@see tagged()}).
     *
     * The bucket is modified in place: it is the one the target carries -- getUnprotectedHeader() of the message,
     * of the CoseSignature or of the CoseRecipient -- and the countersignature has to end up in the message. The
     * target's own signature or tag does not cover it, so nothing else changes.
     *
     * @throws InvalidArgumentException when the bucket already carries a value under label 11 that is not a
     *                                  COSE_Countersignature or an array of them
     */
    public static function attach(
        MapObject|IndefiniteLengthMapObject $unprotectedHeader,
        CoseSignature $countersignature,
        bool $tagged = false
    ): void {
        $entry = $tagged ? self::tagged($countersignature) : $countersignature->toListObject();
        $label = UnsignedIntegerObject::create(CoseHeaders::LABEL_COUNTERSIGNATURE_V2);

        $existing = HeaderMapHelper::findLabel($unprotectedHeader, CoseHeaders::LABEL_COUNTERSIGNATURE_V2);
        if ($existing === null) {
            $unprotectedHeader->add($label, $entry);

            return;
        }

        $items = self::carriedCountersignatureItems($existing);
        $items[] = $entry;
        $unprotectedHeader->set(MapItem::create($label, ListObject::create($items)));
    }

    /**
     * Places an abbreviated countersignature in the unprotected bucket of its target, under label 12, replacing
     * one already there: the parameter holds one value (RFC 9338 section 2).
     */
    public static function attach0(MapObject|IndefiniteLengthMapObject $unprotectedHeader, string $countersignature0): void
    {
        $unprotectedHeader->set(MapItem::create(
            UnsignedIntegerObject::create(CoseHeaders::LABEL_COUNTERSIGNATURE0_V2),
            ByteStringObject::create($countersignature0)
        ));
    }

    /**
     * A COSE_Countersignature under the CBOR tag 19 (RFC 9338 section 3.1, "COSE_Countersignature_Tagged =
     * #6.19(COSE_Countersignature)"), for a countersignature that travels on its own or that a protocol asks to
     * be tagged in the header. The bytes are the ones a dedicated tag class produces; {@see HeaderMapHelper::countersignatureItems()}
     * reads either.
     */
    public static function tagged(CoseSignature $countersignature): Tag
    {
        return GenericTag::createFromLoadedData(
            HeaderMapHelper::TAG_COUNTERSIGNATURE,
            null,
            $countersignature->toListObject()
        );
    }

    /**
     * The items carried under label 11, each as it is on the wire, after the check that each of them is a
     * COSE_Countersignature: what a second countersignature is appended to.
     *
     * @return list<CBORObject>
     */
    private static function carriedCountersignatureItems(CBORObject $value): array
    {
        // The shape check first: the list of wrapped items is what it returns, the raw items are what is kept.
        HeaderMapHelper::countersignatureItems($value, 'Countersignature version 2');
        if ($value instanceof Tag) {
            return [$value];
        }
        /** @var ListObject|IndefiniteLengthListObject $value */
        $first = $value->get(0);
        if ($first instanceof ByteStringObject || $first instanceof IndefiniteLengthByteStringObject) {
            return [$value];
        }

        $items = [];
        foreach ($value as $item) {
            $items[] = $item;
        }

        return $items;
    }

    /**
     * An "alg" the countersigner's headers carry has to be the algorithm in hand: a countersignature that announces
     * one algorithm and is computed or verified with another is the confusion RFC 9052 section 3.1 puts the
     * parameter in the protected bucket to prevent.
     */
    private static function assertAlgorithmMatches(CoseHeaders $headers, SignatureAlgorithm $algorithm): void
    {
        $announced = $headers->getHeaderParameter(1);
        if ($announced === null) {
            return;
        }
        if (! $announced instanceof UnsignedIntegerObject && ! $announced instanceof NegativeIntegerObject) {
            throw new InvalidArgumentException(
                'The "alg" header parameter of the countersignature shall be an integer identifier (RFC 9052 section 3.1).'
            );
        }
        if ($announced->normalize() !== (string) $algorithm::identifier()) {
            throw new InvalidArgumentException(sprintf(
                'The countersignature announces the algorithm %s; the algorithm given is %d.',
                $announced->normalize(),
                $algorithm::identifier()
            ));
        }
    }
}
