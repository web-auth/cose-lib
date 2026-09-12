<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\VerifiableDataStructure;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Key\Ec2Key;
use Cose\Structure\CoseHeaders;
use Cose\Structure\VerifiableDataStructure\ReceiptVerifier;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256InclusionProof;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * The two-step verification of a receipt: RFC 9942 section 5.2 for a receipt of inclusion, section 5.3.1 for a
 * receipt of consistency, on receipts signed here with ES256 over the tree heads of the CT leaves.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.2
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.3.1
 * @see https://github.com/web-auth/cose-lib/issues/218
 */
final class ReceiptVerifierTest extends TestCase
{
    use ReceiptBuilding;

    private static function verifier(): ReceiptVerifier
    {
        return ReceiptVerifier::create(Manager::create()->add(ES256::create()));
    }

    /**
     * A receipt of inclusion for leaf 5 of the eight CT leaves, detached payload, as bytes decoded back.
     */
    private static function receiptOfInclusion(int $leaf = 5, bool $attach = false, ?ByteStringObject $externalAad = null): CoseSign1Tag
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::signedReceipt(
            self::receiptProtectedHeader(),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([$tree->inclusionProof($leaf)]))]),
            $tree->root(),
            $attach,
            $externalAad
        );

        return self::roundTrip($receipt);
    }

    private static function roundTrip(CoseSign1Tag $receipt): CoseSign1Tag
    {
        $decoded = Decoder::create()->decode(StringStream::create((string) $receipt));
        static::assertInstanceOf(CoseSign1Tag::class, $decoded);

        return $decoded;
    }

    // --- receipts of inclusion -------------------------------------------------------------------------------------

    #[Test]
    public function aReceiptOfInclusionVerifiesForTheEntryItWasIssuedFor(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::receiptOfInclusion();

        // Then
        static::assertTrue(self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic()));
    }

    #[Test]
    public function aReceiptOfInclusionDoesNotVerifyForAnotherEntry(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::receiptOfInclusion();

        // Then: another leaf of the same tree, and an entry that is in no tree
        static::assertFalse(self::verifier()->verifyInclusion($receipt, $tree->entry(4), self::issuerKey()->toPublic()));
        static::assertFalse(self::verifier()->verifyInclusion($receipt, 'not in the log', self::issuerKey()->toPublic()));
    }

    #[Test]
    public function aReceiptOfInclusionDoesNotVerifyWithAnotherKey(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::receiptOfInclusion();
        $other = Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => hex2bin('863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c'),
            Ec2Key::DATA_Y => hex2bin('ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca'),
        ]);

        // Then
        static::assertFalse(self::verifier()->verifyInclusion($receipt, $tree->entry(5), $other));
    }

    /**
     * A proof node tampered with leads to another root, over which the signature does not verify -- step 2 of
     * section 5.2 catches what step 1 cannot see.
     */
    #[Test]
    public function aTamperedProofLeadsToARootTheSignatureDoesNotCover(): void
    {
        // Given: the genuine receipt, with the first node of its path flipped in the unprotected header
        $tree = MerkleTree::certificateTransparencyLeaves();
        $proof = $tree->inclusionProof(5);
        $path = $proof->inclusionPath();
        $path[0] ^= ("\x01" . str_repeat("\x00", 31));
        $tampered = Rfc9162Sha256InclusionProof::create(8, 5, ...$path);
        $genuine = self::receiptOfInclusion();
        $receipt = self::receipt(
            $genuine->getProtectedHeader(),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([$tampered]))]),
            NullObject::create(),
            $genuine->getSignature()
                ->getValue()
        );

        // Then
        static::assertFalse(self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic()));
    }

    /**
     * Section 4.4: the payload SHOULD be detached, and when it travels it has to be what the proof leads to.
     */
    #[Test]
    public function anAttachedPayloadIsAcceptedWhenItIsTheRootTheProofLeadsTo(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();

        static::assertTrue(self::verifier()->verifyInclusion(self::receiptOfInclusion(attach: true), $tree->entry(5), self::issuerKey()->toPublic()));
    }

    #[Test]
    public function anAttachedPayloadThatIsNotTheRootTheProofLeadsToFails(): void
    {
        // Given: the payload of a genuine receipt over the 8-leaf root, replaced by the 7-leaf root the signature
        // does not cover -- and, separately, a receipt genuinely signed over a root the proof does not lead to
        $tree = MerkleTree::certificateTransparencyLeaves();
        $genuine = self::receiptOfInclusion();
        $replaced = self::receipt(
            $genuine->getProtectedHeader(),
            $genuine->getUnprotectedHeader(),
            ByteStringObject::create($tree->root(7)),
            $genuine->getSignature()
                ->getValue()
        );
        $inconsistent = self::signedReceipt(
            self::receiptProtectedHeader(),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([$tree->inclusionProof(5)]))]),
            $tree->root(7),
            true
        );

        // Then
        static::assertFalse(self::verifier()->verifyInclusion($replaced, $tree->entry(5), self::issuerKey()->toPublic()));
        static::assertFalse(self::verifier()->verifyInclusion($inconsistent, $tree->entry(5), self::issuerKey()->toPublic()));
    }

    #[Test]
    public function theExternalAadIsPartOfWhatIsSigned(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $aad = ByteStringObject::create('profile-specific');
        $receipt = self::receiptOfInclusion(externalAad: $aad);

        // Then
        static::assertTrue(self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic(), $aad));
        static::assertFalse(self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic()));
    }

    /**
     * "[ + inclusion-proof ]": the receipt verifies as soon as one of its proofs leads to the signed root.
     */
    #[Test]
    public function aReceiptWithSeveralProofsVerifiesForEachOfTheirEntries(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::roundTrip(self::signedReceipt(
            self::receiptProtectedHeader(),
            MapObject::create([MapItem::create(
                UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP),
                self::vdp([$tree->inclusionProof(1), $tree->inclusionProof(6)])
            )]),
            $tree->root()
        ));

        // Then
        static::assertTrue(self::verifier()->verifyInclusion($receipt, $tree->entry(1), self::issuerKey()->toPublic()));
        static::assertTrue(self::verifier()->verifyInclusion($receipt, $tree->entry(6), self::issuerKey()->toPublic()));
        static::assertFalse(self::verifier()->verifyInclusion($receipt, $tree->entry(2), self::issuerKey()->toPublic()));
    }

    /**
     * The receipt as it travels in a message: read with getReceipts(), verified as is.
     */
    #[Test]
    public function aReceiptCarriedByAMessageVerifies(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $message = self::messageWithReceipts([self::receiptOfInclusion()]);

        // When
        $receipts = CoseHeaders::fromMessage($message)->getReceipts();

        // Then
        static::assertCount(1, $receipts);
        static::assertTrue(self::verifier()->verifyInclusion($receipts[0], $tree->entry(5), self::issuerKey()->toPublic()));
    }

    // --- receipts of consistency -----------------------------------------------------------------------------------

    #[Test]
    public function aReceiptOfConsistencyVerifiesForTheOlderRootItWasIssuedFor(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::roundTrip(self::signedReceipt(
            self::receiptProtectedHeader(),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp(consistency: [$tree->consistencyProof(6)]))]),
            $tree->root()
        ));

        // Then
        static::assertTrue(self::verifier()->verifyConsistency($receipt, $tree->root(6), self::issuerKey()->toPublic()));
        static::assertFalse(self::verifier()->verifyConsistency($receipt, $tree->root(5), self::issuerKey()->toPublic()));
        static::assertFalse(self::verifier()->verifyConsistency($receipt, $tree->root(7), self::issuerKey()->toPublic()));
    }

    #[Test]
    public function aReceiptOfConsistencyWithAnAttachedNewerRootVerifies(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::roundTrip(self::signedReceipt(
            self::receiptProtectedHeader(),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp(consistency: [$tree->consistencyProof(6)]))]),
            $tree->root(),
            true
        ));

        // Then
        static::assertTrue(self::verifier()->verifyConsistency($receipt, $tree->root(6), self::issuerKey()->toPublic()));
    }

    #[Test]
    public function aReceiptOfInclusionIsNotAReceiptOfConsistency(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A receipt of consistency shall carry at least one consistency proof under the label -2');
        self::verifier()->verifyConsistency(self::receiptOfInclusion(), MerkleTree::certificateTransparencyLeaves()->root(6), self::issuerKey()->toPublic());
    }

    #[Test]
    public function aReceiptOfConsistencyIsNotAReceiptOfInclusion(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::signedReceipt(
            self::receiptProtectedHeader(),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp(consistency: [$tree->consistencyProof(6)]))]),
            $tree->root()
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A receipt of inclusion shall carry at least one inclusion proof under the label -1');
        self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic());
    }

    // --- the registries and the algorithm --------------------------------------------------------------------------

    /**
     * Section 4.3: an unregistered "vds" is an error, before any verification.
     */
    #[Test]
    public function aReceiptForAnUnregisteredStructureIsRejected(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::signedReceipt(
            self::receiptProtectedHeader(vds: 2),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([$tree->inclusionProof(5)]))]),
            $tree->root()
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The verifiable data structure 2 is not RFC9162_SHA256 (1)');
        self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic());
    }

    #[Test]
    public function aReceiptWithAnUnregisteredProofLabelIsRejected(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $vdp = self::vdp([$tree->inclusionProof(5)]);
        $vdp->add(NegativeIntegerObject::create(-3), ListObject::create([]));
        $receipt = self::signedReceipt(
            self::receiptProtectedHeader(),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), $vdp)]),
            $tree->root()
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The proof label -3 is not registered for RFC9162_SHA256');
        self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic());
    }

    /**
     * Section 5.2.1: "alg (label: 1): REQUIRED."
     */
    #[Test]
    public function aReceiptWithoutAlgIsRejected(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::signedReceipt(
            self::receiptProtectedHeader(alg: null),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([$tree->inclusionProof(5)]))]),
            $tree->root()
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "alg" header parameter is required in the protected header (RFC 9942 section 5.2.1)');
        self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic());
    }

    #[Test]
    public function aReceiptWithATextAlgIsRejected(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::signedReceipt(
            self::receiptProtectedHeader(alg: null, extra: [
                1 => TextStringObject::create('ES256'),
            ]),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([$tree->inclusionProof(5)]))]),
            $tree->root()
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "alg" header parameter shall be an integer (RFC 9942 section 5.2.1), got "CBOR\TextStringObject".');
        self::verifier()->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic());
    }

    /**
     * The set of acceptable algorithms is the Manager the operator built: "alg" cannot select a verifier that was
     * not registered.
     */
    #[Test]
    public function anAlgorithmTheOperatorDidNotRegisterIsRefused(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::receiptOfInclusion();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm');
        ReceiptVerifier::create(Manager::create()->add(ES384::create()))
            ->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic());
    }

    #[Test]
    public function anAlgorithmThatIsNotASignatureIsRefused(): void
    {
        // Given: a receipt announcing HS256 (5), registered
        $tree = MerkleTree::certificateTransparencyLeaves();
        $receipt = self::signedReceipt(
            self::receiptProtectedHeader(alg: 5),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([$tree->inclusionProof(5)]))]),
            $tree->root()
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm identifier 5 of the receipt is not registered with a signature algorithm.');
        ReceiptVerifier::create(Manager::create()->add(HS256::create()))
            ->verifyInclusion($receipt, $tree->entry(5), self::issuerKey()->toPublic());
    }

    #[Test]
    public function theStructureIsNamedByTheReceipt(): void
    {
        static::assertSame(1, CoseHeaders::fromMessage(self::receiptOfInclusion())->getVds());
        static::assertSame(Rfc9162Sha256::IDENTIFIER, CoseHeaders::fromMessage(self::receiptOfInclusion())->getVds());
    }
}
