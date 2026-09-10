<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag\CoseSignTag;
use CBOR\UnsignedIntegerObject;
use Cose\Signature\CoseSignature;
use Cose\Tests\CoseInnerLists;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The checked view over one entry of a "signatures" list.
 *
 * cbor-php checks that the item is a list and stops there, so a COSE_Sign can carry an empty list or a list of
 * integers and still decode. This view is where RFC 9052 section 4.1 is applied.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-4.1
 */
final class CoseSignatureTest extends TestCase
{
    use CoseInnerLists;

    #[Test]
    public function aWellFormedEntryExposesItsHeadersAndSignature(): void
    {
        // Given: a signer with its own protected bucket, as a COSE_Sign signer has
        $signerProtectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);
        $entry = ListObject::create([
            ByteStringObject::create((string) $signerProtectedHeader),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('signer-1'))]),
            ByteStringObject::create('the-signature'),
        ]);

        // When
        $signature = CoseSignature::create($entry);

        // Then
        static::assertSame('-7', $signature->getProtectedHeaderParameter(1)?->normalize());
        static::assertSame('signer-1', $signature->getUnprotectedHeaderParameter(4)?->getValue());
        static::assertSame('the-signature', $signature->getSignature()->getValue());
        static::assertSame((string) $entry, (string) $signature->toListObject());
    }

    /**
     * The upstream class accepts a list of anything; walking it through the view is what turns that into a typed
     * list of signers.
     */
    #[Test]
    public function everyEntryOfAMessageIsWrapped(): void
    {
        // Given
        $message = CoseSignTag::createFromComponents(
            MapObject::create(),
            MapObject::create(),
            ByteStringObject::create('content'),
            self::signatures('a', 'b')
        );

        // When
        $signers = CoseSignature::all($message->getSignatures());

        // Then
        static::assertCount(2, $signers);
        static::assertSame('a', $signers[0]->getUnprotectedHeaderParameter(4)?->getValue());
        static::assertSame('b', $signers[1]->getUnprotectedHeaderParameter(4)?->getValue());
    }

    /**
     * RFC 9052 section 4.1 writes the list as "[+ COSE_Signature]": at least one entry.
     */
    #[Test]
    public function anEmptyListIsRejected(): void
    {
        // Given: a message cbor-php decodes without complaint
        $message = CoseSignTag::createFromComponents(
            MapObject::create(),
            MapObject::create(),
            ByteStringObject::create('content'),
            ListObject::create([])
        );
        static::assertCount(0, $message->getSignatures());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one COSE_Signature');
        CoseSignature::all($message->getSignatures());
    }

    #[Test]
    public function anEntryOfTheWrongShapeIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('shall be a COSE_Signature');

        // When: two items instead of three
        CoseSignature::create(ListObject::create([ByteStringObject::create(''), MapObject::create()]));
    }

    #[Test]
    public function anEntryThatIsNotAListIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        CoseSignature::all(ListObject::create([UnsignedIntegerObject::create(1)]));
    }
}
