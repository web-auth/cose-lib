<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\Tag\CoseEncryptTag;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\CoseRecipient;
use Cose\Tests\CoseInnerLists;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The checked view over one entry of a "recipients" list.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-5.1
 */
final class CoseRecipientTest extends TestCase
{
    use CoseInnerLists;

    #[Test]
    public function aWellFormedEntryExposesItsHeadersAndCiphertext(): void
    {
        // Given
        $entry = self::recipient('recipient-1', 'wrapped-key');

        // When
        $recipient = CoseRecipient::create($entry);

        // Then
        static::assertSame('recipient-1', $recipient->getUnprotectedHeaderParameter(4)?->getValue());
        static::assertFalse($recipient->hasDetachedCiphertext());
        static::assertSame('wrapped-key', $recipient->getCiphertext()->getValue());
        static::assertFalse($recipient->hasRecipients());
        static::assertSame([], $recipient->getRecipients());
    }

    /**
     * RFC 9052 section 5.1 types the ciphertext of a recipient as "bstr / nil".
     */
    #[Test]
    public function aDetachedCiphertextIsReported(): void
    {
        // Given
        $recipient = CoseRecipient::create(self::recipient('r', null));

        // Then
        static::assertTrue($recipient->hasDetachedCiphertext());
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('detached');
        $recipient->getCiphertext();
    }

    /**
     * "? recipients : [+COSE_recipient]" -- a recipient may carry recipients of its own, which is how RFC 9052
     * expresses key layering.
     */
    #[Test]
    public function nestedRecipientsAreWalked(): void
    {
        // Given: one recipient carrying two of its own
        $entry = ListObject::create([
            ByteStringObject::create(''),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('outer'))]),
            NullObject::create(),
            self::recipients('inner-1', 'inner-2'),
        ]);

        // When
        $recipient = CoseRecipient::create($entry);

        // Then
        static::assertTrue($recipient->hasRecipients());
        $nested = $recipient->getRecipients();
        static::assertCount(2, $nested);
        static::assertSame('inner-1', $nested[0]->getUnprotectedHeaderParameter(4)?->getValue());
        static::assertSame('inner-2', $nested[1]->getUnprotectedHeaderParameter(4)?->getValue());
        static::assertSame((string) $entry, (string) $recipient->toListObject());
    }

    #[Test]
    public function everyEntryOfAMessageIsWrapped(): void
    {
        // Given
        $message = CoseEncryptTag::createFromComponents(
            MapObject::create(),
            MapObject::create(),
            ByteStringObject::create('ciphertext'),
            self::recipients('a', 'b')
        );

        // When
        $recipients = CoseRecipient::all($message->getRecipients());

        // Then
        static::assertCount(2, $recipients);
        static::assertSame('a', $recipients[0]->getUnprotectedHeaderParameter(4)?->getValue());
    }

    #[Test]
    public function anEmptyListIsRejected(): void
    {
        // Given: a message cbor-php decodes without complaint
        $message = CoseEncryptTag::createFromComponents(
            MapObject::create(),
            MapObject::create(),
            ByteStringObject::create('ciphertext'),
            ListObject::create([])
        );
        static::assertCount(0, $message->getRecipients());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one COSE_recipient');
        CoseRecipient::all($message->getRecipients());
    }

    #[Test]
    public function aMalformedNestedLevelIsRejected(): void
    {
        // Given: a well-formed recipient whose nested list holds a text string
        $entry = ListObject::create([
            ByteStringObject::create(''),
            MapObject::create(),
            ByteStringObject::create('wrapped'),
            ListObject::create([NegativeIntegerObject::create(-1)]),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        CoseRecipient::create($entry);
    }

    #[Test]
    public function anEntryOfTheWrongArityIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('shall be a COSE_recipient');

        // When: five items, where the CDDL allows three or four
        CoseRecipient::create(ListObject::create([
            ByteStringObject::create(''),
            MapObject::create(),
            ByteStringObject::create('c'),
            ListObject::create([]),
            ByteStringObject::create('extra'),
        ]));
    }
}
