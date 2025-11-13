<?php

declare(strict_types=1);

namespace Cose\Tests\Mac;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Cose\Mac\CoseMacTag;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CoseMacTagTest extends TestCase
{
    #[Test]
    public function tagIdIsCorrect(): void
    {
        static::assertSame(97, CoseMacTag::getTagId());
    }

    #[Test]
    public function canCreateCoseMacTag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test payload');
        $tag = ByteStringObject::create('mac tag');
        $recipients = ListObject::create([]);

        $coseTag = CoseMacTag::create($protectedHeader, $unprotectedHeader, $payload, $tag, $recipients);

        static::assertInstanceOf(CoseMacTag::class, $coseTag);
        static::assertInstanceOf(ByteStringObject::class, $coseTag->getProtectedHeader());
        static::assertInstanceOf(MapObject::class, $coseTag->getUnprotectedHeader());
        static::assertInstanceOf(ByteStringObject::class, $coseTag->getPayload());
        static::assertInstanceOf(ByteStringObject::class, $coseTag->getTag());
        static::assertInstanceOf(ListObject::class, $coseTag->getRecipients());
    }

    #[Test]
    public function canDecodeValidCoseMacTag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test payload');
        $tag = ByteStringObject::create('mac tag');
        $recipients = ListObject::create([]);

        $coseTag = CoseMacTag::create($protectedHeader, $unprotectedHeader, $payload, $tag, $recipients);

        $encoded = (string) $coseTag;
        $stream = new StringStream($encoded);
        $decoder = $this->getDecoder();

        $decoded = $decoder->decode($stream);

        static::assertInstanceOf(CoseMacTag::class, $decoded);
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()
            ->add(CoseMacTag::class);

        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }
}
