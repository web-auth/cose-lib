<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Cose\Signature\CoseSignTag;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CoseSignTagTest extends TestCase
{
    #[Test]
    public function tagIdIsCorrect(): void
    {
        static::assertSame(98, CoseSignTag::getTagId());
    }

    #[Test]
    public function canCreateCoseSignTag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test payload');
        $signatures = ListObject::create([]);

        $tag = CoseSignTag::create($protectedHeader, $unprotectedHeader, $payload, $signatures);

        static::assertInstanceOf(CoseSignTag::class, $tag);
        static::assertInstanceOf(ByteStringObject::class, $tag->getProtectedHeader());
        static::assertInstanceOf(MapObject::class, $tag->getUnprotectedHeader());
        static::assertInstanceOf(ByteStringObject::class, $tag->getPayload());
        static::assertInstanceOf(ListObject::class, $tag->getSignatures());
    }

    #[Test]
    public function canDecodeValidCoseSignTag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test payload');
        $signatures = ListObject::create([]);

        $tag = CoseSignTag::create($protectedHeader, $unprotectedHeader, $payload, $signatures);

        $encoded = (string) $tag;
        $stream = new StringStream($encoded);
        $decoder = $this->getDecoder();

        $decoded = $decoder->decode($stream);

        static::assertInstanceOf(CoseSignTag::class, $decoded);
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()
            ->add(CoseSignTag::class);

        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }
}
