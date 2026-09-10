<?php

declare(strict_types=1);

namespace Cose\Tests\Mac;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Cose\Mac\CoseMac0Tag;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The class under test is deprecated since 4.8.0 in favour of its cbor-php 3.4.0 counterpart (issue #176). Its
 * behaviour is frozen for the 4.8.x line, so these tests keep running against it with the deprecation silenced;
 * {@see \Cose\Tests\Structure\DeprecatedTagClassesTest} is what asserts the notice is raised.
 */
#[IgnoreDeprecations]
final class CoseMac0TagTest extends TestCase
{
    #[Test]
    public function tagIdIsCorrect(): void
    {
        static::assertSame(17, CoseMac0Tag::getTagId());
    }

    #[Test]
    public function canCreateCoseMac0Tag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test payload');
        $tag = ByteStringObject::create('mac tag');

        $coseTag = CoseMac0Tag::create($protectedHeader, $unprotectedHeader, $payload, $tag);

        static::assertInstanceOf(CoseMac0Tag::class, $coseTag);
        static::assertInstanceOf(ByteStringObject::class, $coseTag->getProtectedHeader());
        static::assertInstanceOf(MapObject::class, $coseTag->getUnprotectedHeader());
        static::assertInstanceOf(ByteStringObject::class, $coseTag->getPayload());
        static::assertInstanceOf(ByteStringObject::class, $coseTag->getTag());
    }

    #[Test]
    public function canDecodeValidCoseMac0Tag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test payload');
        $tag = ByteStringObject::create('mac tag');

        $coseTag = CoseMac0Tag::create($protectedHeader, $unprotectedHeader, $payload, $tag);

        $encoded = (string) $coseTag;
        $stream = new StringStream($encoded);
        $decoder = $this->getDecoder();

        $decoded = $decoder->decode($stream);

        static::assertInstanceOf(CoseMac0Tag::class, $decoded);
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()
            ->add(CoseMac0Tag::class);

        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }
}
