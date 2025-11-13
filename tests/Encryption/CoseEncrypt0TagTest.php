<?php

declare(strict_types=1);

namespace Cose\Tests\Encryption;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Cose\Encryption\CoseEncrypt0Tag;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CoseEncrypt0TagTest extends TestCase
{
    #[Test]
    public function tagIdIsCorrect(): void
    {
        static::assertSame(16, CoseEncrypt0Tag::getTagId());
    }

    #[Test]
    public function canCreateCoseEncrypt0Tag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $ciphertext = ByteStringObject::create('encrypted data');

        $tag = CoseEncrypt0Tag::create($protectedHeader, $unprotectedHeader, $ciphertext);

        static::assertInstanceOf(CoseEncrypt0Tag::class, $tag);
        static::assertInstanceOf(ByteStringObject::class, $tag->getProtectedHeader());
        static::assertInstanceOf(MapObject::class, $tag->getUnprotectedHeader());
        static::assertInstanceOf(ByteStringObject::class, $tag->getCiphertext());
    }

    #[Test]
    public function canDecodeValidCoseEncrypt0Tag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $ciphertext = ByteStringObject::create('encrypted data');

        $tag = CoseEncrypt0Tag::create($protectedHeader, $unprotectedHeader, $ciphertext);

        $encoded = (string) $tag;
        $stream = new StringStream($encoded);
        $decoder = $this->getDecoder();

        $decoded = $decoder->decode($stream);

        static::assertInstanceOf(CoseEncrypt0Tag::class, $decoded);
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()
            ->add(CoseEncrypt0Tag::class);

        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }
}
