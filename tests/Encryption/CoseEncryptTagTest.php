<?php

declare(strict_types=1);

namespace Cose\Tests\Encryption;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Cose\Encryption\CoseEncryptTag;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CoseEncryptTagTest extends TestCase
{
    #[Test]
    public function tagIdIsCorrect(): void
    {
        static::assertSame(96, CoseEncryptTag::getTagId());
    }

    #[Test]
    public function canCreateCoseEncryptTag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $ciphertext = ByteStringObject::create('encrypted data');
        $recipients = ListObject::create([]);

        $tag = CoseEncryptTag::create($protectedHeader, $unprotectedHeader, $ciphertext, $recipients);

        static::assertInstanceOf(CoseEncryptTag::class, $tag);
        static::assertInstanceOf(ByteStringObject::class, $tag->getProtectedHeader());
        static::assertInstanceOf(MapObject::class, $tag->getUnprotectedHeader());
        static::assertInstanceOf(ByteStringObject::class, $tag->getCiphertext());
        static::assertInstanceOf(ListObject::class, $tag->getRecipients());
    }

    #[Test]
    public function canDecodeValidCoseEncryptTag(): void
    {
        $protectedHeader = MapObject::create();
        $unprotectedHeader = MapObject::create();
        $ciphertext = ByteStringObject::create('encrypted data');
        $recipients = ListObject::create([]);

        $tag = CoseEncryptTag::create($protectedHeader, $unprotectedHeader, $ciphertext, $recipients);

        $encoded = (string) $tag;
        $stream = new StringStream($encoded);
        $decoder = $this->getDecoder();

        $decoded = $decoder->decode($stream);

        static::assertInstanceOf(CoseEncryptTag::class, $decoded);
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()
            ->add(CoseEncryptTag::class);

        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }
}
