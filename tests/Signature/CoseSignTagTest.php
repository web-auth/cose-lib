<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use CBOR\UnsignedIntegerObject;
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

    #[Test]
    public function canAccessProtectedHeaderAsMap(): void
    {
        $protectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)), // alg: ES256
        ]);
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test payload');
        $signatures = ListObject::create([]);

        $tag = CoseSignTag::create($protectedHeader, $unprotectedHeader, $payload, $signatures);

        static::assertInstanceOf(ByteStringObject::class, $tag->getProtectedHeader());

        $decodedHeader = $tag->getProtectedHeaderAsMap();
        static::assertInstanceOf(MapObject::class, $decodedHeader);
        static::assertCount(1, $decodedHeader);
    }

    #[Test]
    public function canCreateWithMultipleSignatures(): void
    {
        $protectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);

        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('Document to be signed by multiple parties');

        // Create multiple signature structures
        $signature1 = ListObject::create([
            ByteStringObject::create(''),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('signer-1')),
            ]),
            ByteStringObject::create(random_bytes(64)),
        ]);

        $signature2 = ListObject::create([
            ByteStringObject::create(''),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('signer-2')),
            ]),
            ByteStringObject::create(random_bytes(64)),
        ]);

        $signatures = ListObject::create([$signature1, $signature2]);

        $tag = CoseSignTag::create($protectedHeader, $unprotectedHeader, $payload, $signatures);

        static::assertInstanceOf(CoseSignTag::class, $tag);
        static::assertCount(2, $tag->getSignatures());
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()->add(CoseSignTag::class);

        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }
}
