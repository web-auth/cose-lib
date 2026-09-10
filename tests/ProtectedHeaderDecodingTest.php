<?php

declare(strict_types=1);

namespace Cose\Tests;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag;
use CBOR\Tag\TagManager;
use CBOR\UnsignedIntegerObject;
use function chr;
use Cose\Encryption\CoseEncrypt0Tag;
use Cose\Encryption\CoseEncryptTag;
use Cose\Mac\CoseMac0Tag;
use Cose\Mac\CoseMacTag;
use Cose\Signature\CoseSign1Tag;
use Cose\Signature\CoseSignTag;
use function count;
use function in_array;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * The header-map rules of RFC 9052 are enforced by the CBOR decoder, not by this library: section 3 and section 9
 * make a message malformed when a label appears twice in a map, and the decoder is what bounds the nesting depth.
 * That is why the package declares a floor of 3.3.4 on spomky-labs/cbor-php, and why the decoder built when the
 * caller does not provide one is bounded far below the cbor-php default of 1000 levels.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-9
 * @see https://github.com/web-auth/cose-lib/issues/171
 */
/**
 * The class under test is deprecated since 4.8.0 in favour of its cbor-php 3.4.0 counterpart (issue #176). Its
 * behaviour is frozen for the 4.8.x line, so these tests keep running against it with the deprecation silenced;
 * {@see \Cose\Tests\Structure\DeprecatedTagClassesTest} is what asserts the notice is raised.
 */
#[IgnoreDeprecations]
final class ProtectedHeaderDecodingTest extends TestCase
{
    /**
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('getTagClasses')]
    public function aWellFormedProtectedHeaderIsDecoded(string $class, int $tagId, int $items): void
    {
        // Given: {1: -7, 33: [h'cert']} — an algorithm and an x5chain-like array
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
            MapItem::create(UnsignedIntegerObject::create(33), ListObject::create([ByteStringObject::create('cert')])),
        ]);
        $tag = self::tagWithProtectedHeader($class, $tagId, $items, (string) $header);

        // When
        $decoded = $tag->getProtectedHeaderAsMap();

        // Then
        static::assertCount(2, $decoded);
        static::assertSame('-7', $decoded->get(1)->normalize());
    }

    /**
     * RFC 9052 section 9: "Applications MUST NOT parse and process messages with the same label used twice as a key
     * in a single map." Rejection comes from spomky-labs/cbor-php 3.3.4 or later (GHSA-388j-mw2g-rx5f).
     *
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('getTagClasses')]
    public function aProtectedHeaderRepeatingALabelIsRejected(string $class, int $tagId, int $items): void
    {
        // Given: {1: -7, 1: -8}
        $tag = self::tagWithProtectedHeader($class, $tagId, $items, "\xa2\x01\x26\x01\x27");

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key "1" is defined more than once in the map.');
        $tag->getProtectedHeaderAsMap();
    }

    /**
     * A protected header nested thousands of levels deep used to exhaust the memory of the process, which no
     * try/catch around the decoding can recover from.
     *
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('getTagClasses')]
    public function anExcessivelyNestedProtectedHeaderIsRejected(string $class, int $tagId, int $items): void
    {
        // Given: {1: [[[ ... ]]]}, 5000 levels deep
        $tag = self::tagWithProtectedHeader($class, $tagId, $items, self::deeplyNestedHeader(5000));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Maximum nesting depth of 32 exceeded.');
        $tag->getProtectedHeaderAsMap();
    }

    /**
     * The bound applies to the decoder built here; a caller who needs another one passes it, or passes its own
     * decoder, and nothing else changes.
     *
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('getTagClasses')]
    public function theNestingBoundCanBeChanged(string $class, int $tagId, int $items): void
    {
        // Given: a header nested deeper than the default bound
        $tag = self::tagWithProtectedHeader($class, $tagId, $items, self::deeplyNestedHeader(40));

        // Then
        static::assertSame(32, $class::DEFAULT_PROTECTED_HEADER_MAX_DEPTH);
        static::assertCount(1, $tag->getProtectedHeaderAsMap(null, 128));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Maximum nesting depth of 32 exceeded.');
        $tag->getProtectedHeaderAsMap();
    }

    /**
     * A caller-provided decoder keeps its own bound: the $maxDepth argument is then ignored.
     *
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('getTagClasses')]
    public function aCallerProvidedDecoderKeepsItsOwnBound(string $class, int $tagId, int $items): void
    {
        // Given
        $tag = self::tagWithProtectedHeader($class, $tagId, $items, self::deeplyNestedHeader(40));
        $decoder = Decoder::create(TagManager::create(), OtherObjectManager::create(), 128);

        // Then
        static::assertCount(1, $tag->getProtectedHeaderAsMap($decoder, 1));
    }

    /**
     * @return iterable<string, array{class-string, int, int}>
     */
    public static function getTagClasses(): iterable
    {
        yield 'COSE_Sign1' => [CoseSign1Tag::class, 18, 4];
        yield 'COSE_Sign' => [CoseSignTag::class, 98, 4];
        yield 'COSE_Mac0' => [CoseMac0Tag::class, 17, 4];
        yield 'COSE_Mac' => [CoseMacTag::class, 97, 5];
        yield 'COSE_Encrypt0' => [CoseEncrypt0Tag::class, 16, 3];
        yield 'COSE_Encrypt' => [CoseEncryptTag::class, 96, 4];
    }

    /**
     * A protected header that is a valid map at the top level — {1: [[[ ... ]]]} — whose only value is $levels
     * nested one-element arrays.
     */
    private static function deeplyNestedHeader(int $levels): string
    {
        return "\xa1\x01" . str_repeat("\x81", $levels) . "\xa0";
    }

    /**
     * Builds the tag object of $class around the given protected header bytes, as the decoder would.
     *
     * @param class-string $class
     */
    private static function tagWithProtectedHeader(string $class, int $tagId, int $items, string $header): Tag
    {
        $list = [ByteStringObject::create($header), MapObject::create()];
        // The last item of COSE_Sign, COSE_Mac and COSE_Encrypt is an array (signatures or recipients); every other
        // item of every structure is a byte string.
        $trailingList = in_array($class, [CoseSignTag::class, CoseMacTag::class, CoseEncryptTag::class], true);
        while (count($list) < $items) {
            $last = count($list) === $items - 1;
            $list[] = $last && $trailingList ? ListObject::create() : ByteStringObject::create('');
        }
        $components = $tagId <= 23 ? [$tagId, null] : [Tag::LENGTH_1_BYTE, chr($tagId)];

        $tag = $class::createFromLoadedData($components[0], $components[1], ListObject::create($list));
        static::assertInstanceOf(CBORObject::class, $tag);

        return $tag;
    }
}
