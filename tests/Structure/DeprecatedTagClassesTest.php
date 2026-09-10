<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\Tag;
use CBOR\Tag\CoseEncrypt0Tag as UpstreamCoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag as UpstreamCoseEncryptTag;
use CBOR\Tag\CoseMac0Tag as UpstreamCoseMac0Tag;
use CBOR\Tag\CoseMacTag as UpstreamCoseMacTag;
use CBOR\Tag\CoseSign1Tag as UpstreamCoseSign1Tag;
use CBOR\Tag\CoseSignTag as UpstreamCoseSignTag;
use function chr;
use function class_exists;
use Cose\Encryption\CoseEncrypt0Tag;
use Cose\Encryption\CoseEncryptTag;
use Cose\Mac\CoseMac0Tag;
use Cose\Mac\CoseMacTag;
use Cose\Signature\CoseSign1Tag;
use Cose\Signature\CoseSignTag;
use const E_USER_DEPRECATED;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;

/**
 * The six COSE tag classes of this library are deprecated since 4.8.0 in favour of the ones cbor-php 3.4.0 ships,
 * and are removed in 5.0.0.
 *
 * This is the checklist for that removal: one case per class asserting the notice is raised, one asserting the
 * replacement exists and carries the same tag number, and one asserting that a message written by the deprecated
 * class is read by the replacement -- which is what makes the deprecation window safe to sit in.
 *
 * @see https://github.com/web-auth/cose-lib/issues/176
 */
final class DeprecatedTagClassesTest extends TestCase
{
    /**
     * The deprecated classes, their replacements and their tag numbers.
     *
     * @return iterable<string, array{class-string, class-string, int}>
     */
    public static function getDeprecatedClasses(): iterable
    {
        yield 'COSE_Encrypt0' => [CoseEncrypt0Tag::class, UpstreamCoseEncrypt0Tag::class, 16];
        yield 'COSE_Mac0' => [CoseMac0Tag::class, UpstreamCoseMac0Tag::class, 17];
        yield 'COSE_Sign1' => [CoseSign1Tag::class, UpstreamCoseSign1Tag::class, 18];
        yield 'COSE_Encrypt' => [CoseEncryptTag::class, UpstreamCoseEncryptTag::class, 96];
        yield 'COSE_Mac' => [CoseMacTag::class, UpstreamCoseMacTag::class, 97];
        yield 'COSE_Sign' => [CoseSignTag::class, UpstreamCoseSignTag::class, 98];
    }

    /**
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('getDeprecatedClasses')]
    public function constructingTheClassRaisesTheDeprecation(string $class, string $replacement): void
    {
        // When
        [$deprecations] = self::capture(static fn () => self::build($class));

        // Then
        static::assertCount(1, $deprecations);
        static::assertStringContainsString($class, $deprecations[0]);
        static::assertStringContainsString('deprecated since 4.8.0', $deprecations[0]);
        static::assertStringContainsString('removed in 5.0.0', $deprecations[0]);
        static::assertStringContainsString($replacement, $deprecations[0]);
    }

    /**
     * The replacement the message points at has to exist, and stand for the same CBOR tag.
     *
     * @param class-string $class
     * @param class-string $replacement
     */
    #[Test]
    #[DataProvider('getDeprecatedClasses')]
    public function theReplacementExistsAndCarriesTheSameTagNumber(
        string $class,
        string $replacement,
        int $tagId
    ): void {
        // Then
        static::assertTrue(class_exists($replacement), $replacement . ' is missing; cbor-php 3.4.0 or later is needed');
        static::assertSame($tagId, $class::getTagId());
        static::assertSame($tagId, $replacement::getTagId());
    }

    /**
     * A message written by the deprecated class decodes as its replacement, byte for byte: the deprecation changes
     * no wire format, so an application can migrate one side at a time.
     *
     * @param class-string $class
     * @param class-string $replacement
     */
    #[Test]
    #[DataProvider('getDeprecatedClasses')]
    public function aMessageWrittenByTheDeprecatedClassIsReadByItsReplacement(
        string $class,
        string $replacement
    ): void {
        // Given
        [, $built] = self::capture(static fn () => self::build($class));
        static::assertInstanceOf(Tag::class, $built);

        // When: the default decoder of cbor-php 3.4.0 resolves the COSE tags on its own
        $decoded = Decoder::create()
            ->decode(StringStream::create((string) $built));

        // Then
        static::assertInstanceOf($replacement, $decoded);
        static::assertSame((string) $built, (string) $decoded);
    }

    /**
     * The upstream classes raise nothing.
     *
     * @param class-string $class
     * @param class-string $replacement
     */
    #[Test]
    #[DataProvider('getDeprecatedClasses')]
    public function theReplacementRaisesNoDeprecation(string $class, string $replacement): void
    {
        // When
        [$deprecations] = self::capture(static fn () => $replacement::create(self::itemsFor($class)));

        // Then
        static::assertSame([], $deprecations);
    }

    /**
     * One message of the given type, built through the deprecated factory.
     *
     * @param class-string $class
     */
    private static function build(string $class): Tag
    {
        [$additionalInformation, $data] = $class::getTagId() <= 23
            ? [$class::getTagId(), null]
            : [Tag::LENGTH_1_BYTE, chr($class::getTagId())];

        return $class::createFromLoadedData($additionalInformation, $data, self::itemsFor($class));
    }

    /**
     * The items of one message type. The deprecated classes require a byte string everywhere, which is the subset
     * both they and their replacements accept.
     *
     * @param class-string $class
     */
    private static function itemsFor(string $class): ListObject
    {
        $head = [ByteStringObject::create(''), MapObject::create(), ByteStringObject::create('content')];
        $inner = ListObject::create([
            ListObject::create([
                ByteStringObject::create(''),
                MapObject::create(),
                ByteStringObject::create('inner'),
            ]),
        ]);

        return ListObject::create(match ($class) {
            CoseSign1Tag::class => [...$head, ByteStringObject::create('signature')],
            CoseSignTag::class => [...$head, $inner],
            CoseMac0Tag::class => [...$head, ByteStringObject::create('tag')],
            CoseMacTag::class => [...$head, ByteStringObject::create('tag'), $inner],
            CoseEncrypt0Tag::class => $head,
            CoseEncryptTag::class => [...$head, $inner],
            default => throw new InvalidArgumentException('Unknown message class ' . $class),
        });
    }

    /**
     * Runs $callback with an error handler that records E_USER_DEPRECATED rather than letting PHPUnit fail the test
     * on it, and hands back both the messages and the result.
     *
     * @return array{list<string>, mixed}
     */
    private static function capture(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(
            static function (int $severity, string $message) use (&$deprecations): bool {
                $deprecations[] = $message;

                return true;
            },
            E_USER_DEPRECATED
        );

        try {
            $result = $callback();
        } finally {
            restore_error_handler();
        }

        return [$deprecations, $result];
    }
}
