<?php

declare(strict_types=1);

namespace Cose\Tests;

use Cose\BigInteger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class BigIntegerTest extends TestCase
{
    /**
     * toBytes() renders zero as the empty string; reading that string back used to raise a Brick\Math exception
     * instead of yielding zero again.
     */
    #[Test]
    public function theEmptyStringIsZero(): void
    {
        // When
        $zero = BigInteger::createFromBinaryString('');

        // Then
        static::assertTrue($zero->isZero());
        static::assertSame('', $zero->toBytes());
        static::assertSame(0, $zero->compare(BigInteger::createFromDecimal(0)));
    }

    #[Test]
    #[DataProvider('getBinaryStrings')]
    public function aBinaryStringRoundTripsWithoutItsLeadingZeroOctets(string $bytes, string $expected): void
    {
        // When
        $value = BigInteger::createFromBinaryString($bytes);

        // Then
        static::assertSame($expected, $value->toBytes());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function getBinaryStrings(): iterable
    {
        yield 'one octet' => ["\x2a", "\x2a"];
        yield 'a leading zero octet' => ["\x00\x2a", "\x2a"];
        yield 'zero octets only' => ["\x00\x00", ''];
        yield 'a value whose first nibble is zero' => ["\x0f\xff", "\x0f\xff"];
        yield 'a wide value' => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"];
    }
}
