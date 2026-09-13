<?php

declare(strict_types=1);

namespace Cose;

use function bin2hex;
use Brick\Math\BigInteger as BrickBigInteger;
use Brick\Math\Exception\MathException;
use function chr;
use function hex2bin;
use function strlen;

/**
 * @internal
 */
final class BigInteger
{
    private function __construct(
        private readonly BrickBigInteger $value
    ) {
    }

    /**
     * Reads a big-endian unsigned integer. The empty string is what toBytes() returns for zero, and reads back as such.
     */
    public static function createFromBinaryString(string $value): self
    {
        if ($value === '') {
            return new self(BrickBigInteger::zero());
        }

        return new self(BrickBigInteger::fromBase(bin2hex($value), 16));
    }

    public static function createFromDecimal(int $value): self
    {
        return new self(BrickBigInteger::of($value));
    }

    /**
     * Converts a BigInteger to a binary string.
     */
    public function toBytes(): string
    {
        if ($this->value->isEqualTo(BrickBigInteger::zero())) {
            return '';
        }

        $temp = $this->value->toBase(16);
        $temp = 0 !== (strlen($temp) & 1) ? '0' . $temp : $temp;

        // hex2bin() only fails on an odd length or a non-hexadecimal digit, and neither can come out of toBase(16)
        // once the string is padded to an even length.
        return ltrim((string) hex2bin($temp), chr(0));
    }

    /**
     * Adds two BigIntegers.
     */
    public function add(self $y): self
    {
        $value = $this->value->plus($y->value);

        return new self($value);
    }

    /**
     * Subtracts two BigIntegers.
     */
    public function subtract(self $y): self
    {
        $value = $this->value->minus($y->value);

        return new self($value);
    }

    /**
     * Multiplies two BigIntegers.
     */
    public function multiply(self $x): self
    {
        $value = $this->value->multipliedBy($x->value);

        return new self($value);
    }

    /**
     * Performs modular exponentiation.
     */
    public function modPow(self $e, self $n): self
    {
        $value = $this->value->modPow($e->value, $n->value);

        return new self($value);
    }

    /**
     * Returns the modular multiplicative inverse of this number modulo $m.
     *
     * @throws MathException if this number is not invertible modulo $m, i.e. if they are not coprime
     */
    public function modInverse(self $m): self
    {
        $value = $this->value->modInverse($m->value);

        return new self($value);
    }

    /**
     * Performs modular exponentiation.
     */
    public function mod(self $d): self
    {
        $value = $this->value->mod($d->value);

        return new self($value);
    }

    /**
     * Compares two numbers.
     */
    public function compare(self $y): int
    {
        return $this->value->compareTo($y->value);
    }

    /**
     * The quotient of the division by 2^$bits, i.e. the number with its $bits low-order bits dropped.
     */
    public function shiftRight(int $bits): self
    {
        return new self($this->value->shiftedRight($bits));
    }

    public function isOdd(): bool
    {
        return $this->value->isOdd();
    }

    public function isZero(): bool
    {
        return $this->value->isZero();
    }
}
