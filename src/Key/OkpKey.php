<?php

declare(strict_types=1);

namespace Cose\Key;

use InvalidArgumentException;
use function array_key_exists;
use function in_array;
use function is_int;

/**
 * @final
 * @see \Cose\Tests\Key\OkpKeyTest
 */
class OkpKey extends Key
{
    final public const CURVE_X25519 = 4;

    final public const CURVE_X448 = 5;

    final public const CURVE_ED25519 = 6;

    final public const CURVE_ED448 = 7;

    final public const DATA_CURVE = -1;

    final public const DATA_X = -2;

    final public const DATA_D = -4;

    private const SUPPORTED_CURVES_INT = [
        self::CURVE_X25519,
        self::CURVE_X448,
        self::CURVE_ED25519,
        self::CURVE_ED448,
    ];

    private const SUPPORTED_CURVES_NAME = ['X25519', 'X448,', 'Ed25519', 'Ed448'];

    /**
     * @param array<int|string, mixed> $data
     */
    public function __construct(array $data)
    {
        parent::__construct($data);
        if ($data[self::TYPE] !== self::TYPE_OKP && $data[self::TYPE] !== self::TYPE_NAME_OKP) {
            throw new InvalidArgumentException('Invalid OKP key. The key type does not correspond to an OKP key');
        }
        if (! isset($data[self::DATA_CURVE], $data[self::DATA_X])) {
            throw new InvalidArgumentException('Invalid EC2 key. The curve or the "x" coordinate is missing');
        }
        if (is_int($data[self::DATA_CURVE])) {
            if (! in_array($data[self::DATA_CURVE], self::SUPPORTED_CURVES_INT, true)) {
                throw new InvalidArgumentException('The curve is not supported');
            }
        } elseif (! in_array($data[self::DATA_CURVE], self::SUPPORTED_CURVES_NAME, true)) {
            throw new InvalidArgumentException('The curve is not supported');
        }
    }

    /**
     * @param array<int|string, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    public function x(): string
    {
        return $this->get(self::DATA_X);
    }

    public function isPrivate(): bool
    {
        return array_key_exists(self::DATA_D, $this->getData());
    }

    public function d(): string
    {
        if (! $this->isPrivate()) {
            throw new InvalidArgumentException('The key is not private.');
        }

        return $this->get(self::DATA_D);
    }

    public function curve(): int|string
    {
        return $this->get(self::DATA_CURVE);
    }
}
