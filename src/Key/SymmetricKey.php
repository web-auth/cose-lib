<?php

declare(strict_types=1);

namespace Cose\Key;

use InvalidArgumentException;
use function is_string;

/**
 * @final
 */
class SymmetricKey extends Key
{
    final public const DATA_K = -1;

    /**
     * @param array<int|string, mixed> $data
     */
    public function __construct(array $data)
    {
        // The three sibling key classes normalise and store the key type; this one used to cast it inside its own
        // comparison only, so a key decoded from CBOR kept the string "4" that every HMAC algorithm then rejected.
        $data = self::normalizeIntegerEntries($data, self::TYPE);
        parent::__construct($data);
        if ($data[self::TYPE] !== self::TYPE_OCT && $data[self::TYPE] !== self::TYPE_NAME_OCT) {
            throw new InvalidArgumentException(
                'Invalid symmetric key. The key type does not correspond to a symmetric key'
            );
        }
        // RFC 9053 section 7.3, table 21 types "k" as a byte string.
        if (! isset($data[self::DATA_K]) || ! is_string($data[self::DATA_K])) {
            throw new InvalidArgumentException(
                'Invalid symmetric key. The parameter "k" is missing or is not a byte string'
            );
        }
    }

    /**
     * @param array<int|string, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    public function k(): string
    {
        return $this->get(self::DATA_K);
    }
}
