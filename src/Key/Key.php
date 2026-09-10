<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_key_exists;
use InvalidArgumentException;
use function is_string;
use function preg_match;
use function sprintf;

class Key
{
    public const TYPE = 1;

    public const TYPE_OKP = 1;

    public const TYPE_EC2 = 2;

    public const TYPE_RSA = 3;

    public const TYPE_OCT = 4;

    public const TYPE_NAME_OKP = 'OKP';

    public const TYPE_NAME_EC2 = 'EC';

    public const TYPE_NAME_RSA = 'RSA';

    public const TYPE_NAME_OCT = 'oct';

    public const KID = 2;

    public const ALG = 3;

    public const KEY_OPS = 4;

    public const BASE_IV = 5;

    /**
     * @var array<int|string, mixed>
     */
    private readonly array $data;

    /**
     * @param array<int|string, mixed> $data
     */
    public function __construct(array $data)
    {
        if (! array_key_exists(self::TYPE, $data)) {
            throw new InvalidArgumentException('Invalid key: the type is not defined');
        }
        $this->data = $data;
    }

    /**
     * @param array<int|string, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    /**
     * Builds the key class the "kty" of the data designates.
     *
     * The data is expected to be the output of spomky-labs/cbor-php's normalize(), which renders a CBOR integer as a
     * numeric string, or an equivalent PHP array: both the string and the native integer form of a registered key
     * type are dispatched, as is its name (RFC 9052, section 7.1, table 4 types "kty" as "tstr / int").
     *
     * @param array<int|string, mixed> $data
     */
    public static function createFromData(array $data): self
    {
        if (! array_key_exists(self::TYPE, $data)) {
            throw new InvalidArgumentException('Invalid key: the type is not defined');
        }

        return match ($data[self::TYPE]) {
            self::TYPE_OKP, '1', self::TYPE_NAME_OKP => new OkpKey($data),
            self::TYPE_EC2, '2', self::TYPE_NAME_EC2 => new Ec2Key($data),
            self::TYPE_RSA, '3', self::TYPE_NAME_RSA => new RsaKey($data),
            self::TYPE_OCT, '4', self::TYPE_NAME_OCT => new SymmetricKey($data),
            default => self::create($data),
        };
    }

    public function type(): int|string
    {
        return $this->data[self::TYPE];
    }

    public function alg(): int
    {
        return (int) $this->get(self::ALG);
    }

    /**
     * @return array<int|string, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    public function has(int|string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function get(int|string $key): mixed
    {
        if (! array_key_exists($key, $this->data)) {
            throw new InvalidArgumentException(sprintf('The key has no data at index %d', $key));
        }

        return $this->data[$key];
    }

    /**
     * spomky-labs/cbor-php normalises a CBOR integer to a numeric string (UnsignedIntegerObject::normalize()), so a
     * key decoded from CBOR carries its "kty" and its "crv" as such a string. Each listed entry that holds one is
     * replaced by the integer it denotes, before anything compares it against a registry value.
     *
     * Only an integer-looking string is converted. A float, or a string such as "1.5", " 1" or "4abc", is left as it
     * is so that the checks that follow reject it, instead of a lenient cast silently turning it into a valid
     * identifier.
     *
     * @param array<int|string, mixed> $data
     * @return array<int|string, mixed>
     */
    protected static function normalizeIntegerEntries(array $data, int|string ...$keys): array
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $data) && is_string($data[$key])
                && preg_match('/^-?\\d+$/', $data[$key]) === 1) {
                $data[$key] = (int) $data[$key];
            }
        }

        return $data;
    }

    protected function pem(string $type, string $der): string
    {
        return sprintf("-----BEGIN %s-----\n", strtoupper($type)) .
            chunk_split(base64_encode($der), 64, "\n") .
            sprintf("-----END %s-----\n", strtoupper($type));
    }
}
