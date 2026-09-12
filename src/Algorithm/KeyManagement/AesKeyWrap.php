<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use AESKW\A128KW as Rfc3394A128KW;
use AESKW\A192KW as Rfc3394A192KW;
use AESKW\A256KW as Rfc3394A256KW;
use AESKW\Wrapper;
use CBOR\MapObject;
use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\KeyRestrictionEnforcement;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use function intdiv;
use InvalidArgumentException;
use function is_string;
use function sprintf;
use function strlen;
use Throwable;

/**
 * The AES Key Wrap of RFC 3394 (RFC 9053 section 6.2.1), "with the initial value [...] fixed to the value specified
 * in Section 2.2.3.1 of [RFC3394]": A128KW, A192KW and A256KW, one per key size of table 13.
 *
 * The primitive is spomky-labs/aes-key-wrap, which implements the wrap and the unwrap with the integrity check of
 * RFC 3394 section 2.2.3; what is added here is what COSE says around it. "Implementations that are encrypting or
 * decrypting MUST validate that the key type, key length, and algorithm are correct and appropriate for the
 * entities involved": the KEK has to be a symmetric key of exactly the size the identifier names, and its "alg" and
 * "key_ops" restrictions are enforced by default -- "encrypt" or "wrap key" to wrap, "decrypt" or "unwrap key" to
 * unwrap -- as {@see KeyRestrictionAware} describes, these classes being new. "The protected header bucket MUST be
 * empty": a recipient carrying one is refused on both sides, the primitive taking no additional data that could
 * authenticate it.
 *
 * The key to wrap is "a multiple of 64 bits" (RFC 3394 section 2), at least 128; a wrapped key is one 64-bit block
 * longer. A wrapped key that does not pass the integrity check is reported with one message, UNWRAP_FAILED, whether
 * the KEK is wrong or the value was tampered with: the primitive cannot tell the two apart.
 *
 * The KEK "needs to have some method of being regularly updated over time" (section 6.2.1.1); nothing here does it.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.2.1
 * @see https://www.rfc-editor.org/rfc/rfc3394
 * @see \Cose\Tests\Algorithm\KeyManagement\AesKeyWrapTest
 */
abstract class AesKeyWrap implements KeyWrap, KeyRestrictionAware
{
    use KeyRestrictionEnforcement;

    public const UNWRAP_FAILED = 'The wrapped key could not be unwrapped: the integrity check of RFC 3394 section 2.2.3 failed for this key-encryption key.';

    /**
     * RFC 3394 section 2: the key data is "n 64-bit blocks", with n at least 2 -- the smallest key AES Key Wrap is
     * defined for is 128 bits.
     */
    private const BLOCK_SIZE = 8;

    private const MINIMUM_KEY_LENGTH = 16;

    public function __construct()
    {
        // RFC 9053 section 6.2.1 makes the "alg" and "key_ops" checks a MUST, and these algorithms have no caller to
        // keep compatible: they enforce the restrictions unless told otherwise.
        $this->enforceKeyRestrictions = true;
    }

    public function isDirect(): bool
    {
        return false;
    }

    public function keyLength(): int
    {
        return intdiv(static::keyLengthInBits(), 8);
    }

    /**
     * The name of RFC 9053 table 13: "A128KW", ...
     */
    public function name(): string
    {
        return sprintf('A%dKW', static::keyLengthInBits());
    }

    public function wrap(SymmetricKey $kek, string $key): string
    {
        // RFC 9053 section 6.2.1: "If the 'key_ops' field is present, it MUST include 'encrypt' or 'wrap key' when
        // encrypting."
        $k = $this->checkKek($kek, Key::OP_WRAP_KEY, Key::OP_ENCRYPT);
        if (strlen($key) < self::MINIMUM_KEY_LENGTH || strlen($key) % self::BLOCK_SIZE !== 0) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key to wrap. AES Key Wrap takes a key of at least %d bytes and a multiple of %d bytes (RFC 3394 section 2), the key is %d bytes long.',
                self::MINIMUM_KEY_LENGTH,
                self::BLOCK_SIZE,
                strlen($key)
            ));
        }

        return $this->wrapper()::wrap($k, $key);
    }

    public function unwrap(SymmetricKey $kek, string $wrappedKey): string
    {
        // ... and "it MUST include 'decrypt' or 'unwrap key' when decrypting."
        $k = $this->checkKek($kek, Key::OP_UNWRAP_KEY, Key::OP_DECRYPT);
        // One block more than the smallest key: anything shorter or unaligned cannot be the output of the wrap and is
        // reported as a failed integrity check, which is what it would come out as.
        if (strlen($wrappedKey) < self::MINIMUM_KEY_LENGTH + self::BLOCK_SIZE
            || strlen($wrappedKey) % self::BLOCK_SIZE !== 0) {
            throw new InvalidArgumentException(self::UNWRAP_FAILED);
        }

        try {
            return $this->wrapper()::unwrap($k, $wrappedKey);
        } catch (Throwable $e) {
            throw new InvalidArgumentException(self::UNWRAP_FAILED, 0, $e);
        }
    }

    public function recoverKey(RecipientLayer $layer, Key $recipientKey): string
    {
        LayerRules::assertEmptyProtectedHeader($layer, $this->name(), '6.2.1');

        return $this->unwrap($this->symmetricKey($recipientKey), LayerRules::wrappedKeyOf($layer, $this->name()));
    }

    public function protectKey(RecipientLayer $layer, Key $recipientKey, ?string $key = null): ProtectedKey
    {
        if ($key === null) {
            throw new InvalidArgumentException(sprintf(
                '%s wraps the key of the layer below: the key to protect has to be given.',
                $this->name()
            ));
        }
        LayerRules::assertEmptyProtectedHeader($layer, $this->name(), '6.2.1');

        return ProtectedKey::create($key, MapObject::create(), $this->wrap($this->symmetricKey($recipientKey), $key));
    }

    /**
     * The key length in bits: 128, 192 or 256.
     */
    abstract protected static function keyLengthInBits(): int;

    /**
     * @return class-string<Wrapper>
     */
    private function wrapper(): string
    {
        return match (static::keyLengthInBits()) {
            128 => Rfc3394A128KW::class,
            192 => Rfc3394A192KW::class,
            default => Rfc3394A256KW::class,
        };
    }

    /**
     * @param int $operation the Key::OP_* constant of the operation the KEK is about to be used for
     * @param int $alternative the Key::OP_* constant the key may list that operation under instead
     *
     * @throws InvalidArgumentException when the KEK cannot be used with this algorithm
     * @return string the key value
     */
    private function checkKek(SymmetricKey $kek, int $operation, int $alternative): string
    {
        $k = $kek->k();
        if (strlen($k) !== $this->keyLength()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key-encryption key. %s takes a %d-byte key, the key is %d bytes long.',
                $this->name(),
                $this->keyLength(),
                strlen($k)
            ));
        }
        $this->checkKeyRestrictions($kek, $operation, $alternative);

        return $k;
    }

    /**
     * RFC 9053 section 6.2.1: the "kty" field "MUST be 'Symmetric'". A generic Key of that type is accepted, the way
     * the MAC algorithms accept theirs, and rebuilt as a SymmetricKey so that its value is checked to be a byte
     * string before it is used.
     */
    private function symmetricKey(Key $key): SymmetricKey
    {
        if ($key instanceof SymmetricKey) {
            return $key;
        }
        if (! $key->typeIs(Key::TYPE_OCT)) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key. The key type of a %s key MUST be "Symmetric" (RFC 9053 section 6.2.1), got "%s".',
                $this->name(),
                $key->type()
            ));
        }
        if (! $key->has(SymmetricKey::DATA_K) || ! is_string($key->get(SymmetricKey::DATA_K))) {
            throw new InvalidArgumentException(
                'Invalid key. The value of the key must be a byte string (CBOR objects shall be normalized first)'
            );
        }

        return SymmetricKey::create($key->getData());
    }
}
