<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use CBOR\MapObject;
use Cose\Key\Key;
use InvalidArgumentException;
use function is_string;
use function sprintf;

/**
 * "direct" (RFC 9053 section 6.1.1): "the identified key is directly used as the key for the next layer down in the
 * message".
 *
 * The recipient carries nothing but the identification of the shared secret: "the 'protected' field MUST be zero
 * length" (section 6.1.1), the "ciphertext" "MUST be a zero-length byte string", the "recipients" "MUST be absent",
 * and "it MUST be the only mode used on the message" (RFC 9052 section 8.5.1). All four are checked, on both sides.
 * "The key type MUST be 'Symmetric'" (section 6.1.1): the key value is handed to the layer below as it is.
 *
 * Section 6.1.1 defines no "key_ops" for this algorithm and the key is the content key itself, so the "alg" and
 * "key_ops" restrictions it may carry describe the content encryption or MAC algorithm, which enforces them when it
 * uses the key; nothing is enforced here. Section 6.1.1.1 lists what the application has to live with: the keys
 * "need to have some method of being regularly updated over time", "need to be dedicated to a single algorithm",
 * and "breaking one message means all messages are broken".
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.1.1
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-8.5.1
 * @see \Cose\Tests\Algorithm\KeyManagement\DirectTest
 */
final class Direct implements DirectEncryption
{
    public const ID = -6;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    public function isDirect(): bool
    {
        return true;
    }

    public function recoverKey(RecipientLayer $layer, Key $recipientKey): string
    {
        LayerRules::assertDirectRecipientCarriesAnEmptyCiphertext($layer, 'direct');
        LayerRules::assertEmptyProtectedHeader($layer, 'direct', '6.1.1');

        return self::secretOf($recipientKey);
    }

    public function protectKey(RecipientLayer $layer, Key $recipientKey, ?string $key = null): ProtectedKey
    {
        if ($key !== null) {
            throw new InvalidArgumentException(
                'direct uses the shared secret as the key of the layer below: no key can be given to protect.'
            );
        }
        LayerRules::assertDirectRecipient($layer, 'direct');
        LayerRules::assertEmptyProtectedHeader($layer, 'direct', '6.1.1');

        return ProtectedKey::create(self::secretOf($recipientKey), MapObject::create(), '');
    }

    /**
     * The key value of a symmetric key, checked the way the MAC algorithms check theirs: present, a byte string,
     * not empty.
     */
    private static function secretOf(Key $key): string
    {
        if (! $key->typeIs(Key::TYPE_OCT)) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key. The key type of a direct key MUST be "Symmetric" (RFC 9053 section 6.1.1), got "%s".',
                $key->type()
            ));
        }
        if (! $key->has(-1)) {
            throw new InvalidArgumentException('Invalid key. The value of the key is missing');
        }
        $k = $key->get(-1);
        if (! is_string($k)) {
            throw new InvalidArgumentException(
                'Invalid key. The value of the key must be a byte string (CBOR objects shall be normalized first)'
            );
        }
        if ($k === '') {
            throw new InvalidArgumentException('Invalid key. The value of the key is empty');
        }

        return $k;
    }
}
