<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128CCM_16_64;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\KeyManagement\DirectEncryption;
use Cose\Algorithm\KeyManagement\DirectHkdf;
use Cose\Algorithm\KeyManagement\DirectHKDF_AES128;
use Cose\Algorithm\KeyManagement\DirectHKDF_AES256;
use Cose\Algorithm\KeyManagement\DirectHKDF_SHA256;
use Cose\Algorithm\KeyManagement\DirectHKDF_SHA512;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Algorithm\Manager;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sprintf;
use function strlen;

/**
 * "direct+HKDF-*" (RFC 9053 section 6.1.2): the four identifiers against the values of cose-wg/Examples, the key
 * checks of the section, and the salt-or-nonce rule the sending side enforces.
 *
 * The cose-wg/Examples fixtures cover every identifier end to end, message included; see
 * {@see \Cose\Tests\CoseWg\CoseWgFixtureTest}.
 */
final class DirectHkdfTest extends TestCase
{
    /**
     * The first fixture of each hkdf-*-examples directory: the shared secret, the recipient as it is on the wire
     * (protected h'A1012x', unprotected with the salt), and the CEK the generator recorded for AES-CCM-16-64-128.
     *
     * @return iterable<string, array{DirectHkdf, int, string, string, string, string}>
     */
    public static function fixtures(): iterable
    {
        yield 'direct+HKDF-SHA-256' => [DirectHKDF_SHA256::create(), -10, 'direct+HKDF-SHA-256', '849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'a10129', '32547753d1e24f41579d770ba852d4c9'];
        yield 'direct+HKDF-SHA-512' => [DirectHKDF_SHA512::create(), -11, 'direct+HKDF-SHA-512', '849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'a1012a', self::cekOf('hkdf-hmac-sha-examples/hmac-sha-512-01')];
        yield 'direct+HKDF-AES-128' => [DirectHKDF_AES128::create(), -12, 'direct+HKDF-AES-128', '849b57219dae48de646d07dbb533566e', 'a1012b', 'f0ccbaf836d73da63ed8508ef966eec9'];
        yield 'direct+HKDF-AES-256' => [DirectHKDF_AES256::create(), -13, 'direct+HKDF-AES-256', '0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a798897a6b5c4d3e2f100', 'a1012c', '17b0bca769867bf795d2aa0d77c6984d'];
    }

    #[Test]
    #[DataProvider('fixtures')]
    public function theKeyOfTheLayerBelowIsDerivedFromTheSharedSecret(
        DirectHkdf $algorithm,
        int $identifier,
        string $name,
        string $secret,
        string $protected,
        string $cek
    ): void {
        // Given
        $recipient = self::recipient((string) hex2bin($protected), 'aabbccddeeffgghh');
        $layer = RecipientLayer::fromRecipient($recipient, A128CCM_16_64::create());
        $key = self::key((string) hex2bin($secret));

        // Then
        static::assertSame($identifier, $algorithm::identifier());
        static::assertSame($name, $algorithm->name());
        static::assertInstanceOf(DirectEncryption::class, $algorithm);
        static::assertTrue($algorithm->isDirect());
        static::assertSame($cek, bin2hex($algorithm->recoverKey($layer, $key)));

        // The sending side derives the same key, and the recipient carries nothing but its headers.
        $protectedKey = $algorithm->protectKey($layer, $key);
        static::assertSame($cek, bin2hex($protectedKey->key()));
        static::assertSame('', $protectedKey->ciphertext());
        static::assertCount(0, $protectedKey->headerParameters());
    }

    /**
     * RFC 9053 section 5.1: "If the extract step is skipped, the 'salt' value is not used as part of the HKDF
     * functionality" -- the AES variants derive the same key with and without it.
     */
    #[Test]
    public function theAesVariantsIgnoreTheSalt(): void
    {
        $key = self::key((string) hex2bin('849b57219dae48de646d07dbb533566e'));
        $withSalt = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a1012b'), 'aabbccddeeffgghh'), A128CCM_16_64::create());
        $withoutSalt = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a1012b'), null), A128CCM_16_64::create());

        static::assertSame(
            bin2hex(DirectHKDF_AES128::create()->recoverKey($withSalt, $key)),
            bin2hex(DirectHKDF_AES128::create()->recoverKey($withoutSalt, $key))
        );
        static::assertTrue(DirectHKDF_AES128::create()->hkdf()->skipsExtract());
        static::assertFalse(DirectHKDF_SHA256::create()->hkdf()->skipsExtract());
    }

    /**
     * ... whereas the HMAC variants do use it.
     */
    #[Test]
    public function theHmacVariantsUseTheSalt(): void
    {
        $key = self::key(random_bytes(32));
        $withSalt = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), 'salt'), A128GCM::create());
        $withoutSalt = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), null), A128GCM::create());

        static::assertNotSame(
            bin2hex(DirectHKDF_SHA256::create()->recoverKey($withSalt, $key)),
            bin2hex(DirectHKDF_SHA256::create()->recoverKey($withoutSalt, $key))
        );
    }

    /**
     * The derived key is as long as the layer below needs, and bound to that length through the context: a 128-bit
     * and a 256-bit key for the same algorithm family are not prefixes of one another.
     */
    #[Test]
    public function theDerivedKeyIsBoundToTheAlgorithmAndLengthOfTheLayerBelow(): void
    {
        $key = self::key(random_bytes(32));
        $recipient = self::recipient((string) hex2bin('a10129'), 'salt');

        $for128 = DirectHKDF_SHA256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, 1, 16), $key);
        $for256 = DirectHKDF_SHA256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, 3, 32), $key);
        $for128AsGcm = DirectHKDF_SHA256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, 10, 16), $key);

        static::assertSame(16, strlen($for128));
        static::assertSame(32, strlen($for256));
        static::assertNotSame(bin2hex($for128), bin2hex(substr($for256, 0, 16)));
        static::assertNotSame(bin2hex($for128), bin2hex($for128AsGcm));
    }

    /**
     * RFC 9053 section 6.1.2: "Either the 'salt' parameter for HKDF (Table 9) or the 'PartyU nonce' parameter for
     * the context structure (Table 10) MUST be present" -- the sending side refuses to derive without one of the two.
     */
    #[Test]
    public function theSendingSideRefusesToDeriveWithoutASaltOrAPartyUNonce(): void
    {
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create((string) hex2bin('a10129')), MapObject::create()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A direct+HKDF-SHA-256 recipient MUST carry a "salt" (-20) or a "PartyU nonce" (-22) header parameter, unique for the pair of keys (RFC 9053 section 6.1.2).');

        DirectHKDF_SHA256::create()->protectKey($layer, self::key(random_bytes(32)));
    }

    #[Test]
    public function aPartyUNonceSatisfiesTheSendingSide(): void
    {
        $unprotected = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_NONCE), UnsignedIntegerObject::create(7)),
        ]);
        $headers = CoseHeaders::of(ByteStringObject::create((string) hex2bin('a10129')), $unprotected);
        $key = self::key(random_bytes(32));

        $protected = DirectHKDF_SHA256::create()->protectKey(RecipientLayer::create($headers, A128GCM::create()), $key);

        // What the sender derived, the receiver recovers from the recipient the sender built.
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create((string) hex2bin('a10129')),
            $unprotected,
            ByteStringObject::create($protected->ciphertext()),
        ]));
        static::assertSame(16, strlen($protected->key()));
        static::assertSame(
            bin2hex($protected->key()),
            bin2hex(DirectHKDF_SHA256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), $key))
        );
    }

    /**
     * ... while the receiving side derives with what the message carries: hkdf-hmac-sha-examples/hmac-sha-256-08
     * of cose-wg/Examples carries neither.
     */
    #[Test]
    public function theReceivingSideDerivesWithoutASaltOrANonce(): void
    {
        $recipient = self::recipient((string) hex2bin('a10129'), null);
        $key = self::key(random_bytes(32));

        static::assertSame(16, strlen(DirectHKDF_SHA256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), $key)));
    }

    #[Test]
    public function theSendingSideRefusesAKeyToProtect(): void
    {
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('direct+HKDF-SHA-512 derives the key of the layer below from the shared secret: no key can be given to protect.');

        DirectHKDF_SHA512::create()->protectKey($layer, self::key(random_bytes(32)), random_bytes(16));
    }

    #[Test]
    public function aNonEmptyCiphertextIsRejected(): void
    {
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create((string) hex2bin('a10129')),
            MapObject::create(),
            ByteStringObject::create('wrapped?'),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "ciphertext" field of a direct+HKDF-SHA-256 recipient MUST be a zero-length byte string');

        DirectHKDF_SHA256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), self::key(random_bytes(32)));
    }

    #[Test]
    public function aSiblingRecipientIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('direct+HKDF-SHA-256 decides the key of the layer below and MUST be the only recipient of the message');

        DirectHKDF_SHA256::create()->recoverKey(
            RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), 'salt'), A128GCM::create(), null, 2),
            self::key(random_bytes(32))
        );
    }

    #[Test]
    public function aKeyOfAnotherTypeIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key type of a direct+HKDF-SHA-256 key MUST be "Symmetric" (RFC 9053 section 6.1.2), got "1".');

        DirectHKDF_SHA256::create()->recoverKey(
            RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), 'salt'), A128GCM::create()),
            Key::create([
                Key::TYPE => Key::TYPE_OKP,
            ])
        );
    }

    /**
     * RFC 9053 section 6.1.2: "If the 'alg' field is present, it MUST match the algorithm being used." Enforced by
     * default.
     */
    #[Test]
    public function aKeyRestrictedToAnotherAlgorithmIsRejected(): void
    {
        $key = self::key(random_bytes(32), [
            Key::ALG => DirectHKDF_SHA512::ID,
        ]);
        $layer = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), 'salt'), A128GCM::create());

        static::assertTrue(DirectHKDF_SHA256::create()->enforcesKeyRestrictions());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is restricted to the algorithm -11 and cannot be used with the algorithm -10');

        DirectHKDF_SHA256::create()->recoverKey($layer, $key);
    }

    /**
     * "If the 'key_ops' field is present, it MUST include 'derive key' or 'derive bits'."
     */
    #[Test]
    public function aKeyThatMayNotDeriveIsRejected(): void
    {
        $key = self::key(random_bytes(32), [
            Key::KEY_OPS => [Key::OP_ENCRYPT],
        ]);
        $layer = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), 'salt'), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key does not allow the "derive key" nor the "derive bits" operation');

        DirectHKDF_SHA256::create()->recoverKey($layer, $key);
    }

    #[Test]
    public function aKeyThatMayDeriveBitsIsAccepted(): void
    {
        $key = self::key(random_bytes(32), [
            Key::ALG => DirectHKDF_SHA256::ID,
            Key::KEY_OPS => [Key::OP_DERIVE_BITS],
        ]);
        $layer = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), 'salt'), A128GCM::create());

        static::assertSame(16, strlen(DirectHKDF_SHA256::create()->recoverKey($layer, $key)));
    }

    #[Test]
    public function theEnforcementCanBeTurnedOff(): void
    {
        $key = self::key(random_bytes(32), [
            Key::ALG => DirectHKDF_SHA512::ID,
            Key::KEY_OPS => [Key::OP_ENCRYPT],
        ]);
        $layer = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a10129'), 'salt'), A128GCM::create());
        $lenient = DirectHKDF_SHA256::create()->withKeyRestrictionsEnforced(false);

        static::assertFalse($lenient->enforcesKeyRestrictions());
        static::assertSame(16, strlen($lenient->recoverKey($layer, $key)));
        static::assertSame(16, strlen(Manager::create()->add(DirectHKDF_SHA256::create())->withKeyRestrictionsEnforced(false)->get(-10)->recoverKey($layer, $key)));
    }

    /**
     * RFC 9053 section 5.1: the AES variants use the secret as the PRF key, so it has to be an AES key.
     */
    #[Test]
    public function theAesVariantsRefuseASecretOfAnotherLength(): void
    {
        $layer = RecipientLayer::fromRecipient(self::recipient((string) hex2bin('a1012b'), 'salt'), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('HKDF AES-MAC-128 skips the extract step and uses the shared secret as the PRF key: it must be 16 bytes long, the secret is 32 bytes long.');

        DirectHKDF_AES128::create()->recoverKey($layer, self::key(random_bytes(32)));
    }

    /**
     * @param array<int, mixed> $restrictions
     */
    private static function key(string $secret, array $restrictions = []): SymmetricKey
    {
        return SymmetricKey::create($restrictions + [
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $secret,
        ]);
    }

    private static function recipient(string $protected, ?string $salt): CoseRecipient
    {
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('our-secret')),
        ]);
        if ($salt !== null) {
            $unprotected->add(NegativeIntegerObject::create(CoseHeaders::LABEL_SALT), ByteStringObject::create($salt));
        }

        return CoseRecipient::create(ListObject::create([
            ByteStringObject::create($protected),
            $unprotected,
            ByteStringObject::create(''),
        ]));
    }

    private static function cekOf(string $fixture): string
    {
        $document = json_decode((string) file_get_contents(sprintf('%s/../../fixtures/cose-wg/%s.json', __DIR__, $fixture)), true, 512, JSON_THROW_ON_ERROR);

        return strtolower((string) $document['intermediates']['CEK_hex']);
    }
}
