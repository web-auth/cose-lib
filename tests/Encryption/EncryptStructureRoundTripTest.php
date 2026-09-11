<?php

declare(strict_types=1);

namespace Cose\Tests\Encryption;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128CCM_16_64;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\ContentEncryption\A256GCM;
use Cose\Algorithm\ContentEncryption\Aead;
use Cose\Algorithm\ContentEncryption\ChaCha20Poly1305;
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Encryption\Encrypt0Structure;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\InitializationVector;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;

/**
 * Encrypting and decrypting through the Enc_structure: the ciphertext is bound to the protected header and to the
 * external AAD it was computed with, and to nothing else.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-5.3
 */
final class EncryptStructureRoundTripTest extends TestCase
{
    /**
     * RFC 9052 Appendix C.4.1 / cose-wg encrypted-tests/enc-pass-02: a COSE_Encrypt0 with an external AAD, decrypted
     * from the bytes on the wire, then produced again byte for byte.
     */
    #[Test]
    public function aCoseEncrypt0IsDecryptedFromTheWireAndReproduced(): void
    {
        // Given
        $key = self::key(hex2bin('849b57219dae48de646d07dbb533566e'));
        $externalAad = ByteStringObject::create(hex2bin('0011bbcc22dd4455dd220099'));
        $wire = hex2bin(
            'd08343a10101a1054c02d1f7e6f26c43d4868d87ce582460973a94bb2898009ee52ecfd9ab1dd25867374b1dc3a143880ca2883a5630da08ae1e6e'
        );
        $message = Decoder::create()->decode(StringStream::create($wire));
        static::assertInstanceOf(CoseEncrypt0Tag::class, $message);
        $headers = CoseHeaders::fromMessage($message);
        $algorithm = A128GCM::create();
        static::assertSame('1', $headers->getProtectedHeaderParameter(1)?->normalize());

        // When
        $nonce = InitializationVector::resolve($headers, $algorithm->nonceLength());
        $structure = Encrypt0Structure::create($message->getProtectedHeader(), $externalAad);
        $plaintext = $structure->decrypt($algorithm, $key, $message->getCiphertext()->getValue(), $nonce);

        // Then
        static::assertSame('This is the content.', $plaintext);
        static::assertSame(
            bin2hex($message->getCiphertext()->getValue()),
            bin2hex($structure->encrypt($algorithm, $key, $plaintext, $nonce))
        );
    }

    #[Test]
    public function aCoseEncryptCarriesTheSameContentUnderTheEncryptContext(): void
    {
        // Given
        $algorithm = A256GCM::create();
        $key = self::key(random_bytes(32));
        $nonce = random_bytes(12);
        $protectedHeader = self::protectedHeader($algorithm);
        $structure = EncryptStructure::create($protectedHeader);

        // When: the message is assembled around the ciphertext, with a "direct" recipient
        $ciphertext = $structure->encrypt($algorithm, $key, 'Secret shared with two parties', $nonce);
        $message = CoseEncryptTag::create(ListObject::create([
            $protectedHeader,
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(InitializationVector::IV), ByteStringObject::create($nonce)),
            ]),
            ByteStringObject::create($ciphertext),
            ListObject::create([
                ListObject::create([
                    ByteStringObject::create(''),
                    MapObject::create([
                        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-6)),
                    ]),
                    ByteStringObject::create(''),
                ]),
            ]),
        ]));
        $decoded = Decoder::create()->decode(StringStream::create((string) $message));

        // Then
        static::assertInstanceOf(CoseEncryptTag::class, $decoded);
        $resolved = InitializationVector::resolve(CoseHeaders::fromMessage($decoded), 12);
        static::assertSame(
            'Secret shared with two parties',
            EncryptStructure::create($decoded->getProtectedHeader())
                ->decrypt($algorithm, $key, $decoded->getCiphertext()->getValue(), $resolved)
        );

        // The context is part of what is authenticated: the same bytes do not open as a COSE_Encrypt0
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(Aead::DECRYPTION_FAILED);
        Encrypt0Structure::create($decoded->getProtectedHeader())
            ->decrypt($algorithm, $key, $decoded->getCiphertext()->getValue(), $resolved);
    }

    /**
     * The whole point of the Enc_structure: a protected header rewritten after encryption, or an external AAD the
     * recipient does not share, is a ciphertext that does not authenticate.
     */
    #[Test]
    public function theCiphertextIsBoundToTheProtectedHeaderAndTheExternalAad(): void
    {
        // Given
        $algorithm = ChaCha20Poly1305::isSupported() ? ChaCha20Poly1305::create() : A128GCM::create();
        $key = self::key(random_bytes($algorithm->keyLength()));
        $nonce = random_bytes($algorithm->nonceLength());
        $external = ByteStringObject::create('context the recipient knows');
        $ciphertext = Encrypt0Structure::create(self::protectedHeader($algorithm), $external)
            ->encrypt($algorithm, $key, 'content', $nonce);

        // Then: the same header and external AAD open it
        static::assertSame(
            'content',
            Encrypt0Structure::create(self::protectedHeader($algorithm), $external)
                ->decrypt($algorithm, $key, $ciphertext, $nonce)
        );

        // ... a rewritten protected header does not
        $rewritten = Encrypt0Structure::create(self::protectedHeader($algorithm, [
            4 => 'kid',
        ]), $external);
        try {
            $rewritten->decrypt($algorithm, $key, $ciphertext, $nonce);
            static::fail('Decrypted under a rewritten protected header');
        } catch (InvalidArgumentException $e) {
            static::assertSame(Aead::DECRYPTION_FAILED, $e->getMessage());
        }

        // ... and neither does a missing external AAD
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(Aead::DECRYPTION_FAILED);
        Encrypt0Structure::create(self::protectedHeader($algorithm))
            ->decrypt($algorithm, $key, $ciphertext, $nonce);
    }

    /**
     * RFC 9052 Appendix C.4.2: the message carries a "Partial IV" and the key a "Base IV".
     */
    #[Test]
    public function aMessageWithAPartialIvIsDecryptedWithTheBaseIvOfTheKey(): void
    {
        // Given: AES-CCM-16-64-128, so the fixture runs where the platform has AES-CCM only
        $algorithm = A128CCM_16_64::create();
        if (! $algorithm::isSupported()) {
            static::markTestSkipped('AES-CCM is not supported on this platform');
        }
        $key = self::key(hex2bin('849b5786457c1491be3a76dcea6c4271'), [
            Key::BASE_IV => hex2bin('89f52f65a1c58093'),
        ]);
        $message = Decoder::create()->decode(StringStream::create(hex2bin(
            'd08343a1010aa1064261a7581c252a8911d465c125b6764739700f0141ed09192de139e053bd09abca'
        )));
        static::assertInstanceOf(CoseEncrypt0Tag::class, $message);

        // When
        $nonce = InitializationVector::resolve(CoseHeaders::fromMessage($message), $algorithm->nonceLength(), $key);

        // Then
        static::assertSame('89f52f65a1c5809300000061a7', bin2hex($nonce));
        static::assertSame(
            'This is the content.',
            Encrypt0Structure::create($message->getProtectedHeader())
                ->decrypt($algorithm, $key, $message->getCiphertext()->getValue(), $nonce)
        );
    }

    /**
     * @param array<int, string> $extra
     */
    private static function protectedHeader(ContentEncryption $algorithm, array $extra = []): ByteStringObject
    {
        $map = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($algorithm::identifier())),
        ]);
        foreach ($extra as $label => $value) {
            $map->add(UnsignedIntegerObject::create($label), ByteStringObject::create($value));
        }

        return HeaderMapHelper::encodeProtected($map);
    }

    /**
     * @param array<int, mixed> $extra
     */
    private static function key(string $k, array $extra = []): SymmetricKey
    {
        return SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ] + $extra);
    }
}
