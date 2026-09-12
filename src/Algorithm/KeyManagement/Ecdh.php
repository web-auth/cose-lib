<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\KeyRestrictionEnforcement;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use InvalidArgumentException;
use function sprintf;
use Throwable;

/**
 * The ECDH algorithms of RFC 9053 sections 6.3.1 and 6.4.1: an elliptic curve Diffie-Hellman agreement, an HKDF
 * over its shared secret with the COSE_KDF_Context of section 5.2, and either the derived key itself for the layer
 * below (direct key agreement, table 14) or an AES Key Wrap under it (key agreement with key wrap, table 16).
 *
 * Two things vary between the twelve identifiers, and each subclass fixes them: whether the sender's key is
 * ephemeral or static, and whether a key wrap follows.
 *
 * - Ephemeral-Static: "the sender MUST generate a new ephemeral key for every key agreement operation", and the
 *   receiving side reads it from the "ephemeral key" header parameter (-1). The sender's ephemeral key is generated
 *   here, on the recipient's curve, and only its public half -- "kty", "crv", "x", "y" -- goes into the header;
 *   {@see ProtectedKey::headerParameters()} carries it.
 * - Static-Static: the sender's static key is the application's to supply on both sides,
 *   {@see RecipientLayer::withSenderKey()} -- its private key when sending, the sender's public key when receiving,
 *   resolved from "static key id", "x5t-sender", "x5u-sender" or a validated "x5chain-sender"; a "static key" (-2)
 *   header parameter is used when nothing was supplied. "The sender MUST either generate a new random value or
 *   create a unique value for use as a KDF input": the sending side refuses to run without a "salt" or a "PartyU
 *   nonce" header parameter; the receiving side derives with whatever the message carries.
 *
 * The keys are checked the way section 6.3.1 asks: "kty" is EC2 or OKP, the two keys are of the same type and on
 * the same curve, the curve is one ECDH is defined for, the EC2 point of the other party is on the curve, the OKP
 * shared secret is not all zeros -- see {@see EllipticCurveDiffieHellman}. The "alg" of the recipient's key, when
 * present, "MUST match the key agreement algorithm being used" and its "key_ops", when present, "MUST include
 * 'derive key' or 'derive bits' for the private key" and "MUST be empty for the public key"; both are enforced by
 * default, {@see KeyRestrictionAware}, these classes being new.
 *
 * The KDF context binds the derived key to what it is for: the algorithm and key length of the layer below for
 * direct key agreement, "the size of the key used for the key wrap algorithm" and that algorithm for key agreement
 * with key wrap (section 6.4.1). The HKDF is the HMAC one in every case: "the AES HKDF version cannot be used with
 * ECDH" (section 5.1), and no such identifier exists.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.4.1
 * @see \Cose\Tests\Algorithm\KeyManagement\EcdhTest
 */
abstract class Ecdh implements KeyAgreement, KeyRestrictionAware
{
    use KeyRestrictionEnforcement;

    public function __construct()
    {
        // RFC 9053 section 6.3.1 makes the "alg" and "key_ops" checks a MUST, and these algorithms have no caller to
        // keep compatible: they enforce the restrictions unless told otherwise.
        $this->enforceKeyRestrictions = true;
    }

    /**
     * The name of RFC 9053 tables 14 and 16: "ECDH-ES + HKDF-256", "ECDH-SS + A128KW", ...
     */
    abstract public function name(): string;

    /**
     * The HKDF of RFC 9053 table 8 this identifier selects: HKDF SHA-256 or HKDF SHA-512.
     */
    abstract public function hkdf(): Hkdf;

    public function keyWrap(): ?KeyWrap
    {
        return null;
    }

    public function isDirect(): bool
    {
        return $this->keyWrap() === null;
    }

    public function agree(RecipientLayer $layer, Ec2Key|OkpKey $privateKey, Ec2Key|OkpKey $publicKey): string
    {
        $secret = EllipticCurveDiffieHellman::sharedSecret($privateKey, $publicKey);
        $wrap = $this->keyWrap();
        // RFC 9053 section 6.4.1: "The size of the key used for the key wrap algorithm is fed into the KDF."
        $context = $wrap === null
            ? $layer->kdfContext()
            : $layer->kdfContext($wrap::identifier(), $wrap->keyLength());
        $length = $wrap === null ? $layer->keyLength() : $wrap->keyLength();

        return $this->hkdf()
            ->derive($secret, $layer->headers()->getSalt(), (string) $context, $length);
    }

    public function recoverKey(RecipientLayer $layer, Key $recipientKey): string
    {
        $private = $this->privateKey($recipientKey);
        $public = $this->isEphemeralStatic()
            ? $this->ephemeralKeyOf($layer->headers())
            : $this->staticKeyOf($layer);
        $this->checkPublicKeyRestrictions($public);

        $wrap = $this->keyWrap();
        if ($wrap === null) {
            LayerRules::assertDirectRecipientCarriesAnEmptyCiphertext($layer, $this->name());

            return $this->agree($layer, $private, $public);
        }

        return $wrap->unwrap(
            self::symmetricKey($this->agree($layer, $private, $public)),
            LayerRules::wrappedKeyOf($layer, $this->name())
        );
    }

    public function protectKey(RecipientLayer $layer, Key $recipientKey, ?string $key = null): ProtectedKey
    {
        $recipientPublic = $this->publicKey($recipientKey);
        $this->checkRecipientPublicKeyRestrictions($recipientPublic);

        $wrap = $this->keyWrap();
        if ($wrap === null) {
            if ($key !== null) {
                throw new InvalidArgumentException(sprintf(
                    '%s derives the key of the layer below from the agreement: no key can be given to protect.',
                    $this->name()
                ));
            }
            LayerRules::assertDirectRecipient($layer, $this->name());
            [$sender, $parameters] = $this->senderKeyFor($layer, $recipientPublic);

            return ProtectedKey::create($this->agree($layer, $sender, $recipientPublic), $parameters, '');
        }

        if ($key === null) {
            throw new InvalidArgumentException(sprintf(
                '%s wraps the key of the layer below: the key to protect has to be given.',
                $this->name()
            ));
        }
        [$sender, $parameters] = $this->senderKeyFor($layer, $recipientPublic);
        $kek = self::symmetricKey($this->agree($layer, $sender, $recipientPublic));

        return ProtectedKey::create($key, $parameters, $wrap->wrap($kek, $key));
    }

    /**
     * The sender's key of the agreement, and the header parameters that let the receiving side find it: a fresh
     * ephemeral key on the recipient's curve, carried as the "ephemeral key" parameter, for the Ephemeral-Static
     * algorithms; the static private key the application supplied, carried as nothing -- the application identifies
     * it through "static key", "static key id" or the "*-sender" parameters of RFC 9360 -- for the Static-Static
     * ones, which also have to carry the "salt" or "PartyU nonce" RFC 9053 section 6.3.1 requires of them.
     *
     * @return array{Ec2Key|OkpKey, MapObject}
     */
    private function senderKeyFor(RecipientLayer $layer, Ec2Key|OkpKey $recipientPublic): array
    {
        if ($this->isEphemeralStatic()) {
            $sender = EllipticCurveDiffieHellman::generateEphemeralKey($recipientPublic);
            $parameters = MapObject::create([
                MapItem::create(
                    NegativeIntegerObject::create(CoseHeaders::LABEL_EPHEMERAL_KEY),
                    self::publicKeyToCBOR($sender)
                ),
            ]);

            return [$sender, $parameters];
        }

        $sender = $layer->senderKey() ?? throw new InvalidArgumentException(sprintf(
            '%s needs the sender\'s static private key: give it with RecipientLayer::withSenderKey().',
            $this->name()
        ));
        if (! $sender->isPrivate()) {
            throw new InvalidArgumentException(sprintf(
                '%s needs the sender\'s static private key to send, the key given is public.',
                $this->name()
            ));
        }
        LayerRules::assertSaltOrPartyUNonce($layer, $this->name(), '6.3.1');

        return [$sender, MapObject::create()];
    }

    /**
     * The recipient's private key, with the checks of RFC 9053 section 6.3.1 on its type, its curve and its
     * restrictions: "If the 'key_ops' field is present, it MUST include 'derive key' or 'derive bits' for the
     * private key."
     */
    private function privateKey(Key $key): Ec2Key|OkpKey
    {
        $key = $this->agreementKey($key);
        if (! $key->isPrivate()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key. %s needs the recipient\'s private key to recover the key, the key given is public.',
                $this->name()
            ));
        }
        $this->checkKeyRestrictions($key, Key::OP_DERIVE_KEY, Key::OP_DERIVE_BITS);

        return $key;
    }

    /**
     * The recipient's public key as the sender holds it; a private key is accepted and reduced to its public half.
     */
    private function publicKey(Key $key): Ec2Key|OkpKey
    {
        return $this->agreementKey($key)
            ->toPublic();
    }

    /**
     * RFC 9053 section 6.3.1: "The 'kty' field MUST be present, and it MUST be 'EC2' or 'OKP'." A generic Key of
     * one of those types is rebuilt as the typed class, and anything the constructor objects to reaches the caller
     * as the exception this library documents.
     */
    private function agreementKey(Key $key): Ec2Key|OkpKey
    {
        if ($key instanceof Ec2Key || $key instanceof OkpKey) {
            return $key;
        }
        try {
            return match (true) {
                $key->typeIs(Key::TYPE_EC2) => Ec2Key::create($key->getData()),
                $key->typeIs(Key::TYPE_OKP) => OkpKey::create($key->getData()),
                default => throw new InvalidArgumentException(sprintf(
                    'Invalid key. The key type of a %s key MUST be "EC2" or "OKP" (RFC 9053 section 6.3.1), got "%s".',
                    $this->name(),
                    $key->type()
                )),
            };
        } catch (InvalidArgumentException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidArgumentException('Invalid ECDH key: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * RFC 9052 section 8.5.4: the headers "MUST contain the sender's ephemeral key for the ephemeral-static
     * versions".
     */
    private function ephemeralKeyOf(CoseHeaders $headers): Ec2Key|OkpKey
    {
        return $headers->getEphemeralKey() ?? throw new InvalidArgumentException(sprintf(
            'Invalid recipient. A %s recipient MUST carry the sender\'s "ephemeral key" (-1) header parameter (RFC 9052 section 8.5.4).',
            $this->name()
        ));
    }

    /**
     * The sender's static public key: the one the application resolved and supplied, or else the "static key" the
     * headers carry. A "static key id", "x5t-sender", "x5u-sender" or "x5chain-sender" names a key this library does
     * not hold or does not trust on its own, so their presence without a supplied key is what the message says.
     */
    private function staticKeyOf(RecipientLayer $layer): Ec2Key|OkpKey
    {
        $supplied = $layer->senderKey();
        if ($supplied !== null) {
            return $supplied->toPublic();
        }
        $headers = $layer->headers();
        $carried = $headers->getStaticKey();
        if ($carried !== null) {
            return $carried;
        }
        $identified = $headers->getStaticKeyId() !== null
            || $headers->getHeaderParameter(CoseHeaders::LABEL_X5T_SENDER) !== null
            || $headers->getHeaderParameter(CoseHeaders::LABEL_X5U_SENDER) !== null
            || $headers->getHeaderParameter(CoseHeaders::LABEL_X5CHAIN_SENDER) !== null;

        throw new InvalidArgumentException($identified
            ? sprintf(
                'A %s recipient identifies the sender\'s static key without carrying it: resolve it from the "static key id" (-3) or the "*-sender" (-27, -28, -29) header parameter and give it with RecipientLayer::withSenderKey().',
                $this->name()
            )
            : sprintf(
                'A %s recipient neither carries nor identifies the sender\'s static key: give it with RecipientLayer::withSenderKey().',
                $this->name()
            ));
    }

    /**
     * The restrictions of the sender's public key, read from the message: RFC 9053 section 6.3.1, "If the 'key_ops'
     * field is present, it MUST be empty for the public key", and the "alg", when present, must match as for any key.
     */
    private function checkPublicKeyRestrictions(Ec2Key|OkpKey $public): void
    {
        if (! $this->enforcesKeyRestrictions()) {
            return;
        }
        $this->checkAlgRestriction($public);
        $keyOps = $public->keyOps();
        if ($keyOps !== null && $keyOps !== []) {
            throw new InvalidArgumentException(
                'The sender\'s public key carries a "key_ops" that is not empty, which RFC 9053 section 6.3.1 forbids for the public key of an ECDH agreement.'
            );
        }
    }

    /**
     * The restrictions of the recipient's public key, as the sender holds it. The same rule applies -- an empty
     * "key_ops" -- except that the sender may hold the recipient's full key pair, whose "key_ops" then lists what
     * the private half may do: a "derive key" or "derive bits" is accepted as well.
     */
    private function checkRecipientPublicKeyRestrictions(Ec2Key|OkpKey $public): void
    {
        if (! $this->enforcesKeyRestrictions()) {
            return;
        }
        $this->checkAlgRestriction($public);
        if ($public->keyOps() !== []) {
            $public->assertUsableWithAny(static::identifier(), Key::OP_DERIVE_KEY, Key::OP_DERIVE_BITS);
        }
    }

    private function checkAlgRestriction(Ec2Key|OkpKey $key): void
    {
        if ($key->has(Key::ALG) && $key->alg() !== static::identifier()) {
            throw new InvalidArgumentException(sprintf(
                'The key is restricted to the algorithm %d and cannot be used with the algorithm %d',
                $key->alg(),
                static::identifier()
            ));
        }
    }

    /**
     * The public half of a key as the "ephemeral key" header parameter carries it: "kty", "crv", "x" and "y" (or "x"
     * alone for OKP), the curve as its registry number, and nothing else.
     */
    private static function publicKeyToCBOR(Ec2Key|OkpKey $key): MapObject
    {
        $map = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(Key::TYPE), UnsignedIntegerObject::create($key instanceof Ec2Key ? Key::TYPE_EC2 : Key::TYPE_OKP)),
            MapItem::create(NegativeIntegerObject::create(Ec2Key::DATA_CURVE), UnsignedIntegerObject::create($key->curveId())),
            MapItem::create(NegativeIntegerObject::create(Ec2Key::DATA_X), ByteStringObject::create($key->x())),
        ]);
        if ($key instanceof Ec2Key) {
            $map->add(NegativeIntegerObject::create(Ec2Key::DATA_Y), ByteStringObject::create($key->y()));
        }

        return $map;
    }

    private static function symmetricKey(string $k): SymmetricKey
    {
        return SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ]);
    }
}
