<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\MLDSA;

use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\KeyRestrictionEnforcement;
use Cose\Algorithm\Signature\OpenSslError;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\AkpKey;
use Cose\Key\Key;
use function hash_equals;
use InvalidArgumentException;
use function is_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;
use const PHP_VERSION_ID;
use RuntimeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use function sprintf;
use function str_repeat;
use function strlen;
use Throwable;

/**
 * ML-DSA (FIPS 204), as RFC 9964 registers it for COSE: the pure signature of FIPS 204 algorithm 2, with the empty
 * context string, over a key of the AKP type. No HashML-DSA (section 7.2 of the RFC explains why it is excluded), no
 * non-empty "ctx" (section 5: "The ctx parameter MUST be the empty string").
 *
 * The computation is OpenSSL's, through ext-openssl: OpenSSL 3.5 ships ML-DSA in its default provider, loads the
 * seed-only PrivateKeyInfo of RFC 9881 that an AKP "priv" maps to, and signs and verifies with no digest, which is
 * what a one-shot scheme needs and what PHP only lets openssl_sign() express as of 8.4. Two platform gates follow,
 * both behind isSupported(): the PHP version, and the OpenSSL library actually loaded at runtime - which is not
 * always the one PHP was compiled against, so the gate loads an ML-DSA key rather than reading a version constant.
 * Call isSupported() when the platform is not known in advance; create() throws a RuntimeException naming the
 * missing piece.
 *
 * The key is checked before OpenSSL sees it (RFC 9964, section 7.3): {@see AkpKey} enforces the seed and public key
 * sizes of the parameter set, this class the "alg" the AKP type cannot do without, and - when the key carries both
 * halves - that the public key is the one the seed expands to, since section 7.4 warns that mismatched parameters
 * range "from operations failing to private key compromise".
 *
 * @see https://www.rfc-editor.org/rfc/rfc9964.html#section-5
 * @see \Cose\Tests\Algorithm\Signature\MLDSA\MLDSATest
 */
abstract class MLDSA implements Signature, KeyRestrictionAware
{
    use KeyRestrictionEnforcement;

    /**
     * ML-DSA is a one-shot signature scheme: the message is not hashed beforehand, which OpenSSL expects to be
     * expressed by an empty digest algorithm. Any digest is refused by the provider ("invalid digest"), which is
     * exactly what keeps HashML-DSA out.
     */
    private const NO_DIGEST = 0;

    /**
     * The PrivateKeyInfo of the all-zero-seed ML-DSA-44 key of RFC 9964 appendix A, which is what the runtime probe
     * asks OpenSSL to load: 52 bytes, the seed form, an OpenSSL without ML-DSA rejects the algorithm identifier and
     * one with it derives the whole key.
     */
    private const PROBE_KEY = "-----BEGIN PRIVATE KEY-----\nMDQCAQAwCwYJYIZIAWUDBAMRBCKAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAA\n-----END PRIVATE KEY-----\n";

    private static ?bool $providedByOpenSsl = null;

    public function __construct()
    {
        if (PHP_VERSION_ID < 80400) {
            throw new RuntimeException(sprintf(
                'The %s algorithm requires PHP 8.4 or later, as earlier versions cannot sign or verify without a digest through OpenSSL.',
                static::algorithmName()
            ));
        }
        if (! self::isProvidedByOpenSsl()) {
            throw new RuntimeException(sprintf(
                'The %s algorithm requires an OpenSSL library that provides ML-DSA (OpenSSL 3.5 or later), which the one PHP loaded does not.',
                static::algorithmName()
            ));
        }
    }

    /**
     * @throws RuntimeException when the platform lacks ML-DSA, see isSupported()
     */
    abstract public static function create(): self;

    /**
     * Whether this platform can compute the algorithm: PHP 8.4 or later, and an OpenSSL runtime that provides
     * ML-DSA (3.5 or later). The OpenSSL check is a runtime probe - an ML-DSA key is loaded once and the result kept
     * for the process - because OPENSSL_VERSION_TEXT reports the headers PHP was built against, not the library
     * it loaded.
     */
    public static function isSupported(): bool
    {
        return PHP_VERSION_ID >= 80400 && self::isProvidedByOpenSsl();
    }

    /**
     * The size of the encoded public key of this parameter set (FIPS 204 table 2, RFC 9964 section 5).
     */
    abstract public static function publicKeyLength(): int;

    /**
     * The size of a signature of this parameter set (FIPS 204 table 2, RFC 9964 section 5).
     */
    abstract public static function signatureLength(): int;

    /**
     * The registered name of the algorithm, for the exception messages: "ML-DSA-44".
     */
    abstract protected static function algorithmName(): string;

    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key, Key::OP_SIGN);
        if (! $key->isPrivate()) {
            throw new InvalidArgumentException('The key is not private.');
        }

        OpenSslError::clear();
        $privateKey = openssl_pkey_get_private($key->asPEM());
        if ($privateKey === false) {
            throw new InvalidArgumentException(sprintf(
                'Unable to load the %s private key: %s',
                static::algorithmName(),
                OpenSslError::lastMessage()
            ));
        }
        if (! openssl_sign($data, $signature, $privateKey, self::NO_DIGEST)) {
            throw new InvalidArgumentException('Unable to sign the data: ' . OpenSslError::lastMessage());
        }
        /** @var string $signature */

        return $signature;
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key, Key::OP_VERIFY);

        // FIPS 204 algorithm 3, step 1: a signature that is not sigEncode() output of the parameter set is invalid.
        // The check spares OpenSSL the decoding, and settles the length before any byte is looked at.
        if (strlen($signature) !== static::signatureLength()) {
            return false;
        }

        // A public key OpenSSL cannot load makes the signature invalid; it is a verification outcome, not an error.
        $publicKey = openssl_pkey_get_public($key->toPublic()->asPEM());
        if ($publicKey === false) {
            OpenSslError::clear();

            return false;
        }

        return openssl_verify($data, $signature, $publicKey, self::NO_DIGEST) === 1;
    }

    /**
     * The AKP key pair a seed expands to (FIPS 204 algorithm 6, ML-DSA.KeyGen_internal), with the "alg" of this
     * algorithm: the seed as "priv", the derived public key as "pub".
     *
     * RFC 9964 section 4 makes the seed the only private key representation, so this is how a key pair is created
     * from a fresh random seed - `random_bytes(32)` - and how one is rebuilt from a stored seed.
     *
     * @param string $seed the 32-byte seed of FIPS 204 (RFC 9964, section 4)
     *
     * @throws InvalidArgumentException when the seed is not 32 bytes long
     */
    public function keyPairFromSeed(string $seed): AkpKey
    {
        if (strlen($seed) !== AkpKey::ML_DSA_SEED_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'The seed of an ML-DSA key must be %d bytes long',
                AkpKey::ML_DSA_SEED_LENGTH
            ));
        }

        return AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => static::identifier(),
            AkpKey::DATA_PUB => $this->publicKeyOfSeed($seed),
            AkpKey::DATA_PRIV => $seed,
        ]);
    }

    private function handleKey(Key $key, int $operation): AkpKey
    {
        $this->checkKeyRestrictions($key, $operation);
        try {
            $key = AkpKey::create($key->getData());
        } catch (InvalidArgumentException $e) {
            throw $e;
        } catch (Throwable $e) {
            // A last resort: key material comes from the wire, and every rejection of it has to reach the caller as
            // the exception type this library documents, never as a TypeError or an Error.
            throw new InvalidArgumentException('Invalid AKP key', 0, $e);
        }
        // RFC 9964 section 3: "alg" is REQUIRED on an AKP key, because the key type says nothing about what "pub"
        // and "priv" hold. The comparison is made whether or not the key restrictions are enforced: for this key
        // type, "alg" is what a curve is to an EC2 key, not a usage restriction laid over it.
        if (! $key->has(Key::ALG)) {
            throw new InvalidArgumentException(
                'The AKP key carries no "alg", which RFC 9964 section 3 requires: nothing says which algorithm it belongs to'
            );
        }
        if ($key->alg() !== static::identifier()) {
            throw new InvalidArgumentException('This key cannot be used with this algorithm');
        }
        // RFC 9964 section 7.4: a "pub" that is not what the seed expands to is a mismatched key pair, and the
        // consequences of using one "can range from operations failing to private key compromise".
        if ($key->isPrivate() && ! hash_equals($this->publicKeyOfSeed($key->priv()), $key->pub())) {
            throw new InvalidArgumentException(
                'Invalid AKP key. The "pub" parameter is not the public key the "priv" seed expands to'
            );
        }

        return $key;
    }

    /**
     * The encoded public key of FIPS 204 that OpenSSL derives from the seed: the seed is loaded as a PrivateKeyInfo,
     * and the SubjectPublicKeyInfo OpenSSL reports for the key is read back.
     */
    private function publicKeyOfSeed(string $seed): string
    {
        $pem = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => static::identifier(),
            // A placeholder of the right size: only the seed is written to the PrivateKeyInfo.
            AkpKey::DATA_PUB => str_repeat("\x00", static::publicKeyLength()),
            AkpKey::DATA_PRIV => $seed,
        ])->asPEM();

        OpenSslError::clear();
        $privateKey = openssl_pkey_get_private($pem);
        if ($privateKey === false) {
            throw new InvalidArgumentException(sprintf(
                'Unable to expand the %s seed: %s',
                static::algorithmName(),
                OpenSslError::lastMessage()
            ));
        }
        $details = openssl_pkey_get_details($privateKey);
        $publicKeyPem = $details === false ? null : ($details['key'] ?? null);
        if (! is_string($publicKeyPem)) {
            throw new RuntimeException('OpenSSL reported no public key for the ML-DSA seed');
        }

        return PublicKeyInfo::fromPEM(PEM::fromString($publicKeyPem))
            ->publicKeyData()
            ->string();
    }

    private static function isProvidedByOpenSsl(): bool
    {
        if (self::$providedByOpenSsl === null) {
            OpenSslError::clear();
            self::$providedByOpenSsl = openssl_pkey_get_private(self::PROBE_KEY) !== false;
            OpenSslError::clear();
        }

        return self::$providedByOpenSsl;
    }
}
