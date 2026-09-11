<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\KeyRestrictionEnforcement;
use Cose\Algorithm\Signature\OpenSslError;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use function in_array;
use InvalidArgumentException;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_get_cipher_methods;
use const OPENSSL_RAW_DATA;
use RuntimeException;
use function sprintf;
use function strlen;
use function substr;

/**
 * What the AEAD algorithms of RFC 9053 section 4 share: the checks on the key and on the nonce, the layout of the
 * ciphertext, and the one way a failed decryption is reported.
 *
 * RFC 9053 sections 4.1, 4.2 and 4.3 all require that "implementations that are encrypting or decrypting MUST
 * validate that the key type, key length, and algorithm are correct and appropriate for the entities involved". The
 * key type is settled by the {@see SymmetricKey} type of the argument, the key length is checked here against the
 * length the algorithm fixes, and the "alg" and "key_ops" restrictions of the key go through
 * {@see KeyRestrictionEnforcement}, on by default for these algorithms: a key whose "key_ops" lists neither
 * "encrypt" nor "wrap key" does not encrypt, one that lists neither "decrypt" nor "unwrap key" does not decrypt.
 *
 * The nonce length is fixed by each algorithm and a nonce of any other length is refused before the primitive is
 * called: OpenSSL would otherwise accept a 12-byte nonce for AES-CCM and silently compute with a different L
 * (RFC 3610 section 2.2), producing a ciphertext no conforming recipient can open.
 *
 * A decryption that does not authenticate is reported with one exception and one message, DECRYPTION_FAILED, whether
 * the key is wrong, the nonce is wrong, the additional authenticated data differs, or the tag was tampered with,
 * replaced or truncated: the primitive cannot tell these apart, and saying more would only help an attacker.
 *
 * **The key and nonce pair MUST be unique for every message encrypted** (RFC 9053 sections 4.1.1, 4.2.1 and 4.3.1).
 * Reusing a nonce under the same key is catastrophic for every algorithm here: for AES-GCM and ChaCha20/Poly1305 it
 * leaks the authentication key, and the XOR of the two plaintexts; for AES-CCM it leaks the XOR of the plaintexts.
 * Draw the nonce with random_bytes() for each message, or derive it from a strictly increasing counter as a
 * "Partial IV" (RFC 9052 section 3.1), never from anything that can repeat.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-4
 * @see \Cose\Tests\Algorithm\ContentEncryption\AeadTest
 */
abstract class Aead implements ContentEncryption, KeyRestrictionAware
{
    use KeyRestrictionEnforcement;

    public const DECRYPTION_FAILED = 'The content could not be decrypted: the authentication tag does not verify for this key, nonce and additional authenticated data.';

    public function __construct()
    {
        // RFC 9053 section 4 makes the "alg" and "key_ops" checks a MUST, and these algorithms have no caller to keep
        // compatible: they enforce the restrictions unless told otherwise.
        $this->enforceKeyRestrictions = true;
    }

    public function encrypt(SymmetricKey $key, string $plaintext, string $nonce, string $aad): string
    {
        $k = $this->checkKey($key, Key::OP_ENCRYPT, Key::OP_WRAP_KEY);
        $this->checkNonce($nonce);

        return $this->doEncrypt($k, $plaintext, $nonce, $aad);
    }

    public function decrypt(SymmetricKey $key, string $ciphertext, string $nonce, string $aad): string
    {
        $k = $this->checkKey($key, Key::OP_DECRYPT, Key::OP_UNWRAP_KEY);
        $this->checkNonce($nonce);

        $tagLength = $this->tagLength();
        if (strlen($ciphertext) < $tagLength) {
            // Too short to even carry a tag: the same failure as a tag that does not verify, reported the same way.
            throw new InvalidArgumentException(self::DECRYPTION_FAILED);
        }
        $plaintext = $this->doDecrypt(
            $k,
            substr($ciphertext, 0, strlen($ciphertext) - $tagLength),
            substr($ciphertext, -$tagLength),
            $nonce,
            $aad
        );
        if ($plaintext === null) {
            throw new InvalidArgumentException(self::DECRYPTION_FAILED);
        }

        return $plaintext;
    }

    /**
     * @return string the ciphertext followed by the tag
     */
    abstract protected function doEncrypt(string $k, string $plaintext, string $nonce, string $aad): string;

    /**
     * @return string|null the plaintext, or null when the content does not authenticate
     */
    abstract protected function doDecrypt(string $k, string $ciphertext, string $tag, string $nonce, string $aad): ?string;

    /**
     * Whether the OpenSSL build behind this process implements the cipher.
     */
    final protected static function isOpensslCipherAvailable(string $cipher): bool
    {
        return in_array($cipher, openssl_get_cipher_methods(), true);
    }

    /**
     * openssl_encrypt() with the tag appended to the ciphertext, the way RFC 9053 section 4 lays the two out.
     *
     * @throws RuntimeException when the OpenSSL build of this platform does not implement the cipher, or refuses
     *                          the operation
     */
    final protected function opensslEncrypt(string $cipher, string $k, string $plaintext, string $nonce, string $aad): string
    {
        $this->assertOpensslCipherAvailable($cipher);
        OpenSslError::clear();
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, $cipher, $k, OPENSSL_RAW_DATA, $nonce, $tag, $aad, $this->tagLength());
        if ($ciphertext === false) {
            throw new RuntimeException(sprintf(
                'Unable to encrypt with %s: %s.',
                static::class,
                OpenSslError::lastMessage()
            ));
        }

        return $ciphertext . $tag;
    }

    /**
     * openssl_decrypt(), which answers false for a tag that does not verify - and the same false for a cipher the
     * build does not implement, which is why the cipher is checked first: a missing cipher must not masquerade as a
     * forgery.
     *
     * @throws RuntimeException when the OpenSSL build of this platform does not implement the cipher
     */
    final protected function opensslDecrypt(
        string $cipher,
        string $k,
        string $ciphertext,
        string $tag,
        string $nonce,
        string $aad
    ): ?string {
        $this->assertOpensslCipherAvailable($cipher);
        $plaintext = openssl_decrypt($ciphertext, $cipher, $k, OPENSSL_RAW_DATA, $nonce, $tag, $aad);

        return $plaintext === false ? null : $plaintext;
    }

    private function assertOpensslCipherAvailable(string $cipher): void
    {
        if (! self::isOpensslCipherAvailable($cipher)) {
            throw new RuntimeException(sprintf(
                '%s is not available: the OpenSSL build of this platform does not implement the cipher "%s".',
                static::class,
                $cipher
            ));
        }
    }

    /**
     * @param int $operation the Key::OP_* constant of the operation the key is about to be used for
     * @param int $alternative the Key::OP_* constant the key may list that operation under instead
     *
     * @throws InvalidArgumentException when the key cannot be used with this algorithm
     * @return string the key value
     */
    private function checkKey(SymmetricKey $key, int $operation, int $alternative): string
    {
        $k = $key->k();
        if (strlen($k) !== $this->keyLength()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid key. %s takes a %d-byte key, the key is %d bytes long.',
                static::class,
                $this->keyLength(),
                strlen($k)
            ));
        }
        $this->checkKeyRestrictions($key, $operation, $alternative);

        return $k;
    }

    /**
     * @throws InvalidArgumentException when the nonce is not of the length the algorithm fixes
     */
    private function checkNonce(string $nonce): void
    {
        if (strlen($nonce) !== $this->nonceLength()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid nonce. %s takes a %d-byte nonce, the nonce is %d bytes long.',
                static::class,
                $this->nonceLength(),
                strlen($nonce)
            ));
        }
    }
}
