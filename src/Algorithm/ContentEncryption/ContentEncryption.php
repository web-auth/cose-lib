<?php

declare(strict_types=1);

namespace Cose\Algorithm\ContentEncryption;

use Cose\Algorithm\Algorithm;
use Cose\Key\SymmetricKey;
use InvalidArgumentException;

/**
 * A content encryption algorithm: the AEAD that encrypts the content of a COSE_Encrypt0 or a COSE_Encrypt (RFC 9052
 * section 5, RFC 9053 section 4).
 *
 * The additional authenticated data is the Enc_structure of RFC 9052 section 5.3, never the protected header on its
 * own: {@see \Cose\Encryption\Encrypt0Structure} and {@see \Cose\Encryption\EncryptStructure} build it, and their
 * encrypt() and decrypt() feed it to the algorithm. The nonce is the "IV" of the message, or the one resolved from a
 * "Partial IV" and the "Base IV" of the key, see {@see \Cose\Encryption\InitializationVector}.
 *
 * The ciphertext is laid out the way COSE carries it: the encrypted content followed by the authentication tag
 * (RFC 9053 sections 4.1, 4.2 and 4.3).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-5
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-4
 */
interface ContentEncryption extends Algorithm
{
    /**
     * Encrypts the content, the "encrypt" operation of RFC 9052 section 7.1, Table 5.
     *
     * @param string $nonce exactly nonceLength() bytes; a key and nonce pair MUST be unique for every message
     * @param string $aad the Enc_structure, as bytes
     *
     * @throws InvalidArgumentException when the key cannot be used with this algorithm (wrong length, or - when the
     *                                  algorithm enforces them, see KeyRestrictionAware - an "alg" or a "key_ops"
     *                                  that forbids encrypting with it), or when the nonce is not of the length the
     *                                  algorithm fixes
     * @return string the ciphertext followed by the tagLength() bytes of the authentication tag
     */
    public function encrypt(SymmetricKey $key, string $plaintext, string $nonce, string $aad): string;

    /**
     * Decrypts the content, the "decrypt" operation of RFC 9052 section 7.1, Table 5. It is a distinct operation from
     * the one above: a key may be allowed to perform one and not the other.
     *
     * @param string $ciphertext the ciphertext followed by the authentication tag, as encrypt() lays it out
     *
     * @throws InvalidArgumentException when the key or the nonce cannot be used, as above, or when the content does
     *                                  not authenticate: a wrong key, a wrong nonce, a wrong AAD, a tampered or a
     *                                  truncated tag are one and the same failure and are reported alike
     */
    public function decrypt(SymmetricKey $key, string $ciphertext, string $nonce, string $aad): string;

    /**
     * The length of the key this algorithm takes, in bytes.
     */
    public function keyLength(): int;

    /**
     * The length of the nonce this algorithm fixes, in bytes: what the "IV" must measure, and what a "Partial IV" is
     * padded to.
     */
    public function nonceLength(): int;

    /**
     * The length of the authentication tag, in bytes: the trailing part of the ciphertext.
     */
    public function tagLength(): int;
}
