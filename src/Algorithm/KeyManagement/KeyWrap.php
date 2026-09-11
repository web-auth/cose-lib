<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use Cose\Key\SymmetricKey;
use InvalidArgumentException;

/**
 * The key wrap class of RFC 9052 section 8.5.2: "the CEK is randomly generated, and that key is then encrypted by a
 * shared secret between the sender and the recipient".
 *
 * A128KW, A192KW and A256KW (-3 to -5, RFC 9053 section 6.2.1) are the AES Key Wrap of RFC 3394. The primitive is
 * exposed on its own, wrap() and unwrap(), because the key agreement with key wrap algorithms (section 6.4) run it
 * under a key they derived, and because the AES Key Wrap is what RFC 9052 section 8.5.2 calls an AE algorithm: the
 * recipient carries no protected header and the primitive takes no additional data.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-8.5.2
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.2
 */
interface KeyWrap extends KeyManagement
{
    /**
     * Wraps a key, the "wrap key" (or "encrypt") operation of RFC 9052 section 7.1, Table 5.
     *
     * @param SymmetricKey $kek the key-encryption key, of exactly keyLength() bytes
     * @param string $key the key to wrap: RFC 3394 takes "a multiple of 64 bits", at least 128
     *
     * @throws InvalidArgumentException when the KEK cannot be used with this algorithm, or when the key is not of a
     *                                  length the primitive wraps
     */
    public function wrap(SymmetricKey $kek, string $key): string;

    /**
     * Unwraps a key, the "unwrap key" (or "decrypt") operation of RFC 9052 section 7.1, Table 5.
     *
     * @throws InvalidArgumentException when the KEK cannot be used with this algorithm, when the wrapped key is not
     *                                  of a length the primitive unwraps, or when the integrity check of RFC 3394
     *                                  section 2.2.3 fails -- a wrong KEK and a tampered value are one and the same
     *                                  failure and are reported alike
     */
    public function unwrap(SymmetricKey $kek, string $wrappedKey): string;

    /**
     * The length of the key-encryption key this algorithm takes, in bytes: the "Key Size" of RFC 9053 table 13.
     */
    public function keyLength(): int;
}
