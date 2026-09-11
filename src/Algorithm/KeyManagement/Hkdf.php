<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use function chr;
use Closure;
use Cose\Algorithm\Mac\AesCbcMac;
use Cose\Algorithm\Mac\AESMAC128_128;
use Cose\Algorithm\Mac\AESMAC256_128;
use Cose\Key\SymmetricKey;
use function hash_hmac;
use function in_array;
use function intdiv;
use InvalidArgumentException;
use function sprintf;
use function str_repeat;
use function strlen;
use function substr;

/**
 * The HKDF of RFC 9053 section 5.1: the extract-and-expand construction of RFC 5869, with the pseudorandom
 * function that "is encoded into the HKDF algorithm selection".
 *
 * Two PRFs are defined there (table 8): HMAC, for "HKDF SHA-256" and "HKDF SHA-512", and AES-CBC-MAC, for
 * "HKDF AES-MAC-128" and "HKDF AES-MAC-256". They do not run the same steps. "One can use AES-CBC-MAC as the PRF for
 * the expand step, but not for the extract step. [...] For the AES algorithm versions, the extract step is always
 * skipped." A skipped extract step means the secret is the PRK -- it has to be a uniformly random key of exactly
 * the length the AES PRF takes -- and "the 'salt' value is not used as part of the HKDF functionality". That is why
 * the salt is ignored, not refused, by the AES variants: the header parameter may travel, it just changes nothing.
 *
 * hash_hkdf() is not used even for the HMAC variants: one implementation of the construction with the PRF as a
 * parameter is what keeps the two families on the same code, and the HMAC form is checked against hash_hkdf() and
 * against the vectors of RFC 5869 in the tests.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-5.1
 * @see https://www.rfc-editor.org/rfc/rfc5869
 * @see \Cose\Tests\Algorithm\KeyManagement\HkdfTest
 */
final class Hkdf
{
    /**
     * RFC 5869 section 2.3: "L: length of output keying material in octets (<= 255*HashLen)".
     */
    private const MAX_BLOCKS = 255;

    /**
     * @param Closure(string, string): string $prf PRF(key, data)
     * @param int $prfLength the length of the PRF output, in bytes ("HashLen")
     * @param int|null $prfKeyLength the length the PRF key must have, or null when any length will do (HMAC)
     */
    private function __construct(
        private readonly Closure $prf,
        private readonly int $prfLength,
        private readonly ?int $prfKeyLength,
        private readonly bool $extract,
        private readonly string $name
    ) {
    }

    /**
     * HKDF with HMAC as the PRF, extract and expand: "HKDF SHA-256" and "HKDF SHA-512".
     *
     * @param string $hashAlgorithm the digest, as hash_hmac() spells it: "sha256" or "sha512"
     */
    public static function hmac(string $hashAlgorithm): self
    {
        if (! in_array($hashAlgorithm, ['sha256', 'sha512'], true)) {
            throw new InvalidArgumentException(sprintf(
                'Unsupported HKDF hash algorithm "%s": RFC 9053 section 5.1 defines HKDF SHA-256 and HKDF SHA-512.',
                $hashAlgorithm
            ));
        }

        return new self(
            static fn (string $key, string $data): string => hash_hmac($hashAlgorithm, $data, $key, true),
            strlen(hash_hmac($hashAlgorithm, '', '', true)),
            null,
            true,
            'HKDF ' . strtoupper(substr($hashAlgorithm, 0, 3)) . '-' . substr($hashAlgorithm, 3)
        );
    }

    /**
     * HKDF with the untruncated AES-CBC-MAC of RFC 9053 section 3.2 as the PRF, expand only: "HKDF AES-MAC-128" and
     * "HKDF AES-MAC-256". The secret is used as the PRK and has to be exactly the AES key length: 16 or 32 bytes.
     *
     * @param int $keyLength the AES key length in bits: 128 or 256
     */
    public static function aesCbcMac(int $keyLength): self
    {
        $mac = match ($keyLength) {
            128 => AESMAC128_128::create(),
            256 => AESMAC256_128::create(),
            default => throw new InvalidArgumentException(sprintf(
                'Unsupported HKDF AES-MAC key length %d: RFC 9053 section 5.1 defines HKDF AES-MAC-128 and HKDF AES-MAC-256.',
                $keyLength
            )),
        };

        return new self(
            static fn (string $key, string $data): string => $mac->hash($data, SymmetricKey::create([
                SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
                SymmetricKey::DATA_K => $key,
            ])),
            AesCbcMac::BLOCK_SIZE,
            intdiv($keyLength, 8),
            false,
            sprintf('HKDF AES-MAC-%d', $keyLength)
        );
    }

    /**
     * Whether the extract step is skipped, the secret being used as the PRK: true for the AES-CBC-MAC variants.
     */
    public function skipsExtract(): bool
    {
        return ! $this->extract;
    }

    /**
     * The name of RFC 9053 table 8: "HKDF SHA-256", "HKDF AES-MAC-128", ...
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Derives $length bytes of keying material.
     *
     * @param string $secret the input keying material: a shared secret, or the output of a key agreement
     * @param string|null $salt the salt of the extract step, "a string of HashLen zeros" when absent (RFC 5869
     *                          section 2.2); ignored when the extract step is skipped
     * @param string $info the context, in COSE the encoded COSE_KDF_Context
     *
     * @throws InvalidArgumentException when the secret is empty, when it is not of the length a skipped extract step
     *                                  requires, or when the length asked for exceeds 255 PRF outputs
     */
    public function derive(string $secret, ?string $salt, string $info, int $length): string
    {
        if ($secret === '') {
            throw new InvalidArgumentException('The HKDF secret is empty.');
        }
        if ($length <= 0 || $length > self::MAX_BLOCKS * $this->prfLength) {
            throw new InvalidArgumentException(sprintf(
                'The %s output length must be between 1 and %d bytes, %d requested.',
                $this->name,
                self::MAX_BLOCKS * $this->prfLength,
                $length
            ));
        }

        if ($this->extract) {
            // RFC 5869 section 2.2: PRK = HMAC-Hash(salt, IKM), the salt defaulting to HashLen zeros.
            $prk = ($this->prf)($salt === null || $salt === '' ? str_repeat("\0", $this->prfLength) : $salt, $secret);
        } else {
            // RFC 9053 section 5.1: the extract step is skipped and the secret is the PRK, which the AES-CBC-MAC PRF
            // can only take at its own key length.
            if ($this->prfKeyLength !== null && strlen($secret) !== $this->prfKeyLength) {
                throw new InvalidArgumentException(sprintf(
                    '%s skips the extract step and uses the shared secret as the PRF key: it must be %d bytes long, the secret is %d bytes long.',
                    $this->name,
                    $this->prfKeyLength,
                    strlen($secret)
                ));
            }
            $prk = $secret;
        }

        // RFC 5869 section 2.3: T(i) = PRF(PRK, T(i-1) | info | i), OKM = first L bytes of T(1) | T(2) | ...
        $okm = '';
        $block = '';
        for ($i = 1; strlen($okm) < $length; ++$i) {
            $block = ($this->prf)($prk, $block . $info . chr($i));
            $okm .= $block;
        }

        return substr($okm, 0, $length);
    }
}
