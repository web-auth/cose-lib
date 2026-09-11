<?php

declare(strict_types=1);

namespace Cose\Encryption;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\IndefiniteLengthByteStringObject;
use Cose\Key\Key;
use Cose\Structure\CoseHeaders;
use function get_debug_type;
use InvalidArgumentException;
use function is_string;
use function sprintf;
use function str_pad;
use const STR_PAD_LEFT;
use const STR_PAD_RIGHT;
use function strlen;

/**
 * The nonce of a security layer, as RFC 9052 section 3.1 says to find it: the "IV" header parameter (label 5) as it
 * is, or the "Partial IV" (label 6) combined with the "Base IV" of the key (RFC 9052 section 7.1, label 5).
 *
 * "The 'Initialization Vector' and 'Partial Initialization Vector' header parameters MUST NOT both be present in
 * the same security layer": a layer carrying both is rejected, whichever bucket each sits in.
 *
 * The IV of a message carrying a Partial IV is computed by the two steps of section 3.1:
 *
 * 1. "Left-pad the Partial IV with zeros to the length of IV (determined by the algorithm)."
 * 2. "XOR the padded Partial IV with the Context IV."
 *
 * The Context IV is the Base IV of the key, which is "the base portion of an IV" (section 7.1): a prefix, that the
 * examples of RFC 9052 Appendix C.4.2 and of cose-wg/Examples write shorter than the IV. It is right-padded with
 * zeros to the IV length before the XOR, so that a 8-byte Base IV h'89F52F65A1C58093' and the Partial IV h'61A7'
 * give the 13-byte AES-CCM nonce h'89F52F65A1C5809300000061A7' of that appendix.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3.1
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-7.1
 * @see \Cose\Tests\Encryption\InitializationVectorTest
 */
final class InitializationVector
{
    public const IV = 5;

    public const PARTIAL_IV = 6;

    /**
     * The nonce the headers of a layer designate, of exactly $length bytes.
     *
     * @param int $length the nonce length of the content encryption algorithm, in bytes
     * @param Key|null $key the key whose "Base IV" completes a "Partial IV"; only needed when the layer carries one
     *
     * @throws InvalidArgumentException when the layer carries both parameters or neither, when their value is not a
     *                                  byte string, when the IV is not of the given length, when the Partial IV is
     *                                  longer than it, or when a Partial IV is present and the key carries no usable
     *                                  Base IV
     */
    public static function resolve(CoseHeaders $headers, int $length, ?Key $key = null): string
    {
        $iv = $headers->getHeaderParameter(self::IV);
        $partialIv = $headers->getHeaderParameter(self::PARTIAL_IV);
        if ($iv !== null && $partialIv !== null) {
            throw new InvalidArgumentException(
                'Invalid message. The "IV" (5) and "Partial IV" (6) header parameters MUST NOT both be present in the same security layer (RFC 9052 section 3.1).'
            );
        }
        if ($iv !== null) {
            $value = self::bytes($iv, 'IV');
            if (strlen($value) !== $length) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid message. The "IV" header parameter is %d bytes long, the algorithm takes a %d-byte nonce.',
                    strlen($value),
                    $length
                ));
            }

            return $value;
        }
        if ($partialIv !== null) {
            if ($key === null || ! $key->has(Key::BASE_IV)) {
                throw new InvalidArgumentException(
                    'Invalid message. The layer carries a "Partial IV" (6) but the key has no "Base IV" (5) to complete it with (RFC 9052 section 3.1).'
                );
            }
            $baseIv = $key->get(Key::BASE_IV);
            if (! is_string($baseIv)) {
                throw new InvalidArgumentException(
                    'Invalid key. The "Base IV" (5) parameter must be a byte string (CBOR objects shall be normalized first).'
                );
            }

            return self::fromPartialIv(self::bytes($partialIv, 'Partial IV'), $baseIv, $length);
        }

        throw new InvalidArgumentException(
            'Invalid message. The layer carries neither an "IV" (5) nor a "Partial IV" (6) header parameter.'
        );
    }

    /**
     * The IV a Partial IV and a Base IV give, by the two steps of RFC 9052 section 3.1.
     *
     * The sender computes its nonce the same way: the Partial IV it sends is the counter it chose, the nonce it
     * encrypts with is this.
     *
     * @param int $length the nonce length of the content encryption algorithm, in bytes
     *
     * @throws InvalidArgumentException when the Partial IV or the Base IV is longer than the nonce, or empty
     */
    public static function fromPartialIv(string $partialIv, string $baseIv, int $length): string
    {
        if ($partialIv === '' || strlen($partialIv) > $length) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "Partial IV". It must be between 1 and %d bytes long, it is %d bytes long.',
                $length,
                strlen($partialIv)
            ));
        }
        if ($baseIv === '' || strlen($baseIv) > $length) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "Base IV". It must be between 1 and %d bytes long, it is %d bytes long.',
                $length,
                strlen($baseIv)
            ));
        }

        return str_pad($partialIv, $length, "\0", STR_PAD_LEFT) ^ str_pad($baseIv, $length, "\0", STR_PAD_RIGHT);
    }

    private static function bytes(CBORObject $value, string $name): string
    {
        if (! $value instanceof ByteStringObject && ! $value instanceof IndefiniteLengthByteStringObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid message. The "%s" header parameter must be a byte string, got a %s.',
                $name,
                get_debug_type($value)
            ));
        }

        return $value->getValue();
    }
}
