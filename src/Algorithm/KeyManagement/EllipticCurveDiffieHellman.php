<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

use function base64_decode;
use Cose\Algorithm\Signature\OpenSslError;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\PublicKeyLoader;
use function hash_equals;
use function in_array;
use InvalidArgumentException;
use function is_array;
use function is_string;
use function openssl_get_curve_names;
use const OPENSSL_KEYTYPE_EC;
use function openssl_pkey_derive;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_pkey_new;
use function preg_replace;
use function random_bytes;
use RuntimeException;
use function sprintf;
use function str_pad;
use const STR_PAD_LEFT;
use function str_repeat;
use function strlen;

/**
 * The elliptic curve Diffie-Hellman of RFC 9053 section 6.3.1, on the curves it names: the shared secret of a
 * private and a public key, and the generation of an ephemeral key pair on the curve of a given key.
 *
 * "The math used to obtain the computed secret is based on the curve selected and not on the ECDH algorithm", and
 * it is OpenSSL's: openssl_pkey_derive(), on the keys loaded from their PEM form. "Computed Secret to Shared
 * Secret: [...] The x-coordinate is used for all of the curves defined in this document. For curves X25519 and
 * X448, the resulting value is used directly [...]. For the P-256, P-384, and P-521 curves, the x-coordinate is run
 * through the Integer-to-Octet-String primitive (I2OSP)" -- which is what openssl_pkey_derive() returns: the
 * x-coordinate as a byte string of the length of the field, leading zeros included.
 *
 * Two checks the RFC asks for happen here, before and after the multiplication:
 *
 * - RFC 9053 section 6.3.1.1: "For the 'EC2' key format, [point validation] can be done by checking that the x and
 *   y values form a point on the curve." An EC2 public key is put through {@see Ec2Key::assertOnCurve()} before it
 *   is loaded, and never reaches OpenSSL otherwise; the library does not rely on OpenSSL doing it. A point that is
 *   not on the curve, fed to a scalar multiplication with the private key, is the invalid-curve attack: the
 *   multiplication happens in a weaker group and leaks the private scalar a few bits per message.
 * - "For the 'OKP' format, there is no simple way to perform point validation." RFC 7748 section 6.1 instead:
 *   "implementations [...] MAY check for the all-zero output and abort if so". This one does; an all-zero shared
 *   secret means the peer's key was a low-order point, and is refused.
 *
 * The curves: P-256, P-384 and P-521 for EC2, X25519 and X448 for OKP, as section 6.3.1 lists; and the four
 * Brainpool curves, which ISO/IEC 18013-5 registered for the same use, when the OpenSSL build of the platform has
 * them ({@see isCurveSupported()}). secp256k1 is refused: RFC 8812 registers it for ES256K and nothing registers
 * it for ECDH. The Edwards curves of an OKP key are refused too: Ed25519 and Ed448 sign, they do not agree.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1.1
 * @see https://www.rfc-editor.org/rfc/rfc7748#section-6.1
 * @see \Cose\Tests\Algorithm\KeyManagement\EllipticCurveDiffieHellmanTest
 */
final class EllipticCurveDiffieHellman
{
    /**
     * The EC2 curves ECDH is defined for, each with its OpenSSL name.
     *
     * @var array<int, string>
     */
    private const EC2_CURVES = [
        Ec2Key::CURVE_P256 => 'prime256v1',
        Ec2Key::CURVE_P384 => 'secp384r1',
        Ec2Key::CURVE_P521 => 'secp521r1',
        Ec2Key::CURVE_BP256 => Ec2Key::CURVE_NAME_BP256,
        Ec2Key::CURVE_BP320 => Ec2Key::CURVE_NAME_BP320,
        Ec2Key::CURVE_BP384 => Ec2Key::CURVE_NAME_BP384,
        Ec2Key::CURVE_BP512 => Ec2Key::CURVE_NAME_BP512,
    ];

    /**
     * The OKP curves ECDH is defined for, each with the length of its keys and of its shared secret.
     *
     * @var array<int, int>
     */
    private const OKP_CURVES = [
        OkpKey::CURVE_X25519 => 32,
        OkpKey::CURVE_X448 => 56,
    ];

    /**
     * The Brainpool curves are not in every OpenSSL build, and the check is by name, as for the ESB* signature
     * algorithms.
     *
     * @var list<int>
     */
    private const PLATFORM_GATED_CURVES = [
        Ec2Key::CURVE_BP256,
        Ec2Key::CURVE_BP320,
        Ec2Key::CURVE_BP384,
        Ec2Key::CURVE_BP512,
    ];

    /**
     * Whether ECDH can run on the curve of the key on this platform: the curve is one ECDH is defined for, and the
     * OpenSSL build provides it.
     */
    public static function isCurveSupported(Ec2Key|OkpKey $key): bool
    {
        $curve = $key->curveId();
        if ($key instanceof OkpKey) {
            return isset(self::OKP_CURVES[$curve]);
        }
        if (! isset(self::EC2_CURVES[$curve])) {
            return false;
        }
        if (! in_array($curve, self::PLATFORM_GATED_CURVES, true)) {
            return true;
        }
        $curves = openssl_get_curve_names();

        return $curves !== false && in_array(self::EC2_CURVES[$curve], $curves, true);
    }

    /**
     * The shared secret of the two keys, as RFC 9053 section 6.3.1 turns it into a byte string.
     *
     * @throws InvalidArgumentException when the private key is not private, when the two keys are not of the same
     *                                  type and curve, when the curve is not one ECDH is defined for, when the EC2
     *                                  public key is not a point on the curve, or when the OKP shared secret is
     *                                  all zeros
     * @throws RuntimeException when the OpenSSL build of this platform does not provide the curve, or refuses the
     *                          operation
     */
    public static function sharedSecret(Ec2Key|OkpKey $privateKey, Ec2Key|OkpKey $publicKey): string
    {
        if (! $privateKey->isPrivate()) {
            throw new InvalidArgumentException('Invalid key. The ECDH private key is not private.');
        }
        self::assertSameCurve($privateKey, $publicKey);
        self::assertCurveSupported($privateKey);

        if ($publicKey instanceof Ec2Key) {
            // RFC 9053 section 6.3.1.1: before anything is computed with the point, and independently of OpenSSL.
            $publicKey->assertOnCurve();
        }

        $private = openssl_pkey_get_private($privateKey->asPEM());
        if ($private === false) {
            throw new InvalidArgumentException('Unable to load the ECDH private key: ' . OpenSslError::lastMessage());
        }
        $public = openssl_pkey_get_public($publicKey->toPublic()->asPEM());
        if ($public === false) {
            throw new InvalidArgumentException('Unable to load the ECDH public key: ' . OpenSslError::lastMessage());
        }
        OpenSslError::clear();
        $secret = openssl_pkey_derive($public, $private);
        if ($secret === false) {
            throw new InvalidArgumentException('The ECDH shared secret could not be computed: ' . OpenSslError::lastMessage());
        }
        $expected = $publicKey instanceof OkpKey ? self::OKP_CURVES[$publicKey->curveId()] : strlen($publicKey->x());
        if (strlen($secret) !== $expected) {
            throw new RuntimeException(sprintf(
                'The ECDH shared secret is %d bytes long, the curve gives %d.',
                strlen($secret),
                $expected
            ));
        }
        // RFC 7748 section 6.1: a low-order public key yields the all-zero output, and with it no secret at all.
        if ($publicKey instanceof OkpKey && hash_equals(str_repeat("\0", $expected), $secret)) {
            throw new InvalidArgumentException(
                'Invalid ECDH public key. The shared secret is all zeros: the key is a low-order point (RFC 7748 section 6.1).'
            );
        }

        return $secret;
    }

    /**
     * A fresh key pair on the curve of the given key: the sender's ephemeral key of an ECDH-ES agreement.
     *
     * "When using ephemeral keys, the sender MUST generate a new ephemeral key for every key agreement operation"
     * (RFC 9053 section 6.3.1): this is that generation, from the CSPRNG of OpenSSL for EC2 and of PHP for OKP. The
     * key carries "kty", "crv", "x", "y" or "x", and "d", and nothing else -- no "kid", no "alg", no "key_ops" -- so
     * that its public half, {@see Key::toPublic()}, is exactly what the "ephemeral key" header parameter carries.
     *
     * @throws RuntimeException when the OpenSSL build of this platform does not provide the curve, or refuses to
     *                          generate the key
     */
    public static function generateEphemeralKey(Ec2Key|OkpKey $like): Ec2Key|OkpKey
    {
        self::assertCurveSupported($like);

        if ($like instanceof OkpKey) {
            $d = random_bytes(self::OKP_CURVES[$like->curveId()]);

            return OkpKey::create([
                Key::TYPE => Key::TYPE_OKP,
                OkpKey::DATA_CURVE => $like->curveId(),
                OkpKey::DATA_X => self::okpPublicKeyOf($like->curveId(), $d),
                OkpKey::DATA_D => $d,
            ]);
        }

        OpenSslError::clear();
        $resource = openssl_pkey_new([
            'curve_name' => self::EC2_CURVES[$like->curveId()],
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $details = $resource === false ? false : openssl_pkey_get_details($resource);
        $ec = $details === false ? null : ($details['ec'] ?? null);
        if (! is_array($ec) || ! isset($ec['x'], $ec['y'], $ec['d'])
            || ! is_string($ec['x']) || ! is_string($ec['y']) || ! is_string($ec['d'])) {
            throw new RuntimeException('Unable to generate an ephemeral EC key: ' . OpenSslError::lastMessage());
        }
        // OpenSSL strips the leading zeros of the coordinates; COSE wants them (RFC 9053 section 7.1.1).
        $length = strlen($like->x());

        return Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => $like->curveId(),
            Ec2Key::DATA_X => str_pad($ec['x'], $length, "\0", STR_PAD_LEFT),
            Ec2Key::DATA_Y => str_pad($ec['y'], $length, "\0", STR_PAD_LEFT),
            Ec2Key::DATA_D => str_pad($ec['d'], $length, "\0", STR_PAD_LEFT),
        ]);
    }

    /**
     * The public key of an OKP private scalar, through OpenSSL: loaded from its PKCS #8 form, the public key is
     * read back from the SubjectPublicKeyInfo OpenSSL prints for it. The Sodium extension could do it for X25519
     * but not for X448, and one path serves both.
     */
    private static function okpPublicKeyOf(int $curve, string $d): string
    {
        $private = openssl_pkey_get_private(OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::DATA_D => $d,
        ])->asPEM());
        $details = $private === false ? false : openssl_pkey_get_details($private);
        $pem = $details === false ? null : ($details['key'] ?? null);
        if (! is_string($pem)) {
            throw new RuntimeException('Unable to generate an ephemeral OKP key: ' . OpenSslError::lastMessage());
        }
        $der = base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $pem), true);
        if ($der === false) {
            throw new RuntimeException('Unable to read the public key OpenSSL generated.');
        }
        $public = PublicKeyLoader::fromSubjectPublicKeyInfo($der);
        if (! $public instanceof OkpKey || $public->curveId() !== $curve) {
            throw new RuntimeException('The public key OpenSSL generated is not on the requested curve.');
        }

        return $public->x();
    }

    /**
     * RFC 9053 section 6.3.1: "Implementations MUST verify that the key type and curve are correct", and the issue
     * behind this class spells it out: an EC2 key for an OKP recipient is refused, and so is a curve that differs.
     */
    private static function assertSameCurve(Ec2Key|OkpKey $privateKey, Ec2Key|OkpKey $publicKey): void
    {
        if ($privateKey::class !== $publicKey::class) {
            throw new InvalidArgumentException(sprintf(
                'Invalid ECDH key pair. The private key is of type %s and the public key of type %s: both MUST be of the same key type (RFC 9053 section 6.3.1).',
                $privateKey instanceof Ec2Key ? Key::TYPE_NAME_EC2_IANA : Key::TYPE_NAME_OKP,
                $publicKey instanceof Ec2Key ? Key::TYPE_NAME_EC2_IANA : Key::TYPE_NAME_OKP
            ));
        }
        if ($privateKey->curveId() !== $publicKey->curveId()) {
            throw new InvalidArgumentException(sprintf(
                'Invalid ECDH key pair. The private key is on curve %d and the public key on curve %d: both MUST be on the same curve (RFC 9053 section 6.3.1).',
                $privateKey->curveId(),
                $publicKey->curveId()
            ));
        }
    }

    private static function assertCurveSupported(Ec2Key|OkpKey $key): void
    {
        $curve = $key->curveId();
        if ($key instanceof OkpKey && ! isset(self::OKP_CURVES[$curve])) {
            throw new InvalidArgumentException(sprintf(
                'Invalid ECDH key. The OKP curve %d is not one ECDH is defined for: X25519 (4) and X448 (5) are (RFC 9053 section 6.3.1); the Edwards curves sign, they do not agree.',
                $curve
            ));
        }
        if ($key instanceof Ec2Key && ! isset(self::EC2_CURVES[$curve])) {
            throw new InvalidArgumentException(sprintf(
                'Invalid ECDH key. The EC2 curve %d is not one ECDH is defined for: P-256 (1), P-384 (2), P-521 (3) are (RFC 9053 section 6.3.1), and the Brainpool curves (256-259) where the platform provides them.',
                $curve
            ));
        }
        if (! self::isCurveSupported($key)) {
            throw new RuntimeException(sprintf(
                'ECDH on curve %d requires the %s curve, which this OpenSSL build does not provide.',
                $curve,
                self::EC2_CURVES[$curve] ?? (string) $curve
            ));
        }
    }
}
