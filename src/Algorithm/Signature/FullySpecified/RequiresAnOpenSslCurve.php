<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\FullySpecified;

use function in_array;
use function openssl_get_curve_names;
use RuntimeException;
use function sprintf;

/**
 * The availability gate of an ECDSA algorithm whose curve OpenSSL may have been built without.
 *
 * The NIST curves are in every OpenSSL build; the Brainpool curves are not: some distributions compile them out, and
 * no FIPS provider carries them. On such a build a key on the curve loads fine and the failure only surfaces inside
 * openssl_sign() or openssl_verify(), as an OpenSSL error string. Availability is therefore settled once, when the
 * algorithm is instantiated, the way {@see \Cose\Algorithm\Signature\EdDSA\EdDSA} settles the sodium extension and
 * {@see Ed448} the PHP version; isSupported() lets a registry skip the algorithm rather than fail on it.
 */
trait RequiresAnOpenSslCurve
{
    public function __construct()
    {
        if (! static::isSupported()) {
            throw new RuntimeException(sprintf(
                'The %s algorithm requires the %s curve, which this OpenSSL build does not provide.',
                static::algorithmName(),
                static::curveName()
            ));
        }
    }

    /**
     * Whether OpenSSL was built with the curve this algorithm signs on.
     */
    public static function isSupported(): bool
    {
        $curves = openssl_get_curve_names();

        return $curves !== false && in_array(static::curveName(), $curves, true);
    }

    /**
     * The name OpenSSL gives the curve: the "crv" text name of the COSE Elliptic Curves registry for the Brainpool
     * curves, e.g. "brainpoolP256r1".
     */
    abstract protected static function curveName(): string;

    /**
     * The registered name of the algorithm, for the exception message: "ESB256".
     */
    abstract protected static function algorithmName(): string;
}
