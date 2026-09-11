<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature;

use function base64_decode;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\RsaKey;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * Self-signed X.509 certificates and the private keys that go with them.
 *
 * Each certificate was generated with OpenSSL and signed with its own key. Nothing in the tests depends on the chain
 * being trusted, only on the SubjectPublicKeyInfo each certificate carries; the private keys are stored as the
 * components a COSE key is made of, so that a test can sign with a Cose\Algorithm\Signature\Signature class and then
 * verify through the certificate. CertificatesTest asserts that each private key does match the public key of its
 * certificate, so that the fixtures cannot silently rot.
 */
final class Certificates
{
    /**
     * secp256r1 (P-256), for ES256 and ESP256.
     */
    public const P256_CERTIFICATE = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB0jCCAXegAwIBAgIUQYFM6XWaETMcJoy/C/malnb5zYswCgYIKoZIzj0EAwIw
        PTEbMBkGA1UEAwwSY29zZS1saWIgcDI1NiB0ZXN0MREwDwYDVQQKDAhjb3NlLWxp
        YjELMAkGA1UEBhMCRlIwIBcNMjYwOTEwMTcxNDQ2WhgPMjEyNjA4MTcxNzE0NDZa
        MD0xGzAZBgNVBAMMEmNvc2UtbGliIHAyNTYgdGVzdDERMA8GA1UECgwIY29zZS1s
        aWIxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEivdAj9Jl
        XVfGK3bDJvB84e2YKzCA6zxXwZEa1JUJy5q3qBBj/dpqSd7UhDzI5aen5rySoh4/
        x46dUjhkRMEGq6NTMFEwHQYDVR0OBBYEFHSIEVvGt24FW7DYH0eSPyTdeeG2MB8G
        A1UdIwQYMBaAFHSIEVvGt24FW7DYH0eSPyTdeeG2MA8GA1UdEwEB/wQFMAMBAf8w
        CgYIKoZIzj0EAwIDSQAwRgIhANaarJZLBgitNE7aHt46IfyUKHwck0WX6BiM07dD
        NEDtAiEAyuu9sIbe4E/gDH4HFmNQttQTq5MaYHgIf85YthXT+E8=
        -----END CERTIFICATE-----
        PEM;

    /**
     * secp256k1, for ES256K - the identifier the digest only map of Algorithms could not describe before.
     */
    public const P256K_CERTIFICATE = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB0DCCAXagAwIBAgIUfxedXQ/dUOICRW3RNz9UmvKGJk8wCgYIKoZIzj0EAwIw
        PjEcMBoGA1UEAwwTY29zZS1saWIgcDI1NmsgdGVzdDERMA8GA1UECgwIY29zZS1s
        aWIxCzAJBgNVBAYTAkZSMCAXDTI2MDkxMDE3MTQ0NloYDzIxMjYwODE3MTcxNDQ2
        WjA+MRwwGgYDVQQDDBNjb3NlLWxpYiBwMjU2ayB0ZXN0MREwDwYDVQQKDAhjb3Nl
        LWxpYjELMAkGA1UEBhMCRlIwVjAQBgcqhkjOPQIBBgUrgQQACgNCAASVVi0Bd4Yo
        RbWPPvNQfS3bLFxzpX+KJf9dsgKgYE/lj9Yi24TdF3/9LAmB8OXAesP499DCMA2j
        0iqR29CHFW7Zo1MwUTAdBgNVHQ4EFgQUXcQZ/gY/Xot0S/tRY9WaZbyX/QowHwYD
        VR0jBBgwFoAUXcQZ/gY/Xot0S/tRY9WaZbyX/QowDwYDVR0TAQH/BAUwAwEB/zAK
        BggqhkjOPQQDAgNIADBFAiA/YDBSipHPPEIAuVoJifcBHkDm4kOcP+Zfo7aka/np
        +wIhAPnOwJRjZZoJkqRmhp+Dxuj74H3WsWPI5jfj/JNzc6L4
        -----END CERTIFICATE-----
        PEM;

    /**
     * brainpoolP256r1, for ESB256 - a curve OpenSSL names but pki-framework has no constant for.
     */
    public const BP256_CERTIFICATE = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB1DCCAXqgAwIBAgIUXIJzV/8GyVaEsn4twnKPbROQjF4wCgYIKoZIzj0EAwIw
        PjEcMBoGA1UEAwwTY29zZS1saWIgYnAyNTYgdGVzdDERMA8GA1UECgwIY29zZS1s
        aWIxCzAJBgNVBAYTAkZSMCAXDTI2MDkxMDE3MTQ0NloYDzIxMjYwODE3MTcxNDQ2
        WjA+MRwwGgYDVQQDDBNjb3NlLWxpYiBicDI1NiB0ZXN0MREwDwYDVQQKDAhjb3Nl
        LWxpYjELMAkGA1UEBhMCRlIwWjAUBgcqhkjOPQIBBgkrJAMDAggBAQcDQgAEgJTM
        lYlpqVN6HTyEhEHyQmqKyNTzBysOp08CqRO8wz2iYB8WII5rMXyjFR5ayFK/3Kln
        MTRzpZARKFyD1ex70aNTMFEwHQYDVR0OBBYEFFQqKls14MyH/JgdMy9pKySzj+LB
        MB8GA1UdIwQYMBaAFFQqKls14MyH/JgdMy9pKySzj+LBMA8GA1UdEwEB/wQFMAMB
        Af8wCgYIKoZIzj0EAwIDSAAwRQIhAJVzHKGo6Oda9TiPy4t7cfj1pT/K9PVom6iy
        r++VSDDoAiA5xXT4h0YHwOQEFeEpelG+LKArsYZCRTaiY5Xk8WjUxw==
        -----END CERTIFICATE-----
        PEM;

    /**
     * A 2048 bit RSA key, for RS1, RS256 and the RSASSA-PSS algorithms that no OPENSSL_ALGO_* digest can express.
     */
    public const RSA_CERTIFICATE = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIDWzCCAkOgAwIBAgIUIERQuPP/vktc7aJoSoX/EYrtxAUwDQYJKoZIhvcNAQEL
        BQAwPDEaMBgGA1UEAwwRY29zZS1saWIgcnNhIHRlc3QxETAPBgNVBAoMCGNvc2Ut
        bGliMQswCQYDVQQGEwJGUjAgFw0yNjA5MTAxNzE0NDZaGA8yMTI2MDgxNzE3MTQ0
        NlowPDEaMBgGA1UEAwwRY29zZS1saWIgcnNhIHRlc3QxETAPBgNVBAoMCGNvc2Ut
        bGliMQswCQYDVQQGEwJGUjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
        ALUiG7U651JqSX3j+2eoKmae+yd16QPgDNnsjImOUAJV3JLs/hp5k0G8mb8h6X36
        tNCNyh1CXDr5uoLQQD54oRDtVK9LnBLvgHVTcd6VnADzebQQyIQfBajbC/T+Fexu
        yegEJUHO2H27MWUo6SJPW6KuIxsHkVVIjOHavqs7f1n8S3e5mDxhqHaa9kas2NoV
        c6F1jnjoMmdLVrqRYuv8QYYe9qsE8juzIyeWOEE73F+qY+etDCv8ZJXEiJK5tgP4
        0kw4yTjdaSg4IK88ao5cd87AdaakVloBbV1+nuw6lgZJ3c2WpkdEC3TGx7eggD/F
        UwpWk4SikvorvR1coXhVZdsCAwEAAaNTMFEwHQYDVR0OBBYEFBMQeBUYVogW2h7+
        +NMLBrsjiBXjMB8GA1UdIwQYMBaAFBMQeBUYVogW2h7++NMLBrsjiBXjMA8GA1Ud
        EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKY5PRIUSq6fbnicmjSwSljm
        JBdYHWP3UH327Ag2SQlP5uxqoHHF9eCD70oV+mH5xHsVAB5T2vePQ6YUxMs2Fi7u
        8g/VDj7w6UBYMgfpJmm/DgSS2ddw3Ner6qEmCS8zi90l6DHAZbwdwpbR7/4QAm+0
        T2fmiqil1ZGDhA3ydq80HcrTwfr9y3+TBdY3E9bigrvPW2SfCRH86urbok7PTxnr
        599/AiucuJriTdg7Xq1SR5LYMHx/kbu66kj4K5PACgsloLHwRWXRK4NZiislMqk/
        lqPeVfV85sSCnu65a8ZmbwFz2FJpgpFAQMpoW81kbgGRcqdr4/tY6GJ3lGeTo0A=
        -----END CERTIFICATE-----
        PEM;

    /**
     * An RFC 8410 Ed25519 certificate, for EdDSA (-8) and Ed25519 (-19).
     */
    public const ED25519_CERTIFICATE = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIBlzCCAUmgAwIBAgIUX2Sk5uf0UZrgQ5h2tUWG2rZeqFwwBQYDK2VwMEAxHjAc
        BgNVBAMMFWNvc2UtbGliIGVkMjU1MTkgdGVzdDERMA8GA1UECgwIY29zZS1saWIx
        CzAJBgNVBAYTAkZSMCAXDTI2MDkxMDE3MTQ0NloYDzIxMjYwODE3MTcxNDQ2WjBA
        MR4wHAYDVQQDDBVjb3NlLWxpYiBlZDI1NTE5IHRlc3QxETAPBgNVBAoMCGNvc2Ut
        bGliMQswCQYDVQQGEwJGUjAqMAUGAytlcAMhADs/Xh6SzZlStr5IblHdMG9kexXI
        bWRiQH3sKAHq0oADo1MwUTAdBgNVHQ4EFgQUzXHC5rEVRGBXSUKRYmaMqM+AJy8w
        HwYDVR0jBBgwFoAUzXHC5rEVRGBXSUKRYmaMqM+AJy8wDwYDVR0TAQH/BAUwAwEB
        /zAFBgMrZXADQQAG1T54Z7hqj9oSQSZUgbQo1cyXJwg7g8OOf9ymeXwbL9J6aMtU
        NkGtDwZ3yTl8nb8HSpoWgEthK1cpX3EshckE
        -----END CERTIFICATE-----
        PEM;

    /**
     * An RFC 8410 Ed448 certificate, for Ed448 (-53).
     */
    public const ED448_CERTIFICATE = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB3jCCAV6gAwIBAgIUGH1c5zJ6MMX3R/4m4SKMLypChBwwBQYDK2VxMD4xHDAa
        BgNVBAMME2Nvc2UtbGliIGVkNDQ4IHRlc3QxETAPBgNVBAoMCGNvc2UtbGliMQsw
        CQYDVQQGEwJGUjAgFw0yNjA5MTAxNzE0NDZaGA8yMTI2MDgxNzE3MTQ0NlowPjEc
        MBoGA1UEAwwTY29zZS1saWIgZWQ0NDggdGVzdDERMA8GA1UECgwIY29zZS1saWIx
        CzAJBgNVBAYTAkZSMEMwBQYDK2VxAzoAxSxdsimrEBj/f8YJJLwysaoLKIofBFfO
        kzMHWrssVW56K4vpAvB1uyYvrDMfASBf1ZYa0iMAAbgAo1MwUTAdBgNVHQ4EFgQU
        iZ7OihCqVynIF+lFKDPyrLUKA64wHwYDVR0jBBgwFoAUiZ7OihCqVynIF+lFKDPy
        rLUKA64wDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXEDcwBWI2y3ynSS1yY9oXQhuSEe
        NJDHnTl6kkARQFBUjHAKalJhBUUAjWLGceu0nBPS4oEWttlD05G63QB15moZ9TCb
        DY3b9Q6HpNisr3Mst0f35V4CfcBj5yHCwYDVwzbaCv4BeSq7IJ4Yp0nzquM8zzI9
        MAA=
        -----END CERTIFICATE-----
        PEM;

    public static function p256PrivateKey(): Ec2Key
    {
        return Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => base64_decode('ivdAj9JlXVfGK3bDJvB84e2YKzCA6zxXwZEa1JUJy5o=', true),
            Ec2Key::DATA_Y => base64_decode('t6gQY/3aakne1IQ8yOWnp+a8kqIeP8eOnVI4ZETBBqs=', true),
            Ec2Key::DATA_D => base64_decode('gPsISaTmFiNioge+6zq/qatE6qRDe5fyWGNFvyhC2/I=', true),
        ]);
    }

    public static function p256kPrivateKey(): Ec2Key
    {
        return Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256K,
            Ec2Key::DATA_X => base64_decode('lVYtAXeGKEW1jz7zUH0t2yxcc6V/iiX/XbICoGBP5Y8=', true),
            Ec2Key::DATA_Y => base64_decode('1iLbhN0Xf/0sCYHw5cB6w/j30MIwDaPSKpHb0IcVbtk=', true),
            Ec2Key::DATA_D => base64_decode('XuAQDEta4bPOvyGw0tkGJQzLak3gHWejG4Zoym4KiEU=', true),
        ]);
    }

    public static function bp256PrivateKey(): Ec2Key
    {
        return Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_BP256,
            Ec2Key::DATA_X => base64_decode('gJTMlYlpqVN6HTyEhEHyQmqKyNTzBysOp08CqRO8wz0=', true),
            Ec2Key::DATA_Y => base64_decode('omAfFiCOazF8oxUeWshSv9ypZzE0c6WQEShcg9Xse9E=', true),
            Ec2Key::DATA_D => base64_decode('eA4Zz73Ovqdp/R9eEmi2fqTOeGnms2fn/0KrN3I/NR8=', true),
        ]);
    }

    public static function rsaPrivateKey(): RsaKey
    {
        return RsaKey::create([
            Key::TYPE => Key::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                'tSIbtTrnUmpJfeP7Z6gqZp77J3XpA+AM2eyMiY5QAlXckuz+GnmTQbyZvyHpffq00I3KHUJcOvm6gtBAPnihEO1Ur0ucEu+A' .
                'dVNx3pWcAPN5tBDIhB8FqNsL9P4V7G7J6AQlQc7YfbsxZSjpIk9boq4jGweRVUiM4dq+qzt/WfxLd7mYPGGodpr2RqzY2hVz' .
                'oXWOeOgyZ0tWupFi6/xBhh72qwTyO7MjJ5Y4QTvcX6pj560MK/xklcSIkrm2A/jSTDjJON1pKDggrzxqjlx3zsB1pqRWWgFt' .
                'XX6e7DqWBkndzZamR0QLdMbHt6CAP8VTClaThKKS+iu9HVyheFVl2w==',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
            RsaKey::DATA_D => base64_decode(
                'Cg4Ip7jLWoHX7osXS5vELsooevpKoxJu5DIDYydpPZfylJ1fRaz2BbIofrmtMncWTnVwgMtMP2HZfqV8y3r6xevGxaxWz55H' .
                '7TtimM6JSGw7l0lPODZYpBT0xvbL1MIZpy2Du/F1hxU7Grh4qJTrK06rWDbFVIygdXElIHA/E4mb5bNmScoOkUI4FoF45RRV' .
                'acvGYL0rvHqZOMXgwBUSlShAl1FaBJ8cKsmil3o2dAMWxJMSm+M3cx09Rjgk2eI3Bkn/1NwBPoF3rw9DCGHToqpQCSw9lZ+s' .
                'mqsZiiACrdv4UbCrzx5veDORaZ5/QCRjETMsRUjzLbuJMqMWlL7/YQ==',
                true
            ),
            RsaKey::DATA_P => base64_decode(
                '2v+SQtGvDKCPw1R1CeIeqVoOXhAjTamphZN6xtkS+/ZYPWlwE7IBq8Vyvg3IpYzgAHI3Kvc9ZJQZ3het/lfs5XuBKoVwlq5U' .
                '+RL8BrSJXbnhbZW/FcK3rKbPUBZgch5D+Ew46BQjKo1E2W1buZex6ZEpJpjdjh50uim3Ip7STgk=',
                true
            ),
            RsaKey::DATA_Q => base64_decode(
                '07y97DPtRVTKyZ/G+tbx+G5xu2vBn4Xgd0Qkt4UzrLSXLCCnNjf8kHESEdY5zGkhKwwPVxNnXiLVABYts06pxId2T0PVGcsu' .
                '25NRjay6eMM/YwShyUF9qygjrrtI1+ruzZqhDOLkLfuzW0cJvwMEaKhytIYSZDrNdsQOrkohjcM=',
                true
            ),
            RsaKey::DATA_DP => base64_decode(
                'C7c0aeKxzKkiR77S7A5uuXyZ3Cpc2SDEcuLq5IxkWZpaKh7j4gnZ0QilFMnD/CdHLH7vuJq1bBYINDtsEXk+sSAkTtQIq+bz' .
                'oMeFOA6ccqkpCCXErTNXhCMAYDZyPmikFjptqOy63OHl1wPkrk8RM3+ShgATijDS6cqlg3KfqZE=',
                true
            ),
            RsaKey::DATA_DQ => base64_decode(
                'oQECQhvyLigd01cljRPpBwmkfemgX9cDKm2spcgp1Qe1dB6YR4gnCwaPwPRvGtpOGFehSos8rL47zUcQFSqZuRFwizF/V4/C' .
                '38CT4PEZEj8VcgvRoiGkl4N8Lp/G8jh4wer0z8Gv1K9yYNQRuydmMNb18gOI9KIqHkdTCoDgJtU=',
                true
            ),
            RsaKey::DATA_QI => base64_decode(
                'Pf6a9t5JUtDlTDOpIAME4In3d50QZs4rieCjMFu5YUevzjXBvSMatbcjzJw0lcoD2qiPB6gm83aFXEXtCCa/m1joF4KqFO6l' .
                'O/ZAn13Konu0FYIEX7CWCFuZMcwceWLZeSSXT5v7tZ/+iRskoua5dbIygeu1N9LAG/lBJFtsoaY=',
                true
            ),
        ]);
    }

    public static function ed25519PrivateKey(): OkpKey
    {
        return OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => base64_decode('Oz9eHpLNmVK2vkhuUd0wb2R7FchtZGJAfewoAerSgAM=', true),
            OkpKey::DATA_D => base64_decode('yVNQLc1ukjDdqtakIfBTb4jyOxVxtKJ9MuMEq7xeStU=', true),
        ]);
    }

    /**
     * The DER encoding of a PEM certificate: the form a COSE_X509 carries.
     */
    public static function der(string $certificate): string
    {
        return PEM::fromString($certificate)->data();
    }

    /**
     * The SubjectPublicKeyInfo of a certificate, as its own PEM structure.
     */
    public static function subjectPublicKeyInfo(string $certificate): string
    {
        return Certificate::fromPEM(PEM::fromString($certificate))
            ->tbsCertificate()
            ->subjectPublicKeyInfo()
            ->toPEM()
            ->string();
    }

    public static function ed448PrivateKey(): OkpKey
    {
        return OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => base64_decode(
                'xSxdsimrEBj/f8YJJLwysaoLKIofBFfOkzMHWrssVW56K4vpAvB1uyYvrDMfASBf1ZYa0iMAAbgA',
                true
            ),
            OkpKey::DATA_D => base64_decode(
                'xsoM5pm+De3hXksBXRxqca0DYepK7QppubFRpMXvaR/DI7FZOTWeRHIhiVpz/+HKzhL2rqmlwJ+T',
                true
            ),
        ]);
    }
}
