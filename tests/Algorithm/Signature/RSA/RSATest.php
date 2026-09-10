<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use function base64_decode;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\PSSRSA;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithm\Signature\RSA\RSA;
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use InvalidArgumentException;
use const OPENSSL_KEYTYPE_RSA;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RSATest extends TestCase
{
    #[Test]
    public function theAlgorithmsHaveCorrectInnerParameters(): void
    {
        // Then
        static::assertSame(-65535, RS1::identifier());
        static::assertSame(-257, RS256::identifier());
        static::assertSame(-258, RS384::identifier());
        static::assertSame(-259, RS512::identifier());
        static::assertSame(-37, PS256::identifier());
        static::assertSame(-38, PS384::identifier());
        static::assertSame(-39, PS512::identifier());
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aSignatureCanBeComputedAndVerified(
        RSA|PSSRSA $algorithm,
        RsaKey $key,
        string $data,
        string $signature
    ): void {
        // Given

        // When
        $computedSignature = $algorithm->sign($data, $key);
        $computedSignatureIsValid = $algorithm->verify($data, $key, $computedSignature);
        $signatureIsValid = $algorithm->verify($data, $key, $signature);

        // Then
        static::assertTrue($computedSignatureIsValid);
        static::assertTrue($signatureIsValid);
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aSignatureCanBeVerified(RSA|PSSRSA $algorithm, RsaKey $key, string $data, string $signature): void
    {
        // Given

        // When
        $isValid = $algorithm->verify($data, $key, $signature);

        // Then
        static::assertTrue($isValid);
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aSignatureCanBeVerifiedWithThePublicKey(
        RSA|PSSRSA $algorithm,
        RsaKey $key,
        string $data,
        string $signature
    ): void {
        // Given
        $publicKey = $key->toPublic();

        // When
        $isValid = $algorithm->verify($data, $publicKey, $signature);

        // Then
        static::assertTrue($isValid);
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aTamperedMessageIsRejected(
        RSA|PSSRSA $algorithm,
        RsaKey $key,
        string $data,
        string $signature
    ): void {
        // Given
        $tampered = $data . '.';

        // When
        $isValid = $algorithm->verify($tampered, $key, $signature);

        // Then
        static::assertFalse($isValid);
    }

    /**
     * openssl_sign() reports a modulus too short for the digest with a boolean; the return value used to be ignored,
     * so $signature stayed null and the string return type raised a TypeError instead of the intended exception.
     *
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-8.2.1
     */
    #[Test]
    public function signingWithAModulusTooShortForTheDigestIsRejected(): void
    {
        // Given
        // The bound of RFC 8230 section 6.1 is declared away so that the failure under test is the one openssl_sign()
        // reports, not the policy check that now precedes it.
        $algorithm = RS512::create(RsaKeyValidator::create(minimumModulusLength: 512));
        $key = self::generatedKey(512);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to sign the data');

        // When
        $algorithm->sign('Live long and Prosper.', $key);
    }

    #[Test]
    public function signingWithAPublicKeyIsRejected(): void
    {
        // Given
        $algorithm = RS256::create();
        $key = RsaKeys::publicKey();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is not private.');

        // When
        $algorithm->sign('Live long and Prosper.', $key);
    }

    private static function generatedKey(int $bits): RsaKey
    {
        $details = openssl_pkey_get_details(openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
        ]))['rsa'];

        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => $details['n'],
            RsaKey::DATA_E => $details['e'],
            RsaKey::DATA_D => $details['d'],
            RsaKey::DATA_P => $details['p'],
            RsaKey::DATA_Q => $details['q'],
            RsaKey::DATA_DP => $details['dmp1'],
            RsaKey::DATA_DQ => $details['dmq1'],
            RsaKey::DATA_QI => $details['iqmp'],
        ]);
    }

    /**
     * @return array<array{RSA|PSSRSA, RsaKey, string, string}>
     */
    public static function getVectors(): iterable
    {
        $key = RsaKeys::privateKey();

        yield [
            RS256::create(),
            $key,
            'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoibldzNEIzQ2VaaWpxdnV3anplRDBnRFU1WnpRcW1sOGND' .
                'RUNmc0g1SkpPdjRrU2NtOGFiazhtX0otdkxTNE80R2JUcnpTZFgzam9JaGp2SUxoQ3dVUkJmc0FrRVlpUUdCejZPa3hWWTg0' .
                'UFVSVVh5RG5SbmhpaVdIU3pyQTNUUEsxN1RYMEtTZlBabDRCcHRpbTZySnhablN5aVdqNnBwbHBybGdMXzEtMlZTaWZwUEZs' .
                'RHNlNEpGUkJBQm9IS3hCaWNnekVrZElacV9iMVNpM0pYTmdLRmRBUFBKUXlwN0lKdE1ZdVAtUmJ1WW4wMjF5YmVkSXFicktp' .
                'VzhBaHFxQ093bjE3OHphenhUMHlwVjdTQ3lBTmxvZUJTTk5QSkdVT0V3cXZwcTkwVllPNzNWZkFjdWdtT1pfVTdEZzVIR20t' .
                'V2NTeU9ZZXBxMkNFSFYyVEpmNEJRIiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'mU7xRSbu6YjWaeQ0vhfqc/8gZYlmKCwejqLiTz/T0W9FROLkuezn6DxSz+g2XG3u0MI6uWvXktpOxrQzlCzrJABNB2Bjhb+j' .
                    'lFnqZcykz0JaoNyWC5BzmmrA6haHpKeV33EkVdCNmV7pPAyyc4fZgPBGyoD/6BnnbaIqKllpylNFUseXrSsR68UomYvQU3ZC' .
                    'De2sVcopBnUIxaW4b1IoSmyqnNSvpWeQ0GaCrvDJ9n8l/5wtVuuJKNhWROpkStWzIMcI9yKnIijGLvdWlCCv5SQwG2wEaklF' .
                    'efEccW4Gg0kJUb3xhFS9Fsw0FSJkkQjKel6OlE4NZSY8bRwb3sei7w==',
                true
            ),
        ];

        yield [
            RS384::create(),
            $key,
            'eyJhbGciOiJSUzM4NCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoibldzNEIzQ2VaaWpxdnV3anplRDBnRFU1WnpRcW1sOGND' .
                'RUNmc0g1SkpPdjRrU2NtOGFiazhtX0otdkxTNE80R2JUcnpTZFgzam9JaGp2SUxoQ3dVUkJmc0FrRVlpUUdCejZPa3hWWTg0' .
                'UFVSVVh5RG5SbmhpaVdIU3pyQTNUUEsxN1RYMEtTZlBabDRCcHRpbTZySnhablN5aVdqNnBwbHBybGdMXzEtMlZTaWZwUEZs' .
                'RHNlNEpGUkJBQm9IS3hCaWNnekVrZElacV9iMVNpM0pYTmdLRmRBUFBKUXlwN0lKdE1ZdVAtUmJ1WW4wMjF5YmVkSXFicktp' .
                'VzhBaHFxQ093bjE3OHphenhUMHlwVjdTQ3lBTmxvZUJTTk5QSkdVT0V3cXZwcTkwVllPNzNWZkFjdWdtT1pfVTdEZzVIR20t' .
                'V2NTeU9ZZXBxMkNFSFYyVEpmNEJRIiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'gnd9RzAtF6lST+/OElTx01vKTYCZwRah34R8A4jvcu3FXcZI4tRjscpj1cpkz83tN/fyNQASDSkHpyBRssRnMHDcUiUDdyGk' .
                    'iik4hvSiLSr0dCTwbJSGBmfArRSjYFsVHlG5lqI47J72DyPGC+p8xUXFhVWP82lTPDDyFTfLnkX3Le9rplPm2aml+f/HGrhg' .
                    'yz82JM7Nt+0UQ1gkOB4tktpJO/S8PiolHO/uwH+tX0GeljhtX9hyS6GUsUsk8eWUn/6eugnbQ913jY97Weu33exncXPh0/BF' .
                    '56quDaHchcVyq1WlOQ9HFzZBDxS+LQ0hBwM0XHBmjJFKpR2uPYA/eA==',
                true
            ),
        ];

        yield [
            RS512::create(),
            $key,
            'eyJhbGciOiJSUzUxMiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoibldzNEIzQ2VaaWpxdnV3anplRDBnRFU1WnpRcW1sOGND' .
                'RUNmc0g1SkpPdjRrU2NtOGFiazhtX0otdkxTNE80R2JUcnpTZFgzam9JaGp2SUxoQ3dVUkJmc0FrRVlpUUdCejZPa3hWWTg0' .
                'UFVSVVh5RG5SbmhpaVdIU3pyQTNUUEsxN1RYMEtTZlBabDRCcHRpbTZySnhablN5aVdqNnBwbHBybGdMXzEtMlZTaWZwUEZs' .
                'RHNlNEpGUkJBQm9IS3hCaWNnekVrZElacV9iMVNpM0pYTmdLRmRBUFBKUXlwN0lKdE1ZdVAtUmJ1WW4wMjF5YmVkSXFicktp' .
                'VzhBaHFxQ093bjE3OHphenhUMHlwVjdTQ3lBTmxvZUJTTk5QSkdVT0V3cXZwcTkwVllPNzNWZkFjdWdtT1pfVTdEZzVIR20t' .
                'V2NTeU9ZZXBxMkNFSFYyVEpmNEJRIiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'S1ws65KhsCzthoKh1TsoK5VUqMZhvDdyJoQnt/6W18uAbnGi1OF5GJRyeo9aWC68Y93C81oBu/Yz1EbWaLFg7et6pHlfNVv5' .
                    'whaRvWzh92w7JuBt9wxPwCEFYWTqmw6BRfsbduSSn8n7ORlb/h+lD3zXOuJLZGCnY0hqLPW2k33KO/hUKkKClW1D/Z8olzS0' .
                    'hjk+FmCgiAugJ1Zki5nA/FPMBRj3Y8wnfDlW7oxyo00syr3H14vH8NruAGselhBvKWpEiH8y6KNWvbrjebziU/P4AHC+3q2h' .
                    'w8bIGwXU9AO1EMlzZDNMw+xKYtbIkwJcJeMwZ854ZWal4bfz46JPWA==',
                true
            ),
        ];

        yield [
            PS256::create(),
            $key,
            'eyJhbGciOiJQUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoibldzNEIzQ2VaaWpxdnV3anplRDBnRFU1WnpRcW1sOGND' .
                'RUNmc0g1SkpPdjRrU2NtOGFiazhtX0otdkxTNE80R2JUcnpTZFgzam9JaGp2SUxoQ3dVUkJmc0FrRVlpUUdCejZPa3hWWTg0' .
                'UFVSVVh5RG5SbmhpaVdIU3pyQTNUUEsxN1RYMEtTZlBabDRCcHRpbTZySnhablN5aVdqNnBwbHBybGdMXzEtMlZTaWZwUEZs' .
                'RHNlNEpGUkJBQm9IS3hCaWNnekVrZElacV9iMVNpM0pYTmdLRmRBUFBKUXlwN0lKdE1ZdVAtUmJ1WW4wMjF5YmVkSXFicktp' .
                'VzhBaHFxQ093bjE3OHphenhUMHlwVjdTQ3lBTmxvZUJTTk5QSkdVT0V3cXZwcTkwVllPNzNWZkFjdWdtT1pfVTdEZzVIR20t' .
                'V2NTeU9ZZXBxMkNFSFYyVEpmNEJRIiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'nMKu0GYzZkH1u7EjLE1uPuNZfjSReec26IvLNRnze+adhSlMr7bz+EsOeP/OVqq5Guk9P+KW8WHq83HoJvIeU2nHsvetJvno' .
                    'VlysUg4g4TJPuHUmINv6jaErmKFr4XmOU0LWgvSZ4LD1VGt7IGOfwRoED5697NnZSL5R3A5A+VW5+oWZoZLWf09sZsLwr2X+' .
                    'y9q6Z4gvG4YuAldUSSQJGNg3RmvWQIWEmkF59h5GTLVCfgCi7CVGfXCGjNeNGlC4/nxWPK7hb2SOwL+B/uuKStIaKPPO0+lr' .
                    'b5ejCHi/xaFWEYpRm9WEkfnQ+ECA2L8am0h2AJpnzT1sZGAwMquL2Q==',
                true
            ),
        ];

        yield [
            PS384::create(),
            $key,
            'eyJhbGciOiJQUzM4NCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoibldzNEIzQ2VaaWpxdnV3anplRDBnRFU1WnpRcW1sOGND' .
                'RUNmc0g1SkpPdjRrU2NtOGFiazhtX0otdkxTNE80R2JUcnpTZFgzam9JaGp2SUxoQ3dVUkJmc0FrRVlpUUdCejZPa3hWWTg0' .
                'UFVSVVh5RG5SbmhpaVdIU3pyQTNUUEsxN1RYMEtTZlBabDRCcHRpbTZySnhablN5aVdqNnBwbHBybGdMXzEtMlZTaWZwUEZs' .
                'RHNlNEpGUkJBQm9IS3hCaWNnekVrZElacV9iMVNpM0pYTmdLRmRBUFBKUXlwN0lKdE1ZdVAtUmJ1WW4wMjF5YmVkSXFicktp' .
                'VzhBaHFxQ093bjE3OHphenhUMHlwVjdTQ3lBTmxvZUJTTk5QSkdVT0V3cXZwcTkwVllPNzNWZkFjdWdtT1pfVTdEZzVIR20t' .
                'V2NTeU9ZZXBxMkNFSFYyVEpmNEJRIiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'dUW/GJ9EcZzvEzFqPyvZejO4vsZ7lHkuWb/CrR/DqG/Rnvpg0CQ62OGKMmTzJ/Q2czoLjI27pSlh7PA7O5wL5WlrlWos5WW/' .
                    'Iu6xdCDNXVMZSVg01lryHyWNj8826BTcbQ2YxfQLNlAtOgq2Y/cAtboOQUJEZmxqIZRIM5JptOOFqnSTy9FwwJxWxDsY3v9D' .
                    '/i3s2qRYZ9sdFR5Si4y0M/u/vNaIu4xTvYCoEKLNDHIyfa9ZLVKdKsCXm0k4/qm/MPRek7CXLjNQsx88lH6zTTs83u634IMP' .
                    'wYslXx16X8zTe1+wB976gaKJpB95EBwlkbwVjl2+2ThCYademsgwcQ==',
                true
            ),
        ];

        yield [
            PS512::create(),
            $key,
            'eyJhbGciOiJQUzUxMiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoibldzNEIzQ2VaaWpxdnV3anplRDBnRFU1WnpRcW1sOGND' .
                'RUNmc0g1SkpPdjRrU2NtOGFiazhtX0otdkxTNE80R2JUcnpTZFgzam9JaGp2SUxoQ3dVUkJmc0FrRVlpUUdCejZPa3hWWTg0' .
                'UFVSVVh5RG5SbmhpaVdIU3pyQTNUUEsxN1RYMEtTZlBabDRCcHRpbTZySnhablN5aVdqNnBwbHBybGdMXzEtMlZTaWZwUEZs' .
                'RHNlNEpGUkJBQm9IS3hCaWNnekVrZElacV9iMVNpM0pYTmdLRmRBUFBKUXlwN0lKdE1ZdVAtUmJ1WW4wMjF5YmVkSXFicktp' .
                'VzhBaHFxQ093bjE3OHphenhUMHlwVjdTQ3lBTmxvZUJTTk5QSkdVT0V3cXZwcTkwVllPNzNWZkFjdWdtT1pfVTdEZzVIR20t' .
                'V2NTeU9ZZXBxMkNFSFYyVEpmNEJRIiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'E6+yfXmGPSneTk5iwzq9iSY1AQU/ZeDDvxPAXe5Osz96sf+wAVnIgu2fHkA9vvcQUaACzYcQJtQ8mOhAxkh9mUp7ZDKeiyxH' .
                    '1bBUQEPmfO7+KDI66Ga3B6JWP7iEJeB0lKyc/e6jbhNSH0ghmRxSVCH/y3HgSdVvq9NRETrOTsTPrKvjKXPY0ckJYnY5WBwR' .
                    'LPMdak9Bt6XiDwXVNMiYrX0kQ+54TbgTh0zuUhPY1GkocGrwadiH0EL4knMF/NFf3wc5j++6axhCT7R6ZuGw5/zxg4sHZL13' .
                    'L3rbYHPNYguDKsSSg51ZjZR6IuvRVYkQ9oepXTcwd0LBimrMvXbnZw==',
                true
            ),
        ];
    }
}
