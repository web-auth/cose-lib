<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

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
        $signatureIsValid = $algorithm->verify($data, $key, $computedSignature);

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

    /**
     * @return array<string>[]
     */
    public static function getVectors(): iterable
    {
        $key1 = RsaKeys::privateKey();

        yield [
            RS256::create(),
            $key1,
            'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'QyRlOCcNBMvCEkJRCQA71y2bVX690g0A6wsC2YXf9/VxOYK+g9+xy+1KjghVXkDPe1gDvYSYnL9oWs1PaFKV0/+ijvvJQE6/5pheKTfIVN3Qbkzjxsm4qXTeChBI5MKeBR8z8iWLFT4xPO8NkelwbS2tSUCHrejio6lDDlWhsqSUP8NjHJhqCSZuCDGu3fMMA24cZrYev3tQRc7HHjyi3q/17NZri7feBd7w3NEDkJp7wT/ZclJrYoucHIo1ypaDPJtM+W1+W+lAVREka6Xq4Bg60zdSZ83ODRQTP/IwQrv7hrIcbrRwn1Za/ORZPRPQDP0CMgkb7TkWDZnbPsAzlQ',
                true
            ),
        ];

        yield [
            RS384::create(),
            $key1,
            'eyJhbGciOiJSUzM4NCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'gsBhyBOEDPpHBR8OM2Xb5tybKGeijREZN+smEkvI2188pytujFevbDQJ10afbcdjh5LNKO7U/VD3hGPrC7MIkdtJw4c2d0JnVyhiZT5sFnncnCFjll+Y9GkK7a7jWJJTgF/5LmVEeJSFEEgwT1Stxb+TtZCGqc5ExYizLiuQ2IGB6Sq+hTkpWAXJfmHchE/TxV9A4iLWCMTVM6LsLV6NzDtf2a0iu9XvN1MEdzqM7FNdqNCGN43FveTA0hX8OoFfB2ZjYAjbixUCT4VVI2PuuRyu/Lr8cA73eisolBQLQemPyrCo1s560v2tKD7ICS8Teo1PCJ4HnCuO8bvufI2dKA',
                true
            ),
        ];

        yield [
            RS512::create(),
            $key1,
            'eyJhbGciOiJSUzUxMiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            base64_decode(
                'OMttEbx9fWoJl4gJwp8m249P87nNENhy5RzH84S1iR8b+upQNy8dqHoIVsQ6qINDjDL5YTl4UWvChIr5AO433LjNUimIeEp2cfiqrszTTwhv+EF3Lp3Ft9NmTb+3ZWvDo1WwwUrD0qro7bynaz5O06DxQfTROcrC6hNX05y6nW/+21exs2/w2OoOWA0Ebx9ev1ayZJh1AQ6q18Ajb0Gk1RST1PFjz0Sk/YiUIYRSVJzgv2Lf7R/Lyi5A5OkIfLOyJmKBi6m0FOLoynq/fT96wCbf5Nkhx+RiuFEcefGhgDav7Wfim3zA3ZAHeNWe58BZOf+8v1kXsV+yd6zQlVa8iw',
                true
            ),
        ];

        /*
         * yield [
         * 'algorithm' => PS256::create(),
         * 'key' => $key1,
         * 'data' => 'eyJhbGciOiJQUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
         * 'signature' => base64_decode(
         * 'NTHE3+OfgBuZclNFsolgYuOd+aNUB5FKQL68MwL/EGsb3hTgbiU1A/6QOdQq6DCQ36gs8nSFWpEyM77TyoDWG0t8ctZlqdrjVSSZrbzrBY0iukeAG0NqVaZlKbRiyuIwvRY4nJBCK6BWmHb4ewXOI/3m8hNVmQajcnHy+xEKm2wla0mZizPN44C/NFmbbX1MKbNRIl5wQz+ILyUOqYb3PRdJSTKCkitLYQX6qLgonlFkIHyY0TsainHJaR09SAzdk3XsDAfYBg/RXvz2lW8+IlxIy+FuLB4HrjgpAq2fRDfRtRyfnI2A1rsMJyDaMVjQniTj1fYg/0hm+7v4HLclV0UzQU3Y2zyG7zsoWDqp9b0/fZGZJydVvuPpOYIN7UlLeFbAVBmRBI09uQs3+VDh8GRtpqno7kIt5W3IiD9a6C0btKlb9yLCXdQqCQBkLX++g7B3GiPW99R/4B2WFMo8BKUbSHxrFZzyYGlGCQ/YjxKz6RPcjR2A2RPWpJfDeXzj',
         * true
         * ),
         * ];
         * yield [
         * 'algorithm' => PS384::create(),
         * 'key' => $key1,
         * 'data' => 'eyJhbGciOiJQUzM4NCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
         * 'signature' => base64_decode(
         * 'VGUibk9r/WDX/K2H4MAsN1oi5oOKWRElPFvcVtPP5hIzDqB0K3S40b+WoFplSbPTtQQKA0W9hqzdQPmpIC4yqrtKrOWF+WmyIfNl1zAnHeNJGw85L/k56BU8T1Wa5qGVf7osA8MPSvw9dnPq0DMRArqiCUipoAUzCS18dmUTH0KIMuyebxMLZHm0c0HJ2n91BxXDrET9ycYxaMPEvIvBu9dIgXwwZiPu65xz6zYgLdfbhSKjc5KJc66JLVwI6j8Q7bmlJ0ChtQtf5f65uslRoR2K3Ezn3MR074EtlCt3KjP9BtdS18Kpxu7uYT5L7OYKJutso/hPNDgUnED4QruZjA',
         * true
         * ),
         * ];
         * yield [
         * 'algorithm' => PS512::create(),
         * 'key' => $key1,
         * 'data' => 'eyJhbGciOiJQUzUxMiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
         * 'signature' => base64_decode(
         * 'bBsgpFWir0MvWmgCZ8CVCGTcHm4C9FgTty8NvtyRHAvpTlL8NCbcZ2VNJWKPpCjge/Rv29jguivUHFgudlBYY6LKJd5xUt12uZQL//Jc8Z1YCNq6BDFtH09HMKRAkePLkRXv05DdoL20eOpZGJMITn0LK5STC+c7YNjlwjppclFfEf0Arl8Er3LvPlyoBMJRd1X7osMFamdEDAoqPM/JTVMQMNI/kXv+P42iePERixvX1MDeF/KUfgWwzfYYUltrpG+JPh05iqwlKTsUchqDTdo8l2phEa5qq6MCQemzvKBMFb2u/B4+VXTD60vJVLSrionHncU1jyOwSIgAKPipxQ',
         * true
         * ),
         * ];
         */
    }
}
