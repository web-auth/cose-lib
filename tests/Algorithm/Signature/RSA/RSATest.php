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
    public function aSignatureCanBeComputedAndVerified(RSA|PSSRSA $algorithm, RsaKey $key, string $data): void
    {
        // Given

        // When
        $signature = $algorithm->sign($data, $key);
        $isValid = $algorithm->verify($data, $key, $signature);

        // Then
        static::assertTrue($isValid);
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
        $key1 = RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S+I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0/5rQCpcEt/Dn5iM+BNn7fqpoLIbks8rXKUIj8+qMVqkTXsEKeKinE23t1ykMldsNaaOH+hvGti5Jt2DMnH1JjoXdDXfxvSP/0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY/Cp7J4Mn1ejZ6HNmyvoTE/4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
            RsaKey::DATA_D => base64_decode(
                'Kp0KuZwCZGL1BLgsVM+N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js/pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs+YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1/BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7/TK7wXRlqA4UoRPiH2ACrdU+/cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn+CAQ',
                true
            ),
            RsaKey::DATA_P => base64_decode(
                'zPD+B+nrngwF+O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5+9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                true
            ),
            RsaKey::DATA_Q => base64_decode(
                'bWUC9B+EFRIo8kpGfh0ZuyGPvMNKvYWNtB/ikiH9k20eT+O1q/I78eiZkpXxXQ0UTEs2LsNRS+8uJbvQ+A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA/AKZGh+Q661/42rINLRCe8W+nZ34ui/qOfkLnK9QWDDqpaIsA+bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l+DqEiWxqg82sXt2h+LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L/mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ',
                true
            ),
            RsaKey::DATA_DP => base64_decode(
                'aJrzw/kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70+jhgMEiTZSNU8VXw2u7prAR3kZ+kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll/7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                true
            ),
            RsaKey::DATA_DQ => base64_decode(
                'Swz1+m/vmTFN/pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9+JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm/BVhoIb2/WPkjav6YSkguCUHt4HRd2YwE',
                true
            ),
            RsaKey::DATA_QI => base64_decode(
                'BocuCOEOq+oyLDALwzMXU8gOf3IL1Q1/BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N/PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh+Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
                true
            ),
        ]);

        yield [
            'alg' => RS256::create(),
            'key' => $key1,
            'data' => 'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            'sig' => base64_decode(
                'QyRlOCcNBMvCEkJRCQA71y2bVX690g0A6wsC2YXf9/VxOYK+g9+xy+1KjghVXkDPe1gDvYSYnL9oWs1PaFKV0/+ijvvJQE6/5pheKTfIVN3Qbkzjxsm4qXTeChBI5MKeBR8z8iWLFT4xPO8NkelwbS2tSUCHrejio6lDDlWhsqSUP8NjHJhqCSZuCDGu3fMMA24cZrYev3tQRc7HHjyi3q/17NZri7feBd7w3NEDkJp7wT/ZclJrYoucHIo1ypaDPJtM+W1+W+lAVREka6Xq4Bg60zdSZ83ODRQTP/IwQrv7hrIcbrRwn1Za/ORZPRPQDP0CMgkb7TkWDZnbPsAzlQ',
                true
            ),
        ];

        yield [
            'alg' => RS384::create(),
            'key' => $key1,
            'data' => 'eyJhbGciOiJSUzM4NCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            'sig' => base64_decode(
                'gsBhyBOEDPpHBR8OM2Xb5tybKGeijREZN+smEkvI2188pytujFevbDQJ10afbcdjh5LNKO7U/VD3hGPrC7MIkdtJw4c2d0JnVyhiZT5sFnncnCFjll+Y9GkK7a7jWJJTgF/5LmVEeJSFEEgwT1Stxb+TtZCGqc5ExYizLiuQ2IGB6Sq+hTkpWAXJfmHchE/TxV9A4iLWCMTVM6LsLV6NzDtf2a0iu9XvN1MEdzqM7FNdqNCGN43FveTA0hX8OoFfB2ZjYAjbixUCT4VVI2PuuRyu/Lr8cA73eisolBQLQemPyrCo1s560v2tKD7ICS8Teo1PCJ4HnCuO8bvufI2dKA',
                true
            ),
        ];

        yield [
            'alg' => RS512::create(),
            'key' => $key1,
            'data' => 'eyJhbGciOiJSUzUxMiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            'sig' => base64_decode(
                'OMttEbx9fWoJl4gJwp8m249P87nNENhy5RzH84S1iR8b+upQNy8dqHoIVsQ6qINDjDL5YTl4UWvChIr5AO433LjNUimIeEp2cfiqrszTTwhv+EF3Lp3Ft9NmTb+3ZWvDo1WwwUrD0qro7bynaz5O06DxQfTROcrC6hNX05y6nW/+21exs2/w2OoOWA0Ebx9ev1ayZJh1AQ6q18Ajb0Gk1RST1PFjz0Sk/YiUIYRSVJzgv2Lf7R/Lyi5A5OkIfLOyJmKBi6m0FOLoynq/fT96wCbf5Nkhx+RiuFEcefGhgDav7Wfim3zA3ZAHeNWe58BZOf+8v1kXsV+yd6zQlVa8iw',
                true
            ),
        ];

        /*
        yield [
            'alg' => PS256::create(),
            'key' => $key1,
            'data' => 'eyJhbGciOiJQUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            'sig' => base64_decode(
                'NTHE3+OfgBuZclNFsolgYuOd+aNUB5FKQL68MwL/EGsb3hTgbiU1A/6QOdQq6DCQ36gs8nSFWpEyM77TyoDWG0t8ctZlqdrjVSSZrbzrBY0iukeAG0NqVaZlKbRiyuIwvRY4nJBCK6BWmHb4ewXOI/3m8hNVmQajcnHy+xEKm2wla0mZizPN44C/NFmbbX1MKbNRIl5wQz+ILyUOqYb3PRdJSTKCkitLYQX6qLgonlFkIHyY0TsainHJaR09SAzdk3XsDAfYBg/RXvz2lW8+IlxIy+FuLB4HrjgpAq2fRDfRtRyfnI2A1rsMJyDaMVjQniTj1fYg/0hm+7v4HLclV0UzQU3Y2zyG7zsoWDqp9b0/fZGZJydVvuPpOYIN7UlLeFbAVBmRBI09uQs3+VDh8GRtpqno7kIt5W3IiD9a6C0btKlb9yLCXdQqCQBkLX++g7B3GiPW99R/4B2WFMo8BKUbSHxrFZzyYGlGCQ/YjxKz6RPcjR2A2RPWpJfDeXzj',
                true
            ),
        ];

        yield [
            'alg' => PS384::create(),
            'key' => $key1,
            'data' => 'eyJhbGciOiJQUzM4NCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            'sig' => base64_decode(
                'VGUibk9r/WDX/K2H4MAsN1oi5oOKWRElPFvcVtPP5hIzDqB0K3S40b+WoFplSbPTtQQKA0W9hqzdQPmpIC4yqrtKrOWF+WmyIfNl1zAnHeNJGw85L/k56BU8T1Wa5qGVf7osA8MPSvw9dnPq0DMRArqiCUipoAUzCS18dmUTH0KIMuyebxMLZHm0c0HJ2n91BxXDrET9ycYxaMPEvIvBu9dIgXwwZiPu65xz6zYgLdfbhSKjc5KJc66JLVwI6j8Q7bmlJ0ChtQtf5f65uslRoR2K3Ezn3MR074EtlCt3KjP9BtdS18Kpxu7uYT5L7OYKJutso/hPNDgUnED4QruZjA',
                true
            ),
        ];

        yield [
            'alg' => PS512::create(),
            'key' => $key1,
            'data' => 'eyJhbGciOiJQUzUxMiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg',
            'sig' => base64_decode(
                'bBsgpFWir0MvWmgCZ8CVCGTcHm4C9FgTty8NvtyRHAvpTlL8NCbcZ2VNJWKPpCjge/Rv29jguivUHFgudlBYY6LKJd5xUt12uZQL//Jc8Z1YCNq6BDFtH09HMKRAkePLkRXv05DdoL20eOpZGJMITn0LK5STC+c7YNjlwjppclFfEf0Arl8Er3LvPlyoBMJRd1X7osMFamdEDAoqPM/JTVMQMNI/kXv+P42iePERixvX1MDeF/KUfgWwzfYYUltrpG+JPh05iqwlKTsUchqDTdo8l2phEa5qq6MCQemzvKBMFb2u/B4+VXTD60vJVLSrionHncU1jyOwSIgAKPipxQ',
                true
            ),
        ];
         */
    }
}
