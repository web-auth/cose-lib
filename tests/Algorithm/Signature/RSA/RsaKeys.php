<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use function base64_decode;
use Cose\Key\RsaKey;

/**
 * Test vectors shared by the RSA based algorithm test cases.
 */
final class RsaKeys
{
    public static function privateKey(): RsaKey
    {
        return RsaKey::create([
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
    }
}
