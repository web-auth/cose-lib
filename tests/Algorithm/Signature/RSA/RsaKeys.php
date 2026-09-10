<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use function base64_decode;
use Cose\Key\RsaKey;

/**
 * Test vectors shared by the RSA based algorithm test cases.
 *
 * Every private key below is internally consistent: n = p*q (or p*q*r for the multi-prime one),
 * e*dP = 1 mod (p-1), e*dQ = 1 mod (q-1) and q*qInv = 1 mod p, as RFC 8017 section 3.2 requires.
 * RsaKeysTest asserts these relations so that the fixtures cannot silently rot.
 */
final class RsaKeys
{
    /**
     * A 2048 bit key whose modulus uses the minimum number of octets, as RFC 8230 section 4 requires.
     */
    public static function privateKey(): RsaKey
    {
        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                'nWs4B3CeZijqvuwjzeD0gDU5ZzQqml8cCECfsH5JJOv4kScm8abk8m/J+vLS4O4GbTrzSdX3joIhjvILhCwURBfsAkEYiQGB' .
                'z6OkxVY84PURUXyDnRnhiiWHSzrA3TPK17TX0KSfPZl4Bptim6rJxZnSyiWj6pplprlgL/1+2VSifpPFlDse4JFRBABoHKxB' .
                'icgzEkdIZq/b1Si3JXNgKFdAPPJQyp7IJtMYuP+RbuYn021ybedIqbrKiW8AhqqCOwn178zazxT0ypV7SCyANloeBSNNPJGU' .
                'OEwqvpq90VYO73VfAcugmOZ/U7Dg5HGm+WcSyOYepq2CEHV2TJf4BQ==',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
            RsaKey::DATA_D => base64_decode(
                'Azr9WHW9fAMDi9Oq8Ae/3/B3rM0B9M7WQFSz+KC9N1NAwH9pSeGiM1fYJFy4UO8n7zTolwLOxKKaArKn46Ut7ONnlfioNfBa' .
                'FBzbfd5rrs6IqPK644Ek9jtLH/mYL9HnLAilIL4U5uQ2QnIM330gcxW/7bynaC778aRxocdJEGrad7YSJ889r+LyVQcVnMzN' .
                '+IO9bFxtg0H0b7K3sWYJmAWoUPlcP6WkGXIHYReCuwitmxBsqWA3vuVqn1LZvYH7xs9Rcgs655Yc0GEj+IYm/xAF+kOrK3rF' .
                'owOTYBIQozY4ikOh24hh5NQ0A82ZFyZRWjn11PfJZ9HbeJZKPQXu3w==',
                true
            ),
            RsaKey::DATA_P => base64_decode(
                '0FUhP8CrZSokkpjxG28cK4L2QzYuLQ4ouvVlM6kVOp+5wB7vy5119NBcpUft9y1XBJfepVnN20a1BXsJ+JQz4I2s0l72AR66' .
                '4x1qdSd62pxhhKCtl39qwCcbmeAVwrcLJ9azRWI+7cRMNq3k5Ujh4NJ4PqPslYzd5TSCtZFiz+s=',
                true
            ),
            RsaKey::DATA_Q => base64_decode(
                'wW/eedGyWbvJRM8uFx3nRXU4ZPssG84wRgBD2TJfmD7YZ/S6R0/JL3z3Af1qL8Q7W4x9BIIMdd+rinpxFkTv3h07lsWlinGN' .
                'cbCaXk3SOw94OGl+yHXDT5srzylbXnz6L1seeOFiNSj8HVxz94GO9IM7CIEGGoao0kgXwHZYS88=',
                true
            ),
            RsaKey::DATA_DP => base64_decode(
                'Xx7vbm9nEmq6hiDEvXTu1MMX87oyPSog2LQgwASsh7bUFe9KJ5q+d8gG9QQxl9Eg0R0ScEbfogXXsyfpdpEcWqP1S5xGEF7a' .
                'j8YnjFQ5WMVcFTVT7T8lG5T/mjNhXCU9N7Rk6AIin2coMTMWtsWfNIqEkn1AEUxfKD7gi0xVZH8=',
                true
            ),
            RsaKey::DATA_DQ => base64_decode(
                'UX7rMVGqnWmjW00aMv0TQc0oDEtSAwj0h5l2/FvfsInRrMKLdJ3lug8hFgKJKUS4aVKgHTUZQNQSNo5tdJ9om6CfSV9N5iz/' .
                'FYX9E3wf9WgIE2RG2PfcaH6Mj4PyDbYDxc3S4cS7FoCE723TIdTAwL1FMskBJE3VdHqRHzH88zs=',
                true
            ),
            RsaKey::DATA_QI => base64_decode(
                'Z7gHmrXezlIxetYyYdc/kBRTPAi96hnT8jHSAOoZtYXzEbFfHkPNRCQBTwDPKZiOWrghb4fOnEAcnHZ1nwEPdae514ySt7vJ' .
                'qGLOjY8B3UtniwnaW0fRd3pplbksdbGxxK1FldgAsQUZRVy7uDQlxtyZ7cFmQlIKV3ZeXVmVXb0=',
                true
            ),
        ]);
    }

    public static function publicKey(): RsaKey
    {
        return self::privateKey()
            ->toPublic()
        ;
    }

    /**
     * A 2048 bit key whose public exponent is 3, the smallest value RFC 8017 section 3.1 allows. Signatures produced
     * with it must keep verifying: only exponents below that bound, or even ones, are degenerate.
     */
    public static function smallestExponentPrivateKey(): RsaKey
    {
        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                '3rfK94jUFBdimyYMrEVtMLMJkK0tP612oEEbAVcM40WkFtL7IBKLdNKu/BkFRflz2piKaIcF8SrVks19bLD2U84EbgzPsyhxb55s' .
                'eLJSQkUSp/+JtyZaY3qWPOsjzKqPum5TE0F20J51cmRtY0bTp5ZbMYwGRR1CR96W3+HJ3UTznXc+cAZ6jHhK5Kxtm24Do1paUlT2' .
                '0ZHgyjSuR1J/rN2aklAQiBcmLbwLY98+QQyYapJOoP771cM7VaVsP8UiFeJT/r/cYAu6ToDyImFcI4JgJ2MHw1tnsitgqiD1cSUD' .
                'WfqIqYrxU0wARcmwNiLUKWJtm1TikaV8oO/4IxU9/Q==',
                true
            ),
            RsaKey::DATA_E => base64_decode('Aw==', true),
            RsaKey::DATA_D => base64_decode(
                'lHqHT7CNYrpBvMQIctjzdcyxCx4eKnOkatYSAOSzQi5tZIynarcHozcfUrtY2VD35xBcRa9ZS3HjtzOo8yCkN96tnrM1Ihr2Smmd' .
                'pcw21ti3Gqpbz27m7PxkKJzCiHG1JvQ3YiukixROTELzl4SNGmQ8y7Ku2L4sL+m56paGk4IORl0HlIq778v1gdSnYy8cBGIzm9DY' .
                '6bxo4M/hGTgvXBplXL4sw+tfGw0iVS6qCrUh44tW2/b+aOnB+2bd8QN90jNuPD3r++kYmuEPPCRbt1Ixn6+uW6BdXQss0+6Wi0Ue' .
                'a8gPrPHmb5m/jwWcP4wuJ4nSJYDjLlmtNJG2T+6uaw==',
                true
            ),
            RsaKey::DATA_P => base64_decode(
                '+3+kAQA0+F+jVbVXbrkUq5ss6rwTMUhJ4+O74mFRNeIBAVI23R61HrxHgUP/PvH+JTOk4EpsnVnbU0cE78wyn8pPDQFBJ+hocPTB' .
                '3oc1lRzbIMGmKmzK/UgS76vQ1lH1QINyOz9J45o0VBS9IUh4cV3W0La2Rg6OHluq2l8OMEk=',
                true
            ),
            RsaKey::DATA_Q => base64_decode(
                '4rRHshEBaEUjBOyWA82SrgGaIiyIgCqtX5VA+kAtAsC1ATT78EOA+Mjg1qAaAD7+wGGcbAyf4N6JRRWGL4oNRZBGIaMh0n3FpHFt' .
                'fMD1PXOr9PY1V80f3l6HrcBqPU5IFTTcNebWNBGxDNqEJI5YHZA84axdR72Q2nZqjEwhCBU=',
                true
            ),
            RsaKey::DATA_DP => base64_decode(
                'p6ptVgAjUD/COSOPnyYNx7zInH1iINrb7UJ9QZY2I+wAq4wkk2nOFH2FANf/f0v+w3fDQDGdvjvnjNoDSoghv9w0s1Yrb/BFoKMr' .
                '6a95DhM8wIEZcZ3cqNq3SnKLOYv41az20ioxQmbNjWMowNr69j6PNc8kLrRevufHPD9eyts=',
                true
            ),
            RsaKey::DATA_DQ => base64_decode(
                'lyLadrYA8C4XWJ25V95hyVZmwXMFqsceP7jV/CrIrIB4q3in9YJV+zCV5Gq8ACn/Kuu9nV2/6z8GLg5ZdQazg7WEFmzBNv6DwvZI' .
                '/dX406Jyo07OOoi/6ZRac9WcKN7auM3oI+85eAvLXecCwwmQE7V968g+L9O15vmcXYgWBWM=',
                true
            ),
            RsaKey::DATA_QI => base64_decode(
                '7TlBflaHlS3613bcy5vnFvTeYbZ+wChtZfGsFqdprZPerR/070hyKgK/4W+Qn1/s5Xqf36BC84LDL1e/YvmsaB5a/GJBIGwlBdDp' .
                'icvLSocbBpFAAJneBzf6gz//jYsjz/GkcoQyDhFudtzT5aq0Qrsuh6AX9KInvsd0I8KIGfA=',
                true
            ),
        ]);
    }

    /**
     * The same key reduced to the first private key representation of RFC 8017 section 3.2: (n, e, d).
     */
    public static function privateKeyWithoutCrtParameters(): RsaKey
    {
        $data = self::privateKey()
            ->getData()
        ;
        foreach ([RsaKey::DATA_P, RsaKey::DATA_Q, RsaKey::DATA_DP, RsaKey::DATA_DQ, RsaKey::DATA_QI] as $parameter) {
            unset($data[$parameter]);
        }

        return RsaKey::create($data);
    }

    /**
     * The same key with a modulus carrying the leading zero octet a DER INTEGER would add. The key is still 2048 bits
     * long; only its encoding is not minimal.
     */
    public static function privateKeyWithPaddedModulus(): RsaKey
    {
        $data = self::privateKey()
            ->getData()
        ;
        $data[RsaKey::DATA_N] = "\x00" . $data[RsaKey::DATA_N];

        return RsaKey::create($data);
    }

    /**
     * A 2050 bit key: its modulus is not byte aligned, so EMSA-PSS has to clear six leftmost bits.
     */
    public static function nonByteAlignedPrivateKey(): RsaKey
    {
        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                'AwF33jtlGCN7zLPIbbb5yVKwsEyTYSFbNAbRAUbpqlE/IjIxUvKGQCzQUZX3zeuIJ1Rdkm15f9RuWfu54Q2JkOA69m5ODb2g' .
                'AgPFtOXVYOss6l1/Z6wDcdPql5bC5SNEfkIENjAMuloVMf+ax3tpQY4MjyOxnOAieXmkSS0e/1Q/a3nAdfy1QAUCSZl3G7YN' .
                'ybB0KnIFpxsO7Xux3DVAz2z3MtnH/dB3vTLz6EgYjZsyjAT3Wfd10up7bQ0qN+xfypfwmjBlHiwIZONgfMevT0q2DqOH/2Wu' .
                '1ArTaz5OHs4+2HQGkQdz3nKBOty0Zlxl0ZaiP+H9iP6fUHdRqQRzDuU=',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
            RsaKey::DATA_D => base64_decode(
                'XF9C9vdiZ/QXNWf0v9gJspsSdwbkTKhRvRW/JP+tGhbNqJ/iOMokDx0tBida+ZD9Q7P9/ZVt4pcix0TfvwvKMBjz93b4UFDS' .
                'nRhRaJvuiBz6v6GpVO2O7yVE8GzSLCMvUwaFaMxGXMUZnPk8RFT08TQRxPOwBPouggtWW4vSlA6jj+HtKpGNMfR1r01x38zL' .
                'QANpH8jjlmeL/5CGQwDpeGNMe39GtNbK32EhXhPB9Y+3n2vnrLj1KDxQHOUKaUhv8cR0bDEXPje3JCpWBs1QXr2blEFl3rZF' .
                'lcyTMRBQedmDHbbatVgt00mljpSJUbtuyKjsDzY8GsebQVWPx6EOKw==',
                true
            ),
            RsaKey::DATA_P => base64_decode(
                'AfgMVIlGBKXEAvxoCgaPe2QV3b2E2C3oKHufH6CdUIjoeQDds2aQqSyCbIoGd7ibn5HnDqMzArFhUlNF8FrXTueTQ0v4aKMQ' .
                '7pRtJwxGJAQxbjL6oekbQ+8jJeKyc7Bj2wotFoEuUDg21a/Xtz710RNbjoHwtS4xObETwiCChdFf',
                true
            ),
            RsaKey::DATA_Q => base64_decode(
                'AYbNvLecOobHdZeeCW0pFpGBUN57INYSVzIAFjM2vTkFOXYDkn5abHxph1wzHKAMEDaeUrCphPuGJtPxZDgl8Tw7vHI8CXMj' .
                '2uvQjZyG1j29YA59cZwi0CVH7Dx3PVktuK9Gwn5gX+wUN7F5HgWAr3DVe+ArSjtN3rs6Vv4+UPI7',
                true
            ),
            RsaKey::DATA_DP => base64_decode(
                'AWBxNrcZx2wlR7U4BjKaJzxPcdHvzr0ixRPTqujCtypT6zAo1SWVZ0VhGQXWCeaCoqwBdSG2LF7dXxQtJihOvrR8KyU21+uV' .
                'jk0omZIihVKNQbHRwF7fmrvexsHh57Thzaoq5r6DJMJ5zSb8XfxfI8c2UMoZBob7Eoz39NiIi4tf',
                true
            ),
            RsaKey::DATA_DQ => base64_decode(
                'cQTEw/DZeCrs1gktPrV4QmI8ierf5yjssJgX033MIVZidL+5uPLblutJ6x8Y8ywp8DG/RjnwLHFyfy67RgWrCzlXWU4FiZff' .
                '8vygR5kzEi3XPrmGhpoGyhFPv3jYdBbl50K2cqfadcKvDJMzXHIHysDij0TVteriNBE+IU7SSAs=',
                true
            ),
            RsaKey::DATA_QI => base64_decode(
                'Ae7QEeQChIcK5DgrPishwcVd+jnylR0GDGL00Rb+ZW0V0nB/Q2yUmATYluGT7MEeqUlJ+IIOrkQ7HhUb0oWKB82J6hvXnVaH' .
                '3p/TbUMMmLxqsDOQnpU1wHGb76EeAYCm5gD8nPK56Tq8nabTD+PWb3lC4Gl+ChC3R6ROsx5a9T+E',
                true
            ),
        ]);
    }

    /**
     * A 2048 bit key with three primes, as modelled by RFC 8230 section 4.
     */
    public static function multiPrimePrivateKey(): RsaKey
    {
        $data = [
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                'pC2wVYlRpd5B5jgOy4vxVHp0I4Q+lwRoxP93qbiFLuMHXYRPMyYdD6iduB3JV2b8tRXrgq6B5++o7KFsxafkCKmeqeiDwtNC' .
                'hynJiIOHh1nhb5Gm8AyADsMRi/cwsZXG7TYmXNl2qB/O5XrCNdsS4jwh3VFujdowFVCtD2z+Zo3kEAXhsuu7Gdf0X5IZG41b' .
                '4npu1x6LfQLEDXKFJhtu0SnCgi76KbPi9+eTH9W0jZy82UKAR74KGuSy8/KBrYVmgQi4hnoXIogtPatXghhLIImvWc5irf+A' .
                'vHGDrSNeP30j4MePcLjxtguDOeQ0zbwQFbeIJdkHKC1e3y3Yoommdw==',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
            RsaKey::DATA_D => base64_decode(
                'dtxZGGQ1R2e0wA7/rx+e1XFeGcSJZ94aV904bhiX240j7PF4QWiri4WgwgZWmT+HXzcCbXcXt6pL2x03WZYmQptCsnISyn8W' .
                'YDLBpGLNQRGyY4rIlyx/542p62VDjVv+R7SIKKefdegLdYSl8oIfqE8CT4CpI0BB3hps8yngzShVy+Cq6aY9wkzVzgVnuo27' .
                'r0FxsjDkc9tpIEnn0YuajRUGuPGMlzc2yraMEruGa9B8StQpPC9aweVZbyZ0y7nf5B2YS50Dma25E/5FzgWrHLCHo6nhTvam' .
                '+E9fFI68tTdsrNh7ukD5FEG2vpXOAMJfbPfK5ulyMkkmeuwaB4qwgQ==',
                true
            ),
            RsaKey::DATA_P => base64_decode(
                'tNHgR1Wfjg/oP3Lr0shAFJokR0b7aFKtWNjkXCMgEqy348dGwgB9GgxN9gnQZ1WLZNzoz/vCsfChKtPksmJKyDUNP0+v/THZ' .
                '0TFCG+45MT2pUxUNXz0=',
                true
            ),
            RsaKey::DATA_Q => base64_decode(
                'AfnwTwluDoPVXqPOdoFJEh9HWzDmXOMedVyLNrOlKV9kG6oWL3La/4w2EMJC6T7RsMWraU52+5y4QMDteWIm16w/3tDFK0fj' .
                'guiOoKbQqO0uQttLnpM=',
                true
            ),
            RsaKey::DATA_DP => base64_decode(
                'iKZz0HUs97ed1RWMkuczRl6XPCawqM6SoqqHKfqBqptM/Z8EImksIhtab65LCUzk43zvlP62zLMFmdA47XbK/TLaqBYY8khS' .
                'TH3lcCZAoq3u4RLv4CE=',
                true
            ),
            RsaKey::DATA_DQ => base64_decode(
                'Abau2Ekr5WgIBTRxW62EJzN50qcWxymjCk4A46Bmr/XnPll/PQsQuo3ffy6Bh+6RMP5kPz3qywY7eOIPxrUFSvIuu0s3+uwt' .
                'aB+vM7sQp7hn6U5uRgM=',
                true
            ),
            RsaKey::DATA_QI => base64_decode(
                'dccbWUhgh6J2DAVLNMtz100+ipVgN/MOZWzjojFrzeQfW46bAT9acv5w9ML2TnrFTIuYhAeksGS5bXJ3nu6qoZut7IBLju1S' .
                'AzS59ZL+m1dkAPrfPns=',
                true
            ),
            RsaKey::DATA_OTHER => [[
                RsaKey::DATA_RI => base64_decode(
                    'dZy1uIISM4KqwEqHqiLYcqVoMMekMlcBajur7wPACz5ufias+9lV9frMSHSKpoCf4iGnNKXm05eR2rH3cWUqzBH8qMD1CuZ0' .
                '1rvt0M3xFAnOURSQEQ==',
                    true
                ),
                RsaKey::DATA_DI => base64_decode(
                    'FMCuH/xzkbtAveVowtCbOL+O/ux7QJaxnTkiQW57+H/vpzrT0yyqSlkSqsZFoNOZYqFli5iqfjOEfP5iFxQu1Qtnda92jZHU' .
                'k/9dGzb7jvmb+hqSwQ==',
                    true
                ),
                RsaKey::DATA_TI => base64_decode(
                    'EbLEwojeaVH7lY0BtAm0bmeyRKoULSwsU1WgXi+pw5B1qgfuSruR7pf95rxYQtDs9QWFuWCRQFPjBwKrnGXNBx5V5o/eNdro' .
                'CTAI+34R2eh66QQcaA==',
                    true
                ),
            ]],
        ];

        return RsaKey::create($data);
    }

    /**
     * A 1040 bit key: the smallest modulus PS512 can encode (emLen == hLen + sLen + 2). Far below the RFC 8230
     * section 6.1 minimum, and only used to exercise that boundary.
     */
    public static function shortPrivateKey(): RsaKey
    {
        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                '91p/phyrbdrrG182PL+5Jzg9GuEq06WImXrmLBBKv+fD3HQIUBD1iGMKij6BERM3Crm8KWEoxlx0GTyHndwFigdPaZ9Zwtrn' .
                'S8ipMpj/aLcP+i5xe0yLFQ1sA3TIs2XRWesfCx4sTeJ9ThD9Q5Zf/iwcFZD9bef0uGAYP/GhTm5wzQ==',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
            RsaKey::DATA_D => base64_decode(
                'GFn8fyoLZoFK7CLvgAOQAuByg5bvVG7Th+iliGkCMupqSeXSe69vvMGjZADLTBcMMC4g7CH4la68b0+aOlxS30evaQrGLV3a' .
                'HLMm3p+wywtIgo42Y0hObs65XGn7LXS6yKfVlyjgZICDC55Tzu5+stdQZVask+oPB35kjN9Y6iXGAQ==',
                true
            ),
            RsaKey::DATA_P => base64_decode('/eckwW8Sof6YRmt87BD3c8i5uiQ7Hhf/iLyV/maVrNmQY/R8C9NFWBE1hbWnY4d3Zkv9J0wG/+pC4cgmDDyS0aE=', true),
            RsaKey::DATA_Q => base64_decode('+WWBxJoXAwSbsPObESvIW13Jbh2CCsgoYsFrvcjFBflYvLcmglk/rtWkGYxBStBMJnIqN8uYJmt/nIxF4I5/Z60=', true),
            RsaKey::DATA_DP => base64_decode('B1J9Kt7rKKTQ+2bqKVyr5jjpskaNNeb3RZg6syV+N4fmtBs+4JBtNYb5hiug8ivb86VJXbLBmOvGlgBRqJSun0E=', true),
            RsaKey::DATA_DQ => base64_decode('rFJB5vldex1dAlhgRe4No2vbOXW0HAUPOqVQ77JgyG7wrHyUZC6MvR4rI+fwWWQxqcLqfuDzQWC3rRCTW8S6LYU=', true),
            RsaKey::DATA_QI => base64_decode('7V0Y0KbokK3DJDR0/bX4T30Jdp/izDqRodUuoFUuC32E91NASWmX69LvxIEaTUufFfseeDkKZsDt86bJd+jVbCw=', true),
        ]);
    }

    /**
     * A 1032 bit key: one octet below what PS512 can encode.
     */
    public static function tooShortPrivateKey(): RsaKey
    {
        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => base64_decode(
                'pYAL5CbIyjdpyYlvdloijtpngb9PHLASgg4nLWRThi7wCXxaAetrSX1qS2vtavYaYko5t3SPyxsvlJJw8WOye+aj2Y9RbONi' .
                'VTC05qrFXeJO1AjtXOJWusvy67e3yA0oE6Nvjd9jVctYzUpF68nna/4HlyL3ZG2e6+jKtxJLQm6h',
                true
            ),
            RsaKey::DATA_E => base64_decode('AQAB', true),
            RsaKey::DATA_D => base64_decode(
                'TPfrD9VVxm3U/gyz0NgEgGlkf/wH//CG+wM4By1EhwAnVFIHziK9h7UTDTaJeRgxlwqsIvzLrwraqv8cFbdnF5pjw/i3s5T2' .
                'He8wMi+D+vwnJlD/PgE7tPaZxuZOrg9kzAmvCj+oO+IsxK87uekThS4NuBzYM7y4mKqxpXpOxacB',
                true
            ),
            RsaKey::DATA_P => base64_decode('DbIp9Gk1mPiAlkkR60/lfQTIXAVn0nhmkDfrMfEVWaTLckGIpRTxOsW/BT9UZec4KyR/uKSME3LLGbas1ZVdL9E=', true),
            RsaKey::DATA_Q => base64_decode('DBV41o2Ad7I3RC9t186MXAg71dj9Zf8eMtIyTddCG+ZL/i/6Xr8UqNNv3l3xLhUhk2o7ze+Pt2SAIRgWQ+XuVdE=', true),
            RsaKey::DATA_DP => base64_decode('BIBC7YIODUHN8JX+/5h4UQfbWPKl1jOfcVIPR5B1dcqE2f3TjH0/chM+3dicQgklGniaSPI63sFhIgg48NBvmaE=', true),
            RsaKey::DATA_DQ => base64_decode('C+ff/iy+5bAeybydUiK8ojSul51K1YLOAy6cx5sOFKUMPK6S1WUY+toP/5y5czj4suDZeabOB9gqcfDkhxN1hvE=', true),
            RsaKey::DATA_QI => base64_decode('A042Nryl4pq/C53imTBKSNsnys6JW95kudsevvSwXT3DN0ZVcnGGpVQ6/FRbzApn43ebSTgDqoQyLMycaKJPA0Q=', true),
        ]);
    }
}
