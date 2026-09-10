<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use Brick\Math\Exception\MathException;
use function chr;
use Cose\Algorithm\Signature\Signature;
use Cose\BigInteger;
use Cose\Hash;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use function hash_equals;
use function intdiv;
use InvalidArgumentException;
use function is_string;
use function openssl_error_string;
use const OPENSSL_NO_PADDING;
use function openssl_private_encrypt;
use function ord;
use function pack;
use function random_bytes;
use RuntimeException;
use function str_pad;
use const STR_PAD_LEFT;
use function str_repeat;
use function strlen;
use Throwable;

/**
 * RSASSA-PSS as defined by RFC 8017, section 8.1.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8017#section-8.1
 *
 * @internal
 */
abstract class PSSRSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key);
        RsaKeyValidator::checkPublicParameters($key);
        if (! $key->isPrivate()) {
            throw new InvalidArgumentException('The key is not private.');
        }
        // RFC 8017, section 3.1: modBits is the length in bits of the modulus and k its length in octets. Both are
        // derived from the integer value of n, not from the number of octets used to encode it.
        $modBits = RsaKeyValidator::modulusLength($key);
        $k = intdiv($modBits + 7, 8);

        // RFC 8017, section 8.1.1, steps 1 and 2.
        $em = $this->encodeEMSAPSS($data, $modBits - 1, $this->getHashAlgorithm());
        $signature = $this->rsasp1($key, BigInteger::createFromBinaryString($em));

        return $this->convertIntegerToOctetString($signature, $k);
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        // RFC 8017, section 8.1.2: the verification operation uses the public key (n, e) only.
        $key = $this->handleKey($key)
            ->toPublic();
        try {
            // Section 8.1.2 applies RSAVP1 under the assumption that the public key is valid (section 3.1). Nothing
            // downstream re-establishes it, and with e = 1 the exponentiation below is the identity map: the EMSA-PSS
            // encoding of any message, which anyone can build, would then be accepted as its signature. A key that
            // cannot be verified with is reported as an invalid signature, per the contract of Signature::verify().
            RsaKeyValidator::checkPublicParameters($key);
        } catch (InvalidArgumentException) {
            return false;
        }
        $modBits = RsaKeyValidator::modulusLength($key);
        $k = intdiv($modBits + 7, 8);
        // RFC 8017, section 8.1.2, step 1: "If the length of the signature S is not k octets, output 'invalid
        // signature' and stop."
        if (strlen($signature) !== $k) {
            return false;
        }
        $s = BigInteger::createFromBinaryString($signature);
        // Step 2.b: "If RSAVP1 output 'signature representative out of range', output 'invalid signature' and stop."
        if ($s->compare(BigInteger::createFromBinaryString($key->n())) >= 0) {
            return false;
        }
        $m = $this->rsavp1($key, $s);
        // RFC 8017, section 8.1.2, step 2.c: emLen = ceil((modBits - 1) / 8). "If I2OSP outputs 'integer too large',
        // output 'invalid signature' and stop."
        $emLen = intdiv($modBits - 1 + 7, 8);
        if (strlen($m->toBytes()) > $emLen) {
            return false;
        }
        $em = $this->convertIntegerToOctetString($m, $emLen);

        return $this->verifyEMSAPSS($data, $em, $modBits - 1, $this->getHashAlgorithm());
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem. Operation with primes 'p' and 'q' is appox. 2x faster.
     *
     * The operation is selected from the key: RSASP1 (RFC 8017, section 5.2.1) for a private key, RSAVP1 (section
     * 5.2.2) for a public one.
     *
     * @throws InvalidArgumentException when the public parameters of the key are not those of a valid RSA key
     */
    public function exponentiate(RsaKey $key, BigInteger $c): BigInteger
    {
        RsaKeyValidator::checkPublicParameters($key);

        return $key->isPrivate() ? $this->rsasp1($key, $c) : $this->rsavp1($key, $c);
    }

    abstract protected function getHashAlgorithm(): Hash;

    private function handleKey(Key $key): RsaKey
    {
        return RsaKey::create($key->getData());
    }

    /**
     * RSAVP1 (RFC 8017, section 5.2.2).
     */
    private function rsavp1(RsaKey $key, BigInteger $s): BigInteger
    {
        $n = BigInteger::createFromBinaryString($key->n());
        if ($s->compare(BigInteger::createFromDecimal(0)) < 0 || $s->compare($n) >= 0) {
            throw new RuntimeException('Signature representative out of range');
        }

        return $s->modPow(BigInteger::createFromBinaryString($key->e()), $n);
    }

    /**
     * RSASP1 (RFC 8017, section 5.2.1).
     */
    private function rsasp1(RsaKey $key, BigInteger $m): BigInteger
    {
        $n = BigInteger::createFromBinaryString($key->n());
        if ($m->compare(BigInteger::createFromDecimal(0)) < 0 || $m->compare($n) >= 0) {
            throw new RuntimeException('Message representative out of range');
        }
        $e = BigInteger::createFromBinaryString($key->e());
        $hasCrtParameters = $key->hasPrimes() && $key->hasExponents() && $key->hasCoefficient();

        if ($hasCrtParameters && ! $key->has(RsaKey::DATA_OTHER)) {
            // A two-prime key with a complete CRT quintuple is the only shape RsaKey::asPem() can express, and the
            // only one OpenSSL can therefore compute. Its exponentiation is blinded and runs in constant time, which
            // neither gmp_powm() nor bcpowmod() nor the native brick/math loop does.
            $this->checkCrtParameters($key, $n);
            $signature = $this->rsasp1WithOpenSSL($key, $m);
        } else {
            // Multi-prime keys (RFC 8230, section 4) and (n, e, d) keys have no PEM representation, so they keep the
            // in-process exponentiation. Blinding the base hides it from an attacker timing the operation or watching
            // the cache while it runs; it does not make the exponentiation itself constant-time.
            [$blindingFactor, $unblindingFactor] = $this->blindingFactors($n, $e);
            $blinded = $m->multiply($blindingFactor)
                ->mod($n)
            ;
            $signature = $hasCrtParameters
                ? $this->rsasp1WithCrt($key, $blinded)
                // RFC 8017, section 5.2.1, step 2.a: first form (n, d).
                : $blinded->modPow(BigInteger::createFromBinaryString($key->d()), $n);
            $signature = $signature->multiply($unblindingFactor)
                ->mod($n)
            ;
        }

        // A wrong CRT result must never leave this class: it would be a silently invalid signature and, on faulty
        // hardware, a private key recovery oracle. OpenSSL applies the very same check.
        if ($signature->modPow($e, $n)->compare($m) !== 0) {
            throw new RuntimeException(
                'Inconsistent RSA private key: the CRT parameters do not describe the modulus'
            );
        }

        return $signature;
    }

    /**
     * RSASP1 computed by OpenSSL: base blinding and BN_mod_exp_mont_consttime on the private exponent, plus its own
     * check of the CRT result against the public operation.
     */
    private function rsasp1WithOpenSSL(RsaKey $key, BigInteger $m): BigInteger
    {
        $k = intdiv(RsaKeyValidator::modulusLength($key) + 7, 8);

        try {
            $computed = openssl_private_encrypt(
                $this->convertIntegerToOctetString($m, $k),
                $signature,
                $key->asPem(),
                OPENSSL_NO_PADDING
            );
        } catch (Throwable $throwable) {
            $this->clearOpenSSLErrors();

            throw new RuntimeException('Unable to compute the RSA signature primitive', 0, $throwable);
        }
        if (! $computed || ! is_string($signature)) {
            $this->clearOpenSSLErrors();

            throw new RuntimeException('Unable to compute the RSA signature primitive');
        }

        return BigInteger::createFromBinaryString($signature);
    }

    /**
     * OpenSSL repairs a key whose CRT parameters do not describe the modulus instead of reporting it, so the
     * consistency of the quintuple is established before the exponentiation rather than after it.
     */
    private function checkCrtParameters(RsaKey $key, BigInteger $n): void
    {
        $one = BigInteger::createFromDecimal(1);
        [$pS, $qS] = $key->primes();
        [$dPS, $dQS] = $key->exponents();
        $p = BigInteger::createFromBinaryString($pS);
        $q = BigInteger::createFromBinaryString($qS);
        $e = BigInteger::createFromBinaryString($key->e());
        // A prime of 0 or 1 would make the reductions below meaningless, and n = p * q rules it out on its own only
        // for the other factor.
        $this->assertCrtParameter($p->compare($one) > 0 && $q->compare($one) > 0);
        $this->assertCrtParameter($this->isEqual($p->multiply($q), $n));
        // e * dP = 1 mod (p - 1), e * dQ = 1 mod (q - 1) and q * qInv = 1 mod p (RFC 8017, section 3.2).
        $this->assertCrtParameter(
            $this->isEqual($e->multiply(BigInteger::createFromBinaryString($dPS))->mod($p->subtract($one)), $one)
        );
        $this->assertCrtParameter(
            $this->isEqual($e->multiply(BigInteger::createFromBinaryString($dQS))->mod($q->subtract($one)), $one)
        );
        $this->assertCrtParameter(
            $this->isEqual($q->multiply(BigInteger::createFromBinaryString($key->QInv()))->mod($p), $one)
        );
    }

    private function assertCrtParameter(bool $isConsistent): void
    {
        if (! $isConsistent) {
            throw new RuntimeException(
                'Inconsistent RSA private key: the CRT parameters do not describe the modulus'
            );
        }
    }

    private function isEqual(BigInteger $left, BigInteger $right): bool
    {
        return $left->compare($right) === 0;
    }

    /**
     * A random r coprime with n, returned as the pair (r^e mod n, r^-1 mod n): multiplying the message representative
     * by the first before the exponentiation and the result by the second after it leaves the signature unchanged,
     * while the value actually exponentiated is unpredictable.
     *
     * @return array{BigInteger, BigInteger}
     */
    private function blindingFactors(BigInteger $n, BigInteger $e): array
    {
        $two = BigInteger::createFromDecimal(2);
        // Eight bytes beyond the modulus keep the bias of the reduction below negligible.
        $length = strlen($n->toBytes()) + 8;
        $upperBound = $n->subtract(BigInteger::createFromDecimal(3));

        while (true) {
            $r = BigInteger::createFromBinaryString(random_bytes($length))
                ->mod($upperBound)
                ->add($two)
            ;

            try {
                // Drawing an r sharing a factor with n means having factored n, so this never loops in practice.
                $unblindingFactor = $r->modInverse($n);
            } catch (MathException) {
                continue;
            }

            return [$r->modPow($e, $n), $unblindingFactor];
        }
    }

    /**
     * RFC 8017, section 5.2.1, step 2.b.
     */
    private function rsasp1WithCrt(RsaKey $key, BigInteger $m): BigInteger
    {
        [$pS, $qS] = $key->primes();
        [$dPS, $dQS] = $key->exponents();
        $p = BigInteger::createFromBinaryString($pS);
        $q = BigInteger::createFromBinaryString($qS);

        // Steps 2.b.1, 2.b.3 and 2.b.4.
        $s1 = $m->modPow(BigInteger::createFromBinaryString($dPS), $p);
        $s2 = $m->modPow(BigInteger::createFromBinaryString($dQS), $q);
        $h = $s1->subtract($s2)
            ->multiply(BigInteger::createFromBinaryString($key->QInv()))
            ->mod($p)
        ;
        $signature = $s2->add($h->multiply($q));
        if (! $key->has(RsaKey::DATA_OTHER)) {
            return $signature;
        }

        // Steps 2.b.2 and 2.b.5, for the third to u-th primes of a multi-prime key (RFC 8230, section 4).
        $r = $p->multiply($q);
        foreach ($key->other() as $primeInfo) {
            $rI = BigInteger::createFromBinaryString($primeInfo[RsaKey::DATA_RI]);
            $sI = $m->modPow(BigInteger::createFromBinaryString($primeInfo[RsaKey::DATA_DI]), $rI);
            $h = $sI->subtract($signature)
                ->multiply(BigInteger::createFromBinaryString($primeInfo[RsaKey::DATA_TI]))
                ->mod($rI)
            ;
            $signature = $signature->add($r->multiply($h));
            $r = $r->multiply($rI);
        }

        return $signature;
    }

    /**
     * Drains the OpenSSL error queue so that a failure here is not reported by an unrelated later call.
     */
    private function clearOpenSSLErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }

    private function convertIntegerToOctetString(BigInteger $x, int $xLen): string
    {
        $xB = $x->toBytes();
        if (strlen($xB) > $xLen) {
            throw new RuntimeException('Unable to convert the integer');
        }

        return str_pad($xB, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * MGF1.
     */
    private function getMGF1(string $mgfSeed, int $maskLen, Hash $mgfHash): string
    {
        $t = '';
        $count = intdiv($maskLen + $mgfHash->getLength() - 1, $mgfHash->getLength());
        for ($i = 0; $i < $count; ++$i) {
            $c = pack('N', $i);
            $t .= $mgfHash->hash($mgfSeed . $c);
        }

        return substr($t, 0, $maskLen);
    }

    /**
     * The mask of the leftmost 8emLen - emBits bits of the leftmost octet of maskedDB (RFC 8017, section 9.1.1, step
     * 11 and section 9.1.2, steps 6 and 9). It is 0x00 when the encoded message is byte aligned and nothing has to be
     * cleared.
     */
    private function leftmostBitsMask(int $emBits): string
    {
        $bitsToClear = 8 * intdiv($emBits + 7, 8) - $emBits;

        return chr((0xFF << (8 - $bitsToClear)) & 0xFF);
    }

    /**
     * EMSA-PSS-ENCODE (RFC 8017, section 9.1.1).
     */
    private function encodeEMSAPSS(string $message, int $emBits, Hash $hash): string
    {
        $emLen = intdiv($emBits + 7, 8);
        $hLen = $hash->getLength();
        $sLen = $hLen;
        $mHash = $hash->hash($message);
        if ($emLen < $hLen + $sLen + 2) {
            throw new RuntimeException(
                'Encoding error: the modulus is too short for this hash and salt length'
            );
        }
        $salt = random_bytes($sLen);
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h = $hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $hLen - 2);
        $db = $ps . chr(1) . $salt;
        $dbMask = $this->getMGF1($h, $emLen - $hLen - 1, $hash);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~$this->leftmostBitsMask($emBits) & $maskedDB[0];

        return $maskedDB . $h . chr(0xBC);
    }

    /**
     * EMSA-PSS-VERIFY (RFC 8017, section 9.1.2).
     */
    private function verifyEMSAPSS(string $m, string $em, int $emBits, Hash $hash): bool
    {
        $emLen = intdiv($emBits + 7, 8);
        $hLen = $hash->getLength();
        $sLen = $hLen;
        $mHash = $hash->hash($m);
        // Every check below is a step whose failure RFC 8017, section 9.1.2 defines as "output 'inconsistent' and
        // stop", i.e. an invalid signature rather than an error.
        // Step 3: the modulus is too short for this hash and salt length.
        if ($emLen < $hLen + $sLen + 2) {
            return false;
        }
        // Step 4: the trailer field is not 0xBC.
        if ($em[strlen($em) - 1] !== chr(0xBC)) {
            return false;
        }
        $maskedDB = substr($em, 0, -$hLen - 1);
        $h = substr($em, -$hLen - 1, $hLen);
        $mask = $this->leftmostBitsMask($emBits);
        // Step 6: the leftmost bits of maskedDB are not zero.
        if (($maskedDB[0] & $mask) !== chr(0)) {
            return false;
        }
        $dbMask = $this->getMGF1($h, $emLen - $hLen - 1, $hash/* MGF */);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~$mask & $db[0];
        $temp = $emLen - $hLen - $sLen - 2;
        // Step 10: the padding string is not zero, or the separator octet is not 0x01.
        if (! str_starts_with($db, str_repeat(chr(0), $temp))) {
            return false;
        }
        if (ord($db[$temp]) !== 1) {
            return false;
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h2 = $hash->hash($m2);

        return hash_equals($h, $h2);
    }
}
