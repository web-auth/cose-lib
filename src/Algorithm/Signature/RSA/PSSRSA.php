<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

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
use function ord;
use function pack;
use function random_bytes;
use RuntimeException;
use function str_pad;
use const STR_PAD_LEFT;
use function str_repeat;
use function strlen;

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
        $modBits = RsaKeyValidator::modulusLength($key);
        $k = intdiv($modBits + 7, 8);
        if (strlen($signature) !== $k) {
            throw new InvalidArgumentException('Invalid signature length');
        }
        $m = $this->rsavp1($key, BigInteger::createFromBinaryString($signature));
        // RFC 8017, section 8.1.2, step 2.c: emLen = ceil((modBits - 1) / 8).
        $emLen = intdiv($modBits - 1 + 7, 8);
        $em = $this->convertIntegerToOctetString($m, $emLen);

        return $this->verifyEMSAPSS($data, $em, $modBits - 1, $this->getHashAlgorithm());
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem. Operation with primes 'p' and 'q' is appox. 2x faster.
     *
     * The operation is selected from the key: RSASP1 (RFC 8017, section 5.2.1) for a private key, RSAVP1 (section
     * 5.2.2) for a public one.
     */
    public function exponentiate(RsaKey $key, BigInteger $c): BigInteger
    {
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
        $signature = $key->hasPrimes() && $key->hasExponents() && $key->hasCoefficient()
            ? $this->rsasp1WithCrt($key, $m)
            // RFC 8017, section 5.2.1, step 2.a: first form (n, d).
            : $m->modPow(BigInteger::createFromBinaryString($key->d()), $n);

        // A wrong CRT result must never leave this class: it would be a silently invalid signature and, on faulty
        // hardware, a private key recovery oracle. OpenSSL applies the very same check.
        if ($signature->modPow(BigInteger::createFromBinaryString($key->e()), $n)->compare($m) !== 0) {
            throw new RuntimeException(
                'Inconsistent RSA private key: the CRT parameters do not describe the modulus'
            );
        }

        return $signature;
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
        if ($emLen < $hLen + $sLen + 2) {
            throw new InvalidArgumentException(
                'Inconsistent signature: the modulus is too short for this hash and salt length'
            );
        }
        if ($em[strlen($em) - 1] !== chr(0xBC)) {
            throw new InvalidArgumentException('Inconsistent signature: the trailer field is not 0xBC');
        }
        $maskedDB = substr($em, 0, -$hLen - 1);
        $h = substr($em, -$hLen - 1, $hLen);
        $mask = $this->leftmostBitsMask($emBits);
        if (($maskedDB[0] & $mask) !== chr(0)) {
            throw new InvalidArgumentException(
                'Inconsistent signature: the leftmost bits of maskedDB are not zero'
            );
        }
        $dbMask = $this->getMGF1($h, $emLen - $hLen - 1, $hash/* MGF */);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~$mask & $db[0];
        $temp = $emLen - $hLen - $sLen - 2;
        if (! str_starts_with($db, str_repeat(chr(0), $temp))) {
            throw new InvalidArgumentException('Inconsistent signature: the padding string is not zero');
        }
        if (ord($db[$temp]) !== 1) {
            throw new InvalidArgumentException('Inconsistent signature: the separator octet is not 0x01');
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h2 = $hash->hash($m2);

        return hash_equals($h, $h2);
    }
}
