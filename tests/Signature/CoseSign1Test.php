<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Cose\Signature\CoseSign1Tag;
use Cose\Signature\Signature1;
use PHPUnit\Framework\TestCase;
use function Safe\base64_decode;
use function Safe\openssl_verify;

final class CoseSign1Test extends TestCase
{
    /**
     * @test
     */
    public function theCovidVaccinationPassCanBeLoaded(): CoseSign1Tag
    {
        //Given
        $data = '0oRDoQEmoQRIf1sfUVIx8CBZAQ2kAWJERQQaYqh/zQYaYMdMTTkBA6EBpGF2gapiY2l4L1VSTjpVVkNJOjAxREUvSVoxMjM0NUEvMjFFMEpYRDdVUVk2RUNMTTNXVDdZRiM4YmNvYkRFYmRuAmJkdGoyMDIxLTA0LTAxYmlzdFJvYmVydCBLb2NoLUluc3RpdHV0Ym1hbU9SRy0xMDAwMzExODRibXBsRVUvMS8yMC8xNTA3YnNkAmJ0Z2k4NDA1MzkwMDZidnBqMTExOTM0OTAwN2Nkb2JqMTk2NC0wOC0xMmNuYW2kYmZuak11c3Rlcm1hbm5iZ25lRXJpa2FjZm50ak1VU1RFUk1BTk5jZ250ZUVSSUtBY3ZlcmUxLjAuMFhASoTSiWEI6NFgZVdxvtjgF9walgd6rmesxFMtVFxtseYIXm2N/YBp53na69PZcT/+xmpjtQNFOYWtmaCWxjiUYw==';

        $stream = new StringStream(base64_decode($data, true));
        $decoder = $this->getDecoder();

        //When
        $cbor = $decoder->decode($stream); //We decode the data

        //Then
        static::assertInstanceOf(CoseSign1Tag::class, $cbor, 'Invalid object');

        return $cbor;
    }

    /**
     * @test
     * @depends theCovidVaccinationPassCanBeLoaded
     */
    public function theCovidVaccinationPassCanBeVerified(CoseSign1Tag $cbor): void
    {
        //Given
        $structure = Signature1::create($cbor->getProtectedHeader(), $cbor->getPayload());
        $derSignature = ECSignature::toAsn1($cbor->getSignature()->normalize(), 64);

        //When
        $isValid = openssl_verify((string) $structure, $derSignature, $this->getCertificate(), 'sha256');

        //Then
        static::assertSame(1, $isValid, 'Invalid signature');
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()
            ->add(CoseSign1Tag::class)
        ;
        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }

    private function getCertificate(): string
    {
        return <<<'CODE_SAMPLE'
-----BEGIN CERTIFICATE-----
MIIGXjCCBBagAwIBAgIQQ50Ye2SIZLH9KhoLQeBFLjA9BgkqhkiG9w0BAQowMKAN
MAsGCWCGSAFlAwQCA6EaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgOiAwIBQDBg
MQswCQYDVQQGEwJERTEVMBMGA1UEChMMRC1UcnVzdCBHbWJIMSEwHwYDVQQDExhE
LVRSVVNUIFRlc3QgQ0EgMi0yIDIwMTkxFzAVBgNVBGETDk5UUkRFLUhSQjc0MzQ2
MB4XDTIxMDUwNjE5MjEzMFoXDTIyMDUwOTE5MjEzMFowfjELMAkGA1UEBhMCREUx
FDASBgNVBAoTC1ViaXJjaCBHbWJIMRQwEgYDVQQDEwtVYmlyY2ggR21iSDEOMAwG
A1UEBwwFS8O2bG4xHDAaBgNVBGETE0RUOkRFLVVHTk9UUFJPVklERUQxFTATBgNV
BAUTDENTTTAxNzI0OTU3MzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBAvcrr3
ib8nS7E6vmdWJ6k7d6rqBHlD0U41OdMP2dJf9xqec4uOlwfJdOriwncgcWRpmli7
vbFVP9w9dxX++ESjggJfMIICWzAfBgNVHSMEGDAWgBRQdpKgGuyBrpHC3agJUmg3
3lGETzAtBggrBgEFBQcBAwQhMB8wCAYGBACORgEBMBMGBgQAjkYBBjAJBgcEAI5G
AQYCMIH+BggrBgEFBQcBAQSB8TCB7jArBggrBgEFBQcwAYYfaHR0cDovL3N0YWdp
bmcub2NzcC5kLXRydXN0Lm5ldDBHBggrBgEFBQcwAoY7aHR0cDovL3d3dy5kLXRy
dXN0Lm5ldC9jZ2ktYmluL0QtVFJVU1RfVGVzdF9DQV8yLTJfMjAxOS5jcnQwdgYI
KwYBBQUHMAKGamxkYXA6Ly9kaXJlY3RvcnkuZC10cnVzdC5uZXQvQ049RC1UUlVT
VCUyMFRlc3QlMjBDQSUyMDItMiUyMDIwMTksTz1ELVRydXN0JTIwR21iSCxDPURF
P2NBQ2VydGlmaWNhdGU/YmFzZT8wFwYDVR0gBBAwDjAMBgorBgEEAaU0AgICMIG/
BgNVHR8EgbcwgbQwgbGgga6ggauGcGxkYXA6Ly9kaXJlY3RvcnkuZC10cnVzdC5u
ZXQvQ049RC1UUlVTVCUyMFRlc3QlMjBDQSUyMDItMiUyMDIwMTksTz1ELVRydXN0
JTIwR21iSCxDPURFP2NlcnRpZmljYXRlcmV2b2NhdGlvbmxpc3SGN2h0dHA6Ly9j
cmwuZC10cnVzdC5uZXQvY3JsL2QtdHJ1c3RfdGVzdF9jYV8yLTJfMjAxOS5jcmww
HQYDVR0OBBYEFHgZ4+qwUzVKynAvnUl5YL6XWUK9MA4GA1UdDwEB/wQEAwIGwDA9
BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCA6EaMBgGCSqGSIb3DQEBCDALBglg
hkgBZQMEAgOiAwIBQAOCAgEAHNnaBolwPHWiEZ6QKD6iIFFQhEiYzWvQxxvas1NQ
Sd/Xhw1Bth81aG5HRV1GCciD7Pa0yRl3wN3Dlixw2zdaU76kJlwYoXBbP6c0BQxV
lMFgWPEmG4Gt4+CrmcJ7EsrtYHeCZ7WiOuV1PJ2Pdb1Rsj1sxAhJxkv3I4eQrwlu
b3qHbQaT6uXV9X2V3qyqKPi0X12vzr9c0ca8D5GDD4+PgdGTraGU029YVeEKLe+F
qEgYVsEo0l9eSzNLp8HYuHr++5OU63pSBpTJmW7gI39VHkiEwZE87RkbuVQvFYcT
5rmqM9TIgcJVtHoUozhsitoMjL7zlx5aFTHMxnqSh7D7H0kwXgYM/wM8TQ++AV2v
gRK5q0mGp2MJPWuWRjtWrjxth71dF+pQr3Ls6hJXg1yMweVLzkd8mIzTnmtgtwP2
pFgrSP1zW1B8ThBtb7ldXfcenP7qlOG/JyldLxy2hJjYgRST1TCPQMfeJ3yF/ONo
fxPMAefqfoadzm7BFPHBNOkaJIZ09+QJqZAS+pIoYFImrswjiykn5ZruspEYj0Tc
P5wzV01e+KTaHweT3Ii+j7ZJcUha+9OosmkhTc02g2BxzliB+PmexyY9JZkXPA8V
xF/0c/gGysbrPQtz3n09XfX/JX9Hh0cMPs4YZHk5xUpLsrKPivSCR1wJC7tCvC6J
1Xk=
-----END CERTIFICATE-----
CODE_SAMPLE;
    }
}
