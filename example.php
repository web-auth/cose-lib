<?php

declare(strict_types=1);

require_once 'vendor/autoload.php';

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

// ---------------------------------------------------------------- the key
// A P-256 key pair. OpenSSL strips the leading zero bytes of the coordinates; COSE requires them fixed size.
$details = openssl_pkey_get_details(openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name' => 'prime256v1',
]))['ec'];
$pad = static fn (string $value): string => str_pad($value, 32, "\x00", STR_PAD_LEFT);

$privateKey = Ec2Key::create([
    Ec2Key::TYPE => Ec2Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
    Ec2Key::DATA_X => $pad($details['x']),
    Ec2Key::DATA_Y => $pad($details['y']),
    Ec2Key::DATA_D => $pad($details['d']),
]);
$publicKey = $privateKey->toPublic();
$algorithm = ES256::create();

// ---------------------------------------------------------------- signing
$protectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(1),                       // alg
        NegativeIntegerObject::create(ES256::identifier())      // ES256 (-7)
    ),
]);
$unprotectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(4),                       // kid
        ByteStringObject::create('my-key-id')
    ),
]);
$payload = ByteStringObject::create('Message to sign');

// The signature covers the Sig_structure, never the payload on its own. Encode the protected bucket once, so the
// bytes that are signed are the bytes the message carries.
$protectedHeaderAsBytes = HeaderMapHelper::encodeProtected($protectedHeader);
$toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);
$signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $privateKey));

$coseSign1 = CoseSign1Tag::create(ListObject::create([
    $protectedHeaderAsBytes,
    $unprotectedHeader,
    $payload,
    $signature,
]));

$encoded = (string) $coseSign1;
echo 'COSE_Sign1: ', bin2hex($encoded), PHP_EOL;

// ---------------------------------------------------------------- verifying
// cbor-php 3.4.0 registers the COSE tags in the default decoder, so tag 18 resolves on its own.
$decoded = Decoder::create()->decode(StringStream::create($encoded));
assert($decoded instanceof CoseSign1Tag);

$headers = CoseHeaders::fromMessage($decoded);

// RFC 9052 §3.1: the algorithm the protected header declares has to be the one you accept for that key.
$alg = $headers->getProtectedHeaderParameter(1);
if ($alg === null || (int) $alg->normalize() !== ES256::identifier()) {
    throw new RuntimeException('Unexpected or missing "alg" in the protected header');
}
echo 'kid: ', $headers->getHeaderParameter(4)?->getValue(), PHP_EOL;

$decodedPayload = $decoded->getPayload();
if ($decodedPayload instanceof NullObject) {
    throw new RuntimeException('The payload is detached; supply it from the application');
}

$toBeVerified = Signature1::create($decoded->getProtectedHeader(), $decodedPayload);
$isValid = $algorithm->verify((string) $toBeVerified, $publicKey, $decoded->getSignature()->getValue());

echo 'payload:   ', $decodedPayload->getValue(), PHP_EOL;
echo 'signature: ', $isValid ? 'valid' : 'INVALID', PHP_EOL;
