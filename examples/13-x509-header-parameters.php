<?php

declare(strict_types=1);

/**
 * X.509 certificates in COSE headers (RFC 9360): x5chain, x5bag, x5t and x5u.
 *
 * The certificates are the ones of cose-wg/Examples x509-examples -- Alice's end-entity certificate, issued by a
 * sample CA -- and the key is Alice's, so that what is built here is what the cose-wg signed-03/04/05 fixtures carry.
 *
 * Where the library stops is the point of this example. It reads the parameters and applies their CDDL rules; it
 * verifies a signature with the certificate a chain names; it hands the certificates to spomky-labs/pki-framework.
 * It builds no path, checks no revocation, holds no trust anchor and fetches no URI. RFC 9360 section 5: "both the
 * signature validation and the certificate validation MUST be completed successfully before acting on any requests."
 * The second half is the application's, and its last section below shows it done with pki-framework.
 */

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\CertificateSignatureVerifier;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\CoseX509;
use Cose\Structure\X509\X5Bag;
use Cose\Structure\X509\X5Chain;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9360: X.509 header parameters');

$fixtures = __DIR__ . '/../tests/fixtures/cose-wg/x509-examples';
$read = static function (string $name) use ($fixtures): string {
    $bytes = file_get_contents($fixtures . '/' . $name);
    if ($bytes === false) {
        throw new RuntimeException('Unable to read ' . $name);
    }

    return $bytes;
};
$aliceDer = $read('alice.der');
$caDer = $read('ca.der');

// Alice's key pair, as the cose-wg fixtures give it (x, y, d of signed-05).
$alice = Ec2Key::create([
    Ec2Key::TYPE => Ec2Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
    Ec2Key::DATA_X => hex2bin('863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c'),
    Ec2Key::DATA_Y => hex2bin('ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca'),
    Ec2Key::DATA_D => hex2bin('d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5'),
]);
$algorithm = ES256::create();

// RFC 9360 section 2: SHA-256 MUST be supported for x5t. SHA-1 is registered too: a thumbprint filters, it does not
// vouch, which is the one use RFC 9054 admits SHA-1 for.
$manager = Manager::create()->add($algorithm, SHA256::create(), SHA1::create());
$verifier = CertificateSignatureVerifier::create($manager);

// --- 1. COSE_X509: one certificate is a bstr, two or more an array, one is never an array ---

$one = CoseX509::create($aliceDer)->toCBOR();
$two = CoseX509::create($aliceDer, $caDer)->toCBOR();
example_assert($one instanceof ByteStringObject, 'one certificate encodes as a byte string');
example_assert($two instanceof ListObject && $two->count() === 2, 'two certificates encode as an array of two');

try {
    CoseX509::fromCBOR(ListObject::create([ByteStringObject::create($aliceDer)]), 'x5chain');
    throw new LogicException('unreachable');
} catch (InvalidArgumentException $exception) {
    example_line('rejected', $exception->getMessage());
    example_assert(str_contains($exception->getMessage(), '2*certs'), 'an array of one certificate is rejected on decode');
}
echo PHP_EOL;

// --- 2. signing: x5chain in the protected bucket, x5t next to it ------------------

// RFC 9360 section 2: "The end-entity certificate MUST be integrity protected by COSE." The simplest way is the
// protected bucket, which the signature covers.
$chain = X5Chain::create($aliceDer, $caDer);
$thumbprint = CoseCertHash::compute(SHA256::create(), $aliceDer);
$protected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($algorithm::identifier())),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5CHAIN), $chain->toCBOR()),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5T), $thumbprint->toCBOR()),
]));
// x5u may sit in the unprotected bucket: the thumbprint in the protected one names what it must resolve to.
$unprotected = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5U), TextStringObject::create('https://example.com/alice.cer')),
]);
$payload = ByteStringObject::create('This is the content.');

$toBeSigned = Signature1::create($protected, $payload);
$signature = $algorithm->sign((string) $toBeSigned, $alice);
$message = CoseSign1Tag::create(ListObject::create([$protected, $unprotected, $payload, ByteStringObject::create($signature)]));
example_hex('COSE_Sign1', (string) $message);
example_hex('x5t', (string) $thumbprint->toCBOR());
example_assert(
    bin2hex($thumbprint->hashValue()) === '11fa0500d6763ae15a3238296e04c048a8fdd220a0dda0234824b18fb6666600',
    'the thumbprint is the one cose-wg signed-05 carries'
);
echo PHP_EOL;

// --- 3. verifying: read the chain, verify with its end-entity certificate ----------

$decoded = Decoder::create()->decode(new StringStream((string) $message));
if (! $decoded instanceof CoseSign1Tag) {
    throw new RuntimeException('Not a COSE_Sign1');
}
$headers = CoseHeaders::fromMessage($decoded);

$receivedChain = $headers->getX5Chain();
if ($receivedChain === null) {
    throw new RuntimeException('No x5chain');
}
example_line('x5chain', sprintf('%d certificate(s), end-entity first', count($receivedChain)));
example_assert($receivedChain->endEntityCertificate() === $aliceDer, 'the end-entity certificate is Alice\'s');

$structure = Signature1::create($decoded->getProtectedHeader(), $decoded->getPayload());
$isValid = $verifier->verifyWithX5Chain(-7, $receivedChain, (string) $structure, $decoded->getSignature()->getValue());
example_assert($isValid, 'the signature verifies with the end-entity certificate of the chain');
example_assert(
    ! $verifier->verify(-7, $caDer, (string) $structure, $decoded->getSignature()->getValue()),
    'and not with the CA certificate that follows it'
);
echo PHP_EOL;

// --- 4. x5t: the thumbprint selects a certificate, SHA-256 or SHA-1 -----------------

$receivedThumbprint = $headers->getX5T();
if ($receivedThumbprint === null) {
    throw new RuntimeException('No x5t');
}
$hash = $receivedThumbprint->hashAlgorithm($manager);
example_line('x5t hashAlg', sprintf('%d -> %s', $receivedThumbprint->hashAlg(), $hash::class));
example_assert($receivedChain->find($receivedThumbprint, $hash) === $aliceDer, 'the x5t selects Alice\'s certificate in the chain');

// The same over a bag, where nothing but the thumbprint says which certificate is the signer's; and with SHA-1.
$bag = X5Bag::fromCBOR(X5Bag::create($caDer, $aliceDer)->toCBOR());
$sha1 = SHA1::create();
$bySha1 = CoseCertHash::compute($sha1, $aliceDer);
example_assert($bag->find($bySha1, $sha1) === $aliceDer, 'a SHA-1 thumbprint selects the same certificate in a bag');
example_assert(X5Bag::create($caDer)->find($bySha1, $sha1) === null, 'and nothing in a bag that does not hold it');

// A thumbprint compared with the wrong algorithm is a bug, not a mismatch.
try {
    $receivedThumbprint->matches($aliceDer, $sha1);
    throw new LogicException('unreachable');
} catch (InvalidArgumentException $exception) {
    example_assert(true, 'comparing a SHA-256 thumbprint with SHA-1 throws: ' . $exception->getMessage());
}
echo PHP_EOL;

// --- 5. x5u: a string, and nothing else --------------------------------------------

$uri = $headers->getX5U();
example_line('x5u', (string) $uri);
example_assert($uri === 'https://example.com/alice.cer', 'the URI is returned as text; the library never fetches it');
echo PHP_EOL;

// --- 6. where the library stops: the application validates the path -----------------

// Everything above proves that the signature was made by the key of the first certificate of the chain. Nothing
// above says that certificate is to be trusted. RFC 9360 section 2: "Parties that intend to rely on the assertions
// made by a certificate obtained from any of these methods still need to validate it." Here, with pki-framework,
// against the CA of the fixtures as the trust anchor, at a date inside the validity of both certificates.
$trustAnchor = Certificate::fromPEM(PEM::fromFile($fixtures . '/ca.crt'));
$config = PathValidationConfig::create(new DateTimeImmutable('2021-06-01T00:00:00Z'), 3)
    ->withTrustAnchor($trustAnchor);
$result = CertificationPath::fromCertificateChain($receivedChain->toCertificateChain())->validate($config);
example_assert(
    $result->certificate()->equals(Certificate::fromDER($receivedChain->endEntityCertificate())),
    'the path validates against the trust anchor the application chose -- the application did this, not the library'
);
example_line('subject', $result->certificate()->tbsCertificate()->subject()->toString());
