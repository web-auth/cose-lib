<?php

declare(strict_types=1);

/**
 * The COSE Key Thumbprint of RFC 9679, and the compressed EC2 points it made the library accept.
 *
 * Three points to take away:
 *
 * 1. The thumbprint is a digest of the key and of nothing else. It is computed over a COSE_Key rebuilt from the
 *    required parameters of the key type, in deterministic CBOR: "kid", "alg", "key_ops", the private parts, the
 *    order of the members, the spelling of "kty" and "crv" and the form of the point make no difference.
 * 2. It is therefore a stable identifier for the key - a "kid", the "ckt" confirmation method of a CWT, a URI -
 *    that anyone holding the public key can recompute.
 * 3. An EC2 key may carry "y" as the sign bit of the compressed point (RFC 9053, section 7.1.1). The key is
 *    decompressed on load, so that y() is always the coordinate and the thumbprint is always the uncompressed one
 *    RFC 9679 requires.
 */

use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512_256;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Key\Thumbprint;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9679: COSE Key Thumbprint');

// --- the worked example of RFC 9679, section 6 -------------------------------

$x = hex2bin('65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d');
$y = hex2bin('1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c');
example_assert($x !== false && $y !== false, 'the coordinates of the RFC 9679 example decode');

// The key as the RFC prints it: kty, crv, x, y and a kid, which is the thumbprint itself.
$key = Ec2Key::create([
    Key::TYPE => Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
    Ec2Key::DATA_X => $x,
    Ec2Key::DATA_Y => $y,
    Key::KID => hex2bin('496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec'),
]);

// Step 1 and 2 of section 3: the required parameters only, in deterministic CBOR. Paste it into cbor.me.
$canonicalForm = Thumbprint::canonicalForm($key);
example_hex('canonical COSE_Key', $canonicalForm);
example_assert(
    bin2hex($canonicalForm) === 'a40102200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c',
    'the canonical form is the one section 6 prints'
);

// Step 3: the hash, SHA-256 by default.
$thumbprint = Thumbprint::of($key);
example_hex('thumbprint', $thumbprint->value());
example_assert(
    bin2hex($thumbprint->value()) === '496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec',
    'the thumbprint is the one section 6 prints'
);

// Section 5.7: the URI, the hash named as the IANA "Named Information Hash Algorithm Registry" spells it.
example_line('URI', $thumbprint->toUri());
example_assert(
    $thumbprint->toUri() === 'urn:ietf:params:oauth:ckt:sha-256:SWvYr63zB-WwjGSwQhv53AFSijRKQ72oj63RZp2iU-w',
    'the URI is the one section 5.7 prints'
);
echo PHP_EOL;

// --- one key, many representations, one thumbprint ---------------------------

$representations = [
    'kid, alg and key_ops added' => $key->getData() + [
        Key::ALG => -7,
        Key::KEY_OPS => [Key::OP_VERIFY],
    ],
    'members in another order' => [
        Ec2Key::DATA_Y => $y,
        Ec2Key::DATA_X => $x,
        Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
        Key::TYPE => Key::TYPE_EC2,
    ],
    'kty and crv as names' => [
        Key::TYPE => 'EC2',
        Ec2Key::DATA_CURVE => 'P-256',
        Ec2Key::DATA_X => $x,
        Ec2Key::DATA_Y => $y,
    ],
    'y as the sign bit' => [
        Key::TYPE => Key::TYPE_EC2,
        Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
        Ec2Key::DATA_X => $x,
        Ec2Key::DATA_Y => (ord($y[31]) & 1) === 1, // SEC 1, section 2.3.3: the parity of y
    ],
];
foreach ($representations as $what => $data) {
    example_assert(
        Thumbprint::of(Key::createFromData($data))->equals($thumbprint->value()),
        sprintf('%s: same thumbprint', $what)
    );
}

// A private key has the thumbprint of its public half: the private parts are not required parameters.
$privateKey = example_ec_key();
example_assert(
    Thumbprint::of($privateKey)->equals(Thumbprint::of($privateKey->toPublic())->value()),
    'a private key has the thumbprint of its public key'
);
echo PHP_EOL;

// --- a compressed point ------------------------------------------------------

// RFC 9053, section 7.1.1: "y" may be the sign bit of the point instead of the coordinate. The library decompresses
// it on load - a square root modulo the field prime - and checks that the result is on the curve.
$compressed = Ec2Key::create([
    Key::TYPE => Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
    Ec2Key::DATA_X => $x,
    Ec2Key::DATA_Y => false,
]);
example_hex('decompressed y', $compressed->y());
example_assert($compressed->y() === $y, 'y() is the coordinate the RFC prints');
example_assert($compressed->get(Ec2Key::DATA_Y) === false, 'getData() still carries the sign bit');
example_assert($compressed->asPEM() === $key->asPEM(), 'the PEM is the one of the uncompressed key');

try {
    Ec2Key::create([
        Key::TYPE => Key::TYPE_EC2,
        Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
        Ec2Key::DATA_X => str_pad("\x01", 32, "\0", STR_PAD_LEFT), // x = 1 is on no point of P-256
        Ec2Key::DATA_Y => true,
    ]);
    example_assert(false, 'a point off the curve was accepted');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'a sign bit that names no point of the curve is refused: ' . $e->getMessage());
}
echo PHP_EOL;

// --- other hashes ------------------------------------------------------------

// Section 3: SHA-256 MUST be supported, others MAY be. Any Hash of RFC 9054 does; the URI needs a name the IANA
// "Named Information Hash Algorithm Registry" has, which SHA-512/256 and the SHAKE functions lack.
$sha384 = Thumbprint::of($key, SHA384::create());
example_line('SHA-384 URI', $sha384->toUri());
$sha512_256 = Thumbprint::of($key, SHA512_256::create());
example_hex('SHA-512/256', $sha512_256->value());
try {
    $sha512_256->toUri();
    example_assert(false, 'a URI was produced for a hash the registry does not name');
} catch (InvalidArgumentException) {
    example_assert(true, 'SHA-512/256 has no registered name, so no URI');
}
echo PHP_EOL;

// --- symmetric keys ----------------------------------------------------------

// The thumbprint of a symmetric key is a digest of the secret. RFC 9679, section 7: fine for a random key of
// 128 bits or more, "MUST NOT be used with passwords or other low-entropy secrets" - a hash of a password is a
// password to brute-force.
$symmetric = SymmetricKey::create([
    Key::TYPE => Key::TYPE_OCT,
    SymmetricKey::DATA_K => random_bytes(32),
]);
example_hex('symmetric thumbprint', Thumbprint::of($symmetric)->value());
example_line('note', 'a public identifier of a secret value: only for keys with enough entropy');
