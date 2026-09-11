<?php

declare(strict_types=1);

/**
 * The fully-specified signature identifiers of RFC 9864, next to the polymorphic ones of RFC 9053 they refine.
 *
 * Three points to take away:
 *
 * 1. ES256 (-7) and ESP256 (-9) run the same primitive on the same key, and still do not verify each other's
 *    messages: the identifier is part of the protected header, so it is part of the Sig_structure that is signed.
 * 2. A fully-specified identifier names one curve, and the algorithm class refuses a key on any other -- what makes
 *    ESP256 and ESB256 distinct although both are ECDSA with SHA-256 over 32-byte coordinates.
 * 3. Two of the families depend on the platform: Ed448 on PHP 8.4, the Brainpool ESB* on the OpenSSL build. Each
 *    class says so through isSupported(), so a registry skips what it cannot compute instead of failing later.
 *
 * RFC 9864 also marks -7, -8, -35 and -36 as Deprecated in the IANA registry. WebAuthn and CTAP authenticators emit
 * -7 and -8 all the same, and will for years, so a relying party registers both forms and lets the credential decide.
 */

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed448;
use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESB320;
use Cose\Algorithm\Signature\FullySpecified\ESB384;
use Cose\Algorithm\Signature\FullySpecified\ESB512;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\ESP384;
use Cose\Algorithm\Signature\FullySpecified\ESP512;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\HeaderMapHelper;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9864: fully-specified algorithms');

// --- one registry, both forms ----------------------------------------------

// The polymorphic identifiers stay: they are what today's authenticators emit. The fully-specified ones come next to
// them, not instead of them.
$manager = Manager::create()->add(
    ES256::create(),   // -7
    ESP256::create(),  // -9
    ESP384::create(),  // -51
    ESP512::create(),  // -52
    new EdDSA(),       // -8
    Ed25519::create(), // -19
);

// Ed448 needs PHP 8.4 (OpenSSL's digest-less signature for Edwards curves); the Brainpool curves are compiled out of
// some OpenSSL builds and of every FIPS provider. Ask before registering.
if (Ed448::isSupported()) {
    $manager->add(Ed448::create());
}
foreach ([ESB256::class, ESB320::class, ESB384::class, ESB512::class] as $brainpool) {
    if ($brainpool::isSupported()) {
        $manager->add($brainpool::create());
    } else {
        example_line('skipped', $brainpool . ': its curve is not in this OpenSSL build');
    }
}
example_line('registered', implode(', ', array_map(strval(...), iterator_to_array($manager->list(), false))));
example_assert($manager->has(ES256::identifier()) && $manager->has(ESP256::identifier()), 'both -7 and -9 are registered');
echo PHP_EOL;

// --- same key, same primitive, two identifiers -----------------------------

$key = example_ec_key();
$payload = ByteStringObject::create('Message to sign');

$toBeSigned = static function (int $identifier) use ($payload): Signature1 {
    $protected = HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($identifier)),
    ]));

    return Signature1::create($protected, $payload);
};

$es256 = $manager->get(ES256::identifier());
$esp256 = $manager->get(ESP256::identifier());
$signedAsEs256 = $es256->sign((string) $toBeSigned(ES256::identifier()), $key);

example_hex('Sig_structure (-7)', (string) $toBeSigned(ES256::identifier()));
example_hex('Sig_structure (-9)', (string) $toBeSigned(ESP256::identifier()));
example_assert(
    $es256->verify((string) $toBeSigned(ES256::identifier()), $key->toPublic(), $signedAsEs256),
    'the ES256 signature verifies as ES256'
);
// The primitive is identical, the key is the same, and the check still fails: the "alg" label sits in the protected
// header, and the protected header is inside the Sig_structure. Relabelling a message changes what was signed.
example_assert(
    ! $esp256->verify((string) $toBeSigned(ESP256::identifier()), $key->toPublic(), $signedAsEs256),
    'relabelled as ESP256, the same bytes no longer verify'
);
echo PHP_EOL;

// --- the identifier is bound to its curve ----------------------------------

// A brainpoolP256r1 key has the same shape as a P-256 one: 32-byte x, y and d. Only the curve differs, and that is
// exactly what the fully-specified identifier fixes.
$brainpoolKey = Ec2Key::create([
    Ec2Key::TYPE => Ec2Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_BP256,
    Ec2Key::DATA_X => base64_decode('Uvdvpl/MgjjNn74X3dJ8oC6NkYhs3q3J2ew9SCqzSlg=', true),
    Ec2Key::DATA_Y => base64_decode('Q5Fq3FoYkC+Pbq04EDqf4HKLZPqljRxuHf/UnT2sx5k=', true),
    Ec2Key::DATA_D => base64_decode('GESlTdoGJy2QEk6EyLd/cxH2vzCjJ28Z0hnWzuKptdU=', true),
]);

try {
    $esp256->sign((string) $toBeSigned(ESP256::identifier()), $brainpoolKey);
    example_assert(false, 'ESP256 must refuse a Brainpool key');
} catch (InvalidArgumentException $e) {
    example_assert(true, 'ESP256 refuses a brainpoolP256r1 key: ' . $e->getMessage());
}

if (ESB256::isSupported()) {
    $esb256 = $manager->get(ESB256::identifier());
    $signedAsEsb256 = $esb256->sign((string) $toBeSigned(ESB256::identifier()), $brainpoolKey);
    example_assert(
        $esb256->verify((string) $toBeSigned(ESB256::identifier()), $brainpoolKey->toPublic(), $signedAsEsb256),
        'ESB256 signs and verifies with it'
    );
    try {
        $esb256->verify((string) $toBeSigned(ESB256::identifier()), $key->toPublic(), $signedAsEsb256);
        example_assert(false, 'ESB256 must refuse a P-256 key');
    } catch (InvalidArgumentException $e) {
        example_assert(true, 'and refuses the P-256 key in return: ' . $e->getMessage());
    }
} else {
    // What the gate looks like from the caller's side: a clear message, before any key is touched.
    try {
        ESB256::create();
        example_assert(false, 'ESB256::create() must throw on a build without the curve');
    } catch (RuntimeException $e) {
        example_assert(true, 'ESB256::create() refuses this build: ' . $e->getMessage());
    }
}
