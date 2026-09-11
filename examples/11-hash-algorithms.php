<?php

declare(strict_types=1);

/**
 * The hash algorithms of RFC 9054, and what "Filter Only" means in practice.
 *
 * Three points to take away:
 *
 * 1. A hash is a COSE algorithm like the others: it has an identifier, it registers in a Manager, and a message
 *    names it by that identifier -- the "x5t" header parameter of RFC 9360 is [hashAlg, hashValue].
 * 2. Two of the eight are marked "Filter Only" by IANA: SHA-1 (-14) and SHA-256/64 (-15). They are fine for picking
 *    the candidate certificates a thumbprint might name, since each candidate is verified afterwards, and not fine
 *    for standing in for the data. The library says so with a type: they implement FilterOnlyHash and not Hash.
 * 3. SHAKE128 and SHAKE256 have no PHP primitive; a Keccak sponge computes them, at the 256 and 512 bits RFC 9054
 *    stores.
 */

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\NegativeIntegerObject;
use Cose\Algorithm\Hash\FilterOnlyHash;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA256_64;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Hash\SHA512_256;
use Cose\Algorithm\Hash\SHAKE128;
use Cose\Algorithm\Hash\SHAKE256;
use Cose\Algorithm\Manager;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9054: hash algorithms');

// --- eight identifiers, one registry ---------------------------------------

$manager = Manager::create()->add(
    SHA1::create(),       // -14, Filter Only
    SHA256_64::create(),  // -15, Filter Only
    SHA256::create(),     // -16
    SHA512_256::create(), // -17
    SHAKE128::create(),   // -18
    SHA384::create(),     // -43
    SHA512::create(),     // -44
    SHAKE256::create(),   // -45
);
example_line('registered', implode(', ', array_map(strval(...), iterator_to_array($manager->list(), false))));

$data = 'This is the content.';
foreach ($manager->all() as $identifier => $algorithm) {
    example_assert($algorithm instanceof FilterOnlyHash, sprintf('%d is a hash algorithm', $identifier));
    $digest = $algorithm->hash($data);
    example_assert(strlen($digest) === $algorithm->length(), sprintf('%d yields %d bytes', $identifier, $algorithm->length()));
    example_hex(sprintf('%-4d %s', $identifier, substr($algorithm::class, strrpos($algorithm::class, '\\') + 1)), $digest);
}
echo PHP_EOL;

// --- a certificate thumbprint, as x5t carries it -----------------------------

// The certificate of cose-wg/Examples x509-examples, whose signed-05 fixture carries its x5t.
$certificate = file_get_contents(__DIR__ . '/../tests/fixtures/cose-wg/x509-examples/alice.der');
if ($certificate === false) {
    throw new RuntimeException('Unable to read the certificate');
}
$thumbprint = SHA256::create()->hash($certificate);
// x5t = [hashAlg, hashValue] (RFC 9360, section 2): the algorithm travels as its identifier.
$x5t = ListObject::create([
    NegativeIntegerObject::create(SHA256::identifier()),
    ByteStringObject::create($thumbprint),
]);
example_hex('x5t', (string) $x5t);
example_assert(
    bin2hex($thumbprint) === '11fa0500d6763ae15a3238296e04c048a8fdd220a0dda0234824b18fb6666600',
    'the thumbprint is the one the cose-wg signed-05 fixture carries'
);

// A verifier reads the identifier back and asks the registry for the algorithm.
$hashAlgorithm = $manager->get(-16);
example_assert($hashAlgorithm instanceof FilterOnlyHash, 'the identifier of the x5t resolves to a hash');
example_assert(hash_equals($thumbprint, $hashAlgorithm->hash($certificate)), 'and it reproduces the thumbprint');
echo PHP_EOL;

// --- Filter Only is a type ---------------------------------------------------

/**
 * Which of these certificates might be the one the thumbprint names? A collision only adds a candidate, and each
 * candidate is verified afterwards, so any of the eight will do: the parameter is typed FilterOnlyHash.
 *
 * @param array<string, string> $certificates name => DER
 * @return list<string>
 */
$candidates = static fn (FilterOnlyHash $hash, string $thumbprint, array $certificates): array => array_keys(
    array_filter($certificates, static fn (string $der): bool => hash_equals($thumbprint, $hash->hash($der)))
);

/**
 * The digest stands for the data and nothing checks it afterwards: the parameter is typed Hash, and SHA1 or
 * SHA256_64 cannot be passed - PHPStan and Psalm report it, PHP throws a TypeError.
 */
$commitment = static fn (Hash $hash, string $data): string => $hash->hash($data);

$certificates = [
    'alice' => $certificate,
    'other' => random_bytes(300),
];
example_line('SHA-1 candidates', implode(', ', $candidates(SHA1::create(), SHA1::create()->hash($certificate), $certificates)));
example_line('SHA-256/64 candidates', implode(', ', $candidates(SHA256_64::create(), SHA256_64::create()->hash($certificate), $certificates)));
example_hex('SHA-256 commitment', $commitment(SHA256::create(), $data));

try {
    // @phpstan-ignore argument.type (the point of the call is that it is a type error)
    $commitment(SHA1::create(), $data);
    example_assert(false, 'a Filter Only hash was accepted as a Hash');
} catch (TypeError) {
    example_assert(true, 'SHA1 is refused where a Hash is expected');
}
example_assert(! SHA1::create() instanceof Hash, 'SHA1 is a FilterOnlyHash and not a Hash');
example_assert(! SHA256_64::create() instanceof Hash, 'SHA256_64 is a FilterOnlyHash and not a Hash');
example_assert(SHA256::create() instanceof Hash, 'SHA256 is a Hash');
echo PHP_EOL;

// --- two names that look alike ----------------------------------------------

// SHA-256/64 is the truncation of SHA-256; SHA-512/256 is a SHA-2 function of its own, not SHA-512 cut short.
example_assert(
    SHA256_64::create()->hash($data) === substr(SHA256::create()->hash($data), 0, 8),
    'SHA-256/64 is the first 8 bytes of SHA-256'
);
example_assert(
    SHA512_256::create()->hash($data) !== substr(SHA512::create()->hash($data), 0, 32),
    'SHA-512/256 is not the first 32 bytes of SHA-512'
);

// SHAKE: an extendable-output function, fixed by RFC 9054 at 256 bits for SHAKE128 and 512 bits for SHAKE256.
example_assert(SHAKE128::isSupported(), 'this build has the 64-bit integers the Keccak sponge needs');
example_assert(
    bin2hex(SHAKE128::create()->hash('')) === '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
    'SHAKE128 of the empty message matches the NIST example'
);
