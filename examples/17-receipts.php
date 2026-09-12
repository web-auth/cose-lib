<?php

declare(strict_types=1);

/**
 * COSE receipts (RFC 9942): the "receipts", "vds" and "vdp" header parameters, and the RFC9162_SHA256 inclusion and
 * consistency proofs a transparency service issues over a binary Merkle Tree.
 *
 * The tree is the eight-leaf tree of the Certificate Transparency test vectors -- the inputs "", 00, 10, 2021,
 * 3031, 40414243, 5051..57 and 6061..6f -- whose tree heads every RFC 6962 / RFC 9162 implementation computes the
 * same, so that what is printed here can be checked against transparency-dev/merkle, trillian, or any CT log. The
 * transparency service is played by this script: it builds the tree, signs its head, and hands out a receipt; the
 * verifier, further down, gets the receipt and the entry and nothing else.
 *
 * Where the library stops is, again, the point. It reads the three header parameters with their CDDL rules, walks
 * the proofs as RFC 9162 defines them, and verifies the signature over the tree head the proof leads to. It does not
 * know who the issuer is, whether the log is honest, or whether the receipt is still valid: the key it verifies with
 * is the application's to resolve and trust, and the last section shows what that leaves to the application.
 */

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
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\VerifiableDataStructure\ReceiptVerifier;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256ConsistencyProof;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256InclusionProof;

require_once __DIR__ . '/_bootstrap.php';

example_title('RFC 9942: COSE receipts and RFC9162_SHA256 proofs');

$issuerKey = example_ec_key();
$algorithm = ES256::create();
$manager = Manager::create()->add($algorithm);

// --- 1. the log: eight entries, and the tree heads RFC 9162 computes for them ---------------------------------------

$entries = ["", "\x00", "\x10", "\x20\x21", "\x30\x31", "\x40\x41\x42\x43", "\x50\x51\x52\x53\x54\x55\x56\x57", "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"];
$rootOf8 = Rfc9162Sha256::treeHash(...$entries);
$rootOf6 = Rfc9162Sha256::treeHash(...array_slice($entries, 0, 6));
example_hex('MTH(D[8])', $rootOf8);
example_hex('MTH(D[6])', $rootOf6);
example_assert(
    bin2hex($rootOf8) === '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
    'the tree head of the eight CT leaves is the one every RFC 6962 implementation computes'
);
example_assert(bin2hex(Rfc9162Sha256::leafHash($entries[5])) === bin2hex(hash('sha256', "\x00\x40\x41\x42\x43", true)), 'a leaf hashes as HASH(0x00 || entry)');
echo PHP_EOL;

// --- 2. the transparency service issues a receipt of inclusion for entry 5 ------------------------------------------

// The inclusion proof for d[5] in a tree of 8: PATH(5, D[8]) = [MTH(d4), MTH(D[6:8]), MTH(D[0:4])] (RFC 9162 §2.1.3.1).
// The library verifies proofs; producing them is the log's job, done here by hand from the tree heads.
$proof = Rfc9162Sha256InclusionProof::create(
    8,
    5,
    Rfc9162Sha256::leafHash($entries[4]),
    Rfc9162Sha256::treeHash(...array_slice($entries, 6, 2)),
    Rfc9162Sha256::treeHash(...array_slice($entries, 0, 4)),
);
example_assert($proof->root($entries[5]) === $rootOf8, 'the proof leads from entry 5 to MTH(D[8])');

// RFC 9942 §5.2.1: {1: alg, 395: vds} protected, {396: {-1: [proof]}} unprotected, payload = the tree head, detached.
$protected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($algorithm::identifier())),
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), UnsignedIntegerObject::create(Rfc9162Sha256::IDENTIFIER)),
]));
$unprotected = MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), MapObject::create([
        MapItem::create(NegativeIntegerObject::create(Rfc9162Sha256::LABEL_INCLUSION_PROOF), ListObject::create([$proof->toCBOR()])),
    ])),
]);
$signature = $algorithm->sign((string) Signature1::create($protected, ByteStringObject::create($rootOf8)), $issuerKey);
$receipt = CoseSign1Tag::create(ListObject::create([$protected, $unprotected, NullObject::create(), ByteStringObject::create($signature)]));
example_hex('receipt', (string) $receipt);

// The statement that was logged, with the receipt attached in its unprotected header (RFC 9942 §4.3, Figure 2):
// the receipts travel as byte strings, each wrapping the tagged COSE_Sign1.
$statementProtected = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($algorithm::identifier())),
]));
$statementSignature = $algorithm->sign((string) Signature1::create($statementProtected, ByteStringObject::create($entries[5])), $issuerKey);
$statement = CoseSign1Tag::create(ListObject::create([
    $statementProtected,
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_RECEIPTS), ListObject::create([ByteStringObject::create((string) $receipt)])),
    ]),
    ByteStringObject::create($entries[5]),
    ByteStringObject::create($statementSignature),
]));
example_hex('statement + receipt', (string) $statement);
echo PHP_EOL;

// --- 3. the verifier: read the receipts, verify the one it was given -------------------------------------------------

$decoded = Decoder::create()->decode(new StringStream((string) $statement));
if (! $decoded instanceof CoseSign1Tag) {
    throw new RuntimeException('Not a COSE_Sign1');
}
$receipts = CoseHeaders::fromMessage($decoded)->getReceipts();
example_line('receipts', sprintf('%d, each a %s', count($receipts), $receipts[0]::class));

$receiptHeaders = CoseHeaders::fromMessage($receipts[0]);
example_line('vds', sprintf('%d (%s)', $receiptHeaders->getVds(), Rfc9162Sha256::NAME));
$proofs = Rfc9162Sha256::inclusionProofs($receiptHeaders);
example_line('inclusion proof', sprintf('tree size %d, leaf index %d, %d node(s)', $proofs[0]->treeSize(), $proofs[0]->leafIndex(), count($proofs[0]->inclusionPath())));

// RFC 9942 §5.2, the two steps in one call: apply the proof to the entry, then verify the signature over the root
// it leads to. The entry is what the application logged -- here the payload of the statement.
$verifier = ReceiptVerifier::create($manager);
$entry = $decoded->getPayload()->getValue();
example_assert($verifier->verifyInclusion($receipts[0], $entry, $issuerKey->toPublic()), 'the receipt proves the entry is in a tree the issuer signed');
example_assert(! $verifier->verifyInclusion($receipts[0], $entries[4], $issuerKey->toPublic()), 'and proves nothing about another entry');
example_assert(! $verifier->verifyInclusion($receipts[0], $entry, example_ec_key()->toPublic()), 'nor anything to a verifier holding another key');
echo PHP_EOL;

// --- 4. what a tampered proof does -----------------------------------------------------------------------------------

// A proof is unprotected: nothing stops a relay from changing it. A changed proof leads to another root, and the
// signature does not cover that root -- which is what the detached payload of §4.4 guarantees the verifier sees.
$path = $proof->inclusionPath();
$path[1] = $path[1] ^ ("\x80" . str_repeat("\x00", 31));
$tampered = Rfc9162Sha256InclusionProof::create(8, 5, ...$path);
$forged = CoseSign1Tag::create(ListObject::create([
    $protected,
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-1), ListObject::create([$tampered->toCBOR()])),
        ])),
    ]),
    NullObject::create(),
    ByteStringObject::create($signature),
]));
example_assert($tampered->root($entry) !== $rootOf8, 'the tampered proof leads to another root');
example_assert(! $verifier->verifyInclusion($forged, $entry, $issuerKey->toPublic()), 'over which the signature does not verify');

// RFC 9162 §2.1.3.2 step 1, quoted by RFC 9942 §5.2: a leaf index at or beyond the tree size fails before any hash.
example_assert(Rfc9162Sha256InclusionProof::create(8, 8, ...$proof->inclusionPath())->root($entry) === null, 'leaf-index >= tree-size fails the proof');
echo PHP_EOL;

// --- 5. a receipt of consistency: the log grew from 6 to 8 entries and changed nothing --------------------------------

// PROOF(6, D[8]) = [MTH(D[4:6]), MTH(D[6:8]), MTH(D[0:4])] (RFC 9162 §2.1.4.1), signed over the newer tree head.
$consistency = Rfc9162Sha256ConsistencyProof::create(
    6,
    8,
    Rfc9162Sha256::treeHash(...array_slice($entries, 4, 2)),
    Rfc9162Sha256::treeHash(...array_slice($entries, 6, 2)),
    Rfc9162Sha256::treeHash(...array_slice($entries, 0, 4)),
);
$consistencyReceipt = CoseSign1Tag::create(ListObject::create([
    $protected,
    MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), MapObject::create([
            MapItem::create(NegativeIntegerObject::create(Rfc9162Sha256::LABEL_CONSISTENCY_PROOF), ListObject::create([$consistency->toCBOR()])),
        ])),
    ]),
    NullObject::create(),
    ByteStringObject::create($signature), // the same tree head, MTH(D[8]), so the same signature
]));
example_assert($consistency->newerRoot($rootOf6) === $rootOf8, 'the consistency proof binds MTH(D[6]) to MTH(D[8])');
example_assert($verifier->verifyConsistency($consistencyReceipt, $rootOf6, $issuerKey->toPublic()), 'the receipt proves the 6-entry tree is a prefix of the signed 8-entry one');
example_assert(! $verifier->verifyConsistency($consistencyReceipt, Rfc9162Sha256::treeHash(...array_slice($entries, 0, 5)), $issuerKey->toPublic()), 'and not the 5-entry tree');
echo PHP_EOL;

// --- 6. what the library does not decide ------------------------------------------------------------------------------

// A receipt for another structure is refused by name, not skipped (RFC 9942 §4.3): 2 is unassigned at IANA.
$foreign = CoseSign1Tag::create(ListObject::create([
    HeaderMapHelper::encodeProtected(MapObject::create([
        MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), UnsignedIntegerObject::create(2)),
    ])),
    $unprotected,
    NullObject::create(),
    ByteStringObject::create($signature),
]));
try {
    $verifier->verifyInclusion($foreign, $entry, $issuerKey->toPublic());
    throw new LogicException('unreachable');
} catch (InvalidArgumentException $exception) {
    example_assert(str_contains($exception->getMessage(), 'is not RFC9162_SHA256 (1)'), 'an unregistered vds is refused: ' . $exception->getMessage());
}

// Everything above proves that entry 5 is a leaf of a tree whose head the holder of $issuerKey signed. It does not say
// that $issuerKey belongs to a transparency service worth trusting, that the service shows the same tree to everyone,
// or that the receipt is not stale (RFC 9942 §7.2, §7.3). Those are the application's: the key comes from its own
// configuration -- a "kid" it maps to a key, an "x5chain" it validates (examples/13) -- and the freshness from the
// claims it chose to require in the receipt.
example_line('trust', 'the issuer key was supplied by the application, not read from the receipt');
