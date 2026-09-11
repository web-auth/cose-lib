<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_key_exists;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use function basename;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\StringStream;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use function count;
use function dirname;
use function file_get_contents;
use function hex2bin;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use LogicException;
use function sprintf;
use function strtolower;

/**
 * One file of cose-wg/Examples, the interoperability fixtures of the IETF COSE working group.
 *
 * A fixture is a JSON document with three parts, and this class exposes each of them typed:
 *
 * - "input": the plaintext, the keys, the headers and the external AAD the generator started from -- what a test
 *   needs to produce the message itself, or to verify it;
 * - "intermediates": the bytes the generator computed on the way -- the Sig_structure or MAC_structure it signed
 *   or MACed, the Enc_structure it used as AAD, the content encryption key. These are the point of the fixtures:
 *   when a message fails to verify, they tell whether the *structure* this library built differs from the
 *   generator's, or whether the structure matches and it is the *primitive* that diverged;
 * - "output": the message, as CBOR bytes and as CBOR diagnostic notation.
 *
 * A fixture flagged "fail" is a message the generator deliberately broke -- a flipped signature, an unknown
 * algorithm, a protected header the signature does not cover -- and a test must assert that it is rejected.
 *
 * @see https://github.com/cose-wg/Examples/blob/master/examples.cddl the schema
 * @see \Cose\Tests\CoseWg\CoseWgFixtureTest
 */
final class CoseWgFixture
{
    public const SIGN = 'sign';

    public const SIGN1 = 'sign0';

    public const MAC = 'mac';

    public const MAC0 = 'mac0';

    public const ENCRYPT = 'enveloped';

    public const ENCRYPT0 = 'encrypted';

    /**
     * The tag class of cbor-php 3.4 each message type decodes to.
     *
     * @var array<string, class-string<CoseSignTag|CoseSign1Tag|CoseMacTag|CoseMac0Tag|CoseEncryptTag|CoseEncrypt0Tag>>
     */
    public const MESSAGE_CLASSES = [
        self::SIGN => CoseSignTag::class,
        self::SIGN1 => CoseSign1Tag::class,
        self::MAC => CoseMacTag::class,
        self::MAC0 => CoseMac0Tag::class,
        self::ENCRYPT => CoseEncryptTag::class,
        self::ENCRYPT0 => CoseEncrypt0Tag::class,
    ];

    /**
     * @var array<string, mixed>
     */
    private readonly array $input;

    /**
     * @var array<string, mixed>
     */
    private readonly array $intermediates;

    /**
     * @var array<string, mixed>
     */
    private readonly array $output;

    private readonly string $messageType;

    /**
     * @param array<string, mixed> $document
     */
    private function __construct(
        private readonly string $name,
        private readonly array $document
    ) {
        $this->input = $this->object($document, 'input');
        $this->intermediates = $this->object($document, 'intermediates');
        $this->output = $this->object($document, 'output');

        $types = array_values(array_filter(
            array_keys(self::MESSAGE_CLASSES),
            fn (string $type): bool => array_key_exists($type, $this->input)
        ));
        if (count($types) !== 1) {
            throw new LogicException(sprintf('%s: the input names %d message types, expected one', $name, count($types)));
        }
        $this->messageType = $types[0];
    }

    /**
     * Loads one fixture file. The name is the path relative to the fixture root, without the extension:
     * "sign1-tests/sign-pass-01".
     */
    public static function load(string $file): self
    {
        $json = file_get_contents($file);
        if ($json === false) {
            throw new LogicException(sprintf('Unable to read the fixture %s', $file));
        }
        $name = basename(dirname($file)) . '/' . basename($file, '.json');
        $document = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($document)) {
            throw new LogicException(sprintf('%s: the fixture is not a JSON object', $name));
        }
        /** @var array<string, mixed> $document */

        return self::fromDocument($name, $document);
    }

    /**
     * A fixture from its decoded JSON document, for a test that alters one before running it.
     *
     * @param array<string, mixed> $document
     */
    public static function fromDocument(string $name, array $document): self
    {
        return new self($name, $document);
    }

    /**
     * The JSON document as decoded, for a test that wants to alter it and rebuild the fixture with fromDocument().
     *
     * @return array<string, mixed>
     */
    public function document(): array
    {
        return $this->document;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function title(): string
    {
        $title = $this->document['title'] ?? '';

        return is_string($title) ? $title : '';
    }

    /**
     * Whether the generator broke the message on purpose. The message of such a fixture must be rejected.
     */
    public function mustFail(): bool
    {
        return ($this->document['fail'] ?? false) === true;
    }

    /**
     * One of the SIGN, SIGN1, MAC, MAC0, ENCRYPT and ENCRYPT0 constants.
     */
    public function messageType(): string
    {
        return $this->messageType;
    }

    /**
     * @return class-string<CoseSignTag|CoseSign1Tag|CoseMacTag|CoseMac0Tag|CoseEncryptTag|CoseEncrypt0Tag>
     */
    public function messageClass(): string
    {
        return self::MESSAGE_CLASSES[$this->messageType];
    }

    // --- input ------------------------------------------------------------------------------------------------------

    /**
     * The content the message carries or protects, as bytes.
     */
    public function plaintext(): string
    {
        if (array_key_exists('plaintext_hex', $this->input)) {
            return self::bytes($this->string($this->input, 'plaintext_hex'), $this->name . ' "plaintext_hex"');
        }

        return $this->string($this->input, 'plaintext');
    }

    /**
     * Whether the payload travels outside the message (RFC 9052 section 4.1: "payload : bstr / nil").
     */
    public function isDetached(): bool
    {
        return ($this->input['detached'] ?? false) === true;
    }

    /**
     * The message block of the input: the "sign", "sign0", "mac", "mac0", "enveloped" or "encrypted" object.
     *
     * @return array<string, mixed>
     */
    public function message(): array
    {
        return $this->object($this->input, $this->messageType);
    }

    /**
     * The algorithm name of the message block: the content algorithm of a MAC or an encryption, the only algorithm
     * of a COSE_Sign1. A COSE_Sign names its algorithms per signer, see signers().
     */
    public function algorithmName(): ?string
    {
        return $this->body()
            ->algorithmName();
    }

    public function algorithmIdentifier(): ?int
    {
        return $this->body()
            ->algorithmIdentifier();
    }

    /**
     * @return array<string, mixed> the body "protected" headers as the fixture writes them, by name
     */
    public function protectedHeader(): array
    {
        return $this->body()
            ->protectedHeader();
    }

    /**
     * @return array<string, mixed> the body "unprotected" headers as the fixture writes them, by name
     */
    public function unprotectedHeader(): array
    {
        return $this->body()
            ->unprotectedHeader();
    }

    /**
     * The external_aad of the body structure -- the MAC_structure or the Enc_structure -- or the empty string RFC
     * 9052 defaults to. The Sig_structure of a COSE_Sign carries one per signer, see CoseWgParty::externalAad().
     */
    public function externalAad(): string
    {
        return $this->body()
            ->externalAad();
    }

    /**
     * The signers of the message: the "signers" list of a COSE_Sign, or the single signer of a COSE_Sign1, which is
     * the "sign0" block itself.
     *
     * @return list<CoseWgParty>
     */
    public function signers(): array
    {
        if ($this->messageType === self::SIGN1) {
            return [$this->body()];
        }
        if ($this->messageType !== self::SIGN) {
            return [];
        }

        return $this->parties('signers');
    }

    /**
     * The recipients of the message. A COSE_Mac0 or a COSE_Encrypt0 has none on the wire, but the fixture still
     * lists the "direct" recipient whose key is the content key.
     *
     * @return list<CoseWgParty>
     */
    public function recipients(): array
    {
        return $this->parties('recipients');
    }

    /**
     * Every algorithm identifier the fixture needs answered to be verified end to end: the content algorithm, the one
     * of each signer and the one of each recipient, nested recipients included. "direct" is left out: it is not an
     * algorithm class, the harness resolves it.
     *
     * A name the {@see CoseWgAlgorithms} table does not know is returned as is, so that the skip message names it.
     *
     * @return list<int|string>
     */
    public function requiredAlgorithms(): array
    {
        $required = [];
        $collect = static function (CoseWgParty $party) use (&$required, &$collect): void {
            $name = $party->algorithmName();
            if ($name !== null) {
                $required[] = CoseWgAlgorithms::identifierOf($name) ?? $name;
            }
            foreach ($party->recipients() as $recipient) {
                $collect($recipient);
            }
        };

        $collect($this->body());
        if ($this->messageType === self::SIGN) {
            foreach ($this->signers() as $signer) {
                $collect($signer);
            }
        }

        return array_values(array_unique(array_filter(
            $required,
            static fn (int|string $algorithm): bool => $algorithm !== CoseWgAlgorithms::DIRECT
        )));
    }

    // --- intermediates ----------------------------------------------------------------------------------------------

    /**
     * The Sig_structure the generator signed for the given signer, or null when it recorded none.
     */
    public function toBeSigned(int $signer = 0): ?string
    {
        $signers = $this->signers();
        if (! array_key_exists($signer, $signers)) {
            throw new LogicException(sprintf('%s has no signer %d', $this->name, $signer));
        }

        return $signers[$signer]->toBeSigned();
    }

    /**
     * The MAC_structure the generator authenticated, or null when it recorded none.
     */
    public function toBeMaced(): ?string
    {
        return $this->intermediateBytes('ToMac_hex');
    }

    /**
     * The Enc_structure the generator used as additional authenticated data, or null when it recorded none.
     */
    public function aad(): ?string
    {
        return $this->intermediateBytes('AAD_hex');
    }

    /**
     * The content encryption key -- the MAC key or the AEAD key -- the generator used, or null when it recorded none.
     */
    public function cek(): ?string
    {
        return $this->intermediateBytes('CEK_hex');
    }

    // --- output -----------------------------------------------------------------------------------------------------

    /**
     * The message the generator produced, as CBOR bytes.
     */
    public function outputCbor(): string
    {
        return self::bytes($this->string($this->output, 'cbor'), $this->name . ' "output.cbor"');
    }

    /**
     * The same message in CBOR diagnostic notation, as the generator printed it.
     */
    public function outputDiagnostic(): ?string
    {
        return array_key_exists('cbor_diag', $this->output) ? $this->string($this->output, 'cbor_diag') : null;
    }

    /**
     * The payload of a detached message, carried outside of it.
     */
    public function detachedContent(): ?string
    {
        return array_key_exists('content', $this->output)
            ? self::bytes($this->string($this->output, 'content'), $this->name . ' "output.content"')
            : null;
    }

    /**
     * The output, decoded by the default cbor-php decoder: one of the six COSE tag classes when the message is
     * tagged with the number the fixture expects, a generic tag when the generator changed the number, and a bare
     * list when it removed it.
     */
    public function decodeOutput(): CBORObject
    {
        return Decoder::create()->decode(StringStream::create($this->outputCbor()));
    }

    // --- helpers ----------------------------------------------------------------------------------------------------

    /**
     * The bytes a hex field denotes.
     */
    public static function bytes(string $hex, string $what): string
    {
        $bytes = @hex2bin(strtolower($hex));
        if ($bytes === false) {
            throw new LogicException(sprintf('%s is not hex', $what));
        }

        return $bytes;
    }

    /**
     * The message block as a party: what a COSE_Sign1 and a COSE_Mac0 sign or MAC with.
     */
    private function body(): CoseWgParty
    {
        // The intermediates of a COSE_Sign1 or a COSE_Mac0 sit at the top level, where the party reads them.
        return CoseWgParty::create($this->name, $this->message(), $this->intermediates);
    }

    /**
     * @return list<CoseWgParty>
     */
    private function parties(string $list): array
    {
        $message = $this->message();
        $entries = $message[$list] ?? [];
        $intermediates = $this->intermediates[$list] ?? [];
        if (! is_array($entries) || ! is_array($intermediates)) {
            throw new LogicException(sprintf('%s: "%s" is not a list', $this->name, $list));
        }
        /** @var array<int, array<string, mixed>|mixed> $entries */
        /** @var array<int, array<string, mixed>|mixed> $intermediates */

        return array_values(array_map(
            fn (int $index, mixed $entry): CoseWgParty => CoseWgParty::create(
                sprintf('%s %s[%d]', $this->name, $list, $index),
                is_array($entry) ? $entry : throw new LogicException(
                    sprintf('%s: the entry %d of "%s" is not an object', $this->name, $index, $list)
                ),
                is_array($intermediates[$index] ?? null) ? $intermediates[$index] : []
            ),
            array_keys($entries),
            $entries
        ));
    }

    private function intermediateBytes(string $field): ?string
    {
        return array_key_exists($field, $this->intermediates)
            ? self::bytes($this->string($this->intermediates, $field), sprintf('%s "%s"', $this->name, $field))
            : null;
    }

    /**
     * @param array<string, mixed> $source
     * @return array<string, mixed>
     */
    private function object(array $source, string $field): array
    {
        $value = $source[$field] ?? [];
        if (! is_array($value)) {
            throw new LogicException(sprintf('%s: "%s" is not an object', $this->name, $field));
        }
        /** @var array<string, mixed> $value */

        return $value;
    }

    /**
     * @param array<string, mixed> $source
     */
    private function string(array $source, string $field): string
    {
        $value = $source[$field] ?? null;
        if (! is_string($value)) {
            throw new LogicException(sprintf('%s: "%s" is missing or not a string', $this->name, $field));
        }

        return $value;
    }
}
