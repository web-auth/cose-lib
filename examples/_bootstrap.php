<?php

declare(strict_types=1);

/**
 * Shared plumbing for the examples: the autoloader, key generation and a little output formatting.
 *
 * Nothing here is part of the library's API. It exists so that each example can open on the COSE code it is about
 * rather than on twenty lines of setup.
 */

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Normalizable;
use CBOR\StringStream;
use CBOR\Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Key\Ec2Key;
use Cose\Key\SymmetricKey;
use Symfony\Component\VarDumper\Caster\Caster;
use Symfony\Component\VarDumper\Cloner\Stub;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * A freshly generated P-256 key pair, private part included.
 *
 * OpenSSL strips the leading zero bytes of the coordinates; COSE requires them to be a fixed size, so they are
 * padded back. Getting this wrong produces a key that fails roughly one time in 256.
 */
function example_ec_key(): Ec2Key
{
    $key = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);
    if ($key === false) {
        throw new RuntimeException('Unable to generate an EC key: ' . openssl_error_string());
    }
    $details = openssl_pkey_get_details($key)['ec'];
    $pad = static fn (string $value): string => str_pad($value, 32, "\x00", STR_PAD_LEFT);

    return Ec2Key::create([
        Ec2Key::TYPE => Ec2Key::TYPE_EC2,
        Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
        Ec2Key::DATA_X => $pad($details['x']),
        Ec2Key::DATA_Y => $pad($details['y']),
        Ec2Key::DATA_D => $pad($details['d']),
    ]);
}

/**
 * A 256-bit symmetric COSE key.
 */
function example_symmetric_key(): SymmetricKey
{
    return SymmetricKey::create([
        SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        SymmetricKey::DATA_K => random_bytes(32),
    ]);
}

function example_title(string $title): void
{
    echo $title, PHP_EOL, str_repeat('=', strlen($title)), PHP_EOL, PHP_EOL;
}

function example_line(string $label, string $value): void
{
    printf("%-22s %s\n", $label . ':', $value);
}

/**
 * A CBOR item, printed as hex in full.
 *
 * Never truncated: the whole point of printing it is that it can be pasted into a decoder such as
 * https://cbor.me to see the structure the example just built.
 */
function example_hex(string $label, string $binary): void
{
    example_line($label, bin2hex($binary));
}

/**
 * The same item as the object tree cbor-php decodes it into, dumped with symfony/var-dumper.
 *
 * The hex is the reference; this is the readable companion, printed right after it so the reader can see the
 * structure -- which class wraps the message, which tag number it carries, which item is the protected header --
 * without leaving the terminal. A string is decoded first, which is how a Sig_structure or a MAC_structure gets in
 * here: they are only ever bytes.
 *
 * Casters strip the objects down to what they mean: the tag number and the tagged item, the items of a list, the
 * entries of a map keyed by their label, and the value of a scalar. Byte strings that are not printable text (a
 * protected header, a signature, a key) are written as h'..', the way cbor.me shows them.
 */
function example_dump(string $label, CBORObject|string $item): void
{
    if (! $item instanceof CBORObject) {
        $item = Decoder::create()->decode(StringStream::create($item));
    }

    $virtual = Caster::PREFIX_VIRTUAL;
    $scalar = static function (Stub $stub, CBORObject $object, string $rendering): array {
        // A scalar item fits on the line of its key: the class, then the value. Turning the stub into a scalar is
        // what keeps var-dumper from opening a block for it.
        $stub->type = Stub::TYPE_SCALAR;
        $stub->attr['value'] = $object::class . ' ' . $rendering;
        $stub->value = null;

        return [];
    };
    $cloner = new VarCloner([
        CBORObject::class => static function (CBORObject $object, array $properties, Stub $stub) use ($virtual, $scalar): array {
            if ($object instanceof Tag) {
                return [$virtual . 'tag' => example_tag_number($object), $virtual . 'value' => $object->getValue()];
            }
            if ($object instanceof ListObject || $object instanceof IndefiniteLengthListObject) {
                $items = [];
                foreach ($object as $index => $item) {
                    $items[$virtual . $index] = $item;
                }

                return $items;
            }
            if ($object instanceof MapObject || $object instanceof IndefiniteLengthMapObject) {
                $entries = [];
                foreach ($object as $entry) {
                    $key = $entry->getKey();
                    $entries[$virtual . ($key instanceof Normalizable ? $key->normalize() : spl_object_id($key))] = $entry->getValue();
                }

                return $entries;
            }
            if ($object instanceof ByteStringObject || $object instanceof IndefiniteLengthByteStringObject) {
                return $scalar($stub, $object, example_printable($object->getValue()));
            }
            if ($object instanceof UnsignedIntegerObject || $object instanceof NegativeIntegerObject) {
                return $scalar($stub, $object, $object->normalize());
            }
            if ($object instanceof Normalizable) {
                return $scalar($stub, $object, json_encode($object->normalize(), JSON_THROW_ON_ERROR));
            }

            return $properties;
        },
    ]);

    echo $label, ' (decoded):', PHP_EOL;
    (new CliDumper())->dump(
        $cloner->cloneVar($item)->withRefHandles(false),
        static function (string $line, int $depth, string $indentPad): void {
            // -1 is the dumper's end-of-dump marker, not a line.
            if ($depth >= 0) {
                echo '  ', str_repeat($indentPad, $depth), $line, PHP_EOL;
            }
        }
    );
}

/**
 * RFC 8949 section 3: the tag number is the argument of the major type 6 head, either the additional information
 * itself or the one, two, four or eight bytes that follow it.
 */
function example_tag_number(Tag $tag): int
{
    $data = $tag->getData();
    if ($data === null) {
        return $tag->getAdditionalInformation();
    }

    return (int) hexdec(bin2hex($data));
}

/**
 * Printable text quoted, anything else as h'..'.
 */
function example_printable(string $value): string
{
    if ($value !== '' && preg_match('/^[\P{C}\n\t]+$/u', $value) === 1) {
        return '"' . $value . '"';
    }

    return sprintf("h'%s'", bin2hex($value));
}

/**
 * Fails the example loudly rather than printing a wrong result quietly.
 */
function example_assert(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException('FAILED: ' . $message);
    }
    example_line('ok', $message);
}
