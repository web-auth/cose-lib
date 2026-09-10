<?php

declare(strict_types=1);

/**
 * Shared plumbing for the examples: the autoloader, key generation and a little output formatting.
 *
 * Nothing here is part of the library's API. It exists so that each example can open on the COSE code it is about
 * rather than on twenty lines of setup.
 */

use Cose\Key\Ec2Key;
use Cose\Key\SymmetricKey;

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
 * Fails the example loudly rather than printing a wrong result quietly.
 */
function example_assert(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException('FAILED: ' . $message);
    }
    example_line('ok', $message);
}
