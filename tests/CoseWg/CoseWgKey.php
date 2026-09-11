<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_key_exists;
use function base64_decode;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\RsaKey;
use Cose\Key\SymmetricKey;
use function get_debug_type;
use function hex2bin;
use function in_array;
use function is_string;
use LogicException;
use function sprintf;
use function str_ends_with;
use function strtr;
use function substr;

/**
 * The keys of cose-wg/Examples, turned into the COSE_Key maps of RFC 9052 section 7.
 *
 * The fixtures write their keys the JOSE way: text parameter names, a text "kty" and "crv", base64url values, with an
 * "_hex" variant of every byte parameter. A COSE_Key is a map keyed by integer labels. The translation is one table
 * per key type; the "kty" and "crv" names are kept as they are, because RFC 9052 section 7.1 and RFC 9053 section 7
 * type both as "tstr / int" and the key classes accept the names since #186. A fixture whose key still fails to load
 * points at a bug in those classes, not at this table.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-7
 * @see https://github.com/cose-wg/Examples/blob/master/examples.cddl
 */
final class CoseWgKey
{
    /**
     * The parameter names common to every key type, RFC 9052 section 7.1, table 4.
     *
     * @var array<string, int>
     */
    private const COMMON_LABELS = [
        'kty' => Key::TYPE,
        'kid' => Key::KID,
    ];

    private const EC2_LABELS = [
        'crv' => Ec2Key::DATA_CURVE,
        'x' => Ec2Key::DATA_X,
        'y' => Ec2Key::DATA_Y,
        'd' => Ec2Key::DATA_D,
    ];

    private const OCT_LABELS = [
        'k' => SymmetricKey::DATA_K,
    ];

    /**
     * The type-specific parameters, RFC 9053 section 7 tables 19 to 21 and RFC 8230 section 4 table 4, under each
     * "kty" name the fixtures use: most write the JOSE names ("EC", "oct"), the X.509 examples the IANA ones.
     *
     * @var array<string, array<string, int>>
     */
    private const TYPE_LABELS = [
        Key::TYPE_NAME_EC2 => self::EC2_LABELS,
        Key::TYPE_NAME_EC2_IANA => self::EC2_LABELS,
        Key::TYPE_NAME_OKP => [
            'crv' => OkpKey::DATA_CURVE,
            'x' => OkpKey::DATA_X,
            'd' => OkpKey::DATA_D,
        ],
        Key::TYPE_NAME_OCT => self::OCT_LABELS,
        Key::TYPE_NAME_OCT_IANA => self::OCT_LABELS,
        Key::TYPE_NAME_RSA => [
            'n' => RsaKey::DATA_N,
            'e' => RsaKey::DATA_E,
            'd' => RsaKey::DATA_D,
            'p' => RsaKey::DATA_P,
            'q' => RsaKey::DATA_Q,
            'dP' => RsaKey::DATA_DP,
            'dQ' => RsaKey::DATA_DQ,
            'qi' => RsaKey::DATA_QI,
        ],
    ];

    /**
     * The JOSE parameters that have no COSE counterpart and carry nothing a verification needs.
     */
    private const IGNORED = ['use', 'comment'];

    /**
     * The parameters whose value is a text string in both encodings.
     */
    private const TEXT_VALUES = ['kty', 'crv'];

    /**
     * @param array<string, mixed> $json the "key" object of a fixture
     *
     * @throws LogicException for a parameter the table does not know: a fixture form this harness has not met yet
     */
    public static function toCoseKey(array $json): Key
    {
        return Key::createFromData(self::toCoseKeyData($json));
    }

    /**
     * The COSE_Key map itself, for a test that wants to alter it before building the key.
     *
     * @param array<string, mixed> $json
     * @return array<int, mixed>
     */
    public static function toCoseKeyData(array $json): array
    {
        $type = $json['kty'] ?? throw new LogicException('The fixture key has no "kty"');
        if (! is_string($type)) {
            throw new LogicException(sprintf('The fixture key type is a %s, not a name', get_debug_type($type)));
        }
        if (! array_key_exists($type, self::TYPE_LABELS)) {
            throw new LogicException(sprintf('The fixture key type "%s" is not one this harness knows', $type));
        }
        $labels = self::COMMON_LABELS + self::TYPE_LABELS[$type];

        $data = [];
        foreach ($json as $name => $value) {
            if (in_array($name, self::IGNORED, true)) {
                continue;
            }
            $isHex = str_ends_with($name, '_hex');
            $parameter = $isHex ? substr($name, 0, -4) : $name;
            $label = $labels[$parameter] ?? throw new LogicException(sprintf(
                'The fixture key parameter "%s" is not one this harness knows for a "%s" key',
                $name,
                $type
            ));
            if (! is_string($value)) {
                throw new LogicException(sprintf('The fixture key parameter "%s" is not a string', $name));
            }
            $data[$label] = match (true) {
                in_array($parameter, self::TEXT_VALUES, true) => $value,
                $isHex => self::hex($value, $name),
                $parameter === 'kid' => $value,
                default => self::base64url($value, $name),
            };
        }

        return $data;
    }

    private static function hex(string $value, string $name): string
    {
        $bytes = @hex2bin($value);
        if ($bytes === false) {
            throw new LogicException(sprintf('The fixture key parameter "%s" is not hex', $name));
        }

        return $bytes;
    }

    private static function base64url(string $value, string $name): string
    {
        $bytes = base64_decode(strtr($value, '-_', '+/'), true);
        if ($bytes === false) {
            throw new LogicException(sprintf('The fixture key parameter "%s" is not base64url', $name));
        }

        return $bytes;
    }
}
