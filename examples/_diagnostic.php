<?php

declare(strict_types=1);

/**
 * CBOR diagnostic notation (RFC 8949 section 8) annotated with the CDDL of the RFCs, the way their appendices present
 * their own examples:
 *
 *     18([
 *       / protected h'a10126' / << {
 *         / alg / 1 : -7 / ES256 /
 *       } >>,
 *       / unprotected / {
 *         / kid / 4 : 'my-key-id'
 *       },
 *       / payload / 'Message to sign',
 *       / signature / h'0aa9...'
 *     ])
 *
 * Two layers, deliberately kept apart. ExampleEdn knows CBOR and nothing else: how an item is spelled in the
 * notation, `<< >>` for a byte string that carries CBOR, `h''` for bytes and `'text'` for a byte string that reads as
 * text. ExampleDiagnostic knows COSE: which CDDL production a list is, from the tag that wraps it or the position it
 * sits at, what a label means in a header map, a claims set or a COSE_Key, and which name an algorithm identifier
 * stands for. The first layer is what a CBOR library could ship; the second is the knowledge this library holds.
 *
 * Nothing here is part of the library's API. Every production quoted in a dump is copied from the RFC that defines
 * it and cited by section.
 */

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Normalizable;
use CBOR\OtherObject\FalseObject;
use CBOR\OtherObject\NullObject;
use CBOR\OtherObject\TrueObject;
use CBOR\OtherObject\UndefinedObject;
use CBOR\StringStream;
use CBOR\Tag;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\Tag\CwtTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithms;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;

/**
 * The CBOR layer: diagnostic notation of any item, with no idea of what the item means.
 *
 * Every method returns the lines of the notation. The first line is meant to be prefixed by whatever the caller
 * wants to say about the item (a `/ name /` comment) and the last one to be suffixed (a comma, a `>>`); the lines in
 * between carry their own indentation, relative to the first.
 */
final class ExampleEdn
{
    /**
     * @return list<string>
     */
    public static function any(CBORObject $item): array
    {
        if ($item instanceof Tag) {
            return self::tagged(example_tag_number($item), self::any($item->getValue()));
        }
        if ($item instanceof ListObject || $item instanceof IndefiniteLengthListObject) {
            $children = [];
            foreach ($item as $child) {
                $children[] = ['', self::any($child)];
            }

            return self::block('[', $children, ']');
        }
        if ($item instanceof MapObject || $item instanceof IndefiniteLengthMapObject) {
            $children = [];
            foreach ($item as $entry) {
                $children[] = [self::scalar($entry->getKey()) . ' : ', self::any($entry->getValue())];
            }

            return self::block('{', $children, '}');
        }

        return [self::scalar($item)];
    }

    /**
     * A byte string that carries CBOR, written `<< item >>` as RFC 8949 section 8.1 allows.
     *
     * @param list<string> $inner the notation of the embedded item
     * @return list<string>
     */
    public static function embedded(array $inner): array
    {
        $inner[0] = '<< ' . $inner[0];
        $inner[count($inner) - 1] .= ' >>';

        return $inner;
    }

    /**
     * @param list<string> $inner
     * @return list<string>
     */
    public static function tagged(int $number, array $inner): array
    {
        $inner[0] = $number . '(' . $inner[0];
        $inner[count($inner) - 1] .= ')';

        return $inner;
    }

    /**
     * An array or a map: the children on their own lines, indented, separated by commas.
     *
     * @param list<array{string, list<string>}> $children each a prefix (comment, key) and the lines of the value
     * @return list<string>
     */
    public static function block(string $open, array $children, string $close): array
    {
        if ($children === []) {
            return [$open . $close];
        }
        $lines = [$open];
        $last = count($children) - 1;
        foreach ($children as $index => [$prefix, $inner]) {
            $inner[0] = $prefix . $inner[0];
            if ($index !== $last) {
                $inner[count($inner) - 1] .= ',';
            }
            foreach ($inner as $line) {
                $lines[] = '  ' . $line;
            }
        }
        $lines[] = $close;

        return $lines;
    }

    public static function scalar(CBORObject $item): string
    {
        if ($item instanceof ByteStringObject || $item instanceof IndefiniteLengthByteStringObject) {
            return self::bytes($item->getValue());
        }
        if ($item instanceof TextStringObject || $item instanceof IndefiniteLengthTextStringObject) {
            return json_encode($item->getValue(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        if ($item instanceof UnsignedIntegerObject || $item instanceof NegativeIntegerObject) {
            return $item->normalize();
        }
        if ($item instanceof NullObject) {
            return 'null';
        }
        if ($item instanceof TrueObject) {
            return 'true';
        }
        if ($item instanceof FalseObject) {
            return 'false';
        }
        if ($item instanceof UndefinedObject) {
            return 'undefined';
        }
        if ($item instanceof Normalizable) {
            return json_encode($item->normalize(), JSON_THROW_ON_ERROR);
        }

        return sprintf('simple(%d)', $item->getAdditionalInformation());
    }

    /**
     * RFC 8949 section 8: `h'..'` for bytes, and `'..'` when the bytes read as text, which is how RFC 9052 Appendix C
     * writes a payload of ASCII.
     */
    public static function bytes(string $value): string
    {
        if ($value !== '' && preg_match('/^[\P{C}]+$/u', $value) === 1 && ! str_contains($value, "'")) {
            return "'" . $value . "'";
        }

        return "h'" . bin2hex($value) . "'";
    }
}

/**
 * The COSE layer: the same notation, with every list named after the CDDL production it is an instance of and every
 * label after the header parameter, claim or key parameter it stands for.
 *
 * A production is recognized from the tag that wraps it, from the position it sits at in its parent (the items of
 * "signatures" are COSE_Signature, the value of label 11 is a COSE_Countersignature) or, for the structures a
 * signature or a MAC is computed over, from the context string that opens them. The productions met on the way are
 * printed before the notation, quoted from the RFC.
 */
final class ExampleDiagnostic
{
    /**
     * @var array<string, string> production => the CDDL that defines it, with the RFC and the section it is quoted from
     */
    private const CDDL = [
        'COSE_Sign1_Tagged' => 'COSE_Sign1_Tagged = #6.18(COSE_Sign1)  ; RFC 9052 section 4.2',
        'COSE_Sign1' => 'COSE_Sign1 = [ Headers, payload : bstr / nil, signature : bstr ]',
        'COSE_Sign_Tagged' => 'COSE_Sign_Tagged = #6.98(COSE_Sign)  ; RFC 9052 section 4.1',
        'COSE_Sign' => 'COSE_Sign = [ Headers, payload : bstr / nil, signatures : [+ COSE_Signature] ]',
        'COSE_Signature' => 'COSE_Signature = [ Headers, signature : bstr ]',
        'COSE_Encrypt_Tagged' => 'COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)  ; RFC 9052 section 5.1',
        'COSE_Encrypt' => 'COSE_Encrypt = [ Headers, ciphertext : bstr / nil, recipients : [+COSE_recipient] ]',
        'COSE_recipient' => 'COSE_recipient = [ Headers, ciphertext : bstr / nil, ? recipients : [+COSE_recipient] ]',
        'COSE_Encrypt0_Tagged' => 'COSE_Encrypt0_Tagged = #6.16(COSE_Encrypt0)  ; RFC 9052 section 5.2',
        'COSE_Encrypt0' => 'COSE_Encrypt0 = [ Headers, ciphertext : bstr / nil ]',
        'COSE_Mac_Tagged' => 'COSE_Mac_Tagged = #6.97(COSE_Mac)  ; RFC 9052 section 6.1',
        'COSE_Mac' => 'COSE_Mac = [ Headers, payload : bstr / nil, tag : bstr, recipients : [+COSE_recipient] ]',
        'COSE_Mac0_Tagged' => 'COSE_Mac0_Tagged = #6.17(COSE_Mac0)  ; RFC 9052 section 6.2',
        'COSE_Mac0' => 'COSE_Mac0 = [ Headers, payload : bstr / nil, tag : bstr ]',
        'Headers' => 'Headers = ( protected : empty_or_serialized_map, unprotected : header_map )  ; RFC 9052 section 3',
        'empty_or_serialized_map' => 'empty_or_serialized_map = bstr .cbor header_map / bstr .size 0',
        'Sig_structure' => 'Sig_structure = [ context : "Signature" / "Signature1", body_protected : empty_or_serialized_map, ? sign_protected : empty_or_serialized_map, external_aad : bstr, payload : bstr ]  ; RFC 9052 section 4.4',
        'MAC_structure' => 'MAC_structure = [ context : "MAC" / "MAC0", protected : empty_or_serialized_map, external_aad : bstr, payload : bstr ]  ; RFC 9052 section 6.3',
        'Enc_structure' => 'Enc_structure = [ context : "Encrypt" / "Encrypt0" / "Enc_Recipient" / "Mac_Recipient" / "Rec_Recipient", protected : empty_or_serialized_map, external_aad : bstr ]  ; RFC 9052 section 5.3',
        'COSE_Key' => 'COSE_Key = { 1 => tstr / int, ? 2 => bstr, ? 3 => tstr / int, ? 4 => [+ (tstr / int)], ? 5 => bstr, * label => values }  ; RFC 9052 section 7',
        'COSE_Countersignature' => 'COSE_Countersignature = COSE_Signature  ; RFC 9338 section 3.1',
        'COSE_Countersignature_Tagged' => 'COSE_Countersignature_Tagged = #6.19(COSE_Countersignature)',
        'COSE_Countersignature0' => 'COSE_Countersignature0 = bstr  ; RFC 9338 section 3.2',
        'Countersign_structure' => 'Countersign_structure = [ context : "CounterSignature" / "CounterSignature0" / "CounterSignatureV2" / "CounterSignature0V2", body_protected : empty_or_serialized_map, ? sign_protected : empty_or_serialized_map, external_aad : bstr, payload : bstr, ? other_fields : [+ bstr] ]  ; RFC 9338 section 3.3',
        'CWT' => 'CWT = #6.61(COSE_Messages)  ; RFC 8392 section 6, the tag is optional',
        'Claims-Set' => 'Claims-Set = { * Claim-Label => any }  ; RFC 8392 section 3, labels 1 to 7 in section 4',
        'Hash_Envelope_Protected_Header' => 'Hash_Envelope_Protected_Header = { ? &(alg: 1) => int, &(payload_hash_alg: 258) => int, ? &(payload_preimage_content_type: 259) => uint / tstr, ? &(payload_location: 260) => tstr, * (int / tstr) => any }  ; RFC 9995 section 2',
        'Receipt' => '&(receipts: 394) => [+ bstr .cbor Receipt], Receipt = Receipt_For_Inclusion / Receipt_For_Consistency  ; RFC 9942 section 2',
        'RFC9162_SHA256_Inclusion_Proof_Content' => 'RFC9162_SHA256_Inclusion_Proof_Content = [ tree_size: uint, leaf_index: uint, inclusion_path: [+ bstr] ]  ; RFC 9942 section 2',
        'RFC9162_SHA256_Consistency_Proof_Content' => 'RFC9162_SHA256_Consistency_Proof_Content = [ tree_size_1: uint, tree_size_2: uint, consistency_path: [+ bstr] ]  ; RFC 9942 section 2',
    ];

    /**
     * The IANA "COSE Header Parameters" registry, as far as the examples go.
     */
    private const HEADER_LABELS = [
        1 => 'alg',
        2 => 'crit',
        3 => 'content type',
        4 => 'kid',
        5 => 'IV',
        6 => 'Partial IV',
        7 => 'counter signature',
        CoseHeaders::LABEL_COUNTERSIGNATURE_V2 => 'Countersignature version 2',
        CoseHeaders::LABEL_COUNTERSIGNATURE0_V2 => 'Countersignature0 version 2',
        CoseHeaders::LABEL_CWT_CLAIMS => 'CWT Claims',
        CoseHeaders::LABEL_TYP => 'typ',
        CoseHeaders::LABEL_X5BAG => 'x5bag',
        CoseHeaders::LABEL_X5CHAIN => 'x5chain',
        CoseHeaders::LABEL_X5T => 'x5t',
        CoseHeaders::LABEL_X5U => 'x5u',
        CoseHeaders::LABEL_PAYLOAD_HASH_ALG => 'payload hash alg',
        CoseHeaders::LABEL_PREIMAGE_CONTENT_TYPE => 'payload preimage content type',
        CoseHeaders::LABEL_PAYLOAD_LOCATION => 'payload location',
        CoseHeaders::LABEL_3161_TTC => '3161-ttc',
        CoseHeaders::LABEL_3161_CTT => '3161-ctt',
        CoseHeaders::LABEL_RECEIPTS => 'receipts',
        CoseHeaders::LABEL_VDS => 'vds',
        CoseHeaders::LABEL_VDP => 'vdp',
        CoseHeaders::LABEL_EPHEMERAL_KEY => 'ephemeral key',
        CoseHeaders::LABEL_STATIC_KEY => 'static key',
        CoseHeaders::LABEL_STATIC_KEY_ID => 'static kid',
        CoseHeaders::LABEL_SALT => 'salt',
        CoseHeaders::LABEL_PARTY_U_IDENTITY => 'PartyU identity',
        CoseHeaders::LABEL_PARTY_U_NONCE => 'PartyU nonce',
        CoseHeaders::LABEL_PARTY_U_OTHER => 'PartyU other',
        CoseHeaders::LABEL_PARTY_V_IDENTITY => 'PartyV identity',
        CoseHeaders::LABEL_PARTY_V_NONCE => 'PartyV nonce',
        CoseHeaders::LABEL_PARTY_V_OTHER => 'PartyV other',
        CoseHeaders::LABEL_X5T_SENDER => 'x5t-sender',
        CoseHeaders::LABEL_X5U_SENDER => 'x5u-sender',
        CoseHeaders::LABEL_X5CHAIN_SENDER => 'x5chain-sender',
    ];

    /**
     * RFC 8392 section 4.
     */
    private const CLAIM_LABELS = [
        1 => 'iss',
        2 => 'sub',
        3 => 'aud',
        4 => 'exp',
        5 => 'nbf',
        6 => 'iat',
        7 => 'cti',
    ];

    /**
     * The common COSE_Key parameters (RFC 9052 section 7.1), then the ones of each key type (RFC 9053 section 7,
     * RFC 8230 section 4, RFC 9964 section 3).
     */
    private const KEY_LABELS = [
        Key::TYPE => 'kty',
        Key::KID => 'kid',
        Key::ALG => 'alg',
        Key::KEY_OPS => 'key_ops',
        Key::BASE_IV => 'Base IV',
    ];

    private const KEY_TYPE_LABELS = [
        Key::TYPE_OKP => [-1 => 'crv', -2 => 'x', -4 => 'd'],
        Key::TYPE_EC2 => [-1 => 'crv', -2 => 'x', -3 => 'y', -4 => 'd'],
        Key::TYPE_RSA => [-1 => 'n', -2 => 'e', -3 => 'd', -4 => 'p', -5 => 'q', -6 => 'dP', -7 => 'dQ', -8 => 'qInv'],
        Key::TYPE_OCT => [-1 => 'k'],
        Key::TYPE_AKP => [-1 => 'pub', -2 => 'priv'],
    ];

    private const KEY_TYPE_NAMES = [
        Key::TYPE_OKP => 'OKP',
        Key::TYPE_EC2 => 'EC2',
        Key::TYPE_RSA => 'RSA',
        Key::TYPE_OCT => 'Symmetric',
        Key::TYPE_AKP => 'AKP',
    ];

    private const CURVE_NAMES = [
        Ec2Key::CURVE_P256 => Ec2Key::CURVE_NAME_P256,
        Ec2Key::CURVE_P384 => Ec2Key::CURVE_NAME_P384,
        Ec2Key::CURVE_P521 => Ec2Key::CURVE_NAME_P521,
        OkpKey::CURVE_X25519 => OkpKey::CURVE_NAME_X25519,
        OkpKey::CURVE_X448 => OkpKey::CURVE_NAME_X448,
        OkpKey::CURVE_ED25519 => OkpKey::CURVE_NAME_ED25519,
        OkpKey::CURVE_ED448 => OkpKey::CURVE_NAME_ED448,
        Ec2Key::CURVE_P256K => Ec2Key::CURVE_NAME_SECP256K1,
        Ec2Key::CURVE_BP256 => Ec2Key::CURVE_NAME_BP256,
        Ec2Key::CURVE_BP320 => Ec2Key::CURVE_NAME_BP320,
        Ec2Key::CURVE_BP384 => Ec2Key::CURVE_NAME_BP384,
        Ec2Key::CURVE_BP512 => Ec2Key::CURVE_NAME_BP512,
    ];

    private const KEY_OPS_NAMES = [
        Key::OP_SIGN => 'sign',
        Key::OP_VERIFY => 'verify',
        Key::OP_ENCRYPT => 'encrypt',
        Key::OP_DECRYPT => 'decrypt',
        Key::OP_WRAP_KEY => 'wrap key',
        Key::OP_UNWRAP_KEY => 'unwrap key',
        Key::OP_DERIVE_KEY => 'derive key',
        Key::OP_DERIVE_BITS => 'derive bits',
        Key::OP_MAC_CREATE => 'MAC create',
        Key::OP_MAC_VERIFY => 'MAC verify',
    ];

    /**
     * The message tags and the fields of the list each one wraps, RFC 9052 sections 4 to 6.
     */
    private const MESSAGES = [
        CoseSign1Tag::class => ['COSE_Sign1', ['protected', 'unprotected', 'payload', 'signature']],
        CoseSignTag::class => ['COSE_Sign', ['protected', 'unprotected', 'payload', 'signatures']],
        CoseEncryptTag::class => ['COSE_Encrypt', ['protected', 'unprotected', 'ciphertext', 'recipients']],
        CoseEncrypt0Tag::class => ['COSE_Encrypt0', ['protected', 'unprotected', 'ciphertext']],
        CoseMacTag::class => ['COSE_Mac', ['protected', 'unprotected', 'payload', 'tag', 'recipients']],
        CoseMac0Tag::class => ['COSE_Mac0', ['protected', 'unprotected', 'payload', 'tag']],
    ];

    /**
     * The structures a signature, a MAC or an AEAD is computed over, by the context string that opens them.
     */
    private const STRUCTURES = [
        'Signature1' => ['Sig_structure', ['context', 'body_protected', 'external_aad', 'payload']],
        'Signature' => ['Sig_structure', ['context', 'body_protected', 'sign_protected', 'external_aad', 'payload']],
        'MAC' => ['MAC_structure', ['context', 'protected', 'external_aad', 'payload']],
        'MAC0' => ['MAC_structure', ['context', 'protected', 'external_aad', 'payload']],
        'Encrypt' => ['Enc_structure', ['context', 'protected', 'external_aad']],
        'Encrypt0' => ['Enc_structure', ['context', 'protected', 'external_aad']],
        'Enc_Recipient' => ['Enc_structure', ['context', 'protected', 'external_aad']],
        'Mac_Recipient' => ['Enc_structure', ['context', 'protected', 'external_aad']],
        'Rec_Recipient' => ['Enc_structure', ['context', 'protected', 'external_aad']],
        'CounterSignature' => ['Countersign_structure', ['context', 'body_protected', 'sign_protected', 'external_aad', 'payload']],
        'CounterSignature0' => ['Countersign_structure', ['context', 'body_protected', 'external_aad', 'payload']],
        'CounterSignatureV2' => ['Countersign_structure', ['context', 'body_protected', 'sign_protected', 'external_aad', 'payload', 'other_fields']],
        'CounterSignature0V2' => ['Countersign_structure', ['context', 'body_protected', 'external_aad', 'payload', 'other_fields']],
    ];

    /**
     * @var array<string, true> the productions met while rendering, in order of first use
     */
    private array $used = [];

    /**
     * Whether the COSE_Sign1 being rendered is a CWT (tag 61, "typ", or CWT Claims in the protected header), so that
     * its payload is shown as the claims set it is.
     */
    private bool $cwt = false;

    /**
     * @var array<int, string>|null the identifier => name map of the IANA COSE Algorithms registry, from Cose\Algorithms
     */
    private static ?array $algorithms = null;

    /**
     * Prints the CDDL of the productions the item instantiates, then the item in diagnostic notation.
     */
    /**
     * @param string|null $as what a bare map is: 'COSE_Key' or 'Claims-Set'; a header map when not said, since that is
     *                        what the examples decode most
     */
    public static function render(CBORObject $item, ?string $as = null): void
    {
        $self = new self();
        $lines = match ($as) {
            'COSE_Key' => $self->key($item),
            'Claims-Set' => $self->claims($item),
            default => $self->message($item),
        };

        foreach (array_keys($self->used) as $production) {
            echo '  ; ', self::CDDL[$production], PHP_EOL;
        }
        foreach ($lines as $line) {
            echo '  ', $line, PHP_EOL;
        }
    }

    /**
     * A COSE message, a CWT, a structure to be signed, or anything else.
     *
     * @return list<string>
     */
    private function message(CBORObject $item): array
    {
        if ($item instanceof CwtTag) {
            $this->mark('CWT');
            $this->cwt = true;

            return ExampleEdn::tagged(61, $this->message($item->getValue()));
        }
        foreach (self::MESSAGES as $class => [$production, $fields]) {
            if ($item instanceof $class) {
                $this->mark($production . '_Tagged');

                return ExampleEdn::tagged(example_tag_number($item), $this->fields($item->getValue(), $production, $fields));
            }
        }
        if ($item instanceof Tag && example_tag_number($item) === HeaderMapHelper::TAG_COUNTERSIGNATURE) {
            $this->mark('COSE_Countersignature_Tagged');

            return ExampleEdn::tagged(19, $this->countersignature($item->getValue()));
        }
        if (self::isList($item) && count($item) > 0) {
            $context = $item->get(0);
            if ($context instanceof TextStringObject && isset(self::STRUCTURES[$context->getValue()])) {
                [$production, $fields] = self::STRUCTURES[$context->getValue()];

                return $this->fields($item, $production, $fields);
            }
        }
        if (self::isMap($item)) {
            return $this->headerMap($item);
        }

        return ExampleEdn::any($item);
    }

    /**
     * A list whose items are named by a CDDL production, in order.
     *
     * @param list<string> $fields
     * @return list<string>
     */
    private function fields(CBORObject $list, string $production, array $fields): array
    {
        $this->mark($production);
        if (! self::isList($list)) {
            return ExampleEdn::any($list);
        }
        $children = [];
        foreach ($list as $index => $item) {
            $field = $fields[$index] ?? null;
            if ($field === null) {
                $children[] = ['', ExampleEdn::any($item)];
                continue;
            }
            $children[] = $this->field($field, $item, $production);
        }

        return ExampleEdn::block('[', $children, ']');
    }

    /**
     * One named item of a message or a structure: the comment and the value, rendered according to the field.
     *
     * @return array{string, list<string>}
     */
    private function field(string $field, CBORObject $item, string $production): array
    {
        $comment = '/ ' . $field . ' / ';
        switch ($field) {
            case 'protected':
            case 'body_protected':
            case 'sign_protected':
                if (in_array($production, ['COSE_Sign1', 'COSE_Sign', 'COSE_Encrypt', 'COSE_Encrypt0', 'COSE_Mac', 'COSE_Mac0', 'COSE_Signature', 'COSE_recipient', 'COSE_Countersignature'], true)) {
                    $this->mark('Headers');
                }

                return $this->protected($field, $item);
            case 'unprotected':
                return [$comment, self::isMap($item) ? $this->headerMap($item) : ExampleEdn::any($item)];
            case 'signatures':
                return [$comment, $this->listOf($item, fn (CBORObject $entry): array => $this->named('COSE_Signature', $this->fields($entry, 'COSE_Signature', ['protected', 'unprotected', 'signature'])))];
            case 'recipients':
                return [$comment, $this->listOf($item, fn (CBORObject $entry): array => $this->named('COSE_recipient', $this->fields($entry, 'COSE_recipient', ['protected', 'unprotected', 'ciphertext', 'recipients'])))];
            case 'other_fields':
                return [$comment, $this->listOf($item, static fn (CBORObject $entry): array => ExampleEdn::any($entry))];
            case 'payload':
                if ($production === 'COSE_Sign1' && $this->cwt) {
                    return [$comment, $this->embeddedOr($item, fn (CBORObject $claims): array => $this->claims($claims))];
                }

                return [$comment, ExampleEdn::any($item)];
            default:
                return [$comment, ExampleEdn::any($item)];
        }
    }

    /**
     * empty_or_serialized_map: `h''` for no header, otherwise the bytes in the comment and the map they encode as the
     * value, `<< { ... } >>`, which is how RFC 9052 Appendix C presents every protected header.
     *
     * @return array{string, list<string>}
     */
    private function protected(string $field, CBORObject $item): array
    {
        $this->mark('empty_or_serialized_map');
        if (! $item instanceof ByteStringObject && ! $item instanceof IndefiniteLengthByteStringObject) {
            return ['/ ' . $field . ' / ', ExampleEdn::any($item)];
        }
        $bytes = $item->getValue();
        if ($bytes === '') {
            return ['/ ' . $field . ' / ', ["h''"]];
        }
        $map = Decoder::create()->decode(StringStream::create($bytes));
        if (self::isMap($map) && ($map->has(CoseHeaders::LABEL_CWT_CLAIMS) || (
            $map->has(CoseHeaders::LABEL_TYP) && self::scalarOf($map->get(CoseHeaders::LABEL_TYP)) === 'application/cwt'
        ))) {
            $this->cwt = true;
        }

        return [
            sprintf("/ %s h'%s' / ", $field, bin2hex($bytes)),
            ExampleEdn::embedded(self::isMap($map) ? $this->headerMap($map) : ExampleEdn::any($map)),
        ];
    }

    /**
     * header_map: each entry under the name of its label, its value rendered according to what the label expects.
     *
     * @return list<string>
     */
    private function headerMap(CBORObject $map): array
    {
        if (! self::isMap($map)) {
            return ExampleEdn::any($map);
        }
        $children = [];
        foreach ($map as $entry) {
            $key = $entry->getKey();
            $value = $entry->getValue();
            $label = self::intOf($key);
            $name = $label !== null ? (self::HEADER_LABELS[$label] ?? null) : null;
            $prefix = ($name !== null ? '/ ' . $name . ' / ' : '') . ExampleEdn::scalar($key) . ' : ';
            $children[] = [$prefix, $this->headerValue($label, $value)];
        }

        return ExampleEdn::block('{', $children, '}');
    }

    /**
     * @return list<string>
     */
    private function headerValue(?int $label, CBORObject $value): array
    {
        switch ($label) {
            case 1:
            case CoseHeaders::LABEL_PAYLOAD_HASH_ALG:
                return [$this->algorithm($value)];
            case 2:
                return $this->listOf($value, fn (CBORObject $item): array => [ExampleEdn::scalar($item) . self::name(self::HEADER_LABELS, $item)]);
            case 7:
                return $this->countersignature($value);
            case CoseHeaders::LABEL_COUNTERSIGNATURE_V2:
                return $this->countersignatures($value);
            case CoseHeaders::LABEL_COUNTERSIGNATURE0_V2:
                $this->mark('COSE_Countersignature0');

                return ExampleEdn::any($value);
            case CoseHeaders::LABEL_CWT_CLAIMS:
                return $this->claims($value);
            case CoseHeaders::LABEL_X5T:
            case CoseHeaders::LABEL_X5T_SENDER:
                if (self::isList($value) && count($value) === 2) {
                    return ExampleEdn::block('[', [
                        ['/ hashAlg / ', [$this->algorithm($value->get(0))]],
                        ['/ hashValue / ', ExampleEdn::any($value->get(1))],
                    ], ']');
                }

                return ExampleEdn::any($value);
            case CoseHeaders::LABEL_EPHEMERAL_KEY:
            case CoseHeaders::LABEL_STATIC_KEY:
                return $this->key($value);
            case CoseHeaders::LABEL_RECEIPTS:
                $this->mark('Receipt');

                return $this->listOf($value, fn (CBORObject $receipt): array => $this->embeddedOr($receipt, fn (CBORObject $message): array => $this->message($message)));
            case CoseHeaders::LABEL_VDS:
                return [ExampleEdn::scalar($value) . (self::intOf($value) === Rfc9162Sha256::IDENTIFIER ? ' / RFC9162_SHA256 /' : '')];
            case CoseHeaders::LABEL_VDP:
                return $this->proofs($value);
            default:
                return ExampleEdn::any($value);
        }
    }

    /**
     * RFC 9942 section 2: the proofs of a receipt, each a byte string that carries a CBOR array.
     *
     * @return list<string>
     */
    private function proofs(CBORObject $map): array
    {
        if (! self::isMap($map)) {
            return ExampleEdn::any($map);
        }
        $children = [];
        foreach ($map as $entry) {
            $label = self::intOf($entry->getKey());
            [$name, $production, $fields] = match ($label) {
                Rfc9162Sha256::LABEL_INCLUSION_PROOF => ['inclusion-proof', 'RFC9162_SHA256_Inclusion_Proof_Content', ['tree_size', 'leaf_index', 'inclusion_path']],
                Rfc9162Sha256::LABEL_CONSISTENCY_PROOF => ['consistency-proof', 'RFC9162_SHA256_Consistency_Proof_Content', ['tree_size_1', 'tree_size_2', 'consistency_path']],
                default => [null, null, []],
            };
            if ($name === null) {
                $children[] = [ExampleEdn::scalar($entry->getKey()) . ' : ', ExampleEdn::any($entry->getValue())];
                continue;
            }
            $children[] = [
                sprintf('/ %s / %d : ', $name, $label),
                $this->listOf($entry->getValue(), fn (CBORObject $proof): array => $this->embeddedOr($proof, fn (CBORObject $content): array => $this->fields($content, $production, $fields))),
            ];
        }

        return ExampleEdn::block('{', $children, '}');
    }

    /**
     * RFC 9338 section 2: "COSE_Countersignature / [+ COSE_Countersignature]", told apart the way HeaderMapHelper
     * does: a byte string opens a single one, a list or a tag opens the array.
     *
     * @return list<string>
     */
    private function countersignatures(CBORObject $value): array
    {
        if ($value instanceof Tag || (self::isList($value) && count($value) > 0 && (
            $value->get(0) instanceof ByteStringObject || $value->get(0) instanceof IndefiniteLengthByteStringObject
        ))) {
            return $this->countersignature($value);
        }

        return $this->listOf($value, fn (CBORObject $item): array => $this->countersignature($item));
    }

    /**
     * @return list<string>
     */
    private function countersignature(CBORObject $value): array
    {
        $this->mark('COSE_Countersignature');
        if ($value instanceof Tag) {
            $this->mark('COSE_Countersignature_Tagged');

            return ExampleEdn::tagged(example_tag_number($value), $this->countersignature($value->getValue()));
        }
        return $this->named('COSE_Countersignature', $this->fields($value, 'COSE_Signature', ['protected', 'unprotected', 'signature']));
    }

    /**
     * An untagged list, named after the production its position makes it: `/ COSE_recipient / [`.
     *
     * @param list<string> $lines
     * @return list<string>
     */
    private function named(string $production, array $lines): array
    {
        $lines[0] = '/ ' . $production . ' / ' . $lines[0];

        return $lines;
    }

    /**
     * RFC 8392 section 4: the registered claims by name; the values are what they are.
     *
     * @return list<string>
     */
    private function claims(CBORObject $map): array
    {
        $this->mark('Claims-Set');
        if (! self::isMap($map)) {
            return ExampleEdn::any($map);
        }
        $children = [];
        foreach ($map as $entry) {
            $children[] = [self::name(self::CLAIM_LABELS, $entry->getKey(), true) . ExampleEdn::scalar($entry->getKey()) . ' : ', ExampleEdn::any($entry->getValue())];
        }

        return ExampleEdn::block('{', $children, '}');
    }

    /**
     * RFC 9052 section 7: a COSE_Key, the type-specific labels resolved once "kty" is known.
     *
     * @return list<string>
     */
    private function key(CBORObject $map): array
    {
        $this->mark('COSE_Key');
        if (! self::isMap($map)) {
            return ExampleEdn::any($map);
        }
        $type = $map->has(Key::TYPE) ? self::intOf($map->get(Key::TYPE)) : null;
        $labels = self::KEY_LABELS + (self::KEY_TYPE_LABELS[$type] ?? []);
        $children = [];
        foreach ($map as $entry) {
            $key = $entry->getKey();
            $value = $entry->getValue();
            $label = self::intOf($key);
            $prefix = self::name($labels, $key, true) . ExampleEdn::scalar($key) . ' : ';
            $children[] = [$prefix, match (true) {
                $label === Key::TYPE => [ExampleEdn::scalar($value) . self::name(self::KEY_TYPE_NAMES, $value)],
                $label === Key::ALG => [$this->algorithm($value)],
                $label === Key::KEY_OPS => $this->listOf($value, static fn (CBORObject $op): array => [ExampleEdn::scalar($op) . self::name(self::KEY_OPS_NAMES, $op)]),
                $label === -1 && in_array($type, [Key::TYPE_OKP, Key::TYPE_EC2], true) => [ExampleEdn::scalar($value) . self::name(self::CURVE_NAMES, $value)],
                default => ExampleEdn::any($value),
            }];
        }

        return ExampleEdn::block('{', $children, '}');
    }

    /**
     * An algorithm identifier with its name after it, `-7 / ES256 /`, as RFC 9052 Appendix C writes them.
     */
    private function algorithm(CBORObject $value): string
    {
        self::$algorithms ??= self::algorithmNames();

        return ExampleEdn::scalar($value) . self::name(self::$algorithms, $value);
    }

    /**
     * @return array<int, string>
     */
    private static function algorithmNames(): array
    {
        $names = [];
        foreach ((new ReflectionClass(Algorithms::class))->getConstants() as $constant => $identifier) {
            if (! is_int($identifier) || ! str_starts_with($constant, 'COSE_ALGORITHM_')) {
                continue;
            }
            $names[$identifier] ??= str_replace('_', '-', substr($constant, strlen('COSE_ALGORITHM_')));
        }

        return $names;
    }

    /**
     * The name of an integer in a registry, as a `/ name /` comment, empty when the registry has none.
     *
     * @param array<int, string> $registry
     */
    private static function name(array $registry, CBORObject $item, bool $before = false): string
    {
        if (! $item instanceof UnsignedIntegerObject && ! $item instanceof NegativeIntegerObject) {
            return '';
        }
        $name = $registry[(int) $item->normalize()] ?? null;
        if ($name === null) {
            return '';
        }

        return $before ? '/ ' . $name . ' / ' : ' / ' . $name . ' /';
    }

    /**
     * A list whose items are all rendered the same way.
     *
     * @param callable(CBORObject): list<string> $render
     * @return list<string>
     */
    private function listOf(CBORObject $list, callable $render): array
    {
        if (! self::isList($list)) {
            return $render($list);
        }
        $children = [];
        foreach ($list as $item) {
            $children[] = ['', $render($item)];
        }

        return ExampleEdn::block('[', $children, ']');
    }

    /**
     * A byte string that carries CBOR, rendered `<< ... >>` through $render; anything else as it is.
     *
     * @param callable(CBORObject): list<string> $render
     * @return list<string>
     */
    private function embeddedOr(CBORObject $item, callable $render): array
    {
        if (! $item instanceof ByteStringObject && ! $item instanceof IndefiniteLengthByteStringObject) {
            return ExampleEdn::any($item);
        }
        try {
            $inner = Decoder::create()->decode(StringStream::create($item->getValue()));
        } catch (Throwable) {
            return ExampleEdn::any($item);
        }

        return ExampleEdn::embedded($render($inner));
    }

    private function mark(string $production): void
    {
        $this->used[$production] = true;
    }

    private static function intOf(CBORObject $item): ?int
    {
        if (! $item instanceof UnsignedIntegerObject && ! $item instanceof NegativeIntegerObject) {
            return null;
        }

        return (int) $item->normalize();
    }

    private static function scalarOf(CBORObject $item): mixed
    {
        return $item instanceof Normalizable ? $item->normalize() : null;
    }

    /**
     * @phpstan-assert-if-true ListObject|IndefiniteLengthListObject $item
     */
    private static function isList(CBORObject $item): bool
    {
        return $item instanceof ListObject || $item instanceof IndefiniteLengthListObject;
    }

    /**
     * @phpstan-assert-if-true MapObject|IndefiniteLengthMapObject $item
     */
    private static function isMap(CBORObject $item): bool
    {
        return $item instanceof MapObject || $item instanceof IndefiniteLengthMapObject;
    }
}
