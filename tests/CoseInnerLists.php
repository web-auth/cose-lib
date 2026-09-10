<?php

declare(strict_types=1);

namespace Cose\Tests;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\OtherObject\NullObject;
use CBOR\UnsignedIntegerObject;

/**
 * The one-entry "signatures" and "recipients" lists the multi-party messages need.
 *
 * RFC 9052 writes both as "[+ ...]": one or more. A test that only cares about the headers of the enclosing message
 * still has to supply a well-formed entry, and building it in one place keeps the shape in a single spot.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-4.1
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-5.1
 */
trait CoseInnerLists
{
    /**
     * COSE_Signature = [ Headers, signature : bstr ]
     */
    private static function signature(string $kid = 'signer', string $signatureValue = 'signature'): ListObject
    {
        return ListObject::create([
            ByteStringObject::create(''),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid)),
            ]),
            ByteStringObject::create($signatureValue),
        ]);
    }

    private static function signatures(string ...$kids): ListObject
    {
        $kids = $kids === [] ? ['signer'] : $kids;

        return ListObject::create(array_map(static fn (string $kid): ListObject => self::signature($kid), $kids));
    }

    /**
     * COSE_recipient = [ Headers, ciphertext : bstr / nil, ? recipients : [+COSE_recipient] ]
     */
    private static function recipient(string $kid = 'recipient', ?string $ciphertext = 'wrapped'): ListObject
    {
        return ListObject::create([
            ByteStringObject::create(''),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid)),
            ]),
            $ciphertext === null ? NullObject::create() : ByteStringObject::create($ciphertext),
        ]);
    }

    private static function recipients(string ...$kids): ListObject
    {
        $kids = $kids === [] ? ['recipient'] : $kids;

        return ListObject::create(array_map(static fn (string $kid): ListObject => self::recipient($kid), $kids));
    }
}
