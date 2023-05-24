<?php

declare(strict_types=1);

namespace Cose\Signature;

use Assert\Assertion;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\Tag as Base;

final class CoseSign1Tag extends Base
{
    private const TAG_ID = 18;

    private readonly ByteStringObject $protectedHeader;

    private readonly MapObject $unprotectedHeader;

    private readonly ByteStringObject $payload;

    private readonly ByteStringObject $signature;

    public function __construct(int $additionalInformation, ?string $data, CBORObject $object)
    {
        Assertion::isInstanceOf($object, ListObject::class, 'Not a valid CoseSign1 object. No list.');
        Assertion::count($object, 4, 'Not a valid CoseSign1 object. The list shall have 4 items.');
        $protectedHeader = $object->get(0);
        $unprotectedHeader = $object->get(1);
        $payload = $object->get(2);
        $signature = $object->get(3);

        Assertion::isInstanceOf(
            $protectedHeader,
            ByteStringObject::class,
            'Not a valid CoseSign1 object. The item 1 shall be a ByteString object.'
        );
        Assertion::isInstanceOf(
            $unprotectedHeader,
            MapObject::class,
            'Not a valid CoseSign1 object. The item 2 shall be a Map object.'
        );
        Assertion::isInstanceOf(
            $payload,
            ByteStringObject::class,
            'Not a valid CoseSign1 object. The item 3 shall be a ByteString object.'
        );
        Assertion::isInstanceOf(
            $signature,
            ByteStringObject::class,
            'Not a valid CoseSign1 object. The item 4 shall be a ByteString object.'
        );

        parent::__construct($additionalInformation, $data, $object);
        $this->protectedHeader = $protectedHeader;
        $this->unprotectedHeader = $unprotectedHeader;
        $this->payload = $payload;
        $this->signature = $signature;
    }

    public static function getTagId(): int
    {
        return self::TAG_ID;
    }

    public static function createFromLoadedData(int $additionalInformation, ?string $data, CBORObject $object): Base
    {
        return new self($additionalInformation, $data, $object);
    }

    public static function create(
        MapObject $protectedHeader,
        MapObject $unprotectedHeader,
        MapObject $payload,
        ByteStringObject $signature
    ): self {
        $protectedHeaderAsBytesString = ByteStringObject::create((string) $protectedHeader);
        $payloadAsBytesString = ByteStringObject::create((string) $payload);
        $object = ListObject::create([
            $protectedHeaderAsBytesString,
            $unprotectedHeader,
            $payloadAsBytesString,
            $signature,
        ]);

        return new self(self::TAG_ID, null, $object);
    }

    public function getProtectedHeader(): ByteStringObject
    {
        return $this->protectedHeader;
    }

    public function getUnprotectedHeader(): MapObject
    {
        return $this->unprotectedHeader;
    }

    public function getPayload(): ByteStringObject
    {
        return $this->payload;
    }

    public function getSignature(): ByteStringObject
    {
        return $this->signature;
    }
}
