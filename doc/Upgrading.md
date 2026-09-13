# Upgrading from the `Cose\...Tag` classes

[← Documentation index](README.md)

The six COSE message classes were ported into
[spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0, which is where they belong: they describe the
shape of a CBOR structure and nothing more. The `Cose\...Tag` classes of this library are **deprecated since 4.8.0**,
raise an `E_USER_DEPRECATED` on construction, and are **removed in 5.0.0**.

| Deprecated | Replacement |
|---|---|
| `Cose\Signature\CoseSign1Tag` | `CBOR\Tag\CoseSign1Tag` |
| `Cose\Signature\CoseSignTag` | `CBOR\Tag\CoseSignTag` |
| `Cose\Mac\CoseMac0Tag` | `CBOR\Tag\CoseMac0Tag` |
| `Cose\Mac\CoseMacTag` | `CBOR\Tag\CoseMacTag` |
| `Cose\Encryption\CoseEncrypt0Tag` | `CBOR\Tag\CoseEncrypt0Tag` |
| `Cose\Encryption\CoseEncryptTag` | `CBOR\Tag\CoseEncryptTag` |
| — | `CBOR\Tag\CwtTag` (tag 61, new) |

Nothing else changes: the wire format is identical, so a message written by a deprecated class is read by its
replacement and the reverse. What the migration has to handle:

- **`create()` becomes `createFromComponents()`.** This is the one point where renaming the class is not enough:
  upstream `create()` also exists, and takes the whole `ListObject` instead of the four parts. A leftover
  four-argument `create()` call raises an `ArgumentCountError` rather than misbehaving quietly.
- **Registering the tags is no longer needed.** `Decoder::create()` resolves all seven on its own;
  `TagManager::create()->add(...)` was only ever needed because the classes lived here.
- **`getPayload()` can return `NullObject`.** Detached content is representable now, so the return type is
  `ByteStringObject|IndefiniteLengthByteStringObject|NullObject`.
- **The accessors also return the `IndefiniteLength...` variants**, which the deprecated classes rejected outright.
- **The header accessors move to `CoseHeaders`.** `getProtectedHeaderAsMap()` exists upstream but applies only the
  CBOR rules; the RFC 9052 ones — label typing, trailing data, the protected-first lookup — stay here, see
  [Reading Headers](Messages.md#reading-headers):

  ```php
  // before
  $map = $coseSign1->getProtectedHeaderAsMap();
  $alg = $map->has(1) ? $map->get(1) : null;

  // after
  $alg = CoseHeaders::fromMessage($coseSign1)->getProtectedHeaderParameter(1);
  ```

- **`getSignatures()` and `getRecipients()` still return raw lists.** Wrap them in `CoseSignature::all()` or
  `CoseRecipient::all()` to get the `[+ ...]` rule of RFC 9052 and typed entries.

`Signature1` and the other structure builders are **not** superseded and need no change.

[`examples/09-migration.php`](../examples/09-migration.php) shows a message written by a deprecated class being read
by its replacement, and the reverse. The changes of every release are listed in [RELEASES.md](../RELEASES.md).
