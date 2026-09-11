<?php

declare(strict_types=1);

namespace Cose\Algorithm\KeyManagement;

/**
 * The direct encryption class of RFC 9052 section 8.5.1: "share a secret between the sender and the recipient that
 * is used either directly or after manipulation as the CEK".
 *
 * "direct" (-6, RFC 9053 section 6.1.1) uses the shared secret as it is; "direct+HKDF-SHA-256", "direct+HKDF-SHA-512",
 * "direct+HKDF-AES-128" and "direct+HKDF-AES-256" (-10 to -13, section 6.1.2) run it through the HKDF of section 5.1
 * with the COSE_KDF_Context of section 5.2. Nothing is transported: the "ciphertext" of the recipient "MUST be a
 * zero-length byte string", its "recipients" "MUST be absent", and it "MUST be the only mode used on the message".
 *
 * isDirect() is true for the whole family.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-8.5.1
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-6.1
 */
interface DirectEncryption extends KeyManagement
{
}
