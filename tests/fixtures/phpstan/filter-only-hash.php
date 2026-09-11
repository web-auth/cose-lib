<?php

declare(strict_types=1);

use Cose\Algorithm\Hash\FilterOnlyHash;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA256_64;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Hash\SHA512_256;
use Cose\Algorithm\Hash\SHAKE128;
use Cose\Algorithm\Hash\SHAKE256;

// Analysed by Cose\Tests\Algorithm\Hash\FilterOnlyTypeTest, never executed: PHPStan has to reject the two calls marked
// "Filter Only" below and accept the others. The test finds the two lines by that marker.

function integrity(Hash $hash, string $data): string
{
    return $hash->hash($data);
}

function filter(FilterOnlyHash $hash, string $data): string
{
    return $hash->hash($data);
}

integrity(SHA256::create(), 'data');
integrity(SHA512_256::create(), 'data');
integrity(SHAKE128::create(), 'data');
integrity(SHA384::create(), 'data');
integrity(SHA512::create(), 'data');
integrity(SHAKE256::create(), 'data');
integrity(SHA1::create(), 'data'); // Filter Only
integrity(SHA256_64::create(), 'data'); // Filter Only

filter(SHA1::create(), 'data');
filter(SHA256_64::create(), 'data');
filter(SHA256::create(), 'data');
filter(SHAKE256::create(), 'data');
