<?php

$counter = 0;
function dumpit($tag, $ary) {
         global $counter;
         $counter += 1;
         //         echo $tag . '-' . $counter . " " .  bin2hex($ary) . "\n";
}


  /** UINT32 arithmetic using 53-bit floating point numbers
   *
   * PHP ints are signed 32 or 64 bits depending on platform.
   * To be portable, we fake integer math using floating point (53 bits)
   * (same as javascript)
   *
   */
function uint32_add($a, $b)   {  return ($a + $b) & 0xFFFFFFFF; }
function uint32_or($a, $b)    {  return ($a | $b) & 0xFFFFFFFF; }
//function uint32_or($a, $b)    {  return ($a | $b); }
function uint32_and($a, $b)   {  return ($a & $b) & 0xFFFFFFFF; }
//function uint32_and($a, $b)   {  return ($a & $b); }
function uint32_xor($a, $b)   {  return ($a ^ $b) & 0xFFFFFFFF; }
//function uint32_xor($a, $b)   {  return ($a ^ $b); }

function uint32_lsh($a, $val) {  return ($a * pow(2,$val)) & 0xFFFFFFFF; }
function uint32_rsh($a, $val) {  return floor($a / pow(2,$val)) & 0xFFFFFFFF; }
function uint32_rot($a, $val) {
         return uint32_or(uint32_lsh($a, $val), uint32_rsh($a, 32 - $val));
}
function uint32_hex($a) {
    return sprintf("%02s%02s%02s%02s",
                   dechex(uint32_rsh(uint32_and($a, 0xFF000000), 24)),
                   dechex(uint32_rsh(uint32_and($a, 0x00FF0000), 16)),
                   dechex(uint32_rsh(uint32_and($a, 0x0000FF00), 8)),
                   dechex(uint32_and($a, 0xFF)));
}

/** PBKDF2_SHA256
 *
 * http://www.rsa.com/rsalabs/node.asp?id=2127
 * http://www.rfc-editor.org/rfc/rfc3962.txt
 *
 */

function pbkdf2_sha256($password, $salt, $iter_count, $keylen) {
    $hash_alg = 'sha256';

    // Compute the length of hash alg output.
    // Some folks use a static variable and save the value of the hash len.
    // Considering we are doing 1000s hmacs, doing one more won't hurt.
    $hashlen = strlen(hash($hash_alg, null, true));

    // compute number of blocks need to make $keylen number of bytes
    $numblocks = ceil($keylen / $hashlen);

    // blocks are appended to this
    $output = '';
    for ($i = 1; $i <= $numblocks; ++$i) {
        $block = hash_hmac($hash_alg, $salt . pack('N', $i), $password, true);
        $ib = $block;
        for ($j = 1; $j < $iter_count; ++$j) {
            $block = hash_hmac($hash_alg, $block, $password, true);
            $ib ^= $block;
        }
        $output .= $ib;
    }

    // extract the right number of output bytes
    return substr($output, 0, $keylen);
}

/**********************************/

function munge(&$x, $i, $j, $k, $val) {
    $tmp = ($x[$j] + $x[$k]) & 0xFFFFFFFF;
    $x[$i] = $x[$i] ^ ( (($tmp << $val) & 0xFFFFFFFF) | ($tmp >> (32 - $val)));
    //$x[$i] = uint32_xor($x[$i], uint32_rot(uint32_add($x[$j], $x[$k]),  $val));
}

// this is the core salsa20 algorithm WITHOUT the final addition step
//  It's exposed here for testing only.
function salsa20_loop(&$ary, $rounds) {

    for ($i = 0; $i < $rounds; $i += 2) {
// columns
        munge($ary,  4,  0, 12,  7);
        munge($ary,  8,  4,  0,  9);
        munge($ary, 12,  8,  4, 13);
        munge($ary,  0, 12,  8, 18);
        munge($ary,  9,  5,  1,  7);
        munge($ary, 13,  9,  5,  9);
        munge($ary,  1, 13,  9, 13);
        munge($ary,  5,  1, 13, 18);
        munge($ary, 14, 10,  6,  7);
        munge($ary,  2, 14, 10,  9);
        munge($ary,  6,  2, 14, 13);
        munge($ary, 10,  6,  2, 18);
        munge($ary,  3, 15, 11,  7);
        munge($ary,  7,  3, 15,  9);
        munge($ary, 11,  7,  3, 13);
        munge($ary, 15, 11,  7, 18);
// rows
        munge($ary,  1,  0,  3,  7);
        munge($ary,  2,  1,  0,  9);
        munge($ary,  3,  2,  1, 13);
        munge($ary,  0,  3,  2, 18);
        munge($ary,  6,  5,  4,  7);
        munge($ary,  7,  6,  5,  9);
        munge($ary,  4,  7,  6, 13);
        munge($ary,  5,  4,  7, 18);
        munge($ary, 11, 10,  9,  7);
        munge($ary , 8, 11, 10,  9);
        munge($ary,  9,  8, 11, 13);
        munge($ary, 10,  9,  8, 18);
        munge($ary, 12, 15, 14,  7);
        munge($ary, 13, 12, 15,  9);
        munge($ary, 14, 13, 12, 13);
        munge($ary, 15, 14, 13, 18);
    }
}

function salsa20(&$B32, $rounds) {

    // copy
    $x = array_values($B32);
/*
    $x = array();
    for ($i = 0; $i < 16; $i++) {
       $x[] = $B32[$i];
    }
*/
    salsa20_loop($x, $rounds);

    //  original values + new stuff
    for ($i = 0; $i < 16; $i++) {
        $B32[$i] = ($B32[$i] + $x[$i]) & 0xFFFFFFFF; //uint32_add($B32[$i], $x[$i]);
    }
}

function string2ints($s) {
    // needed since unpack returns 1-index arrays
    //    need 0-index array
    return array_values(unpack('V*', $s));
/*
    $vals =  unpack('V*', $s);
    // for some reason the values start at 1...
    //   repurpose to 0-index array
    $ary = array();
    foreach ($vals as $k => $v) {
        $ary[] = $v;
    }
    return $ary;
*/
}

function ints2string($ary) {
    /*
    $s = '';
    foreach ($ary as $a) {
        $s .= pack('V', $a);
    }
    return $s;
    */
    return call_user_func_array('pack', array_merge(array('V*'),$ary));
}

function salsa20_8_str($s) {
    // convert string of 64 bytes to 16 32-bit integers
    $B32 = string2ints($s);
    salsa20($B32, 8);
    return ints2string($B32);
}

/**********************************/

function blkcpy(&$dest, $doffset, $src, $soffset, $len) {
    $dest = substr($dest, 0, $doffset) . substr($src, $soffset, $len) .
        substr($dest, $doffset + $len);
}

function blkxor(&$dest, $doffset, $src, $soffset, $len) {

    $xored = substr($dest, $doffset, $len) ^ substr($src, $soffset, $len);
    /*
    $xored = '';
    for ($i = 0; $i < $len; $i++) {
        $xored .= chr(ord($dest[$doffset+$i]) ^ ord($src[$soffset+$i]));
    }
    */
    $dest = substr($dest, 0, $doffset) . $xored . substr($dest, $doffset + $len);
}

function blockmix_salsa8(&$B, &$Y, $r) {
    $X = str_repeat("\0", 64);
    blkcpy($X, 0, $B, (2 * $r - 1) * 64, 64);
    for ($i = 0; $i < 2 * $r; $i++) {
        blkxor($X, 0, $B, $i * 64, 64);
        $X = salsa20_8_str($X);
        blkcpy($Y, $i * 64, $X, 0, 64);
    }

    for ($i = 0; $i < $r; $i++) {
        blkcpy($B, $i * 64, $Y, ($i * 2) * 64, 64);
    }
    for ($i = 0; $i < $r; $i++) {
        blkcpy($B, ($i + $r) * 64, $Y, ($i * 2 + 1) * 64, 64);
    }
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
function integerify($B, $r) {
    // grab 64-bits
    $s = substr($B, (2 * $r - 1) * 64, 8);
    // hack.. let's only use lower half
    $s = unpack('V', substr($s, 0, 4));
    // unpack is 1-index based
    return $s[1];
}

function smix(&$B, $offset, $r, $N, &$V, &$XY) {
    $X = substr($XY, 0, 128 * $r);
    $Y = substr($XY, 128 * $r);
    blkcpy($X, 0, $B, $offset, 128 * $r);
    for ($i = 0; $i < $N; $i++) {
        blkcpy($V, $i * 128 * $r, $X, 0, 128 * $r);
        blockmix_salsa8($X, $Y, $r);
    }
    for ($i = 0; $i < $N; $i++) {
        $j = integerify($X, $r) & ($N - 1);
        blkxor($X, 0, $V, $j * 128 * $r, 128 * $r);
        blockmix_salsa8($X, $Y, $r);
    }
    blkcpy($B, $offset, $X, 0, 128 * $r);
    $XY = $X . $Y;
}

function scrypt($passwd, $salt, $N, $r, $p, $dklen) {
         echo "$passwd $salt : N = $N, r= $r, p = $p\n";
         echo "best memory usage: " . (256 *$r + 256*$r*$N + $p+128*$r) . "\n";
    $XY = str_repeat("\0", 256 * $r);
    $V  = str_repeat("\0", 256 * $r * $N);
    $B = pbkdf2_sha256($passwd, $salt, 1, $p * 128 * $r);
    for ($i = 0; $i < $p; $i++) {
        $t0 = microtime(true);
        echo "$i of $p\n";
        smix($B, $i * 128 * $r, $r, $N, $V, $XY);
        $t1 = microtime(true);
        printf("   Took %.1f\n", ($t1-$t0));
    }
    return pbkdf2_sha256($passwd, $B, 1, $dklen);
}


//scrypt("password", "NaCl", 1024, 8, 16, 64);
//scrypt("password", "NaCl", 1024, 8, 16, 64);
scrypt("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64);