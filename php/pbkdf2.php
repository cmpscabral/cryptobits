<?php

/**
 *
 * http://www.rsa.com/rsalabs/node.asp?id=2127
 * http://www.rfc-editor.org/rfc/rfc3962.txt
 *
 */
function pbkdf2($password, $salt, $iter_count, $keylen, $hash_alg = 'sha256' ) {

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

?>
