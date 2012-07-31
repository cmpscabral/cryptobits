<?php

/** "Unix crypt using SHA-256", as specified by Ulrich Drepper
 * Version 0.4 2008-04-03, http://www.akkadia.org/drepper/SHA-crypt.txt
 *
 * This version attempts to match the Drepper source code as closely as
 * possible.
 */

/*
  http://code.google.com/p/securestring

  The MIT License

  Copyright (c) 2007, 2010 Nick Galbreath, nickg@client9.com

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/
class Crypt2007 {
    /** helper function to do sha-256 and return raw bytes
     *
     */
    public static function sha256_raw($data) {
        return hash('sha256', $data, true);
    }

    /** helper function to do sha-512 and return raw bytes
     *
     */
    public static function sha512_raw($data) {
        return hash('sha512', $data, true);
    }

    /** Helper function to convert raw binary into something nice for salt
     *
     */
    public static function makesalt($raw) {
        return substr(strtr(base64_encode($raw), '+', '.'), 0, 16);
    }

    /** Crazy base64 algorithm used in crypt
     *
     */
    public static function b64_from_24bit($b2, $b1, $b0, $n) {
        $CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        $w = ($b2 << 16) | ($b1 << 8) | $b0;
        $buf = '';
        while ($n-- > 0) {
            $buf .= substr($CHARS, $w & 0x3f, 1);
            $w >>= 6;
        }
        return $buf;
    }

    /** Explicit crypt using sha-512 as specified by Ulrich Drepper
     *  http://www.akkadia.org/drepper/SHA-crypt.txt
     *
     *  @param $use_native  try to use built-in version if available.
     *   This is mostly present for testing.
     */
    public static function crypt_sha512($key, $rounds, $salt, $use_native=true) {
        // truncate salt to 16 chars
        $salt = substr($salt, 0, 16);
        $salt_len = strlen($salt);

        // use 5.3.2 native function?
        // and if so, convert the above to correct format
        // http://php.net/manual/en/function.crypt.php
        if ($use_native && defined('CRYPT_SHA512') && CRYPT_SHA512 === 1) {
            return crypt($key, "\$6\$rounds=${rounds}\$${salt}$");
        }
        $key_len = strlen($key);

        /* Prepare for the real work.  */
        /* Add the key string.  */
        /* The last part is the salt string.  This must be at most 16
           characters and it ends at the first `$' character (for
           compatibility with existing implementations).  */
        $ctx = $key . $salt;

        /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
           final result will be added to the first context.  */
        /* Add key.  */
        /* Add salt.  */
        /* Add key again.  */
        $alt_ctx = $key . $salt . $key;

        /* Now get result of this (64 bytes) and add it to the other
           context.  */
        $alt_result = self::sha512_raw($alt_ctx);

        /* Add for any character in the key one byte of the alternate sum.  */
        for ($cnt = $key_len; $cnt > 64; $cnt -= 64) {
            $ctx .= $alt_result;
        }
        $ctx .= substr($alt_result, 0, $cnt);

        /* Take the binary representation of the length of the key and for every
           1 add the alternate sum, for every 0 the key.  */
        for ($cnt = $key_len; $cnt > 0; $cnt >>= 1) {
            if (($cnt & 1) != 0) {
                $ctx .= $alt_result;
            } else {
                $ctx .= $key;
            }
        }
        /* Create intermediate result.  */
        $alt_result = self::sha512_raw($ctx);

        /* Start computation of P byte sequence.  */
        $alt_ctx = '';
        /* For every character in the password add the entire password.  */
        for ($cnt = 0; $cnt < $key_len; ++$cnt) {
            $alt_ctx .= $key;
        }
        /* Finish the digest.  */
        $tmp_result = self::sha512_raw($alt_ctx);

        /* Create byte sequence P. */
        $p_bytes = '';
        for ($cnt = $key_len; $cnt >= 64; $cnt -= 64) {
            $p_bytes .= $tmp_result;
        }
        $p_bytes .= substr($tmp_result, 0, $cnt);

        /* Start computation of S byte sequence.  */
        $alt_ctx = '';
        /* For every character in the password add the entire password.  */
        for ($cnt = 0; $cnt < 16 + ord(substr($alt_result, 0, 1)); ++$cnt) {
            $alt_ctx .= $salt;
        }
        /* Finish the digest.  */
        $tmp_result = self::sha512_raw($alt_ctx);

        /* Create byte sequence S.  */
        $s_bytes = '';
        for ($cnt = $salt_len; $cnt >= 64; $cnt -= 64) {
            $s_bytes .= $tmp_result;
        }
        $s_bytes .= substr($tmp_result, 0, $cnt);

        /* Repeatedly run the collected hash value through SHA256 to burn
           CPU cycles.  */
        for ($cnt = 0; $cnt < $rounds; ++$cnt) {
            /* New context.  */
            $ctx = '';

            /* Add key or last result.  */
            if (($cnt & 1) !== 0) {
                $ctx .= $p_bytes;
            } else {
                $ctx .= $alt_result;
            }
            /* Add salt for numbers not divisible by 3.  */
            if ($cnt % 3 != 0) {
                $ctx .= $s_bytes;
            }

            /* Add key for numbers not divisible by 7.  */
            if ($cnt % 7 != 0) {
                $ctx .= $p_bytes;
            }

            /* Add key or last result.  */
            if (($cnt & 1) != 0) {
                $ctx .= $alt_result;
            } else {
                $ctx .= $p_bytes;
            }

            /* Create intermediate result.  */
            $alt_result = self::sha512_raw($ctx);
        }

        /* convert php string to something more C-like */
        $count = strlen($alt_result);
        $strchars = str_split($alt_result);
        $chars = array();
        for ($cnt = 0; $cnt < $count; ++$cnt) {
            array_push($chars, ord($strchars[$cnt]));
        }

        /* do crazy base 64 encoding */
        $encoded = '';
        $encoded .= self::b64_from_24bit($chars[0],  $chars[21], $chars[42], 4);
        $encoded .= self::b64_from_24bit($chars[22], $chars[43], $chars[1],  4);
        $encoded .= self::b64_from_24bit($chars[44], $chars[2],  $chars[23], 4);
        $encoded .= self::b64_from_24bit($chars[3],  $chars[24], $chars[45], 4);
        $encoded .= self::b64_from_24bit($chars[25], $chars[46], $chars[4],  4);
        $encoded .= self::b64_from_24bit($chars[47], $chars[5],  $chars[26], 4);
        $encoded .= self::b64_from_24bit($chars[6],  $chars[27], $chars[48], 4);
        $encoded .= self::b64_from_24bit($chars[28], $chars[49], $chars[7],  4);
        $encoded .= self::b64_from_24bit($chars[50], $chars[8],  $chars[29], 4);
        $encoded .= self::b64_from_24bit($chars[9],  $chars[30], $chars[51], 4);
        $encoded .= self::b64_from_24bit($chars[31], $chars[52], $chars[10], 4);
        $encoded .= self::b64_from_24bit($chars[53], $chars[11], $chars[32], 4);
        $encoded .= self::b64_from_24bit($chars[12], $chars[33], $chars[54], 4);
        $encoded .= self::b64_from_24bit($chars[34], $chars[55], $chars[13], 4);
        $encoded .= self::b64_from_24bit($chars[56], $chars[14], $chars[35], 4);
        $encoded .= self::b64_from_24bit($chars[15], $chars[36], $chars[57], 4);
        $encoded .= self::b64_from_24bit($chars[37], $chars[58], $chars[16], 4);
        $encoded .= self::b64_from_24bit($chars[59], $chars[17], $chars[38], 4);
        $encoded .= self::b64_from_24bit($chars[18], $chars[39], $chars[60], 4);
        $encoded .= self::b64_from_24bit($chars[40], $chars[61], $chars[19], 4);
        $encoded .= self::b64_from_24bit($chars[62], $chars[20], $chars[41], 4);
        $encoded .= self::b64_from_24bit(0,          0,          $chars[63], 2);

        /* Now we can construct the result string.  It consists of three
           parts.  */
        return "\$6\$rounds=${rounds}\$${salt}\$${encoded}";

    }

    /** Explicit crypt using sha-256 as specified by Ulrich Drepper
     *  http://www.akkadia.org/drepper/SHA-crypt.txt
     *
     *  @param $use_native  try to use built-in version if available.
     *   This is mostly present for testing.
     */
    public static function crypt_sha256($key, $rounds, $salt, $use_native=true) {
        // truncate salt to 16 chars
        $salt = substr($salt, 0, 16);
        $salt_len = strlen($salt);

        // use 5.3.2 native function?
        // and if so, convert the above to correct format
        // http://php.net/manual/en/function.crypt.php
        if ($use_native && defined('CRYPT_SHA256') && CRYPT_SHA256 === 1) {
            return crypt($key, "\$5\$rounds=${rounds}\$${salt}$");
        }

        $key_len = strlen($key);

        /* Prepare for the real work.  */
        /* Add the key string.  */
        /* The last part is the salt string.  This must be at most 16
           characters and it ends at the first `$' character (for
           compatibility with existing implementations).  */
        $ctx = $key . $salt;

        /* Compute alternate SHA256 sum with input KEY, SALT, and KEY.  The
           final result will be added to the first context.  */
        /* Add key.  */
        /* Add salt.  */
        /* Add key again.  */
        $alt_ctx = $key . $salt . $key;

        /* Now get result of this (32 bytes) and add it to the other
           context.  */
        $alt_result = self::sha256_raw($alt_ctx);

        /* Add for any character in the key one byte of the alternate sum.  */
        for ($cnt = $key_len; $cnt > 32; $cnt -= 32) {
            $ctx .= $alt_result;
        }
        $ctx .= substr($alt_result, 0, $cnt);

        /* Take the binary representation of the length of the key and for every
           1 add the alternate sum, for every 0 the key.  */
        for ($cnt = $key_len; $cnt > 0; $cnt >>= 1) {
            if (($cnt & 1) != 0) {
                $ctx .= $alt_result;
            } else {
                $ctx .= $key;
            }
        }
        /* Create intermediate result.  */
        $alt_result = self::sha256_raw($ctx);

        /* Start computation of P byte sequence.  */
        $alt_ctx = '';
        /* For every character in the password add the entire password.  */
        for ($cnt = 0; $cnt < $key_len; ++$cnt) {
            $alt_ctx .= $key;
        }
        /* Finish the digest.  */
        $tmp_result = self::sha256_raw($alt_ctx);

        /* Create byte sequence P. */
        $p_bytes = '';
        for ($cnt = $key_len; $cnt >= 32; $cnt -= 32) {
            $p_bytes .= $tmp_result;
        }
        $p_bytes .= substr($tmp_result, 0, $cnt);

        /* Start computation of S byte sequence.  */
        $alt_ctx = '';
        /* For every character in the password add the entire password.  */
        for ($cnt = 0; $cnt < 16 + ord(substr($alt_result, 0, 1)); ++$cnt) {
            $alt_ctx .= $salt;
        }
        /* Finish the digest.  */
        $tmp_result = self::sha256_raw($alt_ctx);

        /* Create byte sequence S.  */
        $s_bytes = '';
        for ($cnt = $salt_len; $cnt >= 32; $cnt -= 32) {
            $s_bytes .= $tmp_result;
        }
        $s_bytes .= substr($tmp_result, 0, $cnt);

        /* Repeatedly run the collected hash value through SHA256 to burn
           CPU cycles.  */
        for ($cnt = 0; $cnt < $rounds; ++$cnt) {
            /* New context.  */
            $ctx = '';

            /* Add key or last result.  */
            if (($cnt & 1) !== 0) {
                $ctx .= $p_bytes;
            } else {
                $ctx .= $alt_result;
            }
            /* Add salt for numbers not divisible by 3.  */
            if ($cnt % 3 != 0) {
                $ctx .= $s_bytes;
            }

            /* Add key for numbers not divisible by 7.  */
            if ($cnt % 7 != 0) {
                $ctx .= $p_bytes;
            }

            /* Add key or last result.  */
            if (($cnt & 1) != 0) {
                $ctx .= $alt_result;
            } else {
                $ctx .= $p_bytes;
            }

            /* Create intermediate result.  */
            $alt_result = self::sha256_raw($ctx);
        }

        /* convert php string to something more C-like */
        $count = strlen($alt_result);
        $strchars = str_split($alt_result);
        $chars = array();
        for ($cnt = 0; $cnt < $count; ++$cnt) {
            array_push($chars, ord($strchars[$cnt]));
        }

        /* do crazy base 64 encoding */
        $encoded = '';
        $encoded .= self::b64_from_24bit($chars[0],  $chars[10], $chars[20], 4);
        $encoded .= self::b64_from_24bit($chars[21], $chars[1],  $chars[11], 4);
        $encoded .= self::b64_from_24bit($chars[12], $chars[22], $chars[2],  4);
        $encoded .= self::b64_from_24bit($chars[3],  $chars[13], $chars[23], 4);
        $encoded .= self::b64_from_24bit($chars[24], $chars[4],  $chars[14], 4);
        $encoded .= self::b64_from_24bit($chars[15], $chars[25], $chars[5],  4);
        $encoded .= self::b64_from_24bit($chars[6],  $chars[16], $chars[26], 4);
        $encoded .= self::b64_from_24bit($chars[27], $chars[7],  $chars[17], 4);
        $encoded .= self::b64_from_24bit($chars[18], $chars[28], $chars[8],  4);
        $encoded .= self::b64_from_24bit($chars[9],  $chars[19], $chars[29], 4);
        $encoded .= self::b64_from_24bit(0,          $chars[31], $chars[30], 3);

        /* Now we can construct the result string.  It consists of three
           parts.  */
        return "\$5\$rounds=${rounds}\$${salt}\$${encoded}";
    }

    /** Validation function
     *
     */
    public static function validate($str, $pw, $use_native=true) {

        // if this defined, we assume SHA256 and Blowfish are defined too
        if ($use_native && defined('CRYPT_SHA512') && CRYPT_SHA512 === 1) {
            return crypt($str, $pw) == $pw;
        }

        $parts = explode('$', $pw);
        if (count($parts) != 5) {
            return false;
        }

        $alg = $parts[1];
        if ($alg != '5' && $alg != '6') {
            return false;
        }

        $roundparts = explode('=', $parts[2]);
        if ($roundparts[0] != 'rounds') {
            return false;
        }
        $rounds = (int) $roundparts[1];
        if ($rounds < 1000) {
            return false;
        }

        $salt = $parts[3];

        if ($alg == '5') {
            return self::crypt_sha256($str, $rounds, $salt, $use_native) == $pw;
        }

        if ($alg == '6') {
            return self::crypt_sha512($str, $rounds, $salt, $use_native) == $pw;
        }
    }
}
?>