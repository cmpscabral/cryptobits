<?php
/*
  The MIT License
  http://code.google.com/p/securestring
  Copyright (c) 2010 Nick Galbreath, nickg@client9.com

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

/**
 * Since PHP's PRNG are broken and change between releases in how they
 * work or don't work.  This wraps up /dev/urandom found on BSD and Linux
 * based systems.   If you don't generate any PRN, this class occurs no cost.
 * Should be reasonable for REASONABLE requests.
 */
class DevURandom {

    const RAND_MAX = 0x7FFFFFFF;

    function __construct() {
        if (PHP_INT_SIZE !== 8) {
            throw new RuntimeException("This is only tested on 64-bit " .
                                       "systems. Abort!");
        }

        // test to make sure PHP overflow works, some versions are "peculiar".
        // This won't trigger on 64-bit systems, but might on 32-bit.
        if (self::RAND_MAX + 1 == self::RAND_MAX ||
            self::RAND_MAX + 1 <= 0) {
            throw new RuntimeException("PHP Numerics is bizarre. Abort!");
        }

        $this->fp = null;
    }

    function __destruct() {
        if ($this->fp !== null) {
            fclose($this->fp);
        }
    }

    /** Returns a random binary string
     *
     */
    function bytes($n) {

        if (!is_int($n) || $n < 0) {
            throw new InvalidArgumentException("Argument must be non-negative integer: got $n");
        }

        if ($this->fp === null) {
            if (defined('MCRYPT_DEV_URANDOM')) {
                $bytes = mcrypt_create_iv($n, MCRYPT_DEV_URANDOM);
                if ($bytes === FALSE || strlen($bytes) != $n) {
                    throw new RuntimeException("mcrypt_create_iv failed!");
                }
                return $bytes;
            }
            $this->fp = fopen('/dev/urandom','rb');
            if ($this->fp === FALSE) {
                $this->fp = null;
                throw new RuntimeException("fopen of /dev/urandom failed");
            }

            // by default PHP reads 4096 of bytes
            // http://stackoverflow.com/questions/4296932/does-phps-fread-always-read-at-least-4096-bytes
            // With php >= 5.3.3, we might be able to speed this up:
            // http://php.net/manual/en/function.stream-set-read-buffer.php
            if (function_exists('stream_set_read_buffer')) {
                stream_set_read_buffer($this->fp, 0);
            }
        }

        $bits = '';
        $count = 0;
        $itermax = 10;

        // possible some weird IO problem is preventing reading of bytes
        // make sure infinite loop doesn't happen.  Not sure how PHP
        // handles E_AGAIN signal under load.
        while ($count < $itermax) {
            $len = strlen($bits);
            if ($len === $n) {
                break;
            }
            $count++;
            $tmp = fread($this->fp, $n - $len);
            if ($tmp === FALSE) {
                continue;
            }
            $bits .= $tmp;
        }
        if ($count === $itermax) {
            throw new RuntimeException("After $itermax iterations, only got $len bytes, requested $n");
        }
        return $bits;
    }

    /** Returns a random integer in the interval [0, RAND_MAX], similar
     *  to how rand/random POSIX functions work
     */
    function rand() {
        $int = -1;
        // since unpack appears to not make sense
        while ($int < 0 || $int > self::RAND_MAX) {
            $ary = unpack("Lint", $this->bytes(4));
            $int = $ary['int'];
        }
        return $int;
    }

    /** Returns random int in interval [0,$n)
     *
     */
    function randint($n) {
        if (!is_int($n) || $n < 0 || $n > self::RAND_MAX) {
            throw new InvalidArgumentException("Arg must be in [0,RAND_MAX], go $n");
        }
        return (int)($n * ( $this->rand() / (self::RAND_MAX + 1) ));
    }

    /** Returns random float in interval [0,1)
     *
     */
    function randfloat() {
        // there are other ways to do this but PHP isn't so
        // great with raw IEEE handling.
        return $this->rand() / (self::RAND_MAX + 1);
    }
}
?>