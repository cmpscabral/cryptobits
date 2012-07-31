<?php
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

require_once 'PHPUnit/Framework.php';

require_once 'SecureCookie.php';

/**
 * Our awesome random number generator for salts
 */
class NotRandom {
    public function bytes($n) {
        return '123456';
    }
}

/**
 * here's the real tests
 */
class SecureCookieTest extends PHPUnit_Framework_TestCase
{
    public function testSmoke() {
        $keys = array(1 => md5('whatever!'));
        $kid  = 1;
        $random = new NotRandom();
        $cname = 'foo';
        $domain = 'client9.com';
        $path = '/';
        $secure = true;
        $httponly = true;
        $expiration = 86400;

        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);

        // new cookie is not dirty
        $this->assertFalse($sc->dirty);

        // test non-exsistant property
        $this->assertEquals($sc->get('foo', 1), 1);
        $this->assertFalse($sc->dirty);

        // set and get property
        $sc->set('foo', 2);
        $this->assertEquals($sc->get('foo'), 2);
        $this->assertTrue($sc->dirty);

        // set and then unset
        $sc->set('ding', 'bat');
        $this->assertEquals($sc->get('ding'), 'bat');
        $sc->set('ding', null);
        $this->assertTrue(is_null($sc->get('ding')));

        // doing a read should wipe everything out
        $sc->read();
        $this->assertEquals($sc->get('foo', 1), 1);

        $sc->set('lead', 'gold');

        // fake time in seconds
        $now = 123456789;
        $str = $sc->_write($now);

        // since keys, salt, and time are all fixed this should
        // always be the same
        $expected = "lead=gold&_now=123456789&_slt=MTIzNDU2&_kid=1&_ver=1&_mac=fExl2Kj9ASCkVGvA7EfoOkc10RE5ehIwAXdzNJR6Jxc.";
        $this->assertEquals($str, $expected);

        //
        // TEST URL ENCODING
        //

        // write
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_URL);
        $sc->set('lead', 'gold');
        // new cookie is not dirty
        $this->assertTrue($sc->dirty);

        $now = 123456789;
        $str = $sc->_write($now);
        $this->assertEquals($str, urlencode($expected));

        // written out cookie is not dirty
        $this->assertFalse($sc->dirty);

        // read 1x
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);
        $_COOKIE[$cname] = urlencode($expected);
        $ok = $sc->read($now + 1);
        $this->assertEquals(SecureCookie::REASON_OK, $ok);

        // read 2x
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);
        $_COOKIE[$cname] = urlencode(urlencode($expected));
        $ok = $sc->read($now + 1);
        $this->assertEquals(SecureCookie::REASON_OK, $ok);

        // BASE 64
        // write 64
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_B64);
        $sc->set('lead', 'gold');
        $now = 123456789;
        $str = $sc->_write($now);
        $this->assertEquals($str, SecureString1::b64_urlencode($expected));

        // read base 64
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);
        $_COOKIE[$cname] = SecureString1::b64_urlencode($expected);
        $ok = $sc->read($now + 1);
        $this->assertEquals(SecureCookie::REASON_OK, $ok);

        // TAINT
        $str = SecureString1::b64_urlencode($expected);
        $str[10] = '*'; // invalid char
        $_COOKIE[$cname] = $str;
        $ok = $sc->read($now + 1);
        $this->assertEquals(SecureCookie::REASON_INVALID, $ok);

        //
        // KEY PROBLEMS
        //
        //
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);
        $_COOKIE[$cname] = $expected;
        $ok = $sc->read($now + 1);
        $this->assertEquals(SecureCookie::REASON_OK, $ok);

        // test if the key is different
        $keys2 = array(1 => md5('different key'));
        $sc = new SecureCookie($keys2, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);
        $_COOKIE[$cname] = $expected;
        $ok = $sc->read($now + 1);
        $this->assertEquals(SecureCookie::REASON_INVALID, $ok);

        // let's try again but this time with a bad key id
        $keys2 = array(2 => md5('foo'));
        $sc = new SecureCookie($keys2, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);

        $_COOKIE[$cname] = $expected;
        $ok = $sc->read($now + 1);
        $this->assertEquals(SecureCookie::REASON_INVALID, $ok);

        //
        // EXPIRATION AND CLOCK SKEW
        //
        //
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);
        $_COOKIE[$cname] = $expected;
        $ok = $sc->read($now + $expiration + 1);
        $this->assertEquals(SecureCookie::REASON_EXPIRED, $ok);


        // clock skew
        $sc = new SecureCookie($keys, $kid, $random, $cname, $domain,
                               $path, $secure, $httponly,
                               $expiration, $expiration,
                               SecureCookie::ENCODE_NONE);
        $_COOKIE[$cname] = $expected;
        $ok = $sc->read($now - $expiration);
        $this->assertEquals(SecureCookie::REASON_CLOCK_SKEW, $ok);
    }

}
?>