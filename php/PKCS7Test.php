<?php
/** PKCS7 Padding Tests
 *
 *
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
require_once 'PHPUnit/Framework.php';
require_once 'PKCS7.php';

class PKCS7Test extends PHPUnit_Framework_TestCase {

    public function testSmoke() {
        $plaintext = '';
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("\x08\x08\x08\x08\x08\x08\x08\x08", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);

        $plaintext = "1";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("1\x07\x07\x07\x07\x07\x07\x07", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);

        $plaintext = "12";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("12\x06\x06\x06\x06\x06\x06", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);

        $plaintext = "123";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("123\x05\x05\x05\x05\x05", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);

        $plaintext = "1234";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("1234\x04\x04\x04\x04", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);

        $plaintext = "12345";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("12345\x03\x03\x03", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);

        $plaintext = "123456";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("123456\x02\x02", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);

        $plaintext = "1234567";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 8);
        $this->assertEquals("1234567\x01", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);


        $plaintext = "12345678";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 16);
        $this->assertEquals("12345678\x08\x08\x08\x08\x08\x08\x08\x08", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);


        $plaintext = "123456789";
        $padtext = PKCS7::pad($plaintext, 8);
        $this->assertEquals(strlen($padtext), 16);
        $this->assertEquals("123456789\x07\x07\x07\x07\x07\x07\x07", $padtext);
        $orig = PKCS7::unpad($padtext, 8);
        $this->assertEquals($plaintext, $orig);
    }

    public function testBadDecode() {
        // bad char bigger than blocksize
        $badpad = "1234567\x09";
        $this->assertFalse(PKCS7::unpad($badpad, 8));

        // bad char -- 0
        $badpad = "1234567\x00";
        $this->assertFalse(PKCS7::unpad($badpad, 8));

        // string wrong length
        $badpad = "1234567";
        $this->assertFalse(PKCS7::unpad($badpad, 8));

        // padding corrupted
        $this->assertFalse(PKCS7::unpad("12\x06\x06\x06\x05\x06\x06", 8));
    }
}
?>