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

require_once 'SecureString1.php';

class SecureStringTest extends PHPUnit_Framework_TestCase
{

    public function testSmoke() {
        $salt = '1234567890';
        $keys = array(1 => hash('md5', 'this is my secret key 1', true),
                      10 => hash('md5', 'this is my secret key 10', true),
                      100 => hash('md5', 'this is my secret key 100', true));

        $mac1 =  SecureString1::create('one=1&two=2', $salt, $keys, 1);
        $this->assertTrue(SecureString1::validate($mac1, $keys));
        $this->assertTrue(strpos($mac1, '&_kid=1&') > 0);

        $mac2 =  SecureString1::create('one=1&two=2', $salt, $keys, 10);
        $this->assertTrue(SecureString1::validate($mac2, $keys));
        $this->assertTrue(strpos($mac2, '&_kid=10&') > 0);

        $mac3 =  SecureString1::create('one=1&two=2', $salt, $keys, 100);
        $this->assertTrue(SecureString1::validate($mac3, $keys));
        $this->assertTrue(strpos($mac3, '&_kid=100&') > 0);

        // same inputs == same outputs (with time val passed in)
        $mac1 = SecureString1::create('one=1&two=2', $salt, $keys, 1, 123, 1);
        $mac2 = SecureString1::create('one=1&two=2', $salt, $keys, 1, 123, 1);
        $this->assertEquals($mac1, $mac2);
        $this->assertTrue(SecureString1::validate($mac1, $keys));
        $this->assertTrue(SecureString1::validate($mac2, $keys));
    }

    /*------------- CREATION ------------------------*/
    /* This mostly test that the inputs are valid    */
    /* and if not, throw an exception.  The caller   */
    /* never should be passing in bad input, but...  */
    /* you know how it goes.                         */

    public function testBadPayloadDoesNotCreate() {
        $salt = '1234567890';
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        try {
            $this->assertFalse(SecureString1::create('', $salt, $keys, 1));
            $this->fail('Empty string should not create');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }
    }

    public function testBadKeysDoesNotCreate() {
        $salt = '1234567890';
        $keys = array(1 => '2short');
        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for key being too short');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        $keys = array();
        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for key being too short');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        $keys = '';
        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for key being string not array');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        $keys = 1;
        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for key being integer not array');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }
    }

    public function testBadKidDoesNotCreate() {
        $salt = '1234567890';
        $keys = array(1 => hash('md5', 'this is my secret key', true));

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 100));
            $this->fail('Expected exception for non-existant key');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 'abc'));
            $this->fail('Expected exception for kid as string');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 0));
            $this->fail('Expected exception for kid as 0');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, -1));
            $this->fail('Expected exception for kid as -1');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, '999999999999999999999999999999999999999'));
            $this->fail('Expected exception for kid  as overflow');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }
    }

    public function testBadTimeDoesNotCreate() {
        $salt = '1234567890';

        $keys = array(1 => hash('md5', 'this is my secret key', true));

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1, '9999999999999999999999999999999999999'));
            $this->fail('Expected exception for time as overflow');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1, 'abc'));
            $this->fail('Expected exception for time as string');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1, -1));
            $this->fail('Expected exception for time as -1');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }
    }

    public function testBadVersionDoesNotCreate() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        $salt = '1234567890';
        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1, 0, ''));
            $this->fail('Expected exception for version as empty string');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1, 0, 0));
            $this->fail('Expected exception for version as 0');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }


        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1, 0, -1));
            $this->fail('Expected exception for version as -1');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1, 0, 'abc'));
            $this->fail('Expected exception for version as string');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }
    }

    /**
     * Reject bad salt input.
     * Too short, bad chars, wrong input.
     */
    public function testBadSaltDoesNotCreate() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));

        try {
            $salt = '';
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for salt as empty string');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        try {
            $salt = '1';
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for salt as "1"');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        // 100% invalid chars
        try {
            $salt = '========';
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for salt with invalid chars');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }

        // only 1 invalid char
        try {
            $salt = 'ABCdef=';
            $this->assertFalse(SecureString1::create('blah', $salt, $keys, 1));
            $this->fail('Expected exception for salt with invalid chars');
        } catch (InvalidArgumentException $expected) {
            // NOP
        }
    }

    /*------------- VALIDATION -----------------------*/
    /* Test that both the validation code is correct  */
    /* and does the right thing if invalid inputs are */
    /* passed in.                                     */


    /**
     * Modify each char in the secure string.
     * It should fail.
     */
    public function testModificationDoesNotValidate() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        $salt = '1234567890';
        $macd =  SecureString1::create('one=1&two=2', $salt, $keys, 1);

        for ($i = 0; $i < strlen($macd); ++$i) {
            // this make a copy-by-value
            $bad = $macd;

            // change the character to 'next'
            $bad[$i] = chr(ord($bad[$i]) + 1);
            $this->assertFalse(SecureString1::validate($bad, $keys));

            // change the char to 'previous'
            $bad[$i] = chr(ord($bad[$i]) - 2);
            $this->assertFalse(SecureString1::validate($bad, $keys));

            // and finally change to a truly invalid char
            $bad[$i] = chr(1);
            $this->assertFalse(SecureString1::validate($bad, $keys));
        }

        // this just checks that the orginal string wasn't messed with
        $this->assertTrue(SecureString1::validate($macd, $keys));
    }


    /**
     * Truncate the secure string from beginning or ending.
     * It should fail.
     */
    public function testTruncationDoesNotValidate() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        $salt = '1234567890';
        $macd =  SecureString1::create('one=1&two=2', $salt, $keys, 1);

        // take every substring from front (begining got truncated)
        for ($i = 0; $i < strlen($macd); ++$i) {
            $bad = substr($macd,0,$i);
            $this->assertFalse(SecureString1::validate($bad, $keys));
        }
        // from other direction, (ending got truncated)
        for ($i = 1; $i < strlen($macd); $i++) {
            $bad = substr($macd,$i);
            $this->assertFalse(SecureString1::validate($bad, $keys));
        }
    }

    /**
     * Prepend or Append data to secure string.  It should fail.
     */
    public function testPrependAppendDoesNotValidate() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        $salt = '1234567890';
        $macd =  SecureString1::create('one=1&two=2', $salt, $keys, 1);

        $this->assertFalse(SecureString1::validate('x' . $macd, $keys));
        $this->assertFalse(SecureString1::validate($macd . 'x', $keys));
    }

    /**
     * Passing in bogus strings or non strings to be validate.
     * Should return false.
     */
    public function testBadPayloadDoesNotValidate() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        $this->assertFalse(SecureString1::validate('', $keys));
        $this->assertFalse(SecureString1::validate('   ', $keys));
        $this->assertFalse(SecureString1::validate(1, $keys));
        $this->assertFalse(SecureString1::validate(array(), $keys));
    }

    /**
     * Create with one key, then remove that key.
     * It should fail.
     */
    public function testMissingKeyDoesValidate() {
        $keys = array(100 => hash('md5', 'this is my secret key', true));
        $salt = '1234567890';
        $macd =  SecureString1::create('one=1&two=2', $salt, $keys, 100);

        $newkeys = array(1 => hash('md5', 'yet another key', true));
        $this->assertFalse(SecureString1::validate($macd, $newkeys));
    }

    /**
     * Create with one key, then validate using a different key.
     * It should fail.
     */
    public function testDifferentKeyDoesValidate() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        $salt = '1234567890';
        $macd =  SecureString1::create('one=1&two=2', $salt, $keys, 1);

        $newkeys = array(1 => hash('md5', 'yet another key', true));
        $this->assertFalse(SecureString1::validate($macd, $newkeys));
    }

    /**
     * branch-free string compare
     * make sure there are no off-by-one errors
     */
    public function testStringCompare() {
        // empty
        $this->assertTrue(SecureString1::string_equals('', ''));

        // mismatch1
        $this->assertFalse(SecureString1::string_equals('a', ''));
        $this->assertFalse(SecureString1::string_equals('', 'b'));
        $this->assertFalse(SecureString1::string_equals('a', 'b'));
        $this->assertTrue(SecureString1::string_equals('a', 'a'));

        $this->assertTrue(SecureString1::string_equals('aaa', 'aaa'));
        $this->assertFalse(SecureString1::string_equals('aaa', 'baa'));
        $this->assertFalse(SecureString1::string_equals('aaa', 'aba'));
        $this->assertFalse(SecureString1::string_equals('aaa', 'aab'));
        $this->assertFalse(SecureString1::string_equals('aaa', 'bab'));
    }

    /*------------- BASE 64 TEST ------------------------*/
    public function testBase64() {
        $this->assertEquals("MA..", SecureString1::b64_urlencode("0"));
        $this->assertEquals("0", SecureString1::b64_urldecode("MA.."));
        $this->assertTrue(SecureString1::b64_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."));
        $this->assertFalse(SecureString1::b64_chars("~!@#$%^&*"));

        // go figure, bad input for base64_input doesn't pop an exception
        $this->assertEquals('', SecureString1::b64_urldecode("~!@#$%^&*"));
    }

    /*------------- LANGUAGE TESTS -----------------------*/
    /* These test how certain php functions work.  mostly */
    /* since I find php to be really odd and don't know   */
    /* the rules                                          */

    /**
     * what happens when the SS meta data fields are in the
     * payload?
     *
     * Not sure I like this behavior, but I'm just documenting it.
     * parse_str overwrites the original value when a key is duplicated
     * parse_str has all sorts of other issues.
     */
    public function testPhpParseStrBehavior() {
        $keys = array(1 => hash('md5', 'this is my secret key', true));
        $salt = '1234567890';
        $macd =  SecureString1::create(SecureString1::PREFIX_VERSION . '100' .
                                       SecureString1::PREFIX_CREATED . 'blah' .
                                       SecureString1::PREFIX_KEYID . '666',
                                       $salt, $keys, 1);
        $this->assertTrue(SecureString1::validate($macd, $keys));
        parse_str($macd, $parts);
        $this->assertEquals($parts['_ver'], 1);
        $this->assertEquals($parts['_kid'], 1);
        $this->assertNotEquals($parts['_now'], 'blah');
    }

    /**
     * In arrays, are '0' and 0 the same key?
     * Yes.  Just like javascript, all keys are strings
     */
    public function testPhpArrayKeyBehavior() {
        $keys1 = array ( 10 => 'ten' );
        $keys2 = array ( '10' => 'ten' );
        $keys3 = array ( '10' => 'ten string', 10 => 'ten int' );

        $this->assertEquals($keys1[10], 'ten');
        $this->assertEquals($keys1['10'], 'ten');

        $this->assertEquals($keys2[10], 'ten');
        $this->assertEquals($keys2['10'], 'ten');

        // last one wins
        $this->assertEquals($keys3[10], 'ten int');
        $this->assertEquals($keys3['10'], 'ten int');
    }

    /*
     * 'intval' is a very odd function w.r.t to overflow cases
     * other languages might consider the overflow string below to be
     * 'not an integer'.  PHP just caps it the 'max int' value
     * which is platform specific.  Joy.
     */
    public function testPhpIntValOverflow() {
        $this->assertEquals(intval('9999999999999999999999999999'),
                            PHP_INT_MAX);

        // php doesn't seem to have a decent convert 'this
        // string to an int, IF it's an int-string' function
        // oh well
        $this->assertEquals(intval('10.12345'), 10);
    }
}

?>