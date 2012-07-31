<?php
/** PHPUnit tests for crypt 256 based on Ulrich Drepper's implementation
 *  http://www.akkadia.org/drepper/SHA-crypt.txt
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
require_once 'Crypt2007.php';

class Crypt2007Test extends PHPUnit_Framework_TestCase {

    public function testCryptSHA256()  {

        // TEST 1
        $expected = '$5$rounds=5000$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5';
        $actual = Crypt2007::crypt_sha256('Hello world!', 5000, 'saltstring', true);
        $this->assertEquals($expected, $actual);
        $actual = Crypt2007::crypt_sha256('Hello world!', 5000, 'saltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 2
        $expected = '$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA';
        $actual = Crypt2007::crypt_sha256('Hello world!', 10000, 'saltstringsaltstring', true);
        $this->assertEquals($expected, $actual);
        $actual = Crypt2007::crypt_sha256('Hello world!', 10000, 'saltstringsaltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 3
        $expected = '$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5';
        $actual = Crypt2007::crypt_sha256('This is just a test', 5000, 'toolongsaltstring', true);
        $this->assertEquals($expected, $actual);

        $actual = Crypt2007::crypt_sha256('This is just a test', 5000, 'toolongsaltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 4
        $expected = '$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1';
        $actual = Crypt2007::crypt_sha256('a very much longer text to encrypt.  This one even stretches over morethan one line.', 1400, 'anotherlongsaltstring', true);
        $this->assertEquals($expected, $actual);
        $actual = Crypt2007::crypt_sha256('a very much longer text to encrypt.  This one even stretches over morethan one line.', 1400, 'anotherlongsaltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 5
        $actual = '$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/';
        $expected = Crypt2007::crypt_sha256('we have a short salt string but not a short password', 77777, 'short');
        $this->assertEquals($expected, $actual);

        // TEST 6
        $actual = '$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD';
        $expected = Crypt2007::crypt_sha256('a short string', 123456, 'asaltof16chars..' , true);
        $this->assertEquals($expected, $actual);
        $expected = Crypt2007::crypt_sha256('a short string', 123456, 'asaltof16chars..' , false);
        $this->assertEquals($expected, $actual);

        // TEST 7
        $actual = '$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC';
        $expected = Crypt2007::crypt_sha256('the minimum number is still observed', 1000,
                                 'roundstoolow', true);

        $this->assertEquals($expected, $actual);
        $expected = Crypt2007::crypt_sha256('the minimum number is still observed', 1000,
                                 'roundstoolow', false);

        $this->assertEquals($expected, $actual);
    }

    public function testCryptSHA512()  {

        // TEST 1
        $expected = '$6$rounds=5000$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1';
        $actual = Crypt2007::crypt_sha512('Hello world!', 5000, 'saltstring', true);
        $this->assertEquals($expected, $actual);
        $actual = Crypt2007::crypt_sha512('Hello world!', 5000, 'saltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 2
        $expected = '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.';
        $actual = Crypt2007::crypt_sha512('Hello world!', 10000, 'saltstringsaltstring', true);
        $this->assertEquals($expected, $actual);
        $actual = Crypt2007::crypt_sha512('Hello world!', 10000, 'saltstringsaltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 3
        $expected = '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0';
        $actual = Crypt2007::crypt_sha512('This is just a test', 5000, 'toolongsaltstring', true);
        $this->assertEquals($expected, $actual);

        $actual = Crypt2007::crypt_sha512('This is just a test', 5000, 'toolongsaltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 4
        $expected = '$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1';
        $actual = Crypt2007::crypt_sha512('a very much longer text to encrypt.  This one even stretches over morethan one line.', 1400, 'anotherlongsaltstring', true);
        $this->assertEquals($expected, $actual);
        $actual = Crypt2007::crypt_sha512('a very much longer text to encrypt.  This one even stretches over morethan one line.', 1400, 'anotherlongsaltstring', false);
        $this->assertEquals($expected, $actual);

        // TEST 5
        $actual = '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0';
        $expected = Crypt2007::crypt_sha512('we have a short salt string but not a short password', 77777, 'short');
        $this->assertEquals($expected, $actual);

        // TEST 6
        $actual = '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1';
        $expected = Crypt2007::crypt_sha512('a short string', 123456, 'asaltof16chars..' , true);
        $this->assertEquals($expected, $actual);
        $expected = Crypt2007::crypt_sha512('a short string', 123456, 'asaltof16chars..' , false);
        $this->assertEquals($expected, $actual);

        // TEST 7
        $actual = '$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.';
        $expected = Crypt2007::crypt_sha512('the minimum number is still observed', 1000,
                                 'roundstoolow', true);
        $this->assertEquals($expected, $actual);
        $expected = Crypt2007::crypt_sha512('the minimum number is still observed', 1000,
                                 'roundstoolow', false);

        $this->assertEquals($expected, $actual);
    }

    /**
     * Examples from http://php.net/manual/en/function.crypt.php
     */
    function testCryptPHPExamples() {
        $expected = '$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6';
        $actual  = Crypt2007::crypt_sha256('rasmuslerdorf', 5000, 'usesomesillystringforsalt', false);
        $this->assertEquals($expected, $actual);

        $expected = '$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21';
        $actual = Crypt2007::crypt_sha512('rasmuslerdorf', 5000, 'usesomesillystringforsalt', false);
        $this->assertEquals($expected, $actual);
    }

    function testMakeSalt() {
        // nothing very special here, just making sure it works at all
        $expected = 'MDEyMzQ1Njc4OTAx';
        $actual = Crypt2007::makeSalt('012345678901');
        $this->assertEquals($expected, $actual);
    }

    function testValidate() {

        $expected = '$5$rounds=5000$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5';
        $actual = Crypt2007::crypt_sha256('Hello world!', 5000, 'saltstring', true);
        $this->assertEquals($expected, $actual);

        $this->assertTrue(Crypt2007::validate('Hello world!', $expected, true));
        $this->assertFalse(Crypt2007::validate('Goodbye world!', $expected, true));
        $this->assertTrue(Crypt2007::validate('Hello world!', $expected, false));
        $this->assertFalse(Crypt2007::validate('Goodbye world!', $expected, false));

        $expected = '$6$rounds=5000$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1';
        $actual = Crypt2007::crypt_sha512('Hello world!', 5000, 'saltstring', true);
        $this->assertEquals($expected, $actual);
        $this->assertTrue(Crypt2007::validate('Hello world!', $expected, true));
        $this->assertFalse(Crypt2007::validate('Goodbye world!', $expected, true));

        $this->assertTrue(Crypt2007::validate('Hello world!', $expected, false));
        $this->assertFalse(Crypt2007::validate('Goodbye world!', $expected, false));

        // negative cases

        // unknown algorithm
        $expected = '$1$rounds=5000$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1';
        $this->assertFalse(Crypt2007::validate('Hello world!', $expected, false));

        // not enought '$'
        $expected = '$6$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1';
        $this->assertFalse(Crypt2007::validate('Hello world!', $expected, false));

        // rounds are too low
        $expected = '$6$round=999$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1';
        $this->assertFalse(Crypt2007::validate('Hello world!', $expected, false));

    }
}

?>