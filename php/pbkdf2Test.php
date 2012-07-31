<?php
require_once 'PHPUnit/Framework.php';

include('pbkdf2.php');

class pbkdf2Test extends PHPUnit_Framework_TestCase
{

    // http://tools.ietf.org/search/draft-josefsson-pbkdf2-test-vectors-00
    public function testTestVectors1()  {
        $password = 'password';
        $salt = 'salt';
        $len = 20;
        $algo = 'sha1';

        $iter = 1;
        $this->assertEquals('0c60c80f961f0e71f3a9b524af6012062fe037a6',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $iter = 2;
        $this->assertEquals('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957',
                            bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $iter = 4096;
        $this->assertEquals('4b007901b765489abead49d926f721d065a429c1',
                            bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

    }


    // http://www.rfc-editor.org/rfc/rfc3962.txt
    public function testTestVectors2()  {
        $password = 'password';
        $salt     = 'ATHENA.MIT.EDUraeburn';
        $len      = 16;
        $algo     = 'sha1';

        $iter = 1;
        $len  = 16;
        $this->assertEquals('cdedb5281bb2f801565a1122b2563515',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));
        $iter = 1;
        $len  = 32;
        $this->assertEquals('cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $iter = 2;
        $len  = 16;
        $this->assertEquals('01dbee7f4a9e243e988b62c73cda935d',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));
        $iter = 2;
        $len  = 32;
        $this->assertEquals('01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $iter = 1200;
        $len  = 16;
        $this->assertEquals('5c08eb61fdf71e4e4ec3cf6ba1f5512b',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));
        $iter = 1200;
        $len  = 32;
        $this->assertEquals('5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $iter = 5;
        $salt = pack('H*' , '1234567878563412');
        $len  = 16;
        $this->assertEquals('d1daa78615f287e6a1c8b120d7062a49',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));
        $iter = 5;
        $len  = 32;
        $this->assertEquals('d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $password = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
        $salt = 'pass phrase equals block size';
        $len  = 16;
        $iter = 1200;
        $this->assertEquals('139c30c0966bc32ba55fdbf212530ac9',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $len  = 32;
        $this->assertEquals('139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1',
                            bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));


        $password = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
        $salt = 'pass phrase exceeds block size';
        $len  = 16;
        $iter = 1200;
        $this->assertEquals('9ccad6d468770cd51b10e6a68721be61',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

        $len  = 32;
        $this->assertEquals('9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a',
                           bin2hex(pbkdf2($password, $salt, $iter, $len, $algo)));

    }

}

?>