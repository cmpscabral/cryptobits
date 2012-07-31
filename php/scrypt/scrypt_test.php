<?php
require_once 'scrypt.php';
class scrypt_test extends PHPUnit_Framework_TestCase {
    public function test_blkcpy() {
        $dest = "0123456789abcdefghijklmnopqrstuvwxyz";
        $this->assertEquals(strlen($dest), 36);
        $src  = "xxxxx0123456789yyyyyyyyyyyyyyyy";
        blkcpy($dest, 10, $src, 5, 10);
        $this->assertEquals(strlen($dest), 36);
        $this->assertEquals($dest, "01234567890123456789klmnopqrstuvwxyz");

        $dest = "0123456789abcdefghijklmnopqrstuvwxyz";
        $this->assertEquals(strlen($dest), 36);
        $src  = "xxxxx0123456789yyyyyyyyyyyyyyyy";
        blkcpy($dest, 0, $src, 0, 10);
        $this->assertEquals(strlen($dest), 36);
        $this->assertEquals($dest, "xxxxx01234abcdefghijklmnopqrstuvwxyz");
    }
}
