<?php
require_once 'scrypt.php';
class Uint32Test extends PHPUnit_Framework_TestCase {
public function test_uint32_or() {
$this->assertEquals(0.0, uint32_or(0.0, 0.0));
$this->assertEquals(1.0, uint32_or(0.0, 1.0));
$this->assertEquals(2.0, uint32_or(0.0, 2.0));
$this->assertEquals(3.0, uint32_or(0.0, 3.0));
$this->assertEquals(4.0, uint32_or(0.0, 4.0));
$this->assertEquals(5.0, uint32_or(0.0, 5.0));
$this->assertEquals(6.0, uint32_or(0.0, 6.0));
$this->assertEquals(1.0, uint32_or(1.0, 0.0));
$this->assertEquals(1.0, uint32_or(1.0, 1.0));
$this->assertEquals(3.0, uint32_or(1.0, 2.0));
$this->assertEquals(3.0, uint32_or(1.0, 3.0));
$this->assertEquals(5.0, uint32_or(1.0, 4.0));
$this->assertEquals(5.0, uint32_or(1.0, 5.0));
$this->assertEquals(7.0, uint32_or(1.0, 6.0));
$this->assertEquals(2.0, uint32_or(2.0, 0.0));
$this->assertEquals(3.0, uint32_or(2.0, 1.0));
$this->assertEquals(2.0, uint32_or(2.0, 2.0));
$this->assertEquals(3.0, uint32_or(2.0, 3.0));
$this->assertEquals(6.0, uint32_or(2.0, 4.0));
$this->assertEquals(7.0, uint32_or(2.0, 5.0));
$this->assertEquals(6.0, uint32_or(2.0, 6.0));
$this->assertEquals(3.0, uint32_or(3.0, 0.0));
$this->assertEquals(3.0, uint32_or(3.0, 1.0));
$this->assertEquals(3.0, uint32_or(3.0, 2.0));
$this->assertEquals(3.0, uint32_or(3.0, 3.0));
$this->assertEquals(7.0, uint32_or(3.0, 4.0));
$this->assertEquals(7.0, uint32_or(3.0, 5.0));
$this->assertEquals(7.0, uint32_or(3.0, 6.0));
$this->assertEquals(4.0, uint32_or(4.0, 0.0));
$this->assertEquals(5.0, uint32_or(4.0, 1.0));
$this->assertEquals(6.0, uint32_or(4.0, 2.0));
$this->assertEquals(7.0, uint32_or(4.0, 3.0));
$this->assertEquals(4.0, uint32_or(4.0, 4.0));
$this->assertEquals(5.0, uint32_or(4.0, 5.0));
$this->assertEquals(6.0, uint32_or(4.0, 6.0));
$this->assertEquals(5.0, uint32_or(5.0, 0.0));
$this->assertEquals(5.0, uint32_or(5.0, 1.0));
$this->assertEquals(7.0, uint32_or(5.0, 2.0));
$this->assertEquals(7.0, uint32_or(5.0, 3.0));
$this->assertEquals(5.0, uint32_or(5.0, 4.0));
$this->assertEquals(5.0, uint32_or(5.0, 5.0));
$this->assertEquals(7.0, uint32_or(5.0, 6.0));
$this->assertEquals(6.0, uint32_or(6.0, 0.0));
$this->assertEquals(7.0, uint32_or(6.0, 1.0));
$this->assertEquals(6.0, uint32_or(6.0, 2.0));
$this->assertEquals(7.0, uint32_or(6.0, 3.0));
$this->assertEquals(6.0, uint32_or(6.0, 4.0));
$this->assertEquals(7.0, uint32_or(6.0, 5.0));
$this->assertEquals(6.0, uint32_or(6.0, 6.0));
}

public function test_uint32_and() {
$this->assertEquals(0.0, uint32_and(0.0, 0.0));
$this->assertEquals(0.0, uint32_and(0.0, 1.0));
$this->assertEquals(0.0, uint32_and(0.0, 2.0));
$this->assertEquals(0.0, uint32_and(0.0, 3.0));
$this->assertEquals(0.0, uint32_and(0.0, 4.0));
$this->assertEquals(0.0, uint32_and(0.0, 5.0));
$this->assertEquals(0.0, uint32_and(0.0, 6.0));
$this->assertEquals(0.0, uint32_and(1.0, 0.0));
$this->assertEquals(1.0, uint32_and(1.0, 1.0));
$this->assertEquals(0.0, uint32_and(1.0, 2.0));
$this->assertEquals(1.0, uint32_and(1.0, 3.0));
$this->assertEquals(0.0, uint32_and(1.0, 4.0));
$this->assertEquals(1.0, uint32_and(1.0, 5.0));
$this->assertEquals(0.0, uint32_and(1.0, 6.0));
$this->assertEquals(0.0, uint32_and(2.0, 0.0));
$this->assertEquals(0.0, uint32_and(2.0, 1.0));
$this->assertEquals(2.0, uint32_and(2.0, 2.0));
$this->assertEquals(2.0, uint32_and(2.0, 3.0));
$this->assertEquals(0.0, uint32_and(2.0, 4.0));
$this->assertEquals(0.0, uint32_and(2.0, 5.0));
$this->assertEquals(2.0, uint32_and(2.0, 6.0));
$this->assertEquals(0.0, uint32_and(3.0, 0.0));
$this->assertEquals(1.0, uint32_and(3.0, 1.0));
$this->assertEquals(2.0, uint32_and(3.0, 2.0));
$this->assertEquals(3.0, uint32_and(3.0, 3.0));
$this->assertEquals(0.0, uint32_and(3.0, 4.0));
$this->assertEquals(1.0, uint32_and(3.0, 5.0));
$this->assertEquals(2.0, uint32_and(3.0, 6.0));
$this->assertEquals(0.0, uint32_and(4.0, 0.0));
$this->assertEquals(0.0, uint32_and(4.0, 1.0));
$this->assertEquals(0.0, uint32_and(4.0, 2.0));
$this->assertEquals(0.0, uint32_and(4.0, 3.0));
$this->assertEquals(4.0, uint32_and(4.0, 4.0));
$this->assertEquals(4.0, uint32_and(4.0, 5.0));
$this->assertEquals(4.0, uint32_and(4.0, 6.0));
$this->assertEquals(0.0, uint32_and(5.0, 0.0));
$this->assertEquals(1.0, uint32_and(5.0, 1.0));
$this->assertEquals(0.0, uint32_and(5.0, 2.0));
$this->assertEquals(1.0, uint32_and(5.0, 3.0));
$this->assertEquals(4.0, uint32_and(5.0, 4.0));
$this->assertEquals(5.0, uint32_and(5.0, 5.0));
$this->assertEquals(4.0, uint32_and(5.0, 6.0));
$this->assertEquals(0.0, uint32_and(6.0, 0.0));
$this->assertEquals(0.0, uint32_and(6.0, 1.0));
$this->assertEquals(2.0, uint32_and(6.0, 2.0));
$this->assertEquals(2.0, uint32_and(6.0, 3.0));
$this->assertEquals(4.0, uint32_and(6.0, 4.0));
$this->assertEquals(4.0, uint32_and(6.0, 5.0));
$this->assertEquals(6.0, uint32_and(6.0, 6.0));
}

public function test_uint32_xor() {
$this->assertEquals(0.0, uint32_xor(0.0, 0.0));
$this->assertEquals(1.0, uint32_xor(0.0, 1.0));
$this->assertEquals(2.0, uint32_xor(0.0, 2.0));
$this->assertEquals(3.0, uint32_xor(0.0, 3.0));
$this->assertEquals(4.0, uint32_xor(0.0, 4.0));
$this->assertEquals(5.0, uint32_xor(0.0, 5.0));
$this->assertEquals(6.0, uint32_xor(0.0, 6.0));
$this->assertEquals(1.0, uint32_xor(1.0, 0.0));
$this->assertEquals(0.0, uint32_xor(1.0, 1.0));
$this->assertEquals(3.0, uint32_xor(1.0, 2.0));
$this->assertEquals(2.0, uint32_xor(1.0, 3.0));
$this->assertEquals(5.0, uint32_xor(1.0, 4.0));
$this->assertEquals(4.0, uint32_xor(1.0, 5.0));
$this->assertEquals(7.0, uint32_xor(1.0, 6.0));
$this->assertEquals(2.0, uint32_xor(2.0, 0.0));
$this->assertEquals(3.0, uint32_xor(2.0, 1.0));
$this->assertEquals(0.0, uint32_xor(2.0, 2.0));
$this->assertEquals(1.0, uint32_xor(2.0, 3.0));
$this->assertEquals(6.0, uint32_xor(2.0, 4.0));
$this->assertEquals(7.0, uint32_xor(2.0, 5.0));
$this->assertEquals(4.0, uint32_xor(2.0, 6.0));
$this->assertEquals(3.0, uint32_xor(3.0, 0.0));
$this->assertEquals(2.0, uint32_xor(3.0, 1.0));
$this->assertEquals(1.0, uint32_xor(3.0, 2.0));
$this->assertEquals(0.0, uint32_xor(3.0, 3.0));
$this->assertEquals(7.0, uint32_xor(3.0, 4.0));
$this->assertEquals(6.0, uint32_xor(3.0, 5.0));
$this->assertEquals(5.0, uint32_xor(3.0, 6.0));
$this->assertEquals(4.0, uint32_xor(4.0, 0.0));
$this->assertEquals(5.0, uint32_xor(4.0, 1.0));
$this->assertEquals(6.0, uint32_xor(4.0, 2.0));
$this->assertEquals(7.0, uint32_xor(4.0, 3.0));
$this->assertEquals(0.0, uint32_xor(4.0, 4.0));
$this->assertEquals(1.0, uint32_xor(4.0, 5.0));
$this->assertEquals(2.0, uint32_xor(4.0, 6.0));
$this->assertEquals(5.0, uint32_xor(5.0, 0.0));
$this->assertEquals(4.0, uint32_xor(5.0, 1.0));
$this->assertEquals(7.0, uint32_xor(5.0, 2.0));
$this->assertEquals(6.0, uint32_xor(5.0, 3.0));
$this->assertEquals(1.0, uint32_xor(5.0, 4.0));
$this->assertEquals(0.0, uint32_xor(5.0, 5.0));
$this->assertEquals(3.0, uint32_xor(5.0, 6.0));
$this->assertEquals(6.0, uint32_xor(6.0, 0.0));
$this->assertEquals(7.0, uint32_xor(6.0, 1.0));
$this->assertEquals(4.0, uint32_xor(6.0, 2.0));
$this->assertEquals(5.0, uint32_xor(6.0, 3.0));
$this->assertEquals(2.0, uint32_xor(6.0, 4.0));
$this->assertEquals(3.0, uint32_xor(6.0, 5.0));
$this->assertEquals(0.0, uint32_xor(6.0, 6.0));
}

}
