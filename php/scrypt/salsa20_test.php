<?php
require_once 'scrypt.php';
class Salsa20Test extends PHPUnit_Framework_TestCase {
      public function test_pack() {
          $ary = array( 0xFFFFFFFF, 0xFFFFFFFF);
          $s = ints2string($ary);
          $this->assertEquals('ffffffffffffffff', bin2hex($s));

          $uints = string2ints($s);
          $this->assertEquals(2, count($uints));
          $this->assertEquals(0xFFFFFFFF, $uints[0]);
      }

      public function test_salsa20_Loop_2() {
          $ary = array(
              0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09,
              0x100f0e0d, 0x3320646e, 0x01040103, 0x06020905,
              0x00000007, 0x00000000, 0x79622d32, 0x14131211,
              0x18171615, 0x1c1b1a19, 0x201f1e1d, 0x6b206574
              );

          salsa20_loop($ary, 2);

          $expected = array(
              0xba2409b1, 0x1b7cce6a, 0x29115dcf, 0x5037e027,
              0x37b75378, 0x348d94c8, 0x3ea582b3, 0xc3a9a148,
              0x825bfcb9, 0x226ae9eb, 0x63dd7748, 0x7129a215,
              0x4effd1ec, 0x5f25dc72, 0xa6c3d164, 0x152a26d8
              );

          $this->assertEquals($expected, $ary);
      }

    // intermediate steps
      public function test_salsa20_loop_20() {
          $ary = array(
              0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09,
              0x100f0e0d, 0x3320646e, 0x01040103, 0x06020905,
              0x00000007, 0x00000000, 0x79622d32, 0x14131211,
              0x18171615, 0x1c1b1a19, 0x201f1e1d, 0x6b206574
              );

          salsa20_loop($ary, 20);

          $expected = array(
              0x58318d3e, 0x0292df4f, 0xa28d8215, 0xa1aca723,
              0x697a34c7, 0xf2f00ba8, 0x63e9b0a1, 0x27250e3a,
              0xb1c7f1f3, 0x62066edc, 0x66d3ccf1, 0xb0365cf3,
              0x091ad09e, 0x64f0c40f, 0xd60d95ea, 0x00be78c9
              );

          $this->assertEquals($expected, $ary);
      }

    // full salsa20/20
    public function test_salsa20_20() {
          $ary = array(
              0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09,
              0x100f0e0d, 0x3320646e, 0x01040103, 0x06020905,
              0x00000007, 0x00000000, 0x79622d32, 0x14131211,
              0x18171615, 0x1c1b1a19, 0x201f1e1d, 0x6b206574
              );

          salsa20($ary, 20);

          $expected = array(
              0xb9a205a3, 0x0695e150, 0xaa94881a, 0xadb7b12c,
              0x798942d4, 0x26107016, 0x64edb1a4, 0x2d27173f,
              0xb1c7f1fa, 0x62066edc, 0xe035fa23, 0xc4496f04,
              0x2131e6b3, 0x810bde28, 0xf62cb407, 0x6bdede3d
              );

          $this->assertEquals($expected, $ary);
      }

}