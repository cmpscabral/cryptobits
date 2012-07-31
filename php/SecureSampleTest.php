<?php

/*
 * http://code.google.com/p/securestring
 */

require_once 'PHPUnit/Framework.php';
require_once 'SecureSample.php';

class SecureStringTest extends PHPUnit_Framework_TestCase {

    public function testSmoke() {
        $ss = new SecureSample();
        $ary = array('foo' => 'bar', 'lead' => 'gold');
        $ss->write($ary);

        $ary2 = $ss->read();
        $this->assertTrue(count($ary2) > 0);
        print_r($ary2);
    }
}
?>
