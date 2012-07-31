<?php
require_once 'MicroCurl.php';

class MicroCurlTest extends PHPUnit_Framework_TestCase {

    public function testMatchDomain() {
        $this->assertTrue(CookieJar::matchDomain('.client9.com', 'www.client9.com'));
        $this->assertFalse(CookieJar::matchDomain('.client9.com', 'www.ieunw.com'));

    }

    public function testMatchPath() {
        $this->assertTrue(CookieJar::matchPath('/', '/foo'));
        $this->assertFalse(CookieJar::matchPath('/', 'foo'));
    }

    public function testMatchSecure() {
        $this->assertTrue(CookieJar::matchSecure(TRUE, TRUE));
        $this->assertTrue(CookieJar::matchSecure(FALSE, FALSE));
        $this->assertTrue(CookieJar::matchSecure(FALSE, TRUE));
        $this->assertFalse(CookieJar::matchSecure(TRUE, FALSE));
    }

    public function testOne() {
        $jar = new CookieJar();
        $this->assertEquals(0, $jar->count());
        $jar->add(
            array(
                'name' => 'foo',
                'value' => 'dingbat',
                "domain" => '.client9.com',
                'path' => '/'
            )
        );
        $this->assertEquals(1, $jar->count());
        $jar->add(
            array(
                'name' => 'foo',
                'value' => 'dingbat',
                "domain" => '.sdfs.com',
                'path' => '/'
            )
        );
        $this->assertEquals(2, $jar->count());


        $jar->add(
            array(
                'name' => 'foo',
                'value' => 'asterisk',
                "domain" => '.client9.com',
                'path' => '/'
            )
        );
        $this->assertEquals(2, $jar->count());

        $matches = $jar->get('www.client9.com', '/', FALSE);
        $this->assertEquals(1, count($matches));
        $m = array_shift($matches);
        $this->assertEquals('foo', $m['name']);
        $this->assertEquals('asterisk', $m['value']);

        $jar->clearByDomain('.client9.com');
        $this->assertEquals(1, $jar->count());

        // do nothing
        $jar->clearByDomain('junk');
        $this->assertEquals(1, $jar->count());
        // do nothing
        $jar->clearByName('junk');
        $this->assertEquals(1, $jar->count());

        // all gone
        $jar->clearSessions();
        $this->assertEquals(0, $jar->count());

        $jar->add(
            array(
                'name' => 'foo',
                'value' => 'dingbat',
                "domain" => '.client9.com',
                'path' => '/',
                'expires' => 'Fri, 31-Dec-2010 23:59:59 GMT'
            )
        );
        $this->assertEquals(1, $jar->count());
        $jar->clearSessions();
        $this->assertEquals(1, $jar->count());

        $jar->clearExpired();
        $this->assertEquals(0, $jar->count());
    }
}