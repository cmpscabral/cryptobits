<?php

/** 1 file OO Helper for PHP CURL, with Cookie Support,
 *  to aid in security testing
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
class CookieJar {
    public function __construct() {
        $this->jar = array();
    }

    public function clear() {
        $this->jar = array();
    }

    public function count() {
        return count($this->jar);
    }

    public function add($cookie) {
        // basically deletes any instance of existing cookie
        // then adds it

        // this is mostly for ease of testing
        if (!isset($cookie['secure'])) {
            $cookie['secure'] = FALSE;
        }
        if (!isset($cookie['httponly'])) {
            $cookie['httponly'] = FALSE;
        }

        $this->arg = $cookie;
        $this->jar = array_filter($this->jar,
                                 array(&$this, '_notSameCookie'));
        array_push($this->jar, $cookie);
    }

    public function get($domain, $path, $secure) {
        $this->arg = array(
            'domain' => $domain,
            'path' => $path,
            'secure' => $secure
        );
        return array_filter($this->jar,
                            array(&$this, '_cookieMatch'));
    }

    public function clearByName($name) {
        $this->arg = $name;
        $this->jar = array_filter($this->jar,
                                 array(&$this, '_notSameName'));
    }

    public function clearByDomain($domain) {
        $this->arg = $domain;
        $this->jar = array_filter($this->jar,
                                 array(&$this, '_notSameDomain'));
    }

    public function clearSessions() {
        $this->jar = array_filter($this->jar,
                                  array(&$this, '_isNotSession'));
    }


    public function clearExpired($now = 0) {
        if ($now == 0) {
            $now = time();
        }
        $this->arg = $now;
        $this->jar = array_filter($this->jar,
                                  array(&$this, '_isExpired'));
    }

    public function _cookieMatch($a) {
        $b = $this->arg;
        return (self::matchDomain($a['domain'], $b['domain']) &&
                self::matchPath($a['path'] , $b['path']) &&
                self::matchSecure($a['secure'], $b['secure']));
    }

    public static function matchDomain($a, $b) {

        // GROSS HACK
        // $a = .foobar.com  cookie domain
        // $b = www.foobar.com  current domain
        // is $a is a substr of $b
        return strpos($b, $a) !== FALSE;
    }

    public static function matchPath($a, $b) {

        // more hacks since I don't care
        // $a = "/"
        // $b = "/foobar"
        // match since $b startswith $a
        return strpos($b, $a) === 0;
    }

    public static function matchSecure($a, $b) {
        // a is secure, b is secure == yes
        // a is not secure, b is not secure == yes
        // a is secure, b is not secure == NO
        // a is not secure, b is secure == YES
        return (! $a) || $b;
    }

    public function _sameCookie($a) {
        $b = $this->arg;
        return $a['name'] == $b['name'] &&
            $a['domain'] == $b['domain'] &&
            $a['path'] == $b['path'];
    }

    public function _notSameName($a) {
        $b = $this->arg;
        return $a['name'] != $b;
    }

    public function _notSameDomain($a) {
        $b = $this->arg;
        return $a['domain'] != $b;
    }

    public function _notSameCookie($a) {
        $b = $this->arg;
        return  $a['name'] != $b['name'] ||
            $a['domain'] != $b['domain'];
    }

    public function _isNotSession($cookie) {
        return isset($cookie['expires']);
    }

    public function _isExpired($cookie) {
        if (!isset($cookie['expires'])) {
            // it's a session cookie
            return TRUE;
        }
        $expires = $cookie['expires'];

        $t =strptime($expires, '%a, %d-%h-%Y %H:%M:%S GMT');
        $stamp = gmmktime(
            $t['tm_hour'],
            $t['tm_min'],
            $t['tm_sec'],
            $t['tm_mon'],
            $t['tm_mday'] + 1,
            $t['tm_year'] + 1900
        );

        return $this->arg <  $stamp;
    }
}

class MicroCurl {
    public function __construct($url=NULL) {
        $this->cookiejar = new CookieJar();

        $this->ch = curl_init($url);
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($this->ch, CURLINFO_HEADER_OUT, TRUE);
        curl_setopt($this->ch, CURLOPT_HEADERFUNCTION,
                    array(&$this,'_readResponseHeader'));
    }

    public function _readResponseHeader($ptr, $header) {
        $h = trim($header);
        array_push($this->headers, $h);
        if (preg_match('/^Set-Cookie:/i', $h)) {
            $parts = explode(':', $h, 2);
            $pieces = explode('; ', $parts[1]);
            $keyvalue = explode('=', array_shift($pieces), 2);
            $cookie['name'] = trim($keyvalue[0]);
            $cookie['value'] = trim($keyvalue[1]);
            foreach ($pieces as $piece) {
                $kv = explode('=', $piece, 2);
                if (count($kv) === 2) {
                    $cookie[strtolower(trim($kv[0]))] = trim($kv[1]);
                } else {
                    $cookie[strtolower(trim($kv[0]))] = TRUE;
                }
            }
            $this->cookiejar->add($cookie);
        }
        return strlen($header);
    }
    public function __destruct() {
        if ($this->ch) curl_close($this->ch);
    }
    public function setopt($option, $value) {
        curl_setopt($this->ch, $option, $value);
    }
    public function exec() {
        $url = curl_getinfo($this->ch, CURLINFO_EFFECTIVE_URL);
        $parts = parse_url($url);

        $cookies = $this->cookiejar->get($parts['host'],
                                         $parts['path'],
                                         $parts['scheme'] == 'https');
        $values = array();
        foreach ($cookies as $k => $v) {
            array_push($values, $v['name'] . '=' . $v['value']);
        }
        if (count($values) > 0) {
            curl_setopt($this->ch, CURLOPT_HTTPHEADER, array(
                            'Cookie: ' . implode('; ', $values)));
        }
        $this->headers = array();
        return curl_exec($this->ch);
    }
    public function getinfo($opt=0) {
        return curl_getinfo($this->ch, $opt);
    }
    public function requestHeaders() {
        return explode("\r\n", curl_getinfo($this->ch, CURLINFO_HEADER_OUT));
    }
    public function responseHeaders() {
        return $this->headers;
    }
    public static function findHeader($needle, $haystack) {
        $out = array();
        foreach ($haystack as $header) {
            $parts = explode(':', $header, 2);
            if ($parts[0] == $needle) {
                array_push($out, trim($parts[1]));
            }
        }
        return $out;
    }
}
?>