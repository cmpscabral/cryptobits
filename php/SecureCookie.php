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

require_once 'SecureString1.php';

/*
 * The flow would be ....
 *  in your "request start"
 *
 *  // load all configuration data
 *  $mycookie = new SecureCookie(...);
 *  $ok = $mycookie->read();
 *  // maybe log if not ok
 *  $mycookie->get('foo');
 *  $mycookie->set('foo', 'bar');
 *
 * Then in your response start:
 *  $mycookie->write();
 *
 */
class SecureCookie {

    const REASON_OK      = 0;
    const REASON_MISSING = 1;
    const REASON_INVALID = 2;
    const REASON_EXPIRED = 3;


    // got cookie from the future!
    const REASON_CLOCK_SKEW = 4;

    const ENCODE_NONE    = 0;
    const ENCODE_URL     = 1;
    const ENCODE_B64     = 2;


    /*
     *
     * @param key array  id1 => key1, id2=>key2
     * @param kid current key id to use to make new cookies
     * @param random object -- an object with a function "bytes" that
     *        returns random bytes.
     * @param cookie_name string
     * @param domain string
     * @param path string
     * @param secure boolean
     * @param httpdonly boolean
     * @param expiration seconds is the expiration for cookie (HTTP)
     * @param window seconds is how long the auth token is good for (policy)
     * @param cookie output encoding
     */
    public function __construct($keys,
                                $kid,
                                $random,
                                $cookie_name,
                                $domain,
                                $path,
                                $secure,
                                $httponly,
                                $expiration,
                                $window,
                                $encoding)
    {
        $this->keys = $keys;
        $this->kid = $kid;
        $this->random = $random;
        $this->cookie_name = $cookie_name;
        $this->domain = $domain;
        $this->path = $path;
        $this->secure = $secure;
        $this->httponly = $httponly;
        $this->expiration = $expiration;
        $this->window = $window;
        $this->encoding = $encoding;

        $this->dirty = FALSE;
    }

    public function get($name, $default=null) {
        if (isset($this->payload[$name])) {
            return $this->payload[$name];
        } else {
            return $default;
        }
    }

    public function set($name, $value) {
        $this->dirty = TRUE;

        if (is_null($value)) {
            unset($this->payload[$name]);
        } else {
            $this->payload[$name] = $value;
        }
    }

    /*
     *
     * @param int $now current time in seconds, only needed for unit testing
     * @returns reason code
     */
    public function read($now = 0) {
        // get cookie
        $str = null;
        if (isset($_COOKIE[$this->cookie_name])) {
            $str = $_COOKIE[$this->cookie_name];
        }
        if (empty($str) || $str == 'deleted') {
            $this->payload = array();
            return self::REASON_MISSING;
        }

        // decode any wrappers

        if (SecureString1::b64_chars($str)) {
            // if 100% b64 chars, then decode it
            $str = SecureString1::b64_urldecode($str);
        } else {
            // Some proxies will muck with '=' and '&' inspite of
            // the spec saying these are ok
            if (strpos($str, '%') !== false) {
                $str = urldecode($str);
                // sometimes double encoding happens
                if (strpos($str, '%') !== false) {
                    $str = urldecode($str);
                }
            }
        }

        // Now check for cryptographic integrity
        $ok = SecureString1::validate($str, $this->keys);

        if (!$ok) {
            return self::REASON_INVALID;
        }

        // from query string to array
        parse_str($str, $this->payload);

        // cookie is cryptographically valid, but check for policy on age
        if ($now === 0) {
            $now = time();
        }

        $created = $this->payload[SecureString1::PREFIX_CREATED];
        $elapsed = $now - $created;

        if ($elapsed > $this->window) {
            return self::REASON_EXPIRED;
        }

        // Hmmm someone's got a clock skew.  I'll you figure out what to do
        if ($created > $now) {
            return self::REASON_CLOCK_SKEW;
        }

        // valid
        return self::REASON_OK;
    }

    /*
     * create cookie value.  This is only useful for testing.
     * current time must be explicity passed in
     */
    public function _write($now) {
        $this->dirty = FALSE;

        $ary = $this->payload;
        // we'll strip out meta data
        unset($ary[SecureString1::PREFIX_VERSION]);
        unset($ary[SecureString1::PREFIX_CREATED]);
        unset($ary[SecureString1::PREFIX_KEYID]);
        unset($ary[SecureString1::PREFIX_SALT]);
        unset($ary[SecureString1::PREFIX_MAC]);

        $payload =  http_build_query($ary);

        $salt = SecureString1::b64_urlencode($this->random->bytes(6));

        $str =  SecureString1::create($payload, $salt,
                                      $this->keys, $this->kid, $now);

        switch ($this->encoding) {
        case self::ENCODE_B64:
            $str = SecureString1::b64_urlencode($str);
            break;
        case self::ENCODE_URL:
            $str = urlencode($str);
            break;
        }

        return $str;
    }

    public function write($now = 0) {
        if ($now === 0) {
            $now = time();
        }

        // only do a write if we are dirty
        if (! $this->dirty) {
            return FALSE;
        }

        $str = $this->_write($now);

        if (strlen($str) > 3800) {
            // do not try and set the cookie
            return FALSE;
        }

        return setcookie($this->cookie_name, $str,
                         $now + $this->expiration,
                         $this->path, $this->domain,
                         $this->secure, $this->httponly);
    }

    /*
     * Delete the cookie
     */
    public function zap() {
        $this->payload = array();
        return setcookie($this->cookie_name, '', 0,
                         $this->path, $this->domain,
                         $this->secure, $this->httponly);
    }
}

?>