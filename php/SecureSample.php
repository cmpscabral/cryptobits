<?php

/*
 * http://code.google.com/p/securestring
 *
 * Here's a sample of how SecureString1 might be used to make cookeies
 * or URLs
 *
 */

require_once 'SecureString1.php';

class SecureSample {
    public function __construct() {
        // load your keys
        // This might come DB, a read-only file, a config, a key server

        // we'll just hardwire for fun since this is a sample
        $this->keys = array(1 => md5("blah blah blah"));
        $this->kid = 1;
    }

    public function read() {
        // grab cookie or URL from environment
        // since this is sample we'll just pull from global env
        $str = $GLOBALS['userdata'];
        echo "\n\nSTR = $str\n";
        $ok = SecureString1::validate($str, $this->keys);

        if (!$ok) {
            // do something
            return array();
        }

        parse_str($str, $ary);
        // now we have all the meta data to make policy decisions
        // perhaps the creation date is too old, and need to be expired.
        // perhaps strip out the meta data
        return $ary;
    }

    public function write($ary, $now=0) {
        // for this sample, we'll strip out meta data
        unset($ary[SecureString1::PREFIX_VERSION]);
        unset($ary[SecureString1::PREFIX_CREATED]);
        unset($ary[SecureString1::PREFIX_KEYID]);
        unset($ary[SecureString1::PREFIX_SALT]);
        unset($ary[SecureString1::PREFIX_MAC]);

        $payload =  http_build_query($ary);

        // this is a "ok" 24-bit salt represent as 6 characters
        // (the substr is to remove padding chars which aren't useful here)
        //
        // A BETTER solution is use the DevUrandom
        //
        $salt = substr(SecureString1::b64_urlencode(pack("L", mt_rand())), 0, 6);
        $str =  SecureString1::create($payload, $salt,
                                      $this->keys, $this->kid, $now);

        // grab cookie or URL from environment
        // since this is sample we'll just pull from global env
        $GLOBALS['userdata'] = $str;
    }
};

?>
