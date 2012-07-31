#!/usr/bin/env php
<?php
include('SecureString1.php');



// here some data
$data = array('foo'=>'bar',
              'ding'=>'bat',
              'cow'=>'milk');

// turn it into a query string
$qs = http_build_query($data);

print $qs . "\n";


// ok here's some keys..... ideally from a config file
// notice how the plain-text secret is md5'd to scramble the bits
$keys = array( 1 => hash('md5', "this is my secret key 1", true) );

$mac =  SecureString1::create($qs, $keys, 1);
print $mac . "\n";

// if we do it again, the MAC is different (due to the salting)
$mac =  SecureString1::create($qs, $keys, 1);
print $mac . "\n";


// the SecureString perserves query string formating
//   so you can break it apart just like this:
parse_str($mac,$parts);

// and now you have all the meta data in addition to your
//  data.
print_r($parts);


// Nice thing about PHP is that the associative array
// keeps order.  So we can reassemble the parts as is
// and it still validates
//
print SecureString1::validate(http_build_query($parts), $keys) ? "same\n" : "different\n";


// like wise we can tamper with one element
//  and it won't re-validate
$parts['cow'] = 'juice';
print_r($parts);
print SecureString1::validate(http_build_query($parts), $keys) ? "same\n" : "different\n";

// and of course we can just directly tamper with it
$bad = $mac;
$bad[20] = '*';  // or anything, or add data or truncate
print SecureString1::validate($bad, $keys) ? "same\n" : "different\n";


print_r (substr(SecureString1::b64_urlencode(pack("L", mt_rand())), 0, 6));
print "\n";
?>
