<?php
include('crypt_sha256.php');

$password = 'password';
$salt = '12345678';
$count = 5000;
$imax = 1000;

$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = crypt_sha256($password, $count, $salt);
}
$t1 = microtime(true);
print "crypt_sha256   " . $imax / ($t1 - $t0) . " RPS\n";


?>

