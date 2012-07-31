<?php
include('crypt2007.php');
include('pbkdf2.php');
include('bcrypt.php');

$password = 'password';
$salt = '12345678SuperSalt';
$count = 1000;
$imax = 1000;

$algo = 'sha1';
$len = 32;
$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = hash_hmac('sha1', $password, $salt);
}
$t1 = microtime(true);
print "hmac\tsha-1\t${count}\t" . $imax / ($t1 - $t0) . " RPS\n";

$algo = 'sha256';
$len = 32;
$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = hash_hmac('sha256', $password, $salt);
}
$t1 = microtime(true);
print "hmac\tsha-256\t${count}\t" . $imax / ($t1 - $t0) . " RPS\n";

$algo = 'sha512';
$len = 32;
$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = hash_hmac('sha512', $password, $salt);
}
$t1 = microtime(true);
print "hmac\tsha-512\t${count}\t" . $imax / ($t1 - $t0) . " RPS\n";

if (1) {
$len = 20;
$algo = 'sha1';
$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = pbkdf2($password, $salt, $count, $len, $algo);
}
$t1 = microtime(true);
print "pbkdf2\tsha-1\t${count}\t" . $imax / ($t1 - $t0) . " RPS\n";

$algo = 'sha256';
$len = 32;
$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = pbkdf2($password, $salt, $count, $len, $algo);
}
$t1 = microtime(true);
print "pbkdf2\tsha-256\t${count}\t" . $imax / ($t1 - $t0) . " RPS\n";

$algo = 'sha512';
$len = 32;
$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = pbkdf2($password, $salt, $count, $len, $algo);
}
$t1 = microtime(true);
print "pbkdf2\tsha-512\t${count}\t" . $imax / ($t1 - $t0) . " RPS\n";

$count = 5000;

$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = Crypt2007::crypt_sha512($password, $count, $salt, true);
}
$t1 = microtime(true);
print "crypt_sha512 native\t$count\t" . $imax / ($t1 - $t0) . " RPS\n";

$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = Crypt2007::crypt_sha512($password, $count, $salt, false);
}
$t1 = microtime(true);
print "crypt_sha512 php\t$count\t" . $imax / ($t1 - $t0) . " RPS\n";

$count = 5000;

$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = Crypt2007::crypt_sha256($password, $count, $salt, true);
}
$t1 = microtime(true);
print "crypt_sha256 native\t$count\t" . $imax / ($t1 - $t0) . " RPS\n";

$t0 = microtime(true);
for ($i = 0; $i < $imax; ++$i) {
    $tmp = Crypt2007::crypt_sha256($password, $count, $salt,  false);
}
$t1 = microtime(true);
print "crypt_sha256 php\t$count\t" . $imax / ($t1 - $t0) . " RPS\n";
}

//
$hash_cost_log2 = 7;
$hash_portable = false;
$t0 = microtime(true);
$hasher = new PasswordHash($hash_cost_log2, $hash_portable);
for ($i = 0; $i < $imax; ++$i) {
    $hash = $hasher->HashPassword($password);
}

// $2a$
print "$hash\n";
$t1 = microtime(true);
print "bcrypt blowfish\t${hash_cost_log2}\t" . $imax / ($t1 - $t0) . " RPS\n";


// for "portable hashes" this is 2^(cost+5) iterations
$hash_cost_log2 = 9;
$hash_portable = true;
$t0 = microtime(true);
$hasher = new PasswordHash($hash_cost_log2, $hash_portable);
for ($i = 0; $i < $imax; ++$i) {
    $hash = $hasher->HashPassword($password);
}
// $P$
//print "$hash\n";
$t1 = microtime(true);
print "bcrypt portable\t${hash_cost_log2}\t" . $imax / ($t1 - $t0) . " RPS\n";

?>

