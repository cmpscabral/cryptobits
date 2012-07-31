<?php
function gen_mtrand_str_24()
{
    return base64_encode(pack('N3', mt_rand(), mt_rand(), mt_rand()));
}

function gen_rand_str_24()
{
    return base64_encode(pack('N3', rand(), rand(), rand()));
}

function read_mcrypt() 
{
    return base64_encode(mcrypt_create_iv(12, MCRYPT_DEV_URANDOM));
}

function read_urandom() {

    if ($fh = @fopen('/dev/urandom', 'rb')) {
        $output = fread($fh, 12);
        fclose($fh);
    }
    return base64_encode($output);
}


$imax = 10000;

$t0 = microtime(true);
for ($i =$imax; $i >= 0; --$i) {
    $a = read_urandom();
}
$t1 = microtime(true);
printf("file /dev/urandom: %f\n", $t1-$t0);

$t0 = microtime(true);
for ($i =$imax; $i >= 0; --$i) {
    $a = read_mcrypt();
}
$t1 = microtime(true);
printf("mcrypt: %f\n", $t1-$t0);

$t0 = microtime(true);
for ($i =$imax; $i >= 0; --$i) {
    $a = gen_rand_str_24();
}
$t1 = microtime(true);
printf("rand: %f\n", $t1-$t0);

$t0 = microtime(true);
for ($i =$imax; $i >= 0; --$i) {
    $a = gen_mtrand_str_24();
}
$t1 = microtime(true);
printf("mt_rand: %f\n", $t1-$t0);


?>