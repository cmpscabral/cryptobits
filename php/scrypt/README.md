Pure PHP Implementation of scrypt.
=======================================

This is a pure PHP implementation of scrypt, "a sequentially memory
hard" password hashing algorithm.  Unfortunately, it's at least 500x
slower than a unoptimized (-O0), non SSE C version

## What is scrypt? ##

It's the New Hotness on password storage.  While other password hash
functions burn CPU, scrypt burns CPU *and* memory making it much more
difficult to parallize.  [Read all about
it|http://www.tarsnap.com/scrypt.html].

## Usage  ##

No!  It's too slow.  Do not use this.  This is only for educational purposes.

## Why is it so slow ##

The algorithms involves a lot of memory manipulation.  In PHP each
string manipulation means copying or creating a new string instead of
just manipulating a single byte.  For example:

  $astring[$i] = 'a';

Does not work!  You need to make a new string.  Bah.

In addition, PHP does not (portabily) have a "uint32_t" integer type,
so it has to be simulated using floating point numbers (53 bits).

## Does it work on 32-Bit Platform ##

While it was designed to work on 32-bit platforms, given that it is so
slow I have not tested it.

## Now what? ##

Well, I guess I'll have to make PECL extention or something.

## Are there tests? ##

Yes.  You'll need to install phpunit.  Then

  make test

runs all the fast tests

  make slowtest

might take an hour

## nickg, you're doing it wrong ##

Probably.  Please send patches if you have improvements!