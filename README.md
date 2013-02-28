pretty-arm
==========

otool disasm beatifier.

* cctools patch to make otool output parsable (added '-z' option to use with '-o'). Apply with 'patch -p5 < cctools-836.patch'. Generated with diff -rupN.
* no support for FAT yet
* only thin ARMv7 supported
