#!/bin/sh
set -x
aclocal -I m4
autoheader
automake -a
autoconf
VERSION=`sed '/AC_INIT/ !d; s/^.*, *//; s/).*$//' configure.ac`
sed s/@PACKAGE_VERSION@/$VERSION/ fipscheck.spec.in > fipscheck.spec
