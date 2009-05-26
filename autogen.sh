#!/bin/sh
set -x
aclocal -I m4
autoheader
automake -a
autoconf
VERSION=$(sed '/AC_INIT/ !d; s/^[^[:digit:]]*//; s/[^[:digit:]]*$//' configure.ac)
sed s/@PACKAGE_VERSION@/$VERSION/ fipscheck.spec.in > fipscheck.spec
