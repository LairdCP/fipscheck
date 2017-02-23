#!/bin/sh
set -x
cd $(dirname $0)
autoreconf --install
VERSION=$(sed '/AC_INIT/ !d; s/^[^[:digit:]]*//; s/[^[:digit:]]*$//' configure.ac)
sed s/@PACKAGE_VERSION@/$VERSION/ fipscheck.spec.in > fipscheck.spec
