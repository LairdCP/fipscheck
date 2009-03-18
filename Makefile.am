SUBDIRS = src

EXTRA_DIST = fipscheck.spec fipscheck.spec.in

fipscheck.spec: fipscheck.spec.in
	VERSION=$$(sed '/AC_INIT/ !d; s/^.*, *//; s/).*$$//' configure.ac)
	sed s/\@PACKAGE_VERSION\@/$(VERSION)/ fipscheck.spec.in > fipscheck.spec

dist: fipscheck.spec configure.ac
