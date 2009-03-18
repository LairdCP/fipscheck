# Makefile.am - two binaries fipscheck and fipshmac

bin_PROGRAMS = fipscheck fipshmac

lib_LTLIBRARIES = libfipscheck.la

common_src = filehmac.c

fipscheck_SOURCES = fipscheck.c $(common_src)
fipscheck_LDADD = @LIBCRYPTO@ libfipscheck.la

fipshmac_SOURCES = fipshmac.c $(common_src)
fipshmac_LDADD = @LIBCRYPTO@

libfipscheck_la_SOURCES = library.c fipscheck.h
libfipscheck_la_CPPFLAGS = -DPATH_FIPSCHECK=\"$(bindir)/fipscheck\"
libfipscheck_la_LIBADD = @LIBDL@
libfipscheck_la_LDFLAGS = -no-undefined -version-info 2:0:1

noinst_HEADERS = filehmac.h

include_HEADERS = fipscheck.h
