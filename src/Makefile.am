# Makefile.am - two binaries fipscheck and fipshmac

bin_PROGRAMS = fipscheck fipshmac

lib_LTLIBRARIES = libfipscheck.la

hmacpath_src = hmacpath.c
common_src = filehmac.c $(hmacpath_src)

HMACDIR = $(libdir)/fipscheck

fipscheck_SOURCES = fipscheck.c $(common_src)
fipscheck_CPPFLAGS = -DPATH_HMACDIR=\"$(HMACDIR)\"
fipscheck_LDADD = @LIBCRYPTO@ libfipscheck.la

fipshmac_SOURCES = fipshmac.c $(common_src)
fipshmac_LDADD = @LIBCRYPTO@

libfipscheck_la_SOURCES = library.c fipscheck.h $(hmacpath_src)
libfipscheck_la_CPPFLAGS = -DPATH_FIPSCHECK=\"$(bindir)/fipscheck\" -DPATH_HMACDIR=\"$(HMACDIR)\"
libfipscheck_la_LIBADD = @LIBDL@
libfipscheck_la_LDFLAGS = -no-undefined -version-info 3:1:2

noinst_HEADERS = filehmac.h

include_HEADERS = fipscheck.h
