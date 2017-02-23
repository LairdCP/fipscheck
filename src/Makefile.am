# Makefile.am - two binaries fipscheck and fipshmac
#
# Copyright (C) 2008, 2009, 2010, 2013 Red Hat, Inc. All rights reserved.
# Copyright (C) 2016 Andrew Cagney
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY RED HAT, INC. ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL THE FREEBSD PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of Red Hat, Inc.

bin_PROGRAMS = fipscheck fipshmac

lib_LTLIBRARIES = libfipscheck.la

hmacpath_src = hmacpath.c
common_src = filehmac.c $(hmacpath_src)

HMACDIR = $(libdir)/fipscheck

fipscheck_SOURCES = fipscheck.c $(common_src)
fipscheck_CPPFLAGS = -DPATH_HMACDIR=\"$(HMACDIR)\" @CRYPTO_CFLAGS@
fipscheck_LDADD = libfipscheck.la @CRYPTO_LIBS@

fipshmac_SOURCES = fipshmac.c $(common_src)
fipshmac_CPPFLAGS = @CRYPTO_CFLAGS@
fipshmac_LDADD = @CRYPTO_LIBS@

libfipscheck_la_SOURCES = library.c fipscheck.h $(hmacpath_src)
libfipscheck_la_CPPFLAGS = -DPATH_FIPSCHECK=\"$(bindir)/fipscheck\" -DPATH_HMACDIR=\"$(HMACDIR)\" @CRYPTO_CFLAGS@
libfipscheck_la_LIBADD = @LIBDL@
libfipscheck_la_LDFLAGS = -no-undefined -version-info 3:1:2

noinst_HEADERS = filehmac.h

include_HEADERS = fipscheck.h
