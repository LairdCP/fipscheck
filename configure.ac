# Copyright (C) 2008, 2009, 2010, 2012, 2013 Red Hat, Inc. All rights reserved.
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

AC_INIT([fipscheck],[1.7.0],[support@lairdconnect.com])
AC_CONFIG_HEADERS([config.h])
AC_PREREQ([2.69])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip])

AC_ARG_ENABLE([docs],
    AS_HELP_STRING([--enable-docs], [Enable man genereation @<:@default=yes@:>@]),
    [case "${enableval}" in
        yes) enable_docs=true ;;
        no)  enable_docs=false ;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-docs]) ;;
     esac],[enable_docs=true])
AM_CONDITIONAL([ENABLE_DOCS], [test x$enable_docs = xtrue])

dnl Check for _GNU_SOURCE
AC_USE_SYSTEM_EXTENSIONS

LT_INIT([disable-static])

_LT_TAGVAR(hardcode_libdir_flag_spec, )=""
_LT_TAGVAR(hardcode_minus_L, )=yes

PKG_PROG_PKG_CONFIG()

dnl Checks for programs.

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_CC_C_O

AC_CHECK_HEADERS( \
        fcntl.h \
        stddef.h \
        stdint.h \
        sys/stat.h \
        sys/time.h \
        sys/types.h \
        time.h \
        unistd.h \
        syslog.h
)

AC_CHECK_FUNCS( \
       fcntl \
       vasprintf \
       syslog
)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

dnl Checks for the existence of libdl - on BSD and Tru64 its part of libc
AC_CHECK_LIB([dl], [dlopen], LIBDL="-ldl", LIBDL="")
AC_SUBST(LIBDL)

dnl This is not a strictly correct use of --with, OTOH it is better
dnl than having separate and conflicting --with-nss and --with-openssl
dnl options.  Rather than be "smart" and guess the crypto library
dnl based on what is installed, this logic simply barfs on an error.

AC_ARG_WITH([crypto],
            [AS_HELP_STRING([--with-crypto],
	                    [specify the crypto library to use when computing the HMAC, OpenSSL (the default) and NSS are supported])],
            [],
            [with_crypto=openssl])

dnl Check for the existence of the slected crypto library with FIPS mode
AS_CASE($with_crypto,
    [openssl|ssl], [
	      PKG_CHECK_MODULES([CRYPTO],[libcrypto],[],[AC_MSG_ERROR([OpenSSL library with FIPS mode support is required])])
        CRYPTO_LIBS=-lcrypto
        AC_DEFINE([WITH_OPENSSL], [1], [use HMAC from the OpenSSL crypto library])
	],
    [nss], [
	      PKG_CHECK_MODULES([CRYPTO],[nss],[],[AC_MSG_ERROR([NSS library with FIPS mode support is required])])
	      CRYPTO_LIBS="$CRYPTO_LIBS -lfreebl"
        AC_DEFINE([WITH_NSS], [1], [use HMAC from the NSS crypto library])
	],
    [AC_MSG_ERROR([The --with-crypto library "$with_crypto" is not known])])

AC_SUBST(CRYPTO_LIBS)
AC_SUBST(CRYPTO_CFLAGS)

AC_MSG_CHECKING(sysconfdir)
AC_ARG_WITH(sysconfdir,
[AS_HELP_STRING([--with-sysconfdir=PATH], [Directory containing permission files (default /etc).])],
[ case "$withval" in
  no)
    AC_MSG_ERROR([Need SYSCONFDIR.])
    ;;
  yes)
    SYSCONFDIR=/etc
    AC_MSG_RESULT(/etc)
    ;;
  *)
    SYSCONFDIR="$withval"
    AC_MSG_RESULT($withval)
    ;;
  esac ],
  SYSCONFDIR="/etc"
  AC_MSG_RESULT(/etc)
)
AC_SUBST(SYSCONFDIR)

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_OUTPUT

