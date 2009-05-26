AC_INIT([fipscheck],[1.2.0],[tmraz@redhat.com])
AC_CONFIG_HEADER([config.h])
AC_PREREQ(2.60)

AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip])

dnl Check for _GNU_SOURCE
AC_USE_SYSTEM_EXTENSIONS

AM_PROG_LIBTOOL

dnl Checks for programs.

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

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
AC_TYPE_SIGNAL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

dnl Checks for the existence of libdl - on BSD and Tru64 its part of libc 
AC_CHECK_LIB([dl], [dlopen], LIBDL="-ldl", LIBDL="")
AC_SUBST(LIBDL)

dnl Checks for the existence of OpenSSL with FIPS mode
AC_CHECK_LIB([crypto], [FIPS_mode],
[
	LIBCRYPTO=-lcrypto
],
[
	AC_MSG_ERROR([OpenSSL library with FIPS mode support is required])
])
AC_SUBST(LIBCRYPTO)

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

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

