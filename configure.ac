# vim:ts=2:sw=2:et:
AC_INIT(gimli,1.1,,gimli)
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AS
AC_PROG_LIBTOOL
AC_C_INLINE

CFLAGS=`echo $CFLAGS | sed -e 's/-O2//;'`
CFLAGS="-D_REENTRANT $CFLAGS"
MODULE_SUFFIX=".so"
SHLIB_SUFFIX=".so"
DWARF_DEBUG_FLAGS="-gdwarf-2 -g3"
case $host in
  *darwin*)
    LDFLAGS="-lpthread"
    MODULE_SUFFIX=".bundle"
    SHLIB_SUFFIX=".dylib"
    RLDPATH="-R"
    ;;
  *linux*)
    CORONER_LDFLAGS="-lthread_db -lpthread"
    RLDPATH="-Wl,-rpath="
    ;;
  *solaris*)
    RLDPATH="-R"
    case $CC in
      *gcc*)
        ;;
      *)
        DWARF_DEBUG_FLAGS="-xdebugformat=dwarf"
        ;;
    esac
    LDFLAGS="-lrt"
    CORONER_LDFLAGS="-lc_db"
  ;;
esac
AC_DEFINE_UNQUOTED([MODULE_SUFFIX], "$MODULE_SUFFIX", [platform module suffix])

CFLAGS="$CFLAGS $DWARF_DEBUG_FLAGS -DGIMLI_GLIDER_PATH=\\\"\$(bindir)/glider\\\""
LDFLAGS="$LDFLAGS $DWARF_DEBUG_FLAGS"
AC_SUBST(CORONER_LDFLAGS)

AC_CHECK_LIB(dl, dlopen)

AC_CHECK_SIZEOF(void*)
AC_CONFIG_HEADERS(gimli_config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT

