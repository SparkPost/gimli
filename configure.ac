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

AC_ARG_WITH(codesign,[
  --with-codesign=certname     Mac OS/X: name of a code signing certificate
                               to use to authorize the glider as a debugger],[
  DARWIN_CODESIGN="codesign -s $withval glider"
],[
  DARWIN_CODESIGN="echo"
])
DARWIN_DSYMUTIL="echo"

case $host in
  *darwin*)
    LDFLAGS="-lpthread"
    CORONER_LDFLAGS="-framework Security -framework CoreFoundation -sectcreate __TEXT __info_plist glider.plist"
    MODULE_SUFFIX=".bundle"
    SHLIB_SUFFIX=".dylib"
    RLDPATH="-R"
    DARWIN_DSYMUTIL="dsymutil -o .libs/wedgie.dSYM .libs/wedgie"
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
AC_SUBST(DARWIN_DSYMUTIL)
AC_SUBST(DARWIN_CODESIGN)

AC_CHECK_LIB(dl, dlopen)

AC_CHECK_SIZEOF(void*)

AC_DEFINE(LUA_USE_POSIX, 1, [Use POSIX functions])
AC_DEFINE(LUA_USE_DLOPEN, 1, [Use dlopen for loading modules])
AC_DEFINE_UNQUOTED(LUA_ROOT, "$prefix/", [Installation prefix])
AC_DEFINE(LUA_VERMAJORMINOR, "5.1", [First two version number octets])
AC_SUBST(PACKAGE_VERMAJORMINOR, 5.1)

AC_ARG_WITH(readline,
[  --with-readline   link ldb against libreadline],
[
  LDFLAGS_SAVE="$LDFLAGS"
  LDFLAGS="-L$withval"
  AC_CHECK_LIB(readline, readline, [
    AC_SUBST(RL_LDFLAGS, "-lreadline")
    AC_SUBST(RL_CFLAGS, "-DLUA_USE_READLINE")
  ])
  LDFLAGS="$LDFLAGS_SAVE"
])

AC_ARG_WITH(libedit,
[  --with-libedit    link ldb against libedit],
[
  LDFLAGS_SAVE="$LDFLAGS"
  LDFLAGS="-L$withval"
  AC_CHECK_LIB(edit, readline, [
    AC_SUBST(RL_LDFLAGS, "-ledit")
    AC_SUBST(RL_CFLAGS, "-DLUA_USE_READLINE")
  ])
  LDFLAGS="$LDFLAGS_SAVE"
])

AC_CONFIG_HEADERS(gimli_config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT

