#!/bin/sh -x
# vim:ts=2:sw=2:et:

./tidy.sh

if test `uname` = "Darwin" ; then
  glibtoolize --automake
else
  libtoolize --automake
fi
autoheader
if test -z "$ACLOCAL" ; then
  ACLOCAL=aclocal
fi
$ACLOCAL
if test -z "$AUTOMAKE" ; then
  AUTOMAKE=automake
fi
$AUTOMAKE --add-missing --foreign
autoconf

