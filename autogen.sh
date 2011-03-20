#!/bin/sh -x
# vim:ts=2:sw=2:et:

./tidy.sh

if test `uname` = "Darwin" ; then
  glibtoolize --automake
else
  libtoolize --automake
fi
autoheader
aclocal 
automake --add-missing --foreign
autoconf

./configure "$*"

