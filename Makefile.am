AUTOMAKE_OPTIONS = subdir-objects
RLLDFLAGS = @RL_LDFLAGS@
RLCFLAGS = @RL_CFLAGS@
bin_PROGRAMS = monitor glider ldb
noinst_PROGRAMS = wedgie
lib_LTLIBRARIES = libgimli.la
noinst_LTLIBRARIES = liblua.la
man1_MANS = man/monitor.1 man/glider.1
include_HEADERS = libgimli.h libgimli_ana.h

monitor_SOURCES = main.c proctitle.c config.c
glider_SOURCES = \
	trace.c linux.c elf.c hash.c elf-read.c dwarf-read.c dwarf-unwind.c \
	dwarf-expr.c darwin.c solaris.c demangle.c
glider_LDADD = liblua.la @CORONER_LDFLAGS@

libgimli_la_SOURCES = \
  heartbeat.c

liblua_la_SOURCES = \
	lua/lapi.c lua/lcode.c lua/ldebug.c lua/ldo.c lua/ldump.c lua/lfunc.c \
	lua/lgc.c lua/llex.c lua/lmem.c lua/lobject.c lua/lopcodes.c \
	lua/lparser.c lua/lstate.c lua/lstring.c lua/ltable.c lua/ltm.c  \
	lua/lundump.c lua/lvm.c lua/lzio.c lua/lauxlib.c lua/lbaselib.c \
	lua/ldblib.c lua/liolib.c lua/lmathlib.c lua/loslib.c lua/ltablib.c \
	lua/lstrlib.c lua/loadlib.c lua/linit.c

ldb_SOURCES = lua/lua.c
ldb_CPPFLAGS = $(RLCFLAGS)
ldb_LDADD = liblua.la $(RLLDFLAGS)

wedgie_SOURCES = wedgie.c
wedgie_LDADD = libgimli.la -lpthread

all-local:
	@DARWIN_DSYMUTIL@ ; \
	@DARWIN_CODESIGN@

