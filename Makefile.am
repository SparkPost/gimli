AUTOMAKE_OPTIONS = subdir-objects
RLLDFLAGS = @RL_LDFLAGS@
RLCFLAGS = @RL_CFLAGS@
TRACELDFLAGS = @CORONER_LDFLAGS@
bin_PROGRAMS = monitor glider #wdb
noinst_PROGRAMS = wedgie
lib_LTLIBRARIES = libgimli.la libgimli_ana.la
noinst_LTLIBRARIES = liblua.la
man1_MANS = man/monitor.1 man/glider.1
include_HEADERS = libgimli.h libgimli_ana.h

monitor_SOURCES = main.c proctitle.c config.c
glider_SOURCES = glider.c
glider_LDADD = libgimli_ana.la liblua.la $(TRACELDFLAGS)

libgimli_ana_la_SOURCES = \
	trace.c linux.c elf.c hash.c elf-read.c dwarf-read.c dwarf-unwind.c \
	dwarf-expr.c darwin.c solaris.c demangle.c freebsd.c proc.c \
	proc_service.c symbols.c types.c maps.c apiv2.c print.c slab.c \
	apiv3.c module.c

libgimli_la_SOURCES = \
  heartbeat.c

liblua_la_SOURCES = \
	lua/lapi.c lua/lcode.c lua/ldebug.c lua/ldo.c lua/ldump.c lua/lfunc.c \
	lua/lgc.c lua/llex.c lua/lmem.c lua/lobject.c lua/lopcodes.c \
	lua/lparser.c lua/lstate.c lua/lstring.c lua/ltable.c lua/ltm.c  \
	lua/lundump.c lua/lvm.c lua/lzio.c lua/lauxlib.c lua/lbaselib.c \
	lua/ldblib.c lua/liolib.c lua/lmathlib.c lua/loslib.c lua/ltablib.c \
	lua/lstrlib.c lua/loadlib.c lua/linit.c lua/lposix.c

wdb_SOURCES = wdb.c wdb-objs.c
wdb_CPPFLAGS = -Ilua $(RLCFLAGS)
wdb_LDADD = libgimli_ana.la liblua.la $(RLLDFLAGS) $(TRACELDFLAGS)

wedgie_SOURCES = wedgie.c
wedgie_LDADD = libgimli.la -lpthread

all-local:
	@DARWIN_DSYMUTIL@ ; \
	@DARWIN_CODESIGN@

