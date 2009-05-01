
bin_PROGRAMS = monitor glider
noinst_PROGRAMS = wedgie
lib_LTLIBRARIES = libgimli.la

monitor_SOURCES = main.c proctitle.c config.c
glider_SOURCES = trace.c linux.c elf.c hash.c elf-read.c dwarf-read.c dwarf-unwind.c dwarf-expr.c darwin.c solaris.c
glider_LDADD = @CORONER_LDFLAGS@

libgimli_la_SOURCES = \
  heartbeat.c

wedgie_SOURCES = wedgie.c
wedgie_LDADD = libgimli.la -lpthread


