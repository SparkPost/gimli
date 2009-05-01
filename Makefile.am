
bin_PROGRAMS = gimli_monitor gimli_coroner
noinst_PROGRAMS = wedgie
lib_LTLIBRARIES = libgimli.la

gimli_monitor_SOURCES = main.c proctitle.c config.c
gimli_coroner_SOURCES = trace.c linux.c elf.c hash.c elf-read.c dwarf-read.c dwarf-unwind.c dwarf-expr.c darwin.c solaris.c
gimli_coroner_LDADD = @CORONER_LDFLAGS@

libgimli_la_SOURCES = \
  heartbeat.c

wedgie_SOURCES = wedgie.c
wedgie_LDADD = libgimli.la -lpthread


