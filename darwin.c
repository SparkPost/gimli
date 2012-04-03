/*
 * Copyright (c) 2007-2010 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */

#ifdef __MACH__
#include "impl.h"

/* http://www.omnigroup.com/mailman/archive/macosx-dev/2000-June/014178.html
 * http://web.mit.edu/darwin/src/modules/xnu/osfmk/man/vm_read.html
 * http://developer.apple.com/library/mac/#documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW1
 */

#include <libgen.h>
#include <Security/Authorization.h>
#include <mach/task_info.h>

#if defined(__ppc__)
# error this code assumes intel architecture
#endif

#if __DARWIN_UNIX03 /* Leopard and up */
#define GIMLI_DARWIN_REGNAME(x)  __##x
#else
#define GIMLI_DARWIN_REGNAME(x)  x
#endif

static const cpu_type_t whatami =
#if defined(__LP64__) && defined(__x86_64__)
      CPU_TYPE_X86_64
#elif defined(__i386__)
      CPU_TYPE_X86
#elif defined(__ppc64__)
      CPU_TYPE_POWERPC64
#elif defined(__ppc__)
      CPU_TYPE_POWERPC
#else
# error dont know my own arch
#endif
      ;

/* offset from fp to get to mcontext and siginfo_t in a signal frame.
 * There's a chance that these need to be corrected for the amd64 16-byte
 * alignment requirements */
#define GIMLI_KERNEL_MCTX64 44
#define GIMLI_KERNEL_SIGINFO64 0x2f0

#if 0 /* this seems funky; probably padding related */
struct gimli_kernel_sigframe64 {
  char pad[40];
  _STRUCT_MCONTEXT64 mctx;
  siginfo_t si;
  ucontext64_t uc;
  /* redzone goes here */
};
#endif

struct gimli_kernel_sigframe32 {
  char pad[24];
  int retaddr;
  sig_t catcher;
  int sigstyle;
  int sig;
  siginfo_t *sinfo;
  _STRUCT_UCONTEXT *uctx;
  _STRUCT_MCONTEXT32 mctx;
  siginfo_t si;
  _STRUCT_UCONTEXT uc;
};

static int target_pid;
static int got_task = 0;
static task_t targetTask;
static gimli_addr_t sigtramp = 0;

void gimli_object_file_destroy(gimli_object_file_t obj)
{
}

/* Given a path to an image file, open it, find the correct architecture
 * portion for the header, populate rethdr with it and return the file
 * descriptor */
static int read_mach_header(const char *filename,
  uint32_t *rethdr_offset, gimli_mach_header *rethdr)
{
  int fd;
  gimli_mach_header  hdr;
  uint32_t hdr_offset = 0; /* offset of mach_header from start of file */

  fd = open(filename, O_RDONLY);
  if (fd == -1) return -1;

  if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
    fprintf(stderr, "error reading mach header %s\n", strerror(errno));
    close(fd);
    return -1;
  }

  if (NXSwapBigLongToHost(hdr.magic) == FAT_MAGIC) {
    int nfat = NXSwapBigLongToHost(hdr.cputype);
    int i;
    struct fat_arch fa;
    int found = 0;

    for (i = 0; i < nfat; i++) {
      pread(fd, &fa, sizeof(fa), sizeof(struct fat_header) + (i * sizeof(fa)));
      fa.cputype = NXSwapBigLongToHost(fa.cputype);
      fa.cpusubtype = NXSwapBigLongToHost(fa.cpusubtype);
      fa.offset = NXSwapBigLongToHost(fa.offset);
      fa.size = NXSwapBigLongToHost(fa.size);

      if (fa.cputype == whatami) {
        if (debug) {
          fprintf(stderr, "matching arch %x %x at %x (%x)\n",
            fa.cputype, fa.cpusubtype, fa.offset, fa.size);
        }
        hdr_offset = fa.offset;
        pread(fd, &hdr, sizeof(hdr), hdr_offset);
        found = 1;
        break;
      }
    }
    if (!found) {
      fprintf(stderr, "Couldn't find a suitable matching arch in fat dsym\n");
      close(fd);
      return -1;
    }
  }
  if (hdr.magic != GIMLI_MH_MAGIC) {
    fprintf(stderr, "Couldn't find a valid mach header in %s\n", filename);
    close(fd);
    return -1;
  }
  memcpy(rethdr, &hdr, sizeof(hdr));
  *rethdr_offset = hdr_offset;
//  printf("%s: native @ offset %x %d\n", filename, hdr_offset, hdr_offset);
  return fd;
}

/* Starting with OSX 10.5, apple introduced the concept of a
 * a dSYM bundle which contains a mach-o object file with dwarf
 * segments.
 * Attempt to load such a beast and process the dwarf info from
 * it.
 */
static void find_dwarf_dSYM(gimli_mapped_object_t file)
{
  char dsym[PATH_MAX];
  char *base;
  char basepath[PATH_MAX];
  gimli_mach_header  hdr;
  uint32_t hdr_offset = 0; /* offset of mach_header from start of file */
  uint32_t cmd_offset;
  int n;
  int fd;
  gimli_segment_command scmd;
  char sectname[16];
  gimli_object_file_t container;
  
  strcpy(basepath, file->objname);
  base = basename(basepath);

  snprintf(dsym, sizeof(dsym)-1,
    "%s.dSYM/Contents/Resources/DWARF/%s", file->objname, base);

  if (debug) {
    fprintf(stderr, "dsym: trying %s\n", dsym);
  }
  fd = read_mach_header(dsym, &hdr_offset, &hdr);
  if (debug) {
    fprintf(stderr, "dsym: %s: %s\n", dsym, fd == -1 ? "failed" : "got it");
  }
  if (fd == -1) return;

  container = calloc(1, sizeof(*container));
  container->gobject = file;
  container->objname = strdup(dsym);
  container->is_exec = 1;

  file->aux_elf = container;

  /* we're looking for an LC_SEGMENT with a segname of __DWARF */
  cmd_offset = hdr_offset + sizeof(hdr);
  for (n = 0; n < hdr.ncmds; n++, cmd_offset += scmd.cmdsize) {
    pread(fd, &scmd, sizeof(struct load_command), cmd_offset);
    if (scmd.cmd == GIMLI_LC_SEGMENT) {
      if (pread(fd, &scmd, sizeof(scmd), cmd_offset) != sizeof(scmd)) {
        fprintf(stderr, "pread failed %s\n", strerror(errno));
        continue;
      }
      if (strcmp("__DWARF", scmd.segname) == 0) {
        uint32_t sec_addr = cmd_offset + sizeof(scmd);
        int sno;
        gimli_section sec;
        char *buf;
        struct gimli_section_data *s;

        for (sno = 0; sno < scmd.nsects; sno++, sec_addr += sizeof(sec)) {
          if (pread(fd, &sec, sizeof(sec), sec_addr) != sizeof(sec)) {
            continue;
          }

          // make the names look more like elven versions
          s = calloc(1, sizeof(*s));
          memcpy(sectname, sec.sectname + 1, 15);
          sectname[15] = '\0';
          s->name = strdup(sectname);
          s->name[0] = '.';
          s->addr = sec.addr;
          if (debug) {
            fprintf(stderr, "%s %s s->addr=" PTRFMT " base_addr=" PTRFMT "\n",
              file->objname, sectname, s->addr, file->base_addr);
          }
          s->size = sec.size;
          s->data = malloc(s->size);
          s->offset = sec.offset;
          s->container = container;
          pread(fd, s->data, s->size, s->offset);

          gimli_hash_insert(file->sections, s->name, s);
        }
      }
    }
  }
}

struct gimli_section_data *gimli_get_section_by_name(
  gimli_object_file_t elf, const char *name)
{
  struct gimli_section_data *s = NULL;

  if (gimli_hash_find(elf->gobject->sections, name, (void**)&s)) {
    return s;
  }
  return NULL;
}

typedef int (*symcallback)(
  gimli_mach_header *mhdr,
  void *context,
  const char *strtab, gimli_nlist *nsym);



static void walk_symtab(void *context, symcallback cb,
  int fd, uint32_t cmd_offset, uint32_t file_off,
  gimli_mach_header *mhdr)
{
  struct symtab_command scmd;
  gimli_nlist nl[256];
  int n;
  char *symaddr;
  /* number of nlist entries read from symtab */
  int nsyms;
  char *strtab;
  int i;

  if (cmd_offset == 0) {
    /* find the symtab */
    gimli_segment_command seg;

    cmd_offset = file_off + sizeof(*mhdr);
    for (n = 0; n < mhdr->ncmds; n++, cmd_offset += seg.cmdsize) {
      pread(fd, &seg, sizeof(struct load_command), cmd_offset);
      if (seg.cmd == LC_SYMTAB) {
        break;
      }
    }
  }

  if (pread(fd, &scmd, sizeof(scmd), cmd_offset) != sizeof(scmd)) {
    fprintf(stderr, "pread failed %s\n", strerror(errno));
    return;
  }

  /* compensate for offset of inner file for fat images */
  scmd.symoff += file_off;
  scmd.stroff += file_off;

  strtab = malloc(scmd.strsize + 1);
  strtab[scmd.strsize] = '\0';
  if (pread(fd, strtab, scmd.strsize, scmd.stroff) != scmd.strsize) {
    fprintf(stderr, "failed to read string tab\n");
    return;
  }

  nsyms = 0;

  while (nsyms < scmd.nsyms) {
    n = (scmd.nsyms - nsyms) * sizeof(nl[0]);
    if (n > sizeof(nl)) {
      n = sizeof(nl);
    }
    n = pread(fd, nl, n, scmd.symoff + (nsyms * sizeof(nl[0])));
    if (n == -1) {
      break;
    }
    n /= sizeof(nl[0]);
    nsyms += n;

    for (i = 0; i < n; i++) {
      gimli_nlist *nsym = &nl[i];

      if (nsym->n_un.n_strx > 0 && nsym->n_un.n_strx < scmd.strsize) {
        if (!cb(mhdr, context, strtab, nsym)) {
          return;
        }
      }
    }
  }
}

static int add_symbol(gimli_mach_header *mhdr, void *context,
  const char *strtab, gimli_nlist *nsym)
{
  gimli_mapped_object_t file = context;

  if (nsym->n_value != 0 && nsym->n_type != N_UNDF &&
      strtab[nsym->n_un.n_strx] != '\0') {
    int want_symbol = 0;

    if (nsym->n_type & N_STAB) {
      switch (nsym->n_type) {
        case N_GSYM:
        case N_FNAME:
        case N_FUN: /* may have line numbers */
        case N_LSYM:
        case N_STSYM:
          want_symbol = 1;
          break;
        default:
          want_symbol = 0;
#if 0
          printf("%02x %s sect=%d desc=%d val=%" PRIu64 "\n",
              nsym->n_type,
              strtab + nsym->n_un.n_strx,
              nsym->n_sect, nsym->n_desc, nsym->n_value);
#endif

      }
    } else if (nsym->n_type & N_PEXT) {
      want_symbol = 0;
    } else {
      want_symbol = 1;
#if 0
      printf("sym %d: %.*s\n", i, 8, strtab + nsym->n_un.n_strx);
      printf("        stab:%x pext:%d type:%x ext:%d\n",
          nsym->n_type & N_STAB,
          (nsym->n_type & N_PEXT) == N_PEXT ? 1 : 0,
          nsym->n_type & N_TYPE,
          (nsym->n_type & N_EXT) == N_EXT ? 1 : 0);
#endif
    }
    if (want_symbol) {
      gimli_addr_t value = nsym->n_value;

      if (mhdr->filetype != MH_EXECUTE) {
        value += file->base_addr;
      }
      //          printf("sym: %s %p\n", strtab + nsym->n_un.n_strx, (char*)value);
      gimli_add_symbol(file, strtab + nsym->n_un.n_strx, value, 0);

      if (sigtramp == 0 &&
          !strcmp(strtab + nsym->n_un.n_strx, "__sigtramp")) {
        sigtramp = value;
      }
    }
  }
  return 1;
}

static void read_symtab(gimli_mapped_object_t file,
  int fd, uint32_t cmd_offset, uint32_t file_off,
  gimli_mach_header *mhdr)
{
  walk_symtab(file, add_symbol, fd, cmd_offset, file_off, mhdr);
}

/* dyld bootstrap.
 * For whatever reason, the libc only provides a 32-bit implementation of
 * the nlist() library routine, so we need to manually grub around in dyld
 * to find the dyld symbols we need for discover_maps. */
struct gimli_dyld_bootstrap {
  gimli_addr_t info;
  gimli_addr_t cache;
};

static int find_dyld_symbols(gimli_mach_header *mhdr, void *context,
  const char *strtab, gimli_nlist *nsym)
{
  struct gimli_dyld_bootstrap *dyld = context;
  const char *name = strtab + nsym->n_un.n_strx;

  if (!dyld->info) {
    if (!strcmp(name, "_dyld_all_image_infos")) {
      dyld->info = nsym->n_value;
      return 1;
    }
  }
  if (dyld->cache) {
    if (!strcmp(name, "_dyld_shared_region_ranges")) {
      dyld->cache = nsym->n_value;
      return 1;
    }
  }
  if (dyld->cache && dyld->info) {
    return 0;
  }
  return 1;
}

/* lets see if we can figure out what we have loaded and where.  We assume that
 * the address of dyld_all_image_infos in this process is the same as the
 * target (which should always be true) and read the info out of the target
 * from that address.  This interface is documented in <mach-o/dyld_images.h>
 */
static void discover_maps(gimli_proc_t proc)
{
  int i;
  char *symoff = NULL;
  struct dyld_shared_cache_ranges shared_cache;
  struct dyld_all_image_infos infos;
  int have_shared_cache;
  int in_shared_cache;
  gimli_mach_header hdr;
  struct gimli_dyld_bootstrap dyld;
  int fd;
  uint32_t hdr_offset = 0;
  struct task_dyld_info tinfo;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  kern_return_t kret;

  /* ask the system for the true address of the all_image_info in the
   * target process */
  kret = task_info(targetTask, TASK_DYLD_INFO, (task_info_t)&tinfo, &count);
  dyld.info = tinfo.all_image_info_addr;

  /* load the dyld symbols so that we can find out whether sharedcache
   * is in use */
  fd = read_mach_header("/usr/lib/dyld", &hdr_offset, &hdr);
  if (fd == -1) {
    return;
  }
  memset(&dyld, 0, sizeof(dyld));
  walk_symtab(&dyld, find_dyld_symbols, fd, 0, hdr_offset, &hdr);
  if (dyld.cache) {
    /* adjust the cache information by the same slide that we observe
     * for the difference between the symbol for _dyld_all_image_infos
     * and the value we got from the task_info above */
    dyld.cache -= tinfo.all_image_info_addr - dyld.info;
  }
  dyld.info = tinfo.all_image_info_addr;

  if (dyld.info) {
    if (gimli_read_mem(proc, dyld.info, &infos, sizeof(infos)) != sizeof(infos)) {
      fprintf(stderr, "DYLD: failed to read _dyld_all_image_infos from " PTRFMT "\n"
          "DYLD: no maps, symbols or DWARF info will be available\n",
          dyld.info);
      return;
    }
  } else {
    fprintf(stderr, "DYLD: unable to locate _dyld_all_image_infos\n"
          "DYLD: no maps, symbols or DWARF info will be available\n"
        );
    return;
  }

  /* 10.5 introduces a shared cache; when processing images, if the image
   * addresses match against the shared cache, then we need to perform
   * an additional computation to obtain the relocated address in the target */
  have_shared_cache = 0;
  if (dyld.cache && gimli_read_mem(proc, dyld.cache, &shared_cache,
        sizeof(shared_cache)) == sizeof(shared_cache)) {
    have_shared_cache = 1;
  }

  /* walk the image info and determine the image names */
  for (i = 0; i < infos.infoArrayCount; i++) {
    struct dyld_image_info im;
    char name[PATH_MAX];
    char rname[PATH_MAX];
    gimli_mapped_object_t file = NULL;
    gimli_mach_header mhdr;
    int n, fd;
    char *addr = NULL;
    gimli_segment_command seg;
    char sectname[16];
    uint32_t hdr_offset, cmd_offset;

    gimli_read_mem(proc, (gimli_addr_t)infos.infoArray + (i * sizeof(im)),
        &im, sizeof(im));

    if (im.imageLoadAddress == 0) {
      continue;
    }

    memset(name, 0, sizeof(name));
    gimli_read_mem(proc, (gimli_addr_t)im.imageFilePath, name, sizeof(name));
    if (!realpath(name, rname)) strcpy(rname, name);

    if (debug) {
      fprintf(stderr, "%p [%p] %s\n",
          im.imageLoadAddress, im.imageFilePath, rname);
    }

    file = gimli_add_object(proc, rname, 0);
    file->elf = calloc(1, sizeof(*file->elf));
    file->elf->gobject = file;
    file->elf->is_exec = 1;
    file->elf->objname = file->objname;

    /* now, from the mach header, find each segment and its
     * address range and record the mapping */
    gimli_read_mem(proc, (gimli_addr_t)im.imageLoadAddress, &mhdr, sizeof(mhdr));

    in_shared_cache = 0;
    if (have_shared_cache) {
      for (n = 0; n < shared_cache.sharedRegionsCount; n++) {
        if ((intptr_t)im.imageLoadAddress >= shared_cache.ranges[n].start &&
            (intptr_t)im.imageLoadAddress < shared_cache.ranges[n].start +
            shared_cache.ranges[n].length) {
          in_shared_cache = 1;
          break;
        }
      }
    }

    if (in_shared_cache) {
      /* the contents in memory are rebound instead of adjusted, so we
       * need to compute the adjustment by reading the header from the
       * actual MACH-O file.
       * XXX: given that we always compare to the image on disk, I'm not
       * sure what additional special handling is needed for these?
       */
    }

    fd = read_mach_header(rname, &hdr_offset, &hdr);
    cmd_offset = hdr_offset + sizeof(hdr);
    for (n = 0; n < hdr.ncmds; n++, cmd_offset += seg.cmdsize) {
      pread(fd, &seg, sizeof(struct load_command), cmd_offset);
      if (seg.cmd == LC_SYMTAB) {
        read_symtab(file, fd, cmd_offset, hdr_offset, &mhdr);
        continue;
      }
      if (seg.cmd != GIMLI_LC_SEGMENT) {
        continue;
      }
      if (pread(fd, &seg, sizeof(seg), cmd_offset) != sizeof(seg)) {
        fprintf(stderr, "pread failed %s\n", strerror(errno));
        continue;
      }
      if (!strcmp(seg.segname, SEG_PAGEZERO)) {
        /* ignore zero page mapping */
        continue;
      }
      if (!strcmp(seg.segname, SEG_TEXT) && file->base_addr == 0) {
        /* compute the slide */
        file->base_addr = (intptr_t)im.imageLoadAddress - seg.vmaddr;
      }
      gimli_add_mapping(proc, file->objname,
        (gimli_addr_t)(seg.vmaddr + file->base_addr), seg.vmsize, seg.fileoff);

      if (!strcmp(seg.segname, "__TEXT")) {
        /* look for an __eh_frame section */
        uint32_t sec_addr = cmd_offset + sizeof(seg);
        int sno;
        gimli_section sec;
        char *buf;
        struct gimli_section_data *s;

        for (sno = 0; sno < seg.nsects; sno++, sec_addr += sizeof(sec)) {
          if (pread(fd, &sec, sizeof(sec), sec_addr) != sizeof(sec)) {
            continue;
          }
          if (!strcmp("__eh_frame", sec.sectname)) {

            // make the names look more like elven versions
            s = calloc(1, sizeof(*s));
            memcpy(sectname, sec.sectname + 1, 15);
            sectname[15] = '\0';
            s->name = strdup(sectname);
            s->name[0] = '.';
            s->addr = sec.addr;
            s->size = sec.size;
            s->data = malloc(s->size);
            s->offset = sec.offset + hdr_offset;
            s->container = file->elf;
            pread(fd, s->data, s->size, s->offset);

            gimli_hash_insert(file->sections, s->name, s);
          }
        }
      }

    }
    find_dwarf_dSYM(file);
  }
}

static void make_authz_request(void)
{
  OSStatus st;
  AuthorizationItem item = {"system.privilege.taskport", 0, NULL, 0};
  AuthorizationRights rights = {1, &item};
  AuthorizationRights *copy = NULL;
  AuthorizationRef author;
  AuthorizationFlags flags =
    kAuthorizationFlagExtendRights |
    kAuthorizationFlagPreAuthorize |
    kAuthorizationFlagInteractionAllowed;

  st = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
        flags, &author);

  if (st != errAuthorizationSuccess) {
    return;
  }

  st = AuthorizationCopyRights(author, &rights, kAuthorizationEmptyEnvironment,
        flags, &copy);

  if (st != errAuthorizationSuccess) {
    return;
  }
}

gimli_err_t gimli_attach(gimli_proc_t proc)
{
  kern_return_t rc;
  mach_msg_type_number_t n;
  struct gimli_thread_state *thr;
  thread_act_port_array_t threadlist;
  int i;

  /* task_for_pid() is a restricted system call and will only operate
   * under the following conditions:
   * - process is root
   * - (pre-tiger) process has same user-id as target
   * - (tiger) process is setgid procmod
   * - (leopard) application is signed and contains:
   *   <key>SecTaskAccess</key><string>allowed</string>
   *   in its info.plist, and the signing authority is trusted
   *   by the system.
   * Note that being setgid(procmod) works on systems prior to leopard
   * but that DYLD_LIBRARY_PATH is stripped from the environment when
   * launching a setgid process.
   *
   * See also taskgated(8)
   */
  make_authz_request();
  target_pid = proc->pid;
  rc = task_for_pid(mach_task_self(), proc->pid, &targetTask);
  if (rc != KERN_SUCCESS) {
    /* this will usually fail unless you call this from the
     * parent of the faulting process, or have root */
    fprintf(stderr, 
"task_for_pid returned %d\n"
"One resolution is to run the monitor or glider process with root privileges\n"
"alternatively, if glider was codesigned at build time, you may use keychain\n"
"to trust the signing certificate, so long as that certificate is placed in\n"
"the System keychain.  For more informatio, see:\n"
"http://sourceware.org/gdb/wiki/BuildingOnDarwin\n"
"http://developer.apple.com/library/mac/#documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW1\n"
, rc);
    return GIMLI_ERR_PERM;
  }
  got_task = 1;
  task_suspend(targetTask);

  discover_maps(proc);

  rc = task_threads(targetTask, &threadlist, &n);

  if (rc == KERN_SUCCESS) {
    for (i = 0; i < n; i++) {
#ifdef __x86_64__
      x86_thread_state64_t ts;
      mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;

      thr = gimli_proc_thread_by_lwpid(proc, i, 1);
      memset(&ts, 0, sizeof(ts));
      rc = thread_get_state(threadlist[i], x86_THREAD_STATE64,
          (thread_state_t)&ts, &count);
      if (rc == KERN_SUCCESS) {
        memcpy(&thr->regs, &ts, sizeof(ts));
        thr->pc = (void*)ts.GIMLI_DARWIN_REGNAME(rip);
        thr->fp = (void*)ts.GIMLI_DARWIN_REGNAME(rbp);
        thr->sp = (void*)ts.GIMLI_DARWIN_REGNAME(rsp);
      }
#elif defined(__i386__)
      x86_thread_state32_t ts;
      mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;

      thr = gimli_proc_thread_by_lwpid(proc, i, 1);
      memset(&ts, 0, sizeof(ts));
      rc = thread_get_state(threadlist[i], x86_THREAD_STATE32,
          (thread_state_t)&ts, &count);
      if (rc == KERN_SUCCESS) {
        memcpy(&thr->regs, &ts, sizeof(ts));
        thr->pc = (void*)ts.GIMLI_DARWIN_REGNAME(eip);
        thr->fp = (void*)ts.GIMLI_DARWIN_REGNAME(ebp);
        thr->sp = (void*)ts.GIMLI_DARWIN_REGNAME(esp);
      }
#else
# error unknown architecture
#endif
    }
  }
  return GIMLI_ERR_OK;
}

int gimli_init_unwind(struct gimli_unwind_cursor *cur,
  struct gimli_thread_state *st)
{
  memcpy(&cur->st, st, sizeof(*st));
  return 1;
}

int gimli_unwind_next(struct gimli_unwind_cursor *cur)
{
  struct {
    void *fp;
    void *pc;
  } frame;
  struct gimli_unwind_cursor c;

  if (gimli_is_signal_frame(cur)) {
#if defined(__x86_64__)
    _STRUCT_MCONTEXT64 mctx;
    
    if (gimli_read_mem(cur->proc, (gimli_addr_t)cur->st.fp + GIMLI_KERNEL_MCTX64, &mctx,
        sizeof(mctx)) != sizeof(mctx)) {
      fprintf(stderr, "unable to read old context\n");
      return 0;
    }
#if 0
#define SHOWREG(n) fprintf(stderr, #n ": %p\n", mctx.GIMLI_DARWIN_REGNAME(ss).GIMLI_DARWIN_REGNAME(n));
    SHOWREG(rax);
    SHOWREG(rbx);
    SHOWREG(rcx);
    SHOWREG(rdx);
    SHOWREG(rdi);
    SHOWREG(rsi);
    SHOWREG(rbp);
    SHOWREG(rsp);
    SHOWREG(r8);
    SHOWREG(r9);
    SHOWREG(r10);
    SHOWREG(r11);
    SHOWREG(r12);
    SHOWREG(r13);
    SHOWREG(r14);
    SHOWREG(r15);
    SHOWREG(rip);
#endif

    memcpy(&cur->st.regs, &mctx.GIMLI_DARWIN_REGNAME(ss),
      sizeof(cur->st.regs));
    cur->st.pc = (void*)cur->st.regs.GIMLI_DARWIN_REGNAME(rip);
    cur->st.fp = (void*)cur->st.regs.GIMLI_DARWIN_REGNAME(rbp);
    cur->st.sp = (void*)cur->st.regs.GIMLI_DARWIN_REGNAME(rsp);
    return 1;
#elif defined(__i386__)
    struct gimli_kernel_sigframe32 f;
    if (gimli_read_mem(cur->st.fp, &f, sizeof(f)) != sizeof(f)) {
      fprintf(stderr, "unable to read old context\n");
      return 0;
    };
    memcpy(&cur->st.regs, &f.mctx.GIMLI_DARWIN_REGNAME(ss),
      sizeof(cur->st.regs));
    cur->st.pc = (void*)cur->st.regs.GIMLI_DARWIN_REGNAME(eip);
    cur->st.fp = (void*)cur->st.regs.GIMLI_DARWIN_REGNAME(ebp);
    cur->st.sp = (void*)cur->st.regs.GIMLI_DARWIN_REGNAME(esp);
    return 1;
#else
# error code me
#endif
  }

  c = *cur;
  if (gimli_dwarf_unwind_next(cur) && cur->st.pc) {
#if defined(__x86_64__)
//    cur->st.regs.GIMLI_DARWIN_REGNAME(rsp) = (intptr_t)cur->st.fp;
#endif
    return 1;
  }
  if (debug) {
    fprintf(stderr, "dwarf unwind unsuccessful fp=%p\n", cur->st.fp);
  }

  if (c.st.fp) {
    if (gimli_read_mem(cur->proc, (gimli_addr_t)c.st.fp,
          &frame, sizeof(frame)) != sizeof(frame)) {
      memset(&frame, 0, sizeof(frame));
    }
    if (debug) {
      fprintf(stderr, "read frame: fp=%p pc=%p\n", frame.fp, frame.pc);
    }

    if (c.st.fp == frame.fp) {
      if (debug) fprintf(stderr, "next frame fp is same as current\n");
      return 0;
    }
    cur->st.fp = frame.fp;
    cur->st.pc = frame.pc;
    if (cur->st.pc > 0 && !gimli_is_signal_frame(cur)) {
      cur->st.pc--;
    }
#ifdef __i386__
    cur->st.regs.GIMLI_DARWIN_REGNAME(ebp) = (intptr_t)cur->st.fp;
#elif defined(__x86_64__)
    cur->st.regs.GIMLI_DARWIN_REGNAME(rbp) = (intptr_t)cur->st.fp;
#else
# error code me
#endif
    return 1;
  } else if (debug) {
    fprintf(stderr, "no dwarf and fp is nil\n");
  }
  return 0;
}

gimli_err_t gimli_detach(gimli_proc_t proc)
{
  if (got_task) {
    task_resume(targetTask);
  }
  kill(target_pid, SIGCONT);
  return 0;
}

int gimli_read_mem(gimli_proc_t proc, gimli_addr_t src, void *dest, int len)
{
  kern_return_t rc;
  vm_size_t dataCnt = len;

  rc = vm_read_overwrite(targetTask, (vm_address_t)src, len,
          (vm_address_t)dest, &dataCnt);

  switch (rc) {
    case KERN_SUCCESS:
      return dataCnt;
    case KERN_PROTECTION_FAILURE:
      errno = EFAULT;
      return 0;
    case KERN_INVALID_ADDRESS:
      errno = EINVAL;
      return 0;
    default:
      return 0;
  }
}

void *gimli_reg_addr(struct gimli_unwind_cursor *cur, int col)
{
  switch (col) {
#ifdef __x86_64__
    case 0: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rax);
    case 1: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rbx);
    case 2: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rcx);
    case 3: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rdx);
    case 4: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rsi);
    case 5: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rdi);
    case 6: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rbp);
    case 7: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rsp);
    case 8: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r8);
    case 9: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r9);
    case 10: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r10);
    case 11: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r11);
    case 12: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r12);
    case 13: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r13);
    case 14: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r14);
    case 15: return &cur->st.regs.GIMLI_DARWIN_REGNAME(r15);
    /* return address */
    case 16: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rip);
#elif defined(__i386__)
    case 0: return &cur->st.regs.GIMLI_DARWIN_REGNAME(eax);
    case 1: return &cur->st.regs.GIMLI_DARWIN_REGNAME(ecx);
    case 2: return &cur->st.regs.GIMLI_DARWIN_REGNAME(edx);
    case 3: return &cur->st.regs.GIMLI_DARWIN_REGNAME(ebx);
    case 4: return &cur->st.regs.GIMLI_DARWIN_REGNAME(esp);
    case 5: return &cur->st.regs.GIMLI_DARWIN_REGNAME(ebp);
    case 6: return &cur->st.regs.GIMLI_DARWIN_REGNAME(esi);
    case 7: return &cur->st.regs.GIMLI_DARWIN_REGNAME(edi);
    /* return address */
    case 8: return &cur->st.regs.GIMLI_DARWIN_REGNAME(eip);
    case 9: return &cur->st.regs.GIMLI_DARWIN_REGNAME(eflags);
#else
# error code me
#endif
    default: return 0;
  }
}

int gimli_is_signal_frame(struct gimli_unwind_cursor *cur)
{
  if (cur->st.pc == (void*)-1) {
    memset(&cur->si, 0, sizeof(cur->si));
    return 1;
  }
  if (sigtramp && (gimli_addr_t)cur->st.pc >= sigtramp &&
      (gimli_addr_t)cur->st.pc <= sigtramp + 0xff) {
#if defined(__x86_64__)
    if (gimli_read_mem(cur->proc, (gimli_addr_t)cur->st.fp + GIMLI_KERNEL_SIGINFO64,
        &cur->si, sizeof(cur->si)) != sizeof(cur->si)) {
      memset(&cur->si, 0, sizeof(cur->si));
    }
    return 1;
#elif defined(__i386__)
    struct gimli_kernel_sigframe32 *f = cur->st.fp;
    if (gimli_read_mem(cur->proc, (gimli_addr_t)&f->si,
          &cur->si, sizeof(cur->si)) != sizeof(cur->si)) {
      memset(&cur->si, 0, sizeof(cur->si));
    }
    return 1;
#else
# error no si handler
#endif
    return 1;
  }
  return 0;
}

#endif
/* vim:ts=2:sw=2:et:
 */
