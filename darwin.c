/*
 * Copyright (c) 2007-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */

#ifdef __MACH__
#include "impl.h"

/* http://www.omnigroup.com/mailman/archive/macosx-dev/2000-June/014178.html
 * http://web.mit.edu/darwin/src/modules/xnu/osfmk/man/vm_read.html
 */

#include <libgen.h>

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
# error don't know my own arch
#endif
      ;

static int target_pid;
static int got_task = 0;
static task_t targetTask;

/* Starting with OSX 10.5, apple introduced the concept of a
 * a dSYM bundle which contains a mach-o object file with dwarf
 * segments.
 * Attempt to load such a beast and process the dwarf info from
 * it.
 */
static void find_dwarf_dSYM(struct gimli_object_file *of)
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
  gimli_object_file_t *container;
  
  strcpy(basepath, of->objname);
  base = basename(basepath);

  snprintf(dsym, sizeof(dsym)-1,
    "%s.dSYM/Contents/Resources/DWARF/%s", of->objname, base);

  if (debug) {
    fprintf(stderr, "dsym: trying %s\n", dsym);
  }
  fd = open(dsym, O_RDONLY);
  if (fd == -1) return;

  if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
    fprintf(stderr, "error reading mach header %s\n", strerror(errno));
    return;
  }

  if (NXSwapBigLongToHost(hdr.magic) == FAT_MAGIC) {
    int nfat = NXSwapBigLongToHost(hdr.cputype);
    int i;
    struct fat_arch fa;
    int found = 0;
    for (i = 0; i < nfat; i++) {
      pread(fd, &fa, sizeof(fa), 
        sizeof(struct fat_header) + (i * sizeof(fa))
      );
      fa.cputype = NXSwapBigLongToHost(fa.cputype);
      fa.cpusubtype = NXSwapBigLongToHost(fa.cpusubtype);
      fa.offset = NXSwapBigLongToHost(fa.offset);
      fa.size = NXSwapBigLongToHost(fa.size);

      if (fa.cputype == whatami) {
        fprintf(stderr, "matching arch %x %x at %x (%x)\n", fa.cputype, fa.cpusubtype,
          fa.offset, fa.size);
        hdr_offset = fa.offset;
        pread(fd, &hdr, sizeof(hdr), hdr_offset);
        found = 1;
        break;
      }
    }
    if (!found) {
      fprintf(stderr, "Couldn't find a suitable matching arch in fat dsym\n");
    }
  }
  if (hdr.magic != GIMLI_MH_MAGIC) {
    close(fd);
    return;
  }

  container = calloc(1, sizeof(*container));
  container->gobject = of;
  container->objname = strdup(dsym);
  container->is_exec = 1;

  of->aux_elf = container;

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
          s->size = sec.size;
          s->data = malloc(s->size);
          s->offset = sec.offset;
          s->container = container;
          pread(fd, s->data, s->size, s->offset);

          gimli_hash_insert(of->sections, s->name, s);
        }
      }
    }
  }
}

struct gimli_section_data *gimli_get_section_by_name(
  gimli_object_file_t *elf, const char *name)
{
  struct gimli_section_data *s = NULL;

  if (gimli_hash_find(elf->gobject->sections, name, (void**)&s)) {
    return s;
  }
  return NULL;
}

int gimli_attach(int pid)
{
  kern_return_t rc;
  mach_msg_type_number_t n;
  struct gimli_thread_state *threads;
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
  target_pid = pid;
  rc = task_for_pid(mach_task_self(), pid, &targetTask);
  if (rc != KERN_SUCCESS) {
    /* this will usually fail unless you call this from the
     * parent of the faulting process, or have root */
    fprintf(stderr, "task_for_pid returned %d\n", rc);
    return 0;
  }
  got_task = 1;
  task_suspend(targetTask);

  /* lets see if we can figure out what we have loaded and where.
   * We assume that the address of dyld_all_image_infos in this process
   * is the same as the target (which should always be true) and
   * read the info out of the target from that address.
   * This interface is documented in <mach-o/dyld_images.h>
   */
  {
    struct dyld_all_image_infos infos;
    struct nlist l[2];
    int i;
    char *symoff = NULL;

    memset(&l, 0, sizeof(l));
    l[0].n_un.n_name = "_dyld_all_image_infos";
    nlist("/usr/lib/dyld", l);
    if (l[0].n_value) {
      gimli_read_mem((void*)l[0].n_value, &infos, sizeof(infos));

      for (i = 0; i < infos.infoArrayCount; i++) {
        struct dyld_image_info im;
        char name[PATH_MAX];
        char rname[PATH_MAX];
        struct gimli_object_file *of = NULL;
        gimli_mach_header  mhdr;
        int n;
        char *addr = NULL;
        gimli_segment_command scmd;

        gimli_read_mem((char*)infos.infoArray + (i * sizeof(im)),
            &im, sizeof(im));

        if (im.imageLoadAddress == 0) {
          continue;
        }

        memset(name, 0, sizeof(name));
        gimli_read_mem((void*)im.imageFilePath, name, sizeof(name));
        if (!realpath(name, rname)) strcpy(rname, name);

        if (debug) {
          fprintf(stderr, "%p [%p] %s\n",
            im.imageLoadAddress, im.imageFilePath, rname);
        }

        of = gimli_add_object(rname, (void*)im.imageLoadAddress);
        of->elf = calloc(1, sizeof(*of->elf));
        of->elf->gobject = of;
        of->elf->is_exec = 1;
        of->elf->objname = of->objname;

        /* now, from the mach header, find each segment and its
         * address range and record the mapping */
        gimli_read_mem((void*)im.imageLoadAddress, &mhdr, sizeof(mhdr));

        addr = (char*)im.imageLoadAddress;
        addr += sizeof(mhdr);
        for (n = 0; n < mhdr.ncmds; n++) {
          memset(&scmd, 0, sizeof(scmd));
          gimli_read_mem(addr, &scmd, sizeof(struct load_command));
          if (scmd.cmd == GIMLI_LC_SEGMENT)
          {
            char *mapaddr;
            gimli_read_mem(addr, &scmd, sizeof(scmd));
        
            if (!strcmp("__TEXT", scmd.segname)) {  
              if ((void*)scmd.vmaddr != im.imageLoadAddress) {
                of->base_addr = (uint64_t)(intptr_t)im.imageLoadAddress;
              }
              gimli_add_mapping(of->objname,
                (void*)scmd.vmaddr, scmd.vmsize, 0);
            }
          }

          if (scmd.cmd == LC_SYMTAB) {
            struct symtab_command scmd;
            gimli_nlist nl;
            int n;
            char *symaddr;

            if (!gimli_read_mem(addr, &scmd, sizeof(scmd))) {
              fprintf(stderr, "unable to read symtab_command from %p\n", addr);
              continue;
            }
            symoff = (char*)im.imageLoadAddress + scmd.symoff;
            for (n = 0; n < scmd.nsyms; n++) {
              char *straddr;
              int type;

              symaddr = symoff + (n * sizeof(nl));
              memset(&nl, 0, sizeof(nl));
              if (!gimli_read_mem(symaddr, &nl, sizeof(nl))) {
                fprintf(stderr, "unable to read nlist from %p\n", symaddr);
                continue;
              }
              memset(name, 0, sizeof(name));
              straddr = (char*)im.imageLoadAddress;
              straddr += scmd.stroff + nl.n_un.n_strx;
              gimli_read_mem(straddr, name, sizeof(name));
              if (!isprint(name[0])) continue;
              if (nl.n_sect != 1) {
                continue;
              }
              if (nl.n_type == N_UNDF) continue;
              if (nl.n_un.n_strx == 0) continue;
              if (nl.n_value == 0) continue;
              if (!strlen(name)) continue;

              gimli_add_symbol(of, name, (char*)nl.n_value + of->base_addr, 0);
            }
          }

          addr += scmd.cmdsize;
        }

        find_dwarf_dSYM(of);
      }
    }
  }

  rc = task_threads(targetTask, &threadlist, &n);

  if (rc == KERN_SUCCESS) {
    threads = calloc(n, sizeof(*threads));

    for (i = 0; i < n; i++) {
#if defined(__LP64__) || defined(__ppc__)
# error this code assumes 32-bit intel
#endif
      x86_thread_state32_t ts32;
      mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;
      memset(&ts32, 0, sizeof(ts32));
      rc = thread_get_state(threadlist[i], x86_THREAD_STATE32,
          (thread_state_t)&ts32, &count);
      if (rc == KERN_SUCCESS) {
        threads[i].pc = (void*)ts32.GIMLI_DARWIN_REGNAME(eip);
        threads[i].fp = (void*)ts32.GIMLI_DARWIN_REGNAME(ebp);
        threads[i].sp = (void*)ts32.GIMLI_DARWIN_REGNAME(esp);
      }
    }
    gimli_nthreads = n;
    gimli_threads = threads;
  }
  return 1;
}

int gimli_init_unwind(struct gimli_unwind_cursor *cur,
  struct gimli_thread_state *st)
{
  memcpy(&cur->st, st, sizeof(*st));
  return 1;
}

#if 0
int gimli_unwind_next(struct gimli_unwind_cursor *cur)
{
  /* generic x86 backtrace */
  struct x86_frame {
    struct x86_frame *next;
    void *retpc;
  } frame;
  struct gimli_unwind_cursor c;

  c = *cur;

  if (c.st.fp) {
    if (gimli_read_mem(c.st.fp, &frame, sizeof(frame)) != sizeof(frame)) {
      memset(&frame, 0, sizeof(frame));
    }
    if (c.st.fp == frame.next) return 0;
    cur->st.fp = frame.next;
    cur->st.pc = frame.retpc;
    return 1;
  }

  return 0;
}
#endif
int gimli_unwind_next(struct gimli_unwind_cursor *cur)
{
  struct {
    void *fp;
    void *pc;
  } frame;
  struct gimli_unwind_cursor c;
  
#if 0
  if (gimli_is_signal_frame(cur)) {
    ucontext_t uc;

    if (gimli_read_mem((void*)cur->st.lwpst.pr_oldcontext, &uc, sizeof(uc)) !=
        sizeof(uc)) {
      fprintf(stderr, "unable to read old context\n");
      return 0;
    }
    /* update to next in chain */
    cur->st.lwpst.pr_oldcontext = (intptr_t)uc.uc_link;
    /* copy out register set */
    memcpy(cur->st.regs, uc.uc_mcontext.gregs, sizeof(cur->st.regs));
    /* update local copy */
    cur->st.fp = (void*)cur->st.regs[R_FP];
    cur->st.pc = (void*)cur->st.regs[R_PC];
    cur->st.sp = (void*)cur->st.regs[R_SP];
    return 1;
  }
#endif

  c = *cur;
  if (gimli_dwarf_unwind_next(cur) && cur->st.pc) {
    return 1;
  }
  if (debug) {
    fprintf(stderr, "dwarf unwind unsuccessful\n");
  }

  if (c.st.fp) {
    if (gimli_read_mem(c.st.fp, &frame, sizeof(frame)) != sizeof(frame)) {
      memset(&frame, 0, sizeof(frame));
    }

    if (c.st.fp == frame.fp) {
      return 0;
    }
    cur->st.fp = frame.fp;
    cur->st.pc = frame.pc;
    if (cur->st.pc > 0 && !gimli_is_signal_frame(cur)) {
      cur->st.pc--;
    }
#ifdef __i386__
    cur->st.regs.GIMLI_DARWIN_REGNAME(ebp) = (intptr_t)cur->st.fp;
#endif
    return 1;
  }
  return 0;
}
int gimli_detach(void)
{
  if (got_task) {
    task_resume(targetTask);
  }
  kill(target_pid, SIGCONT);
  return 0;
}

int gimli_read_mem(void *src, void *dest, int len)
{
  kern_return_t rc;
  mach_msg_type_number_t dataCnt = len;

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
  /* See http://wikis.sun.com/display/SunStudio/Dwarf+Register+Numbering */
  switch (col) {
#ifdef __x86_64__
    case 0: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rax);
    case 1: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rdx);
    case 2: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rcx);
    case 3: return &cur->st.regs.GIMLI_DARWIN_REGNAME(rbx);
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
#else
# error code me
#endif
    default: return 0;
  }
}
int gimli_is_signal_frame(struct gimli_unwind_cursor *cur)
{
  if (cur->st.pc == (void*)-1) {
    return 1;
  }
  return 0;
}

#endif
/* vim:ts=2:sw=2:et:
 */
