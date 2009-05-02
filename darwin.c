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
#ifdef __LP64__
typedef struct segment_command_64 my_segment_command;
typedef struct mach_header_64 my_mach_header;
typedef struct nlist_64 my_nlist;
typedef struct section_64 my_section;
# define MY_LC_SEGMENT LC_SEGMENT_64
# define MY_MH_MAGIC MH_MAGIC_64
#else
typedef struct segment_command my_segment_command;
typedef struct mach_header my_mach_header;
typedef struct nlist my_nlist;
typedef struct section my_section;
# define MY_LC_SEGMENT LC_SEGMENT
# define MY_MH_MAGIC MH_MAGIC
#endif



static task_t targetTask;
static mach_port_t exc_port;
static char parent_port_name[256];

#if 0
/* Starting with OSX 10.5, apple introduced the concept of a
 * a dSYM bundle which contains a mach-o object file with dwarf
 * segments.
 * Attempt to load such a beast and process the dwarf info from
 * it.
 */
static void find_dwarf_dSYM(struct gimli_object_file *of)
{
	char dsym[PATH_MAX];
	char *base = basename(of->filename);
	my_mach_header  hdr;
	uint32_t hdr_offset = 0; /* offset of mach_header from start of file */
	uint32_t cmd_offset;
	int n;
	int fd;
	my_segment_command scmd;
	char sectname[16];

	snprintf(dsym, sizeof(dsym)-1, "%s.dSYM/Contents/Resources/DWARF/%s", of->filename, base);

	fprintf(stderr, "dsym: trying %s\n", dsym);
	fd = open(dsym, O_RDONLY);
	if (fd == -1) return;

	if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		fprintf(stderr, "error reading mach header %s\n", strerror(errno));
		return;
	}
	fprintf(stderr, "header magic is %x\n", hdr.magic);
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
	if (hdr.magic != MY_MH_MAGIC) {
		close(fd);
		return;
	}

	/* we're looking for an LC_SEGMENT with a segname of __DWARF */

	cmd_offset = hdr_offset + sizeof(hdr);
	for (n = 0; n < hdr.ncmds; n++, cmd_offset += scmd.cmdsize) {
		pread(fd, &scmd, sizeof(struct load_command), cmd_offset);
		if (scmd.cmd == MY_LC_SEGMENT) {
			if (pread(fd, &scmd, sizeof(scmd), cmd_offset) != sizeof(scmd)) {
				fprintf(stderr, "pread failed %s\n", strerror(errno));
			}
			fprintf(stderr, "segment %d %s\n", n, scmd.segname);
			if (strcmp("__DWARF", scmd.segname) == 0) {
				uint32_t sec_addr = cmd_offset + sizeof(scmd);
				int s;
				my_section sec;
				char *buf;

				for (s = 0; s < scmd.nsects; s++, sec_addr += sizeof(sec)) {
					pread(fd, &sec, sizeof(sec), sec_addr);

					// make the names look more like elven versions
					memcpy(sectname, sec.sectname + 1, sizeof(sec.sectname)-1);
					sectname[0] = '.';
					sectname[sizeof(sectname)-1] = '\0';

					buf = malloc(sec.size);
					pread(fd, buf, sec.size, sec.offset);
					gimli_add_dwarf_section(of, buf, sec.size, sectname);
					free(buf);
				}
			}
		}
	}
	gimli_process_dwarf_info(of);
}
#endif

int gimli_process_mach(struct gimli_object_file *f)
{
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
	rc = task_for_pid(mach_task_self(), pid, &targetTask);
	if (rc != KERN_SUCCESS) {
		/* this will usually fail unless you call this from the
		 * parent of the faulting process, or have root */
		fprintf(stderr, "task_for_pid returned %d\n", rc);
		return 0;
	}
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
			gimli_read_mem(l[0].n_value, &infos, sizeof(infos));
			fprintf(stderr, "version=%x count=%x array=%p\n", infos.version, 
				infos.infoArrayCount, infos.infoArray);

			for (i = 0; i < infos.infoArrayCount; i++) {
				struct dyld_image_info im;
				char name[PATH_MAX];
				char rname[PATH_MAX];
				struct gimli_object_file *of = NULL;
				my_mach_header  mhdr;
				int n;
				char *addr = NULL;
				my_segment_command scmd;

				gimli_read_mem((char*)infos.infoArray + (i * sizeof(im)), &im, sizeof(im));
				if (im.imageLoadAddress == 0) continue;

				memset(name, 0, sizeof(name));
				gimli_read_mem(im.imageFilePath, name, sizeof(name));
				if (!realpath(name, rname)) strcpy(rname, name);
				fprintf(stderr, "%p [%p] %s\n", im.imageLoadAddress, im.imageFilePath, rname);

				of = gimli_add_object(rname, im.imageLoadAddress);
//				of->base_addr = im.imageLoadAddress;

				/* now, from the mach header, find each segment and its
				 * address range and record the mapping */
				gimli_read_mem(im.imageLoadAddress, &mhdr, sizeof(mhdr));
//				fprintf(stderr, "loadaddr=%p magic=%x filetype=%x ncmds=%x sizeofcmds=%x flags=%x\n", im.imageLoadAddress, mhdr.magic, mhdr.filetype, mhdr.ncmds, mhdr.sizeofcmds, mhdr.flags);

				addr = (char*)im.imageLoadAddress;
				addr += sizeof(mhdr);
				for (n = 0; n < mhdr.ncmds; n++) {
					memset(&scmd, 0, sizeof(scmd));
					gimli_read_mem(addr, &scmd, sizeof(struct load_command));
//					fprintf(stderr, "addr=%p command %x size=%x\n", addr, scmd.cmd, scmd.cmdsize);
					if (scmd.cmd == MY_LC_SEGMENT)
					{
						char *mapaddr;
						gimli_read_mem(addr, &scmd, sizeof(scmd));
				
						if (!strcmp("__TEXT", scmd.segname)) {	
//						fprintf(stderr, "segment %s vmaddr=%p vmsize=%p fileoff=%p filesize=%p nsects=%d\n",
//						scmd.segname, scmd.vmaddr, scmd.vmsize, scmd.fileoff, scmd.filesize,
//							scmd.nsects);

							if ((void*)scmd.vmaddr != im.imageLoadAddress) {
								of->base_addr = (uint64_t)(intptr_t)im.imageLoadAddress;
							}
							gimli_add_mapping(of->objname, (void*)scmd.vmaddr, scmd.vmsize, 0);
						}
					}

					if (scmd.cmd == LC_SYMTAB) {
						struct symtab_command scmd;
						my_nlist nl;
						int n;
						char *symaddr;

						if (!gimli_read_mem(addr, &scmd, sizeof(scmd))) {
							fprintf(stderr, "unable to read symtab_command from %p\n", addr);
							continue;
						}
						symoff = (char*)im.imageLoadAddress + scmd.symoff;
						/* 
						fprintf(stderr, "symtab: symoff=%p (la=%p %p) nsyms=%x strof=%p strsize=%x\n",
							scmd.symoff, im.imageLoadAddress, symoff, 
							scmd.nsyms, scmd.stroff, scmd.strsize);
						*/
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
							if (!isprint(name[0])) name[0] = '\0';

//							if (nl.n_type & (N_PEXT|N_STAB)) continue;
							if (nl.n_sect != 1) {
								continue;
							}
							if (nl.n_type == N_UNDF) continue;
							if (nl.n_un.n_strx == 0) continue;
							if (nl.n_value == 0) continue;

/*
							fprintf(stderr, "symaddr=%p (n_strx=%p %s) type=%x sect=%x desc=%x value=%p\n",
								symaddr, nl.n_un.n_strx, name,
								nl.n_type, nl.n_sect, nl.n_desc, nl.n_value);
*/
							if (!strlen(name)) continue;
							gimli_add_symbol(of, name, (char*)nl.n_value + of->base_addr, 0);
						}
					}

					addr += scmd.cmdsize;
				}

//				find_dwarf_dSYM(of);
				gimli_bake_symtab(of);
			}
		}
	}

	rc = task_threads(targetTask, &threadlist, &n);

	if (rc == KERN_SUCCESS) {
		threads = calloc(n, sizeof(*threads));

		for (i = 0; i < n; i++) {
			x86_thread_state32_t ts32;
			mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;
			memset(&ts32, 0, sizeof(ts32));
			rc = thread_get_state(threadlist[i], x86_THREAD_STATE32,
					(thread_state_t)&ts32, &count);
			if (rc == KERN_SUCCESS) {
#if __DARWIN_UNIX03 /* Leopard and up */
				threads[i].pc = (void*)ts32.__eip;
				threads[i].fp = (void*)ts32.__ebp;
				threads[i].sp = (void*)ts32.__esp;
#else
				threads[i].pc = (void*)ts32.eip;
				threads[i].fp = (void*)ts32.ebp;
				threads[i].sp = (void*)ts32.esp;
#endif
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

int gimli_detach(void)
{
	task_resume(targetTask);
	return 0;
}

int gimli_read_mem(void *src, void *dest, int len)
{
	kern_return_t rc;
	mach_msg_type_number_t dataCnt = len;

	rc = vm_read_overwrite(targetTask, (vm_address_t)src, len, (vm_address_t)dest, &dataCnt);

	switch (rc) {
		case KERN_SUCCESS:
			return dataCnt;
		case KERN_PROTECTION_FAILURE:
			errno = EFAULT;
			return -1;
		case KERN_INVALID_ADDRESS:
			errno = EINVAL;
			return -1;
		default:
			return -1;
	}
}

#if 0
static void *darwin_exc_handler(void *unused)
{
	kern_return_t rc;
#define MSG_SIZE 512
	mach_msg_header_t *msg = alloca(MSG_SIZE);

	while (1) {
		rc = mach_msg(msg, MACH_RCV_MSG, MSG_SIZE, MSG_SIZE,
							exc_port, 0, MACH_PORT_NULL);
		if (rc == KERN_SUCCESS) {
			libgimli_spawn_gimli(0);
			exit(1);
		}
	}
}

static int activate(void)
{
	/* rather than unixy signals, use the darwin specific
	 * exception handler port. */
	kern_return_t rc;
	pthread_attr_t attr;
	pthread_t thr;

	rc = mach_port_allocate(mach_task_self(),
				MACH_PORT_RIGHT_RECEIVE, &exc_port);
	if (rc != KERN_SUCCESS) {
		return 0;
	}
	rc = mach_port_insert_right(mach_task_self(),
				exc_port, exc_port,
				MACH_MSG_TYPE_MAKE_SEND);
	if (rc != KERN_SUCCESS) {
		return 0;
	}

	rc = task_set_exception_ports(mach_task_self(),
				EXC_MASK_BAD_ACCESS|EXC_MASK_BAD_INSTRUCTION,
				exc_port, EXCEPTION_STATE, x86_THREAD_STATE32);
	if (rc == KERN_SUCCESS) {
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, 32*1024);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&thr, &attr, darwin_exc_handler, NULL);
		pthread_attr_destroy(&attr);
	}
}
#endif

int dwarf_determine_source_line_number(void *pc, char *src, int srclen,
  uint64_t *lineno)
{
	return 0;
}

int gimli_show_param_info(struct gimli_unwind_cursor *cur)
{
	return 0;
}

int gimli_is_signal_frame(struct gimli_unwind_cursor *cur)
{
	return 0;
}

#endif
/* vim:ts=2:sw=2:noet:
 */
