# Design Notes

The Gimli internals were borne from the frustration of having multiple
systems defining libraries for working with ELF and DWARF data that are
mostly the same and have the same names.  Despite being mostly the same,
they are not the same and this leads to frustration when attempting to
build a stable base over the top.

Gimli's original intent was purely introspection from a debugger
perspective but its future is branching out to be a more general
run-time observability and services facility.  As such, the internals
need to be manipulated and made more general.

## Desirable Features

The following are key attributes:

 * API that works the same regardless of whether it is used by a process
   that wishes to inspect itself or for inspecting a target process.
 * Facilities for manipulating object files to either extract or insert
   augmented debugging and type information. (with a goal of efficiency)
 * DWARF-assisted unwinding for all supported architectures (both
   in-proces and target-process).
 * Facilities to create, merge and consume CTF data for a more compact
   representation of debugging information.
 * Determine whether a more compact representation of DWARF DIE
   information is possible wrt. glider backtrace, and/or how to map the
   pertinent portions to CTF data.

## API Plan

Here's a sketch of how the API should look:

    /* opaque, represents a target process, which may be myself */
    typedef struct gimli_proc *gimli_proc_t;

    /* represents various error states */
    typedef enum {
      GIMLI_ERR_OK,
      GIMLI_ERR_BAD_ADDR,
      GIMLI_ERR_NO_PROC
    } gimli_err_t;

    /* represents a pointer on any architecture */
    typedef uint64_t gimli_addr_t;

    /* reads memory from an address in the target process address
     * space and copies it into the provided buffer */
    gimli_err_t gimli_proc_mem_read(gimli_proc_t p, gimli_addr_t src,
      void *dest, size_t size);
    /* writes memory to an address in the target process address
     * space */
    gimli_err_t gimli_proc_mem_write(gimli_proc_t p, gimli_addr_t dest,
      const void *src, size_t size);

    /* references memory from an address in the target process
     * address space. 
     *  - get_target_addr
     *  - get_size
     *  - get_local_addr
     *  - delete
     * Implementation to use mmap() or equivalent to establish
     * an efficient read/write mapping
     */
    typedef struct gimli_mem_ref *gimli_mem_ref_t;
    gimli_err_t gimli_proc_mem_ref(gimli_proc_t p,
      gimli_addr_t addr, size_t size, gimli_mem_ref_t *ref);

    /* reads a NUL terminated string from the target process address
     * space into the caller provided buffer */
    gimli_err_t gimli_proc_mem_read_string(gimli_proc_t p,
      gimli_addr_t ptr, int *len, char *buf, size_t buflen);

    /* reads a NULL terminated string from the target process address
     * space and allocates a buffer to hold it */
    gimli_err_t gimli_proc_mem_get_string(gimli_proc_t p,
      gimli_addr_t ptr, char **str);

Other bits:

  * attach to a proc, detach
  * enum mapped objects in a proc
  * enum threads in a proc
  * unwind the call stack of a thread (local or remote) with the caveat
    that doing so on a local thread other than the current one is
    dangerous
  * abstracted type API that provides at least both the CTF and DWARF
    type and function description capabilities
  * Symbol table collection and resolution
