/*
 * Copyright (c) 2007-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#ifndef GIMLI_MACHO_H
#define GIMLI_MACHO_H

#ifdef __MACH__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __LP64__
typedef struct segment_command_64 gimli_segment_command;
typedef struct mach_header_64 gimli_mach_header;
typedef struct nlist_64 gimli_nlist;
typedef struct section_64 gimli_section;
# define GIMLI_LC_SEGMENT LC_SEGMENT_64
# define GIMLI_MH_MAGIC MH_MAGIC_64
#else
typedef struct segment_command gimli_segment_command;
typedef struct mach_header gimli_mach_header;
typedef struct nlist gimli_nlist;
typedef struct section gimli_section;
# define GIMLI_LC_SEGMENT LC_SEGMENT
# define GIMLI_MH_MAGIC MH_MAGIC
#endif

struct gimli_macho_object {
  char *objname;
  struct gimli_object_file *gobject;
  int is_exec;
};

#define gimli_object_is_executable(obj)  obj->is_exec


#ifdef __cplusplus
}
#endif

#endif

#endif

/* vim:ts=2:sw=2:et:
 */

