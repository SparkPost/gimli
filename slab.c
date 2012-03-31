/*
 * Copyright (c) 2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

#define SLAB_SIZE 8000
//1024*8000

int gimli_slab_init(struct gimli_slab *slab, uint32_t size, const char *name)
{
  LIST_INIT(&slab->pages);
  slab->name = name;
  slab->total_allocd = 0;
  slab->per_page = (SLAB_SIZE - sizeof(struct gimli_slab_page)) / size;
  slab->item_size = size;
  slab->next_avail = 0;
//  printf("slab_init: per_page=%d of %d each\n", slab->per_page, slab->item_size);

  return 1;
}

void *gimli_slab_alloc(struct gimli_slab *slab)
{
  struct gimli_slab_page *p;
  uint8_t *item;

//  return malloc(slab->item_size);

  if (slab->next_avail + 1 >= slab->per_page || !LIST_FIRST(&slab->pages)) {
    /* need a new page */
    p = malloc(SLAB_SIZE);
    if (!p) return NULL;
    LIST_INSERT_HEAD(&slab->pages, p, list);
    slab->next_avail = 0;
//    printf("allocated a new slab for size=%d\n", slab->item_size);
  }

  p = LIST_FIRST(&slab->pages);
  item = (uint8_t*)(p + 1) + (slab->item_size * slab->next_avail++);
  slab->total_allocd++;
#if 0
  printf("now %" PRIu32 " objects of size %" PRIu32 " via slab %p %s\n",
      slab->total_allocd, slab->item_size, slab, slab->name);
#endif
  return item;
}

void gimli_slab_destroy(struct gimli_slab *slab)
{
  struct gimli_slab_page *p;

  while (LIST_FIRST(&slab->pages)) {
    p = LIST_FIRST(&slab->pages);
    LIST_REMOVE(p, list);
    free(p);
  }
  slab->next_avail = 0;
}


/* vim:ts=2:sw=2:et:
 */

