/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

typedef struct gimli_hash_bucket {
	char *k;
	void *item;
	struct gimli_hash_bucket *next;
	int klen;
} gimli_hash_bucket;

struct libgimli_hash_table {
	gimli_hash_bucket **buckets;
	uint32_t table_size;
	uint32_t initval;
	uint32_t size;
	gimli_hash_free_func_t dtor;
	unsigned vers;
	int no_rebucket;
};

/* This is from http://burtleburtle.net/bob/hash/doobs.html */
#define HASH_INITIAL_SIZE (1<<7)

#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}                              

static uint32_t hashfunc(const char *k, uint32_t length, uint32_t initval)
{
   register uint32_t a,b,c,len;

   /* Set up the internal state */ 
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
      b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
      c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c+=((uint32_t)k[10]<<24);
   case 10: c+=((uint32_t)k[9]<<16);
   case 9 : c+=((uint32_t)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((uint32_t)k[7]<<24);
   case 7 : b+=((uint32_t)k[6]<<16);
   case 6 : b+=((uint32_t)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((uint32_t)k[3]<<24);
   case 3 : a+=((uint32_t)k[2]<<16);
   case 2 : a+=((uint32_t)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}


gimli_hash_t gimli_hash_new(gimli_hash_free_func_t dtor)
{
	gimli_hash_t h = calloc(1, sizeof(*h));
	h->initval = lrand48();
	h->table_size = HASH_INITIAL_SIZE;
	h->buckets = calloc(h->table_size, sizeof(gimli_hash_bucket*));
	h->dtor = dtor;
	return h;
}

static gimli_hash_bucket *new_bucket(const char *k, int klen, void *item)
{
	gimli_hash_bucket *b = calloc(1, sizeof(*b));
	b->k = malloc(klen);
	memcpy(b->k, k, klen);
	b->klen = klen;
	b->item = item;
	return b;
}

static void rebucket(gimli_hash_t h, int newsize)
{
	int i, newoff;
	gimli_hash_bucket **newbuckets, *b, *n;

	if (h->no_rebucket) return;

	i = newsize;
	while (i) {
		if (i & 1) break;
		i >>= 1;
	}
	if (i & ~1) {
		return;
	}
	newbuckets = calloc(newsize, sizeof(*b));
	for (i = 0; i < h->table_size; i++) {
		b = h->buckets[i];
		while (b) {
			n = b->next;
			newoff = hashfunc(b->k, b->klen, h->initval) & (newsize-1);
			b->next = newbuckets[newoff];
			newbuckets[newoff] = b;
			b = n;
		}
	}
	free(h->buckets);
	h->table_size = newsize;
	h->buckets = newbuckets;
}

int gimli_hash_insert(gimli_hash_t h, const char *k, void *item)
{
	int off;
	gimli_hash_bucket *b;
	int klen = strlen(k);

	off = hashfunc(k, klen, h->initval) & (h->table_size - 1);
	b = h->buckets[off];
	while (b) {
		if (b->klen == klen && !memcmp(b->k, k, klen)) {
			return 0;
		}
		b = b->next;
	}
	b = new_bucket(k, klen, item);
	b->next = h->buckets[off];
	h->buckets[off] = b;
	h->size++;
	h->vers++;

	if (h->size > h->table_size - (h->table_size >> 3)) {
		rebucket(h, h->table_size << 1);
	}
	return 1;
}

int gimli_hash_find(gimli_hash_t h, const char *k, void **item_p)
{
	int off;
	gimli_hash_bucket *b;
	int klen = strlen(k);

	off = hashfunc(k, klen, h->initval) & (h->table_size - 1);
	b = h->buckets[off];
	while (b) {
		if (b->klen == klen && !memcmp(b->k, k, klen)) {
			if (item_p) {
				*item_p = b->item;
			}
			return 1;
		}
		b = b->next;
	}
	return 0;
}

int gimli_hash_delete(gimli_hash_t h, const char *k)
{
	int off;
	gimli_hash_bucket *b, *prev = NULL;
	int klen;

	off = hashfunc(k, klen, h->initval) & (h->table_size - 1);
	b = h->buckets[off];
	while (b) {
		if (b->klen == klen && !memcmp(b->k, k, klen)) {
			break;
		}
		prev = b;
		b = b->next;
	}
	if (!b) return 0;
	if (!prev) {
		h->buckets[off] = b->next;
	} else {
		prev->next = b->next;
	}
	free(b->k);
	if (h->dtor) {
		h->dtor(b->item);
	}
	free(b);
	h->size--;
	h->vers++;
	if (h->table_size > HASH_INITIAL_SIZE &&
			h->size < h->table_size >> 2) {
		rebucket(h, h->table_size >> 1);
	}
	return 1;
}

void gimli_hash_delete_all(gimli_hash_t h)
{
	int i;
	gimli_hash_bucket *b, *tofree;

	h->no_rebucket++;
	for (i = 0; i < h->table_size; i++) {
		b = h->buckets[i];
		while (b) {
			tofree = b;
			b = b->next;
			free(b->k);
			if (h->dtor) {
				h->dtor(b->item);
			}
			free(b);
		}
		h->buckets[i] = NULL;
	}
	h->size = 0;
	h->no_rebucket--;
	rebucket(h, HASH_INITIAL_SIZE);
}

void gimli_hash_destroy(gimli_hash_t h)
{
	gimli_hash_delete_all(h);
	if (h->buckets) {
		free(h->buckets);
		h->buckets = NULL;
	}
	free(h);
}

int gimli_hash_iter(gimli_hash_t h, gimli_hash_iter_func_t func, void *arg)
{
	int i, ret;
	gimli_hash_bucket *b;
	int visited = 0;

	h->no_rebucket++;
	for (i = 0; i < h->table_size; i++) {
		b = h->buckets[i];
		while (b) {
			++visited;
			ret = func(b->k, b->klen, b->item, arg);
			if (ret == GIMLI_HASH_ITER_STOP) {
				return visited;
			}
			b = b->next;
		}
	}
	return visited;
}

int gimli_hash_size(gimli_hash_t h)
{
	return h->size;
}

/* vim:ts=2:sw=2:noet:
 */
