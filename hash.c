/*
 * Copyright (c) 2009-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

typedef struct {
	union {
		char *str;
		void *ptr;
		uint64_t u64;
	} u;
	uint32_t len;
} hash_key_t;

typedef struct gimli_hash_bucket {
	hash_key_t k;
	void *item;
	struct gimli_hash_bucket *next;
} gimli_hash_bucket;

struct libgimli_hash_table {
	gimli_hash_bucket **buckets;
	uint32_t table_size;
	uint32_t initval;
	uint32_t size;
	uint32_t flags;
	unsigned vers;
	int no_rebucket;
	void (*compile_key)(hash_key_t *key);
	int (*copy_key)(gimli_hash_bucket *b, hash_key_t *key);
	uint32_t (*hash)(hash_key_t *key, uint32_t initval);
	int (*same_key)(gimli_hash_bucket *b, hash_key_t *key);
	struct gimli_slab bucketslab;
	gimli_hash_free_func_t dtor;
};


/* This is from http://burtleburtle.net/bob/hash/doobs.html */

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

static void u64_key_compile(hash_key_t *key)
{
	key->len = sizeof(uint64_t);
}

static int u64_key_copy(gimli_hash_bucket *b, hash_key_t *key)
{
	b->k = *key;
	return 1;
}

static uint32_t u64_key_hash(hash_key_t *hkey, uint32_t initval)
{
#if 0
	uint32_t a = 0, b = hkey->u.u64 >> 32;
	uint32_t c = hkey->u.u64 & 0xffffffff;

	mix(a, b, c);
	return c;
#elif 1
	/* http://www.cris.com/~Ttwang/tech/inthash.htm -> hash6432shift */
	uint64_t key = hkey->u.u64;

  key = (~key) + (key << 18); // key = (key << 18) - key - 1;
  key = key ^ (key >> 31);
  key = key * 21; // key = (key + (key << 2)) + (key << 4);
  key = key ^ (key >> 11);
  key = key + (key << 6);
  key = key ^ (key >> 22);
  return (uint32_t) key;
#else
	return (uint32_t)hkey->u.u64;
#endif
}

static int u64_key_same(gimli_hash_bucket *b, hash_key_t *key)
{
	return b->k.u.u64 == key->u.u64;
}

static void ptr_key_compile(hash_key_t *key)
{
	key->len = sizeof(void*);
}

static int ptr_key_copy(gimli_hash_bucket *b, hash_key_t *key)
{
	b->k = *key;
	return 1;
}

static uint32_t ptr_key_hash(hash_key_t *key, uint32_t initval)
{
	return (uint32_t)(intptr_t)key->u.ptr;
}

static int ptr_key_same(gimli_hash_bucket *b, hash_key_t *key)
{
	return b->k.u.ptr == key->u.ptr;
}

static int string_key_dup(gimli_hash_bucket *b, hash_key_t *key)
{
	b->k = *key;
	b->k.u.str = malloc(key->len + 1);
	if (!b->k.u.str) return 0;
	memcpy(b->k.u.str, key->u.str, key->len);
	b->k.u.str[key->len] = '\0';
	return 1;
}


static void string_key_compile(hash_key_t *key)
{
	key->len = strlen(key->u.str);
}

static int string_key_same(gimli_hash_bucket *b, hash_key_t *k)
{
	return b->k.len == k->len && !memcmp(b->k.u.str, k->u.str, k->len);
}

static uint32_t string_key_hash(hash_key_t *key, uint32_t initval)
{
   register uint32_t a,b,c,len;
   const char *k = key->u.ptr;

   /* Set up the internal state */
   len = key->len;
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
   c += key->len;
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

gimli_hash_t gimli_hash_new_size(gimli_hash_free_func_t dtor, uint32_t flags, size_t size)
{
	gimli_hash_t h = calloc(1, sizeof(*h));
	h->initval = lrand48();
	h->flags = flags;
	h->table_size = size ? power_2(size) : GIMLI_HASH_INITIAL_SIZE;
	h->buckets = calloc(h->table_size, sizeof(gimli_hash_bucket*));
	h->dtor = dtor;
	gimli_slab_init(&h->bucketslab, sizeof(gimli_hash_bucket), "buckets");

	if (flags & GIMLI_HASH_PTR_KEYS) {
		h->compile_key = ptr_key_compile;
		h->copy_key = ptr_key_copy;
		h->hash = ptr_key_hash;
		h->same_key = ptr_key_same;
	} else if (flags & GIMLI_HASH_U64_KEYS) {
		h->compile_key = u64_key_compile;
		h->copy_key = u64_key_copy;
		h->hash = u64_key_hash;
		h->same_key = u64_key_same;
	} else {
		h->compile_key = string_key_compile;
		h->copy_key = (flags & GIMLI_HASH_DUP_KEYS) ? string_key_dup : ptr_key_copy;
		h->hash = string_key_hash;
		h->same_key = string_key_same;
	}

	return h;
}

gimli_hash_t gimli_hash_new(gimli_hash_free_func_t dtor)
{
	return gimli_hash_new_size(dtor, GIMLI_HASH_DUP_KEYS, GIMLI_HASH_INITIAL_SIZE);
}

static void free_bucket(gimli_hash_t h, gimli_hash_bucket *b)
{
	if (h->flags & GIMLI_HASH_DUP_KEYS) {
		free(b->k.u.str);
	}
	if (h->dtor) {
		h->dtor(b->item);
	}
//	free(b);
}

static gimli_hash_bucket *new_bucket(gimli_hash_t h, hash_key_t *key, void *item)
{
	gimli_hash_bucket *b;

	b = gimli_slab_alloc(&h->bucketslab);

	if (!b) return NULL;
	memset(b, 0, sizeof(*b));

	if (!h->copy_key(b, key)) {
		free(b);
		return NULL;
	}

	b->item = item;
	return b;
}

static void rebucket(gimli_hash_t h, int newsize)
{
	int i, newoff;
	gimli_hash_bucket **newbuckets, *b, *n;

	if (h->no_rebucket) return;

//printf("rebucket(%p, %d) %d\n", h, newsize, h->size);
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
			newoff = h->hash(&b->k, h->initval) & (newsize-1);
			b->next = newbuckets[newoff];
			newbuckets[newoff] = b;
			b = n;
		}
	}
	free(h->buckets);
	h->table_size = newsize;
	h->buckets = newbuckets;
}

static int do_hash_insert(gimli_hash_t h, hash_key_t *key, void *item)
{
	int off;
	gimli_hash_bucket *b;

	h->compile_key(key);

	off = h->hash(key, h->initval) & (h->table_size - 1);
	b = h->buckets[off];
	while (b) {
		if (h->same_key(b, key)) {
			return 0;
		}
		b = b->next;
	}
	b = new_bucket(h, key, item);
	b->next = h->buckets[off];
	h->buckets[off] = b;
	h->size++;
	h->vers++;

	if (h->size > h->table_size - (h->table_size >> 3)) {
		rebucket(h, h->table_size << 1);
	}
	return 1;
}

static int do_hash_find(gimli_hash_t h, hash_key_t *key, void **item_p)
{
	int off;
	gimli_hash_bucket *b;

	h->compile_key(key);

	off = h->hash(key, h->initval) & (h->table_size - 1);
	b = h->buckets[off];
	while (b) {
		if (h->same_key(b, key)) {
			if (item_p) {
				*item_p = b->item;
			}
			return 1;
		}
		b = b->next;
	}
	return 0;
}

static int do_hash_delete(gimli_hash_t h, hash_key_t *key)
{
	int off;
	gimli_hash_bucket *b, *prev = NULL;

	h->compile_key(key);

	off = h->hash(key, h->initval) & (h->table_size - 1);
	b = h->buckets[off];
	while (b) {
		if (h->same_key(b, key)) {
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
	free_bucket(h, b);
	h->size--;
	h->vers++;
	if (h->table_size > GIMLI_HASH_INITIAL_SIZE &&
			h->size < h->table_size >> 2) {
		rebucket(h, h->table_size >> 1);
	}
	return 1;
}

int gimli_hash_insert(gimli_hash_t h, const char *k, void *item)
{
	hash_key_t key;

	key.u.str = (char*)k;

	return do_hash_insert(h, &key, item);
}

int gimli_hash_find(gimli_hash_t h, const char *k, void **item_p)
{
	hash_key_t key;

	key.u.str = (char*)k;

	return do_hash_find(h, &key, item_p);
}

int gimli_hash_delete(gimli_hash_t h, const char *k)
{
	hash_key_t key;

	key.u.str = (char*)k;

	return do_hash_delete(h, &key);
}

int gimli_hash_delete_u64(gimli_hash_t h, uint64_t k)
{
	hash_key_t key;

	key.u.u64 = k;

	return do_hash_delete(h, &key);
}

int gimli_hash_find_u64(gimli_hash_t h, uint64_t k, void **item_p)
{
	hash_key_t key;

	key.u.u64 = k;

	return do_hash_find(h, &key, item_p);
}

int gimli_hash_insert_u64(gimli_hash_t h, uint64_t k, void *item)
{
	hash_key_t key;

	key.u.u64 = k;

	return do_hash_insert(h, &key, item);
}

int gimli_hash_delete_ptr(gimli_hash_t h, void * k)
{
	hash_key_t key;

	key.u.ptr = k;

	return do_hash_delete(h, &key);
}

int gimli_hash_find_ptr(gimli_hash_t h, void * k, void **item_p)
{
	hash_key_t key;

	key.u.ptr = k;

	return do_hash_find(h, &key, item_p);
}

int gimli_hash_insert_ptr(gimli_hash_t h, void * k, void *item)
{
	hash_key_t key;

	key.u.ptr = k;

	return do_hash_insert(h, &key, item);
}

void gimli_hash_delete_all(gimli_hash_t h, int downsize)
{
	int i;
	gimli_hash_bucket *b, *tofree;

	h->no_rebucket++;
	for (i = 0; i < h->table_size; i++) {
		b = h->buckets[i];
		while (b) {
			tofree = b;
			b = b->next;
			free_bucket(h, tofree);
		}
		h->buckets[i] = NULL;
	}
	h->size = 0;
	h->no_rebucket--;
	if (downsize) {
		rebucket(h, GIMLI_HASH_INITIAL_SIZE);
	}
	gimli_slab_destroy(&h->bucketslab);
	gimli_slab_init(&h->bucketslab, sizeof(gimli_hash_bucket), "buckets");
}

void gimli_hash_destroy(gimli_hash_t h)
{
	gimli_hash_delete_all(h, 0);
	gimli_slab_destroy(&h->bucketslab);
	if (h->buckets) {
		free(h->buckets);
		h->buckets = NULL;
	}
	free(h);
}

int gimli_hash_iter(gimli_hash_t h, gimli_hash_iter_func_t func, void *arg)
{
	int i;
	gimli_iter_status_t ret;
	gimli_hash_bucket *b;
	int visited = 0;

	h->no_rebucket++;
	for (i = 0; i < h->table_size; i++) {
		b = h->buckets[i];
		while (b) {
			++visited;
			ret = func(b->k.u.str, b->k.len, b->item, arg);
			if (ret != GIMLI_ITER_CONT) {
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

void gimli_hash_diagnose(gimli_hash_t h)
{
	int num_empty = 0;
	int num_perfect = 0;
	int num_collided = 0;
	int largest_chain = 0;
	int i;
	gimli_hash_bucket *b;

	for (i = 0; i < h->table_size; i++) {
		int run = 0;
		b = h->buckets[i];
		if (!b) {
			num_empty++;
			continue;
		}
		if (!b->next) {
			num_perfect++;
			continue;
		}
		num_collided++;
		while (b) {
			run++;

			b = b->next;
		}
		if (run > largest_chain) largest_chain = run;
	}

	printf("num_empty=%d num_perfect=%d num_collided=%d %.0f%% largest=%d\n",
			num_empty, num_perfect, num_collided,
			h->size ? ((float)num_collided / (float)h->size * 100.0) : 0.0,
			largest_chain);
}

/* vim:ts=2:sw=2:noet:
 */
