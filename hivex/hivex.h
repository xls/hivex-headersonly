/*
*
* Copyright (C) 2009-2011 Red Hat Inc.
* Derived from code by Petter Nordahl-Hagen under a compatible license:
*   Copyright (c) 1997-2007 Petter Nordahl-Hagen.
* Derived from code by Markus Stephany under a compatible license:
*   Copyright (c)2000-2004, Markus Stephany.
* 
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation;
* version 2.1 of the License only.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*
*
* Rewritten and adopted single header/amalgamation style by Thomas Rizos
* no dependencies, use HIVEX_IMPLEMENTATION for default std dependencies
* 
*
*/
#ifndef HIVEX_H_
#define HIVEX_H_


#ifdef _WIN32
	#define __attribute__(x)
	#define HIVEX_UNUSED
#else	/* GCC and the rest */
	#define HIVEX_UNUSED __attribute__((unused))
#endif

#ifndef CUSTOM_HIVEX_IMPLEMENTATION

	#define HIVEX_DUMB_IO

	#include <stdint.h>
	#include <stddef.h>
	#include <errno.h>
	#define hivex_errno				errno

	#define HIVEX_EINVAL			EINVAL
	#define HIVEX_ENOMEM			ENOMEM
	#define HIVEX_ENOTSUP			ENOTSUP
	#define HIVEX_EFAULT			EFAULT
	#define HIVEX_ENOENT			ENOENT
	#define HIVEX_ERANGE			ERANGE
	#define HIVEX_ELOOP				ELOOP
	#define HIVEX_EROFS				EROFS
	#define HIVEX_EEXIST			EEXIST
	#ifdef ENOKEY
	# define HIVEX_ENOKEY ENOKEY
	#else
	# define HIVEX_ENOKEY HIVEX_ENOENT
	#endif

	#include <stdio.h>
	#define hivex_file_t			FILE*
	#define hivex_file_open(x)		fopen(x,"rb")
	#define hivex_file_close(x)		fclose(x)
	#define hivex_get_filesize(x)	get_file_size(x)


	#include <memory.h>
	#define hivex_malloc(x)			malloc((x))
	#define hivex_free(x)			free(x)
	#define hivex_calloc(x,b)		calloc(x,b)
	#define hivex_realloc(a,b)		realloc(a,b)
	#define hivex_memcpy(a,b,l)		memcpy(a,b,l)
	#define hivex_memset(a,b,c)		memset(a,b,c)

	#include <stdlib.h>
	#define hivex_printf			printf
	#define hivex_snprintf			snprintf
	#include <string.h>

	#ifdef _WIN32
		#define hivex_strdup			_strdup
		#define hivex_strncasecmp(a,b,n) _strnicmp((a),(b),(n)) 
		#define hivex_strcasecmp(a,b)	_stricmp((a),(b)) 
	#else
		#define hivex_strdup			strdup
		#define hivex_strncasecmp(a,b,n) strncasecmp((a),(b),(n)) 
		#define hivex_strcasecmp(a,b)	strcasecmp((a),(b)) 
	#endif

	#define hivex_strlen			strlen
	#define hivex_strncpy			strncpy
	#define hivex_strcpy			strcpy
	#define hivex_strrchr			strrchr
	#define hivex_strchr			strchr
	#define hivex_strtoull			strtoull
	#define hivex_strcmp(a,b)		strcmp((a),(b))
	#define hivex_strncmp(a,b,n)	strncmp((a),(b),(n))
	

	#include <assert.h>
	#define hivex_assert(a) assert((a))

	#include <inttypes.h>
	#define HIVEX_SIZE_MAX SIZE_MAX
	typedef uint8_t		hivex_uint8_t;
	typedef int8_t		hivex_int8_t;
	typedef uint16_t	hivex_uint16_t;
	typedef int16_t		hivex_int16_t;
	typedef uint32_t	hivex_uint32_t;
	typedef int32_t		hivex_int32_t;
	typedef uint64_t	hivex_uint64_t;
	typedef int64_t		hivex_int64_t;
#ifdef _WIN32
#include <BaseTsd.h>
	typedef SSIZE_T 	hivex_ssize_t;
#else
	typedef ssize_t 	hivex_ssize_t;
#endif
	typedef size_t		hivex_size_t;
#endif



#ifdef HIVEX_STATIC
#define HIVEX_DEF static HIVEX_UNUSED 
#else
#define HIVEX_DEF extern
#endif

#ifndef HIVEX_ENDIAN
#define HIVEX_LITTLE_ENDIAN
#endif

#ifdef __cplusplus
extern "C" {
#endif

	HIVEX_DEF hivex_size_t hivex_full_read(hivex_file_t f, char *data, long size);
	HIVEX_DEF hivex_size_t hivex_full_write(hivex_file_t f, char *data, long size);

#ifdef HIVEX_DUMB_IO


	HIVEX_DEF long get_file_size(hivex_file_t f)
	{
		long cur = fseek(f, 0, SEEK_CUR);
		fseek(f, 0, SEEK_END);
		long length = ftell(f);
		fseek(f, cur, SEEK_SET);
		return length;
	}

	HIVEX_DEF hivex_size_t hivex_full_read(hivex_file_t f, char *data, long size)
	{

		if (f == NULL) return 0;
		fseek(f, 0, SEEK_SET);
		return fread(data, 1, size, f);
	}

	HIVEX_DEF hivex_size_t hivex_full_write(hivex_file_t f, char *data, long size)
	{

		if (f == NULL) return 0;
		fseek(f, 0, SEEK_SET);
		fwrite(data, 1, size, f);

		return 0;
	}

#endif


	struct hive_h {
		char *filename;
		hivex_file_t fd;
		hivex_size_t size;
		int msglvl;
		int writable;

		/* Registry file, memory mapped if read-only, or malloc'd if writing. */
		union {
			char *addr;
			struct ntreg_header *hdr;
		};

		/* Use a bitmap to store which file offsets are valid (point to a
		* used block).  We only need to store 1 bit per 32 bits of the file
		* (because blocks are 4-byte aligned).  We found that the average
		* block size in a registry file is ~50 bytes.  So roughly 1 in 12
		* bits in the bitmap will be set, making it likely a more efficient
		* structure than a hash table.
		*/
		char *bitmap;
#define BITMAP_SET(bitmap,off) (bitmap[(off)>>5] |= 1 << (((off)>>2)&7))
#define BITMAP_CLR(bitmap,off) (bitmap[(off)>>5] &= ~ (1 << (((off)>>2)&7)))
#define BITMAP_TST(bitmap,off) (bitmap[(off)>>5] & (1 << (((off)>>2)&7)))
#define IS_VALID_BLOCK(h,off)               \
  (((off) & 3) == 0 &&                      \
   (off) >= 0x1000 &&                       \
   (off) < (h)->size &&                     \
   BITMAP_TST((h)->bitmap,(off)))

		/* Fields from the header, extracted from little-endianness hell. */
		hivex_size_t rootoffs;              /* Root key offset (always an nk-block). */
		hivex_size_t endpages;              /* Offset of end of pages. */
		hivex_int64_t last_modified;        /* mtime of base block. */

											/* For writing. */
		hivex_size_t endblocks;             /* Offset to next block allocation (0
											if not allocated anything yet). */

	};

#define STREQ(a,b)			(hivex_strcmp((a),(b)) == 0)
#define STRCASEEQ(a,b)		(hivex_strcasecmp((a),(b)) == 0)
#define STRNEQ(a,b)			(hivex_strcmp((a),(b)) != 0)
#define STRCASENEQ(a,b)		(hivex_strcasecmp((a),(b)) != 0)
#define STREQLEN(a,b,n)		(hivex_strncmp((a),(b),(n)) == 0)
#define STRCASEEQLEN(a,b,n) (hivex_strncasecmp((a),(b),(n)) == 0)
#define STRNEQLEN(a,b,n)	(hivex_strncmp((a),(b),(n)) != 0)
#define STRCASENEQLEN(a,b,n) (hivex_strncasecmp((a),(b),(n)) != 0)
#define STRPREFIX(a,b)		(hivex_strncmp((a),(b),hivex_strlen((b))) == 0)

	/* NOTE: This API is documented in the man page hivex(3). */

	/* Hive handle. */
	typedef struct hive_h hive_h;

	/* Nodes and values. */
	typedef hivex_size_t hive_node_h;
	typedef hivex_size_t hive_value_h;




	/* Pre-defined types. */
	enum hive_type {
		/* Just a key without a value */
		hive_t_REG_NONE,
#define hive_t_none hive_t_REG_NONE

		/* A Windows string (encoding is unknown, but often UTF16-LE) */
		hive_t_REG_SZ,
#define hive_t_string hive_t_REG_SZ

		/* A Windows string that contains %env% (environment variable expansion) */
		hive_t_REG_EXPAND_SZ,
#define hive_t_expand_string hive_t_REG_EXPAND_SZ

		/* A blob of binary */
		hive_t_REG_BINARY,
#define hive_t_binary hive_t_REG_BINARY

		/* DWORD (32 bit integer), little endian */
		hive_t_REG_DWORD,
#define hive_t_dword hive_t_REG_DWORD

		/* DWORD (32 bit integer), big endian */
		hive_t_REG_DWORD_BIG_ENDIAN,
#define hive_t_dword_be hive_t_REG_DWORD_BIG_ENDIAN

		/* Symbolic link to another part of the registry tree */
		hive_t_REG_LINK,
#define hive_t_link hive_t_REG_LINK

		/* Multiple Windows strings.  See http://blogs.msdn.com/oldnewthing/archive/2009/10/08/9904646.aspx */
		hive_t_REG_MULTI_SZ,
#define hive_t_multiple_strings hive_t_REG_MULTI_SZ

		/* Resource list */
		hive_t_REG_RESOURCE_LIST,
#define hive_t_resource_list hive_t_REG_RESOURCE_LIST

		/* Resource descriptor */
		hive_t_REG_FULL_RESOURCE_DESCRIPTOR,
#define hive_t_full_resource_description hive_t_REG_FULL_RESOURCE_DESCRIPTOR

		/* Resouce requirements list */
		hive_t_REG_RESOURCE_REQUIREMENTS_LIST,
#define hive_t_resource_requirements_list hive_t_REG_RESOURCE_REQUIREMENTS_LIST

		/* QWORD (64 bit integer), unspecified endianness but usually little endian */
		hive_t_REG_QWORD,
#define hive_t_qword hive_t_REG_QWORD

	};

	typedef enum hive_type hive_type;

	/* Bitmask of flags passed to hivex_open. */
	/* Verbose messages */
#define HIVEX_OPEN_VERBOSE    1
	/* Debug messages */
#define HIVEX_OPEN_DEBUG      2
	/* Enable writes to the hive */
#define HIVEX_OPEN_WRITE      4

	/* Array of (key, value) pairs passed to hivex_node_set_values. */
	struct hive_set_value {
		char *key;
		hive_type t;
		hivex_size_t len;
		char *value;
	};

	typedef struct hive_set_value hive_set_value;
	HIVEX_DEF void hivex_free_strings(char **argv);
	/* Functions. */
	HIVEX_DEF hive_h *hivex_open(const char *filename, int flags);
	HIVEX_DEF int hivex_close(hive_h *h);
	HIVEX_DEF hive_node_h hivex_root(hive_h *h);
	HIVEX_DEF hivex_int64_t hivex_last_modified(hive_h *h);
	HIVEX_DEF char *hivex_node_name(hive_h *h, hive_node_h node);
	HIVEX_DEF hivex_int64_t hivex_node_timestamp(hive_h *h, hive_node_h node);
	HIVEX_DEF hive_node_h *hivex_node_children(hive_h *h, hive_node_h node);
	HIVEX_DEF hive_node_h hivex_node_get_child(hive_h *h, hive_node_h node, const char *name);
	HIVEX_DEF hive_node_h hivex_node_parent(hive_h *h, hive_node_h node);
	HIVEX_DEF hive_value_h *hivex_node_values(hive_h *h, hive_node_h node);
	HIVEX_DEF hive_value_h hivex_node_get_value(hive_h *h, hive_node_h node, const char *key);
	HIVEX_DEF hivex_size_t hivex_value_key_len(hive_h *h, hive_value_h val);
	HIVEX_DEF char *hivex_value_key(hive_h *h, hive_value_h val);
	HIVEX_DEF int hivex_value_type(hive_h *h, hive_value_h val, hive_type *t, hivex_size_t *len);
	HIVEX_DEF hivex_size_t hivex_node_struct_length(hive_h *h, hive_node_h node);
	HIVEX_DEF hivex_size_t hivex_value_struct_length(hive_h *h, hive_value_h val);
	HIVEX_DEF char *hivex_value_value(hive_h *h, hive_value_h val, hive_type *t, hivex_size_t *len);
	HIVEX_DEF char *hivex_value_string(hive_h *h, hive_value_h val);
	HIVEX_DEF char **hivex_value_multiple_strings(hive_h *h, hive_value_h val);
	HIVEX_DEF hivex_int32_t hivex_value_dword(hive_h *h, hive_value_h val);
	HIVEX_DEF hivex_int64_t hivex_value_qword(hive_h *h, hive_value_h val);
	HIVEX_DEF int hivex_commit(hive_h *h, const char *filename, int flags);
	HIVEX_DEF hive_node_h hivex_node_add_child(hive_h *h, hive_node_h parent, const char *name);
	HIVEX_DEF int hivex_node_delete_child(hive_h *h, hive_node_h node);
	HIVEX_DEF int hivex_node_set_values(hive_h *h, hive_node_h node, hivex_size_t nr_values, const hive_set_value *values, int flags);
	HIVEX_DEF int hivex_node_set_value(hive_h *h, hive_node_h node, const hive_set_value *val, int flags);

	/* Visit all nodes.  This is specific to the C API and is not made
	* available to other languages.  This is because of the complexity
	* of binding callbacks in other languages, but also because other
	* languages make it much simpler to iterate over a tree.
	*/
	struct hivex_visitor {
		int(*node_start) (hive_h *, void *opaque, hive_node_h, const char *name);
		int(*node_end) (hive_h *, void *opaque, hive_node_h, const char *name);
		int(*value_string) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, const char *str);
		int(*value_multiple_strings) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, char **argv);
		int(*value_string_invalid_utf16) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, const char *str);
		int(*value_dword) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, hivex_int32_t);
		int(*value_qword) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, hivex_int64_t);
		int(*value_binary) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, const char *value);
		int(*value_none) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, const char *value);
		int(*value_other) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, const char *value);
		int(*value_any) (hive_h *, void *opaque, hive_node_h, hive_value_h, hive_type t, hivex_size_t len, const char *key, const char *value);
	};


#define HIVEX_VISIT_SKIP_BAD 1

	HIVEX_DEF int hivex_visit(hive_h *h, const struct hivex_visitor *visitor, hivex_size_t len, void *opaque, int flags);
	HIVEX_DEF int hivex_visit_node(hive_h *h, hive_node_h node, const struct hivex_visitor *visitor, hivex_size_t len, void *opaque, int flags);


	/* helpers */

	HIVEX_DEF char* hivex_utf16_to_utf8(const  hivex_uint16_t  *src, hivex_size_t len);
	HIVEX_DEF hivex_size_t utf16_string_len_in_bytes_max(const char *str, hivex_size_t len);
	HIVEX_DEF hivex_size_t utf16_string_len(const char *str, hivex_size_t len);
	inline int hivex_toupper(int c);


	/* These limits are in place to stop really stupid stuff and/or exploits. */
#define HIVEX_MAX_SUBKEYS       15000
#define HIVEX_MAX_VALUES        10000
#define HIVEX_MAX_VALUE_LEN   1000000
#define HIVEX_MAX_ALLOCATION  1000000

#pragma pack(1)
	/* NB. All fields are little endian. */
	struct ntreg_header {
		char magic[4];                /* "regf" */
		hivex_uint32_t sequence1;
		hivex_uint32_t sequence2;
		hivex_int64_t last_modified;
		hivex_uint32_t major_ver;           /* 1 */
		hivex_uint32_t minor_ver;           /* 3 */
		hivex_uint32_t unknown5;            /* 0 */
		hivex_uint32_t unknown6;            /* 1 */
		hivex_uint32_t offset;              /* offset of root key record - 4KB */
		hivex_uint32_t blocks;              /* pointer AFTER last hbin in file - 4KB */
		hivex_uint32_t unknown7;            /* 1 */
											/* 0x30 */
		char name[64];                /* original file name of hive */
		char unknown_guid1[16];
		char unknown_guid2[16];
		/* 0x90 */
		hivex_uint32_t unknown8;
		char unknown_guid3[16];
		hivex_uint32_t unknown9;
		/* 0xa8 */
		char unknown10[340];
		/* 0x1fc */
		hivex_uint32_t csum;                /* checksum: xor of dwords 0-0x1fb. */
											/* 0x200 */
		char unknown11[3528];
		/* 0xfc8 */
		char unknown_guid4[16];
		char unknown_guid5[16];
		char unknown_guid6[16];
		hivex_uint32_t unknown12;
		hivex_uint32_t unknown13;
		/* 0x1000 */
	} __attribute__((__packed__));

	struct ntreg_hbin_page {
		char magic[4];                /* "hbin" */
		hivex_uint32_t offset_first;        /* offset from 1st block */
		hivex_uint32_t page_size;           /* size of this page (multiple of 4KB) */
		char unknown[2];
		/* Linked list of blocks follows here. */
	} __attribute__((__packed__));

	struct ntreg_hbin_block {
		hivex_int32_t seg_len;              /* length of this block (-ve for used block) */
		char id[2];                   /* the block type (eg. "nk" for nk record) */
									  /* Block data follows here. */
	} __attribute__((__packed__));


#define BLOCK_ID_EQ(h,offs,eqid) \
  (STREQLEN (((struct ntreg_hbin_block *)((h)->addr + (offs)))->id, (eqid), 2))

	/* Byte Swap */
#define hivex_swap_bytes16(x) ((((x) & 0x00FF) << 8) | \
                     (((x) & 0xFF00) >> 8))

	/* Given an unsigned 32-bit argument X, return the value corresponding to
	X with reversed byte order.  */
#define hivex_swap_bytes32(x) ((((x) & 0x000000FF) << 24) | \
                     (((x) & 0x0000FF00) << 8) | \
                     (((x) & 0x00FF0000) >> 8) | \
                     (((x) & 0xFF000000) >> 24))

	/* Given an unsigned 64-bit argument X, return the value corresponding to
	X with reversed byte order.  */
#define hivex_swap_bytes64(x) ((((x) & 0x00000000000000FFULL) << 56) | \
                     (((x) & 0x000000000000FF00ULL) << 40) | \
                     (((x) & 0x0000000000FF0000ULL) << 24) | \
                     (((x) & 0x00000000FF000000ULL) << 8) | \
                     (((x) & 0x000000FF00000000ULL) >> 8) | \
                     (((x) & 0x0000FF0000000000ULL) >> 24) | \
                     (((x) & 0x00FF000000000000ULL) >> 40) | \
                     (((x) & 0xFF00000000000000ULL) >> 56))



#ifdef HIVEX_LITTLE_ENDIAN
#ifndef be32toh
#define be32toh(x) hivex_swap_bytes32 (x)
#endif
#ifndef htobe32
#define htobe32(x) hivex_swap_bytes32 (x)
#endif
#ifndef be64toh
#define be64toh(x) hivex_swap_bytes64 (x)
#endif
#ifndef htobe64
#define htobe64(x) hivex_swap_bytes64 (x)
#endif
#ifndef le16toh
#define le16toh(x) (x)
#endif
#ifndef htole16
#define htole16(x) (x)
#endif
#ifndef le32toh
#define le32toh(x) (x)
#endif
#ifndef htole32
#define htole32(x) (x)
#endif
#ifndef le64toh
#define le64toh(x) (x)
#endif
#ifndef htole64
#define htole64(x) (x)
#endif
#else /* __BYTE_ORDER == __BIG_ENDIAN */
#ifndef be32toh
#define be32toh(x) (x)
#endif
#ifndef htobe32
#define htobe32(x) (x)
#endif
#ifndef be64toh
#define be64toh(x) (x)
#endif
#ifndef htobe64
#define htobe64(x) (x)
#endif
#ifndef le16toh
#define le16toh(x) bswap_16 (x)
#endif
#ifndef htole16
#define htole16(x) bswap_16 (x)
#endif
#ifndef le32toh
#define le32toh(x) bswap_32 (x)
#endif
#ifndef htole32
#define htole32(x) bswap_32 (x)
#endif
#ifndef le64toh
#define le64toh(x) bswap_64 (x)
#endif
#ifndef htole64
#define htole64(x) bswap_64 (x)
#endif
#endif /* __BYTE_ORDER == __BIG_ENDIAN */


	static hivex_size_t
		block_len(hive_h *h, hivex_size_t blkoff, int *used)
	{
		struct ntreg_hbin_block *block;
		block = (struct ntreg_hbin_block *) (h->addr + blkoff);

		hivex_int32_t len = le32toh(block->seg_len);
		if (len < 0) {
			if (used) *used = 1;
			len = -len;
		}
		else {
			if (used) *used = 0;
		}

		return (hivex_size_t)len;
	}

	struct ntreg_nk_record {
		hivex_int32_t seg_len;              /* length (always -ve because used) */
		char id[2];                   /* "nk" */
		hivex_uint16_t flags;
		hivex_int64_t timestamp;
		hivex_uint32_t unknown1;
		hivex_uint32_t parent;              /* offset of owner/parent */
		hivex_uint32_t nr_subkeys;          /* number of subkeys */
		hivex_uint32_t nr_subkeys_volatile;
		hivex_uint32_t subkey_lf;           /* lf record containing list of subkeys */
		hivex_uint32_t subkey_lf_volatile;
		hivex_uint32_t nr_values;           /* number of values */
		hivex_uint32_t vallist;             /* value-list record */
		hivex_uint32_t sk;                  /* offset of sk-record */
		hivex_uint32_t classname;           /* offset of classname record */
		hivex_uint16_t max_subkey_name_len; /* maximum length of a subkey name in bytes
											if the subkey was reencoded as UTF-16LE */
		hivex_uint16_t unknown2;
		hivex_uint32_t unknown3;
		hivex_uint32_t max_vk_name_len;     /* maximum length of any vk name in bytes
											if the name was reencoded as UTF-16LE */
		hivex_uint32_t max_vk_data_len;     /* maximum length of any vk data in bytes */
		hivex_uint32_t unknown6;
		hivex_uint16_t name_len;            /* length of name */
		hivex_uint16_t classname_len;       /* length of classname */
		char name[1];                 /* name follows here */
	} __attribute__((__packed__));

	struct ntreg_lf_record {
		hivex_int32_t seg_len;
		char id[2];                   /* "lf"|"lh" */
		hivex_uint16_t nr_keys;             /* number of keys in this record */
		struct {
			hivex_uint32_t offset;            /* offset of nk-record for this subkey */
			char hash[4];               /* hash of subkey name */
		} keys[1];
	} __attribute__((__packed__));

	struct ntreg_ri_record {
		hivex_int32_t seg_len;
		char id[2];                   /* "ri" */
		hivex_uint16_t nr_offsets;          /* number of pointers to lh records */
		hivex_uint32_t offset[1];           /* list of pointers to lh records */
	} __attribute__((__packed__));

	/* This has no ID header. */
	struct ntreg_value_list {
		hivex_int32_t seg_len;
		hivex_uint32_t offset[1];           /* list of pointers to vk records */
	} __attribute__((__packed__));

	struct ntreg_vk_record {
		hivex_int32_t seg_len;              /* length (always -ve because used) */
		char id[2];                   /* "vk" */
		hivex_uint16_t name_len;            /* length of name */
											/* length of the data:
											* If data_len is <= 4, then it's stored inline.
											* Top bit is set to indicate inline.
											*/
		hivex_uint32_t data_len;
		hivex_uint32_t data_offset;         /* pointer to the data (or data if inline) */
		hivex_uint32_t data_type;           /* type of the data */
		hivex_uint16_t flags;               /* bit 0 set => key name ASCII,
											bit 0 clr => key name UTF-16.
											Only seen ASCII here in the wild.
											NB: this is CLEAR for default key. */
		hivex_uint16_t unknown2;
		char name[1];                 /* key name follows here */
	} __attribute__((__packed__));

	struct ntreg_sk_record {
		hivex_int32_t seg_len;              /* length (always -ve because used) */
		char id[2];                   /* "sk" */
		hivex_uint16_t unknown1;
		hivex_uint32_t sk_next;             /* linked into a circular list */
		hivex_uint32_t sk_prev;
		hivex_uint32_t refcount;            /* reference count */
		hivex_uint32_t sec_len;             /* length of security info */
		char sec_desc[1];             /* security info follows */
	} __attribute__((__packed__));

	static hivex_uint32_t
		header_checksum(const hive_h *h)
	{
		hivex_uint32_t *daddr = (hivex_uint32_t *)h->addr;
		hivex_size_t i;
		hivex_uint32_t sum = 0;

		for (i = 0; i < 0x1fc / 4; ++i) {
			sum ^= le32toh(*daddr);
			daddr++;
		}

		return sum;
	}
#pragma pack()
#define HIVEX_OPEN_MSGLVL_MASK (HIVEX_OPEN_VERBOSE|HIVEX_OPEN_DEBUG)

	hive_h *
		hivex_open(const char *filename, int flags)
	{
		hive_h *h = NULL;
		/* Collect some stats. */
		hivex_size_t pages = 0;           /* Number of hbin pages read. */
		hivex_size_t smallest_page = HIVEX_SIZE_MAX, largest_page = 0;
		hivex_size_t blocks = 0;          /* Total number of blocks found. */
		hivex_size_t smallest_block = HIVEX_SIZE_MAX, largest_block = 0, blocks_bytes = 0;
		hivex_size_t used_blocks = 0;     /* Total number of used blocks found. */
		hivex_size_t used_size = 0;       /* Total size (bytes) of used blocks. */
		hivex_uint32_t sum = 0;
		hivex_uint32_t major_ver = 0;
		/* We'll set this flag when we see a block with the root offset (ie.
		* the root block).
		*/
		int seen_root_block = 0, bad_root_block = 0;

		hivex_size_t blkoff;
		struct ntreg_hbin_block* block;
		hivex_size_t seg_len;

		HIVEX_UNUSED int le = sizeof(struct ntreg_header);
		hivex_assert(le == 0x1000);
		hivex_assert(offsetof(struct ntreg_header, csum) == 0x1fc);

		h = (hive_h *)hivex_calloc(1, sizeof *h);
		if (h == NULL)
			goto error;

		h->msglvl = flags & HIVEX_OPEN_MSGLVL_MASK;

		if (h->msglvl >= 2)
			hivex_printf("hivex_open: created handle %p\n", (void*)h);

		h->writable = !!(flags & HIVEX_OPEN_WRITE);
		h->filename = hivex_strdup(filename);
		if (h->filename == NULL)
			goto error;


		h->fd = hivex_file_open(filename);

		if (h->fd == 0)
			goto error;


		h->size = hivex_get_filesize(h->fd);

		{
			h->addr = (char*)hivex_malloc(h->size);
			if (h->addr == NULL)
				goto error;

			if (hivex_full_read(h->fd, h->addr, h->size) < h->size)
				goto error;

			/* We don't need the file descriptor along this path, since we
			* have read all the data.
			*/
			hivex_file_close(h->fd);

			h->fd = 0;
		}

		/* Check header. */
		if (h->hdr->magic[0] != 'r' ||
			h->hdr->magic[1] != 'e' ||
			h->hdr->magic[2] != 'g' ||
			h->hdr->magic[3] != 'f') {
			hivex_printf("hivex: %s: not a Windows NT Registry hive file\n",
				filename);
			hivex_errno = HIVEX_ENOTSUP;
			goto error;
		}

		/* Check major version. */
		major_ver = le32toh(h->hdr->major_ver);
		if (major_ver != 1) {
			hivex_printf(
				"hivex: %s: hive file major version %" PRIu32 " (expected 1)\n",
				filename, major_ver);
			hivex_errno = HIVEX_ENOTSUP;
			goto error;
		}

		h->bitmap = (char*)hivex_calloc(1 + h->size / 32, 1);
		if (h->bitmap == NULL)
			goto error;

		/* Header checksum. */
		sum = header_checksum(h);
		if (sum != le32toh(h->hdr->csum)) {
			hivex_printf("hivex: %s: bad checksum in hive header\n", filename);
			hivex_errno = HIVEX_EINVAL;
			goto error;
		}

		/* Last modified time. */
		h->last_modified = le64toh((hivex_int64_t)h->hdr->last_modified);

		if (h->msglvl >= 2) {
			char *name = hivex_utf16_to_utf8((hivex_uint16_t*)h->hdr->name, 64);

			hivex_printf(
				"hivex_open: header fields:\n"
				"  file version             %" PRIu32 ".%" PRIu32 "\n"
				"  sequence nos             %" PRIu32 " %" PRIu32 "\n"
				"    (sequences nos should match if hive was synched at shutdown)\n"
				"  last modified            %" PRIu64 "\n"
				"    (Windows filetime, x 100 ns since 1601-01-01)\n"
				"  original file name       %s\n"
				"    (only 32 chars are stored, name is probably truncated)\n"
				"  root offset              0x%x + 0x1000\n"
				"  end of last page         0x%x + 0x1000 (total file size 0x%zx)\n"
				"  checksum                 0x%x (calculated 0x%x)\n",
				major_ver, le32toh(h->hdr->minor_ver),
				le32toh(h->hdr->sequence1), le32toh(h->hdr->sequence2),
				h->last_modified,
				name ? name : "(conversion failed)",
				le32toh(h->hdr->offset),
				le32toh(h->hdr->blocks), h->size,
				le32toh(h->hdr->csum), sum);
			hivex_free(name);
		}

		h->rootoffs = le32toh(h->hdr->offset) + 0x1000;
		h->endpages = le32toh(h->hdr->blocks) + 0x1000;

		if (h->msglvl >= 2)
			hivex_printf("hivex_open: root offset = 0x%zx\n", h->rootoffs);

		

		

		/* Read the pages and blocks.  The aim here is to be robust against
		* corrupt or malicious registries.  So we make sure the loops
		* always make forward progress.  We add the address of each block
		* we read to a hash table so pointers will only reference the start
		* of valid blocks.
		*/
		hivex_size_t off;
		struct ntreg_hbin_page *page;
		for (off = 0x1000; off < h->size; off += le32toh(page->page_size)) {
			if (off >= h->endpages)
				break;

			page = (struct ntreg_hbin_page *) (h->addr + off);
			if (page->magic[0] != 'h' ||
				page->magic[1] != 'b' ||
				page->magic[2] != 'i' ||
				page->magic[3] != 'n') {
				hivex_printf("hivex: %s: trailing garbage at end of file "
					"(at 0x%zx, after %zu pages)\n",
					filename, off, pages);
				hivex_errno = HIVEX_ENOTSUP;
				goto error;
			}

			hivex_size_t page_size = le32toh(page->page_size);
			if (h->msglvl >= 2)
				hivex_printf("hivex_open: page at 0x%zx, size %zu\n", off, page_size);
			pages++;
			if (page_size < smallest_page) smallest_page = page_size;
			if (page_size > largest_page) largest_page = page_size;

			if (page_size <= sizeof(struct ntreg_hbin_page) ||
				(page_size & 0x0fff) != 0) {
				hivex_printf("hivex: %s: page size %zu at 0x%zx, bad registry\n",
					filename, page_size, off);
				hivex_errno = HIVEX_ENOTSUP;
				goto error;
			}

			/* Read the blocks in this page. */
			
			for (blkoff = off + 0x20;
				blkoff < off + page_size;
				blkoff += seg_len) {
				blocks++;

				int is_root = blkoff == h->rootoffs;
				if (is_root)
					seen_root_block = 1;

				block = (struct ntreg_hbin_block *) (h->addr + blkoff);
				int used;
				seg_len = block_len(h, blkoff, &used);
				if (seg_len <= 4 || (seg_len & 3) != 0) {
					hivex_printf("hivex: %s: block size %" PRIu32 " at 0x%zx,"
						" bad registry\n",
						filename, le32toh(block->seg_len), blkoff);
					hivex_errno = HIVEX_ENOTSUP;
					goto error;
				}

				if (h->msglvl >= 2)
					hivex_printf("hivex_open: %s block id %d,%d at 0x%zx size %zu%s\n",
						used ? "used" : "free", block->id[0], block->id[1], blkoff,
						seg_len, is_root ? " (root)" : "");

				blocks_bytes += seg_len;
				if (seg_len < smallest_block) smallest_block = seg_len;
				if (seg_len > largest_block) largest_block = seg_len;

				if (is_root && !used)
					bad_root_block = 1;

				if (used) {
					used_blocks++;
					used_size += seg_len;

					/* Root block must be an nk-block. */
					if (is_root && (block->id[0] != 'n' || block->id[1] != 'k'))
						bad_root_block = 1;

					/* Note this blkoff is a valid address. */
					BITMAP_SET(h->bitmap, blkoff);
				}
			}
		}

		if (!seen_root_block) {
			hivex_printf("hivex: %s: no root block found\n", filename);
			hivex_errno = HIVEX_ENOTSUP;
			goto error;
		}

		if (bad_root_block) {
			hivex_printf("hivex: %s: bad root block (free or not nk)\n", filename);
			hivex_errno = HIVEX_ENOTSUP;
			goto error;
		}

		if (h->msglvl >= 1)
			hivex_printf(
				"hivex_open: successfully read Windows Registry hive file:\n"
				"  pages:          %zu [sml: %zu, lge: %zu]\n"
				"  blocks:         %zu [sml: %zu, avg: %zu, lge: %zu]\n"
				"  blocks used:    %zu\n"
				"  bytes used:     %zu\n",
				pages, smallest_page, largest_page,
				blocks, smallest_block, blocks_bytes / blocks, largest_block,
				used_blocks, used_size);

		return h;

	error:;
		int err = hivex_errno;
		if (h) {
			hivex_free(h->bitmap);
			if (h->addr && h->size && h->addr != NULL) {
				hivex_free(h->addr);
			}
			if (h->fd != 0)
				hivex_file_close(h->fd);
			hivex_free(h->filename);
			hivex_free(h);
		}
		hivex_errno = err;
		return NULL;
	}

	int
		hivex_close(hive_h *h)
	{
		int r;

		if (h->msglvl >= 1)
			hivex_printf("hivex_close\n");

		hivex_free(h->bitmap);
		hivex_free(h->addr);
		if (h->fd != 0)
			r = hivex_file_close(h->fd);
		else
			r = 0;
		hivex_free(h->filename);
		hivex_free(h);

		return r;
	}

	/*----------------------------------------------------------------------
	* Reading.
	*/

	hive_node_h
		hivex_root(hive_h *h)
	{
		hive_node_h ret = h->rootoffs;
		if (!IS_VALID_BLOCK(h, ret)) {
			hivex_errno = HIVEX_ENOKEY;
			return 0;
		}
		return ret;
	}

	hivex_size_t
		hivex_node_struct_length(hive_h *h, hive_node_h node)
	{
		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);
		hivex_size_t name_len = le16toh(nk->name_len);
		/* -1 to avoid double-counting the first name character */
		hivex_size_t ret = name_len + sizeof(struct ntreg_nk_record) - 1;
		int used;
		hivex_size_t seg_len = block_len(h, node, &used);
		if (ret > seg_len) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_struct_length: returning HIVEX_EFAULT because"
					" node name is too long (%zu, %zu)\n", name_len, seg_len);
			hivex_errno = HIVEX_EFAULT;
			return 0;
		}
		return ret;
	}

	char *
		hivex_node_name(hive_h *h, hive_node_h node)
	{
		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return NULL;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		/* AFAIK the node name is always plain ASCII, so no conversion
		* to UTF-8 is necessary.  However we do need to nul-terminate
		* the string.
		*/

		/* nk->name_len is unsigned, 16 bit, so this is safe ...  However
		* we have to make sure the length doesn't exceed the block length.
		*/
		hivex_size_t len = le16toh(nk->name_len);
		hivex_size_t seg_len = block_len(h, node, NULL);
		if (sizeof(struct ntreg_nk_record) + len - 1 > seg_len) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_name: returning HIVEX_EFAULT because node name"
					" is too long (%zu, %zu)\n",
					len, seg_len);
			hivex_errno = HIVEX_EFAULT;
			return NULL;
		}

		char *ret = (char*)hivex_malloc(len + 1);
		if (ret == NULL)
			return NULL;
		hivex_memcpy(ret, nk->name, len);
		ret[len] = '\0';
		return ret;
	}

	static hivex_int64_t
		timestamp_check(hive_h *h, hive_node_h node, hivex_int64_t timestamp)
	{
		if (timestamp < 0) {
			if (h->msglvl >= 2)
				hivex_printf("hivex: timestamp_check: "
					"negative time reported at %zu: %" PRIi64 "\n",
					node, timestamp);
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		return timestamp;
	}

	hivex_int64_t
		hivex_last_modified(hive_h *h)
	{
		return timestamp_check(h, 0, h->last_modified);
	}

	hivex_int64_t
		hivex_node_timestamp(hive_h *h, hive_node_h node)
	{
		hivex_int64_t ret;

		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		ret = le64toh(nk->timestamp);
		return timestamp_check(h, node, ret);
	}

#if 0
	/* I think the documentation for the sk and classname fields in the nk
	* record is wrong, or else the offset field is in the wrong place.
	* Otherwise this makes no sense.  Disabled this for now -- it's not
	* useful for reading the registry anyway.
	*/

	hive_security_h
		hivex_node_security(hive_h *h, hive_node_h node)
	{
		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		hive_node_h ret = le32toh(nk->sk);
		ret += 0x1000;
		if (!IS_VALID_BLOCK(h, ret)) {
			hivex_errno = HIVEX_EFAULT;
			return 0;
		}
		return ret;
	}

	hive_classname_h
		hivex_node_classname(hive_h *h, hive_node_h node)
	{
		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		hive_node_h ret = le32toh(nk->classname);
		ret += 0x1000;
		if (!IS_VALID_BLOCK(h, ret)) {
			hivex_errno = HIVEX_EFAULT;
			return 0;
		}
		return ret;
	}
#endif

	/* Structure for returning 0-terminated lists of offsets (nodes,
	* values, etc).
	*/
	struct offset_list {
		hivex_size_t *offsets;
		hivex_size_t len;
		hivex_size_t alloc;
	};

	static void
		init_offset_list(struct offset_list *list)
	{
		list->len = 0;
		list->alloc = 0;
		list->offsets = NULL;
	}

#define INIT_OFFSET_LIST(name) \
  struct offset_list name; \
  init_offset_list (&name)

	/* Preallocates the offset_list, but doesn't make the contents longer. */
	static int
		grow_offset_list(struct offset_list *list, hivex_size_t alloc)
	{
		hivex_assert(alloc >= list->len);
		hivex_size_t *p = (hivex_size_t *)hivex_realloc(list->offsets, alloc * sizeof(hivex_size_t));
		if (p == NULL)
			return -1;
		list->offsets = p;
		list->alloc = alloc;
		return 0;
	}

	static int
		add_to_offset_list(struct offset_list *list, hivex_size_t offset)
	{
		if (list->len >= list->alloc) {
			if (grow_offset_list(list, list->alloc ? list->alloc * 2 : 4) == -1)
				return -1;
		}
		list->offsets[list->len] = offset;
		list->len++;
		return 0;
	}

	static void
		free_offset_list(struct offset_list *list)
	{
		hivex_free(list->offsets);
	}

	static hivex_size_t *
		return_offset_list(struct offset_list *list)
	{
		if (add_to_offset_list(list, 0) == -1)
			return NULL;
		return list->offsets;         /* caller frees */
	}

	/* Iterate over children, returning child nodes and intermediate blocks. */
#define GET_CHILDREN_NO_CHECK_NK 1

	static int
		get_children(hive_h *h, hive_node_h node,
			hive_node_h **children_ret, hivex_size_t **blocks_ret,
			int flags)
	{
		struct ntreg_hbin_block* block = 0;
		hivex_size_t subkey_lf = 0;

		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		hivex_size_t nr_subkeys_in_nk = le32toh(nk->nr_subkeys);

		INIT_OFFSET_LIST(children);
		INIT_OFFSET_LIST(blocks);

		/* Deal with the common "no subkeys" case quickly. */
		if (nr_subkeys_in_nk == 0)
			goto ok;

		/* Arbitrarily limit the number of subkeys we will ever deal with. */
		if (nr_subkeys_in_nk > HIVEX_MAX_SUBKEYS) {
			if (h->msglvl >= 2)
				hivex_printf("hivex: get_children: returning HIVEX_ERANGE because "
					"nr_subkeys_in_nk > HIVEX_MAX_SUBKEYS (%zu > %d)\n",
					nr_subkeys_in_nk, HIVEX_MAX_SUBKEYS);
			hivex_errno = HIVEX_ERANGE;
			goto error;
		}

		/* Preallocate space for the children. */
		if (grow_offset_list(&children, nr_subkeys_in_nk) == -1)
			goto error;

		/* The subkey_lf field can point either to an lf-record, which is
		* the common case, or if there are lots of subkeys, to an
		* ri-record.
		*/
		subkey_lf = le32toh(nk->subkey_lf);
		subkey_lf += 0x1000;
		if (!IS_VALID_BLOCK(h, subkey_lf)) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_children: returning HIVEX_EFAULT"
					" because subkey_lf is not a valid block (0x%zx)\n",
					subkey_lf);
			hivex_errno = HIVEX_EFAULT;
			goto error;
		}

		if (add_to_offset_list(&blocks, subkey_lf) == -1)
			goto error;

		block =
			(struct ntreg_hbin_block *) (h->addr + subkey_lf);

		/* Points to lf-record?  (Note, also "lh" but that is basically the
		* same as "lf" as far as we are concerned here).
		*/
		if (block->id[0] == 'l' && (block->id[1] == 'f' || block->id[1] == 'h')) {
			struct ntreg_lf_record *lf = (struct ntreg_lf_record *) block;

			/* Check number of subkeys in the nk-record matches number of subkeys
			* in the lf-record.
			*/
			hivex_size_t nr_subkeys_in_lf = le16toh(lf->nr_keys);

			if (h->msglvl >= 2)
				hivex_printf("hivex_node_children: nr_subkeys_in_nk = %zu,"
					" nr_subkeys_in_lf = %zu\n",
					nr_subkeys_in_nk, nr_subkeys_in_lf);

			if (nr_subkeys_in_nk != nr_subkeys_in_lf) {
				hivex_errno = HIVEX_ENOTSUP;
				goto error;
			}

			hivex_size_t len = block_len(h, subkey_lf, NULL);
			if (8 + nr_subkeys_in_lf * 8 > len) {
				if (h->msglvl >= 2)
					hivex_printf("hivex_node_children: returning HIVEX_EFAULT"
						" because too many subkeys (%zu, %zu)\n",
						nr_subkeys_in_lf, len);
				hivex_errno = HIVEX_EFAULT;
				goto error;
			}

			hivex_size_t i;
			for (i = 0; i < nr_subkeys_in_lf; ++i) {
				hive_node_h subkey = le32toh(lf->keys[i].offset);
				subkey += 0x1000;
				if (!(flags & GET_CHILDREN_NO_CHECK_NK)) {
					if (!IS_VALID_BLOCK(h, subkey)) {
						if (h->msglvl >= 2)
							hivex_printf("hivex_node_children: returning HIVEX_EFAULT"
								" because subkey is not a valid block (0x%zx)\n",
								subkey);
						hivex_errno = HIVEX_EFAULT;
						goto error;
					}
				}
				if (add_to_offset_list(&children, subkey) == -1)
					goto error;
			}
			goto ok;
		}
		/* Points to ri-record? */
		else if (block->id[0] == 'r' && block->id[1] == 'i') {
			struct ntreg_ri_record *ri = (struct ntreg_ri_record *) block;

			hivex_size_t nr_offsets = le16toh(ri->nr_offsets);

			/* Count total number of children. */
			hivex_size_t i, count = 0;
			for (i = 0; i < nr_offsets; ++i) {
				hive_node_h offset = le32toh(ri->offset[i]);
				offset += 0x1000;
				if (!IS_VALID_BLOCK(h, offset)) {
					if (h->msglvl >= 2)
						hivex_printf("hivex_node_children: returning HIVEX_EFAULT"
							" because ri-offset is not a valid block (0x%zx)\n",
							offset);
					hivex_errno = HIVEX_EFAULT;
					goto error;
				}
				if (!BLOCK_ID_EQ(h, offset, "lf") && !BLOCK_ID_EQ(h, offset, "lh")) {
					if (h->msglvl >= 2)
						hivex_printf("get_children: returning HIVEX_ENOTSUP"
							" because ri-record offset does not point to lf/lh (0x%zx)\n",
							offset);
					hivex_errno = HIVEX_ENOTSUP;
					goto error;
				}

				if (add_to_offset_list(&blocks, offset) == -1)
					goto error;

				struct ntreg_lf_record *lf =
					(struct ntreg_lf_record *) (h->addr + offset);

				count += le16toh(lf->nr_keys);
			}

			if (h->msglvl >= 2)
				hivex_printf("hivex_node_children: nr_subkeys_in_nk = %zu,"
					" counted = %zu\n",
					nr_subkeys_in_nk, count);

			if (nr_subkeys_in_nk != count) {
				hivex_errno = HIVEX_ENOTSUP;
				goto error;
			}

			/* Copy list of children.  Note nr_subkeys_in_nk is limited to
			* something reasonable above.
			*/
			for (i = 0; i < nr_offsets; ++i) {
				hive_node_h offset = le32toh(ri->offset[i]);
				offset += 0x1000;
				if (!IS_VALID_BLOCK(h, offset)) {
					if (h->msglvl >= 2)
						hivex_printf("hivex_node_children: returning HIVEX_EFAULT"
							" because ri-offset is not a valid block (0x%zx)\n",
							offset);
					hivex_errno = HIVEX_EFAULT;
					goto error;
				}
				if (!BLOCK_ID_EQ(h, offset, "lf") && !BLOCK_ID_EQ(h, offset, "lh")) {
					if (h->msglvl >= 2)
						hivex_printf("get_children: returning HIVEX_ENOTSUP"
							" because ri-record offset does not point to lf/lh (0x%zx)\n",
							offset);
					hivex_errno = HIVEX_ENOTSUP;
					goto error;
				}

				struct ntreg_lf_record *lf =
					(struct ntreg_lf_record *) (h->addr + offset);

				hivex_size_t j;
				for (j = 0; j < le16toh(lf->nr_keys); ++j) {
					hive_node_h subkey = le32toh(lf->keys[j].offset);
					subkey += 0x1000;
					if (!(flags & GET_CHILDREN_NO_CHECK_NK)) {
						if (!IS_VALID_BLOCK(h, subkey)) {
							if (h->msglvl >= 2)
								hivex_printf("hivex_node_children: returning HIVEX_EFAULT"
									" because indirect subkey is not a valid block (0x%zx)\n",
									subkey);
							hivex_errno = HIVEX_EFAULT;
							goto error;
						}
					}
					if (add_to_offset_list(&children, subkey) == -1)
						goto error;
				}
			}
			goto ok;
		}
		/* else not supported, set hivex_errno and fall through */
		if (h->msglvl >= 2)
			hivex_printf("get_children: returning HIVEX_ENOTSUP"
				" because subkey block is not lf/lh/ri (0x%zx, %d, %d)\n",
				subkey_lf, block->id[0], block->id[1]);
		hivex_errno = HIVEX_ENOTSUP;
	error:
		free_offset_list(&children);
		free_offset_list(&blocks);
		return -1;

	ok:
		*children_ret = return_offset_list(&children);
		*blocks_ret = return_offset_list(&blocks);
		if (!*children_ret || !*blocks_ret)
			goto error;
		return 0;
	}

	hive_node_h *
		hivex_node_children(hive_h *h, hive_node_h node)
	{
		hive_node_h *children;
		hivex_size_t *blocks;

		if (get_children(h, node, &children, &blocks, 0) == -1)
			return NULL;

		hivex_free(blocks);
		return children;
	}

	/* Very inefficient, but at least having a separate API call
	* allows us to make it more efficient in future.
	*/
	hive_node_h
		hivex_node_get_child(hive_h *h, hive_node_h node, const char *nname)
	{
		hive_node_h *children = NULL;
		char *name = NULL;
		hive_node_h ret = 0;

		children = hivex_node_children(h, node);
		if (!children) goto error;

		hivex_size_t i;
		for (i = 0; children[i] != 0; ++i) {
			name = hivex_node_name(h, children[i]);
			if (!name) goto error;
			if (STRCASEEQ(name, nname)) {
				ret = children[i];
				break;
			}
			hivex_free(name); name = NULL;
		}

	error:
		hivex_free(children);
		hivex_free(name);
		return ret;
	}

	hive_node_h
		hivex_node_parent(hive_h *h, hive_node_h node)
	{
		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		hive_node_h ret = le32toh(nk->parent);
		ret += 0x1000;
		if (!IS_VALID_BLOCK(h, ret)) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_parent: returning HIVEX_EFAULT"
					" because parent is not a valid block (0x%zx)\n",
					ret);
			hivex_errno = HIVEX_EFAULT;
			return 0;
		}
		return ret;
	}

	static int
		get_values(hive_h *h, hive_node_h node,
			hive_value_h **values_ret, hivex_size_t **blocks_ret)
	{
		hivex_size_t len = 0;
		struct ntreg_value_list* vlist = 0;
		hivex_size_t vlist_offset = 0;

		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		hivex_size_t nr_values = le32toh(nk->nr_values);

		if (h->msglvl >= 2)
			hivex_printf("hivex_node_values: nr_values = %zu\n", nr_values);

		INIT_OFFSET_LIST(values);
		INIT_OFFSET_LIST(blocks);

		/* Deal with the common "no values" case quickly. */
		if (nr_values == 0)
			goto ok;

		/* Arbitrarily limit the number of values we will ever deal with. */
		if (nr_values > HIVEX_MAX_VALUES) {
			if (h->msglvl >= 2)
				hivex_printf("hivex: get_values: returning HIVEX_ERANGE"
					" because nr_values > HIVEX_MAX_VALUES (%zu > %d)\n",
					nr_values, HIVEX_MAX_VALUES);
			hivex_errno = HIVEX_ERANGE;
			goto error;
		}

		/* Preallocate space for the values. */
		if (grow_offset_list(&values, nr_values) == -1)
			goto error;

		/* Get the value list and check it looks reasonable. */
		vlist_offset = le32toh(nk->vallist);
		vlist_offset += 0x1000;
		if (!IS_VALID_BLOCK(h, vlist_offset)) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_values: returning HIVEX_EFAULT"
					" because value list is not a valid block (0x%zx)\n",
					vlist_offset);
			hivex_errno = HIVEX_EFAULT;
			goto error;
		}

		if (add_to_offset_list(&blocks, vlist_offset) == -1)
			goto error;

		vlist =
			(struct ntreg_value_list *) (h->addr + vlist_offset);

		len = block_len(h, vlist_offset, NULL);
		if (4 + nr_values * 4 > len) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_values: returning HIVEX_EFAULT"
					" because value list is too long (%zu, %zu)\n",
					nr_values, len);
			hivex_errno = HIVEX_EFAULT;
			goto error;
		}

		hivex_size_t i;
		for (i = 0; i < nr_values; ++i) {
			hive_node_h value = le32toh(vlist->offset[i]);
			value += 0x1000;
			if (!IS_VALID_BLOCK(h, value)) {
				if (h->msglvl >= 2)
					hivex_printf("hivex_node_values: returning HIVEX_EFAULT"
						" because value is not a valid block (0x%zx)\n",
						value);
				hivex_errno = HIVEX_EFAULT;
				goto error;
			}
			if (add_to_offset_list(&values, value) == -1)
				goto error;
		}

	ok:
		*values_ret = return_offset_list(&values);
		*blocks_ret = return_offset_list(&blocks);
		if (!*values_ret || !*blocks_ret)
			goto error;
		return 0;

	error:
		free_offset_list(&values);
		free_offset_list(&blocks);
		return -1;
	}

	hive_value_h *
		hivex_node_values(hive_h *h, hive_node_h node)
	{
		hive_value_h *values;
		hivex_size_t *blocks;

		if (get_values(h, node, &values, &blocks) == -1)
			return NULL;

		hivex_free(blocks);
		return values;
	}

	/* Very inefficient, but at least having a separate API call
	* allows us to make it more efficient in future.
	*/
	hive_value_h
		hivex_node_get_value(hive_h *h, hive_node_h node, const char *key)
	{
		hive_value_h *values = NULL;
		char *name = NULL;
		hive_value_h ret = 0;

		values = hivex_node_values(h, node);
		if (!values) goto error;

		hivex_size_t i;
		for (i = 0; values[i] != 0; ++i) {
			name = hivex_value_key(h, values[i]);
			if (!name) goto error;
			if (STRCASEEQ(name, key)) {
				ret = values[i];
				break;
			}
			hivex_free(name); name = NULL;
		}

	error:
		hivex_free(values);
		hivex_free(name);
		return ret;
	}

	hivex_size_t
		hivex_value_struct_length(hive_h *h, hive_value_h value)
	{
		hivex_size_t key_len;

		hivex_errno = 0;
		key_len = hivex_value_key_len(h, value);
		if (key_len == 0 && hivex_errno != 0)
			return 0;

		/* -1 to avoid double-counting the first name character */
		return key_len + sizeof(struct ntreg_vk_record) - 1;
	}

	hivex_size_t
		hivex_value_key_len(hive_h *h, hive_value_h value)
	{
		if (!IS_VALID_BLOCK(h, value) || !BLOCK_ID_EQ(h, value, "vk")) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		struct ntreg_vk_record *vk = (struct ntreg_vk_record *) (h->addr + value);

		/* vk->name_len is unsigned, 16 bit, so this is safe ...  However
		* we have to make sure the length doesn't exceed the block length.
		*/
		hivex_size_t ret = le16toh(vk->name_len);
		hivex_size_t seg_len = block_len(h, value, NULL);
		if (sizeof(struct ntreg_vk_record) + ret - 1 > seg_len) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_value_key_len: returning HIVEX_EFAULT"
					" because key length is too long (%zu, %zu)\n",
					ret, seg_len);
			hivex_errno = HIVEX_EFAULT;
			return 0;
		}
		return ret;
	}

	char *
		hivex_value_key(hive_h *h, hive_value_h value)
	{
		if (!IS_VALID_BLOCK(h, value) || !BLOCK_ID_EQ(h, value, "vk")) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		struct ntreg_vk_record *vk = (struct ntreg_vk_record *) (h->addr + value);

		/* AFAIK the key is always plain ASCII, so no conversion to UTF-8 is
		* necessary.  However we do need to nul-terminate the string.
		*/
		hivex_errno = 0;
		hivex_size_t len = hivex_value_key_len(h, value);
		if (len == 0 && hivex_errno != 0)
			return NULL;

		char *ret = (char*)hivex_malloc(len + 1);
		if (ret == NULL)
			return NULL;
		hivex_memcpy(ret, vk->name, len);
		ret[len] = '\0';
		return ret;
	}

	int
		hivex_value_type(hive_h *h, hive_value_h value, hive_type *t, hivex_size_t *len)
	{
		if (!IS_VALID_BLOCK(h, value) || !BLOCK_ID_EQ(h, value, "vk")) {
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		struct ntreg_vk_record *vk = (struct ntreg_vk_record *) (h->addr + value);

		if (t)
			*t = (hive_type)le32toh(vk->data_type);

		if (len) {
			*len = le32toh(vk->data_len);
			*len &= 0x7fffffff;         /* top bit indicates if data is stored inline */
		}

		return 0;
	}

	char *
		hivex_value_value(hive_h *h, hive_value_h value,
			hive_type *t_rtn, hivex_size_t *len_rtn)
	{
		if (!IS_VALID_BLOCK(h, value) || !BLOCK_ID_EQ(h, value, "vk")) {
			hivex_errno = HIVEX_EINVAL;
			return NULL;
		}

		struct ntreg_vk_record *vk = (struct ntreg_vk_record *) (h->addr + value);

		hive_type t;
		hivex_size_t len;
		int is_inline;

		t = (hive_type)le32toh(vk->data_type);

		len = le32toh(vk->data_len);
		is_inline = !!(len & 0x80000000);
		len &= 0x7fffffff;

		if (h->msglvl >= 2)
			hivex_printf("hivex_value_value: value=0x%zx, t=%d, len=%zu, inline=%d\n",
				value, t, len, is_inline);

		if (t_rtn)
			*t_rtn = t;
		if (len_rtn)
			*len_rtn = len;

		if (is_inline && len > 4) {
			hivex_errno = HIVEX_ENOTSUP;
			return NULL;
		}

		/* Arbitrarily limit the length that we will read. */
		if (len > HIVEX_MAX_VALUE_LEN) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_value_value: returning HIVEX_ERANGE because data "
					"length > HIVEX_MAX_VALUE_LEN (%zu > %d)\n",
					len, HIVEX_MAX_SUBKEYS);
			hivex_errno = HIVEX_ERANGE;
			return NULL;
		}

		char *ret = (char*)hivex_malloc(len);
		if (ret == NULL)
			return NULL;

		if (is_inline) {
			hivex_memcpy(ret, (char *)&vk->data_offset, len);
			return ret;
		}

		hivex_size_t data_offset = le32toh(vk->data_offset);
		data_offset += 0x1000;
		if (!IS_VALID_BLOCK(h, data_offset)) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_value_value: returning HIVEX_EFAULT because data "
					"offset is not a valid block (0x%zx)\n",
					data_offset);
			hivex_errno = HIVEX_EFAULT;
			hivex_free(ret);
			return NULL;
		}

		/* Check that the declared size isn't larger than the block its in.
		*
		* XXX Some apparently valid registries are seen to have this,
		* so turn this into a warning and substitute the smaller length
		* instead.
		*/
		hivex_size_t blen = block_len(h, data_offset, NULL);
		if (len > blen - 4 /* subtract 4 for block header */) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_value_value: warning: declared data length "
					"is longer than the block it is in "
					"(data 0x%zx, data len %zu, block len %zu)\n",
					data_offset, len, blen);
			len = blen - 4;

			/* Return the smaller length to the caller too. */
			if (len_rtn)
				*len_rtn = len;
		}

		char *data = h->addr + data_offset + 4;
		hivex_memcpy(ret, data, len);
		return ret;
	}

	size_t utf8len(char* s)
	{
		size_t len = 0;
		for (; *s; ++s) if ((*s & 0xC0) != 0x80) ++len;
		return len;
	}

	HIVEX_DEF char * hivex_utf16_to_utf8(const  hivex_uint16_t  *src, hivex_size_t len)
	{
		
		int minlen = utf16_string_len_in_bytes_max((char*)src, len);
		if (minlen == 0)
			return nullptr;
		
		char* retstr = (char*)hivex_malloc(minlen);
		hivex_size_t size = utf16_string_len((char*)src, len);
		char *dest = retstr;

		unsigned int c = 0;
		unsigned int offset;
		unsigned int u;
		unsigned int cpos = 0;
		
		while (c < size) {
			u = src[c];
			if (u < 0x80) {
				
				offset = 0;
				*dest++ = u;
			}
			else if (u < 0x800) {
				offset = 1;

				*dest++ = (((u >> 6) & 0x1f) | 0xc0);
				*dest++ = ((u & 0x3f) | 0x80);
			}
			else if (u < 0x10000) {
				
				offset = 2;
				if (dest >= retstr + minlen - offset -1) // resize
				{
					cpos = dest - retstr;
					minlen *= 2;
					retstr = (char*)hivex_realloc(retstr, minlen);
					if (retstr != nullptr)
						dest = &retstr[cpos];
				}
				*dest++ = (((u >> 12) & 0x0f) | 0xe0);
				*dest++ = (((u >> 6) & 0x3f) | 0x80);
				*dest++ = ((u & 0x3f) | 0x80);
			}
			else if (u < 0x200000) {
				
				offset = 3;
				if (dest >= retstr + minlen - offset - 1) // resize
				{
					cpos = dest - retstr;
					minlen *= 2;
					retstr = (char*)hivex_realloc(retstr, minlen);
					if(retstr != nullptr)
						dest = &retstr[cpos];
				}
				*dest++ = (((u >> 18) & 0x07) | 0xf0);
				*dest++ = (((u >> 12) & 0x3f) | 0x80);
				*dest++ = (((u >> 6) & 0x3f) | 0x80);
				*dest++ = ((u & 0x3f) | 0x80);
			}
			else if (u < 0x4000000) {
				/*<11111011> <00 0000 0000 0000 0000 0000 0000>*/
				offset = 4;
				if (dest >= retstr + minlen - offset - 1) // resize
				{
					cpos = dest - retstr;
					minlen *= 2;
					retstr = (char*)hivex_realloc(retstr, minlen);
					if (retstr != nullptr)
						dest = &retstr[cpos];
				}
				*dest++ = (((u >> 24) & 0x03) | 0xf8);
				*dest++ = (((u >> 18) & 0x3f) | 0x80);
				*dest++ = (((u >> 12) & 0x3f) | 0x80);
				*dest++ = (((u >> 6) & 0x3f) | 0x80);
				*dest++ = ((u & 0x3f) | 0x80);
			}
			else {
				/*<11111101> <0000 0000 0000 0000 0000 0000 0000 0000>*/
				offset = 5;
				*dest++ = (((u >> 30) & 0x01) | 0xfc);
				*dest++ = (((u >> 24) & 0x3f) | 0x80);
				*dest++ = (((u >> 18) & 0x3f) | 0x80);
				*dest++ = (((u >> 12) & 0x3f) | 0x80);
				*dest++ = (((u >> 6) & 0x3f) | 0x80);
				*dest++ = ((u & 0x3f) | 0x80);
			}
			c++;
		}
		*dest = 0;
		return retstr;
	}

	HIVEX_DEF char * hivex_value_string(hive_h *h, hive_value_h value)
	{
		hive_type t;
		hivex_size_t len;
		char *data = hivex_value_value(h, value, &t, &len);

		if (data == NULL)
			return NULL;

		if (t != hive_t_string && t != hive_t_expand_string && t != hive_t_link) {
			hivex_free(data);
			hivex_errno = HIVEX_EINVAL;
			return NULL;
		}

		/* Deal with the case where Windows has allocated a large buffer
		* full of random junk, and only the first few bytes of the buffer
		* contain a genuine UTF-16 string.
		*
		??? whatever
		* In this case, iconv would try to process the junk bytes as UTF-16
		* and inevitably find an illegal sequence (EILSEQ).  Instead, stop
		* after we find the first \0\0.
		*
		* (Found by Hilko Bengen in a fresh Windows XP SOFTWARE hive).
		*/
		hivex_size_t slen = utf16_string_len_in_bytes_max(data, len);
		if (slen < len)
			len = slen;

		char *ret = hivex_utf16_to_utf8((hivex_uint16_t*)data, len);
		hivex_free(data);
		if (ret == NULL)
			return NULL;

		return ret;
	}

	HIVEX_DEF void hivex_free_strings(char **pssv)
	{
		if (pssv) {
			hivex_size_t i;

			for (i = 0; pssv[i] != NULL; ++i)
				hivex_free(pssv[i]);
			hivex_free(pssv);
		}
	}

	/* Get the length of a UTF-16 format string.  Handle the string as
	* pairs of bytes, looking for the first \0\0 pair.  Only read up to
	* 'len' maximum bytes.
	*/


	HIVEX_DEF hivex_size_t utf16_string_len_in_bytes_max(const char *str, hivex_size_t len)
	{
		hivex_size_t ret = 0;

		while (len >= 2 && (str[0] || str[1])) {
			str += 2;
			ret += 2;
			len -= 2;
		}

		return ret;
	}
	HIVEX_DEF hivex_size_t utf16_string_len(const char *str, hivex_size_t len)
	{
		hivex_size_t ret = 0;

		while (len >= 2 && (str[0] || str[1])) {
			str += 2;
			ret += 1;
			len -= 2;
		}
		return ret;
	}


	/* http://blogs.msdn.com/oldnewthing/archive/2009/10/08/9904646.aspx */
	HIVEX_DEF char ** hivex_value_multiple_strings(hive_h *h, hive_value_h value)
	{
		hive_type t;
		hivex_size_t len;
		char *data = hivex_value_value(h, value, &t, &len);

		if (data == nullptr)
			return nullptr;

		if (t != hive_t_multiple_strings) {
			hivex_free(data);
			hivex_errno = HIVEX_EINVAL;
			return nullptr;
		}

		hivex_size_t nr_strings = 0;
		char **ret = (char**)hivex_malloc((1 + nr_strings) * sizeof(char *));
		if (ret == NULL) {
			hivex_free(data);
			return nullptr;
		}
		ret[0] = nullptr;

		char *p = data;
		hivex_size_t plen = 0;

		while (p < data + len && (plen = utf16_string_len_in_bytes_max(p, data + len - p)) > 0) 
			{
			nr_strings++;
			char **ret2 = (char**)hivex_realloc(ret, (1 + nr_strings) * sizeof(char *));
			if (ret2 == nullptr) {
				hivex_free_strings(ret);
				hivex_free(data);
				return nullptr;
			}
			ret = ret2;

			ret[nr_strings - 1] = hivex_utf16_to_utf8((hivex_uint16_t*)p, plen);
			ret[nr_strings] = nullptr;
			if (ret[nr_strings - 1] == nullptr) {
				hivex_free_strings(ret);
				hivex_free(data);
				return nullptr;
			}

			p += plen + 2 /* skip over UTF-16 \0\0 at the end of this string */;
		}

		hivex_free(data);
		return ret;
	}

	HIVEX_DEF hivex_int32_t hivex_value_dword(hive_h *h, hive_value_h value)
	{
		hive_type t;
		hivex_size_t len;
		char *data = hivex_value_value(h, value, &t, &len);

		if (data == NULL)
			return -1;

		if ((t != hive_t_dword && t != hive_t_dword_be) || len != 4) {
			hivex_free(data);
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		hivex_int32_t ret = *(hivex_int32_t*)data;
		hivex_free(data);
		if (t == hive_t_dword)        /* little endian */
			ret = le32toh(ret);
		else
			ret = be32toh(ret);

		return ret;
	}

	HIVEX_DEF hivex_int64_t hivex_value_qword(hive_h *h, hive_value_h value)
	{
		hive_type t;
		hivex_size_t len;
		char *data = hivex_value_value(h, value, &t, &len);

		if (data == NULL)
			return -1;

		if (t != hive_t_qword || len != 8) {
			hivex_free(data);
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		hivex_int64_t ret = *(hivex_int64_t*)data;
		hivex_free(data);
		ret = le64toh(ret);          /* always little endian */

		return ret;
	}

	/*----------------------------------------------------------------------
	* Visiting.
	*/

	int
		hivex_visit(hive_h *h, const struct hivex_visitor *visitor, hivex_size_t len,
			void *opaque, int flags)
	{
		return hivex_visit_node(h, hivex_root(h), visitor, len, opaque, flags);
	}

	static int hivex__visit_node(hive_h *h, hive_node_h node,
		const struct hivex_visitor *vtor,
		char *unvisited, void *opaque, int flags);

	int
		hivex_visit_node(hive_h *h, hive_node_h node,
			const struct hivex_visitor *visitor, hivex_size_t len, void *opaque,
			int flags)
	{
		struct hivex_visitor vtor;
		hivex_memset(&vtor, 0, sizeof vtor);

		/* Note that len might be larger *or smaller* than the expected size. */
		hivex_size_t copysize = len <= sizeof vtor ? len : sizeof vtor;
		hivex_memcpy(&vtor, visitor, copysize);

		/* This bitmap records unvisited nodes, so we don't loop if the
		* registry contains cycles.
		*/
		char *unvisited = (char*)hivex_malloc(1 + h->size / 32);
		if (unvisited == NULL)
			return -1;
		hivex_memcpy(unvisited, h->bitmap, 1 + h->size / 32);

		int r = hivex__visit_node(h, node, &vtor, unvisited, opaque, flags);
		hivex_free(unvisited);
		return r;
	}

	static int
		hivex__visit_node(hive_h *h, hive_node_h node,
			const struct hivex_visitor *vtor, char *unvisited,
			void *opaque, int flags)
	{
		int skip_bad = flags & HIVEX_VISIT_SKIP_BAD;
		char *name = NULL;
		hive_value_h *values = NULL;
		hive_node_h *children = NULL;
		char *key = NULL;
		char *str = NULL;
		char **strs = NULL;
		int i;

		/* Return -1 on all callback errors.  However on internal errors,
		* check if skip_bad is set and suppress those errors if so.
		*/
		int ret = -1;

		if (!BITMAP_TST(unvisited, node)) {
			if (h->msglvl >= 2)
				hivex_printf("hivex__visit_node: contains cycle:"
					" visited node 0x%zx already\n",
					node);

			hivex_errno = HIVEX_ELOOP;
			return skip_bad ? 0 : -1;
		}
		BITMAP_CLR(unvisited, node);

		name = hivex_node_name(h, node);
		if (!name) return skip_bad ? 0 : -1;
		if (vtor->node_start && vtor->node_start(h, opaque, node, name) == -1)
			goto error;

		values = hivex_node_values(h, node);
		if (!values) {
			ret = skip_bad ? 0 : -1;
			goto error;
		}

		for (i = 0; values[i] != 0; ++i) {
			hive_type t;
			hivex_size_t len;

			if (hivex_value_type(h, values[i], &t, &len) == -1) {
				ret = skip_bad ? 0 : -1;
				goto error;
			}

			key = hivex_value_key(h, values[i]);
			if (key == NULL) {
				ret = skip_bad ? 0 : -1;
				goto error;
			}

			if (vtor->value_any) {
				str = hivex_value_value(h, values[i], &t, &len);
				if (str == NULL) {
					ret = skip_bad ? 0 : -1;
					goto error;
				}
				if (vtor->value_any(h, opaque, node, values[i], t, len, key, str) == -1)
					goto error;
				hivex_free(str); str = NULL;
			}
			else {
				switch (t) {
				case hive_t_none:
					str = hivex_value_value(h, values[i], &t, &len);
					if (str == NULL) {
						ret = skip_bad ? 0 : -1;
						goto error;
					}
					if (t != hive_t_none) {
						ret = skip_bad ? 0 : -1;
						goto error;
					}
					if (vtor->value_none &&
						vtor->value_none(h, opaque, node, values[i], t, len, key, str) == -1)
						goto error;
					hivex_free(str); str = NULL;
					break;

				case hive_t_string:
				case hive_t_expand_string:
				case hive_t_link:
					str = hivex_value_string(h, values[i]);
					if (str == NULL) {
						if (hivex_errno != HIVEX_EINVAL) {
							ret = skip_bad ? 0 : -1;
							goto error;
						}
						if (vtor->value_string_invalid_utf16) {
							str = hivex_value_value(h, values[i], &t, &len);
							if (vtor->value_string_invalid_utf16(h, opaque, node, values[i],
								t, len, key, str) == -1)
								goto error;
							hivex_free(str); str = NULL;
						}
						break;
					}
					if (vtor->value_string &&
						vtor->value_string(h, opaque, node, values[i],
							t, len, key, str) == -1)
						goto error;
					hivex_free(str); str = NULL;
					break;

				case hive_t_dword:
				case hive_t_dword_be: {
					hivex_int32_t i32 = hivex_value_dword(h, values[i]);
					if (vtor->value_dword &&
						vtor->value_dword(h, opaque, node, values[i],
							t, len, key, i32) == -1)
						goto error;
					break;
				}

				case hive_t_qword: {
					hivex_int64_t i64 = hivex_value_qword(h, values[i]);
					if (vtor->value_qword &&
						vtor->value_qword(h, opaque, node, values[i],
							t, len, key, i64) == -1)
						goto error;
					break;
				}

				case hive_t_binary:
					str = hivex_value_value(h, values[i], &t, &len);
					if (str == NULL) {
						ret = skip_bad ? 0 : -1;
						goto error;
					}
					if (t != hive_t_binary) {
						ret = skip_bad ? 0 : -1;
						goto error;
					}
					if (vtor->value_binary &&
						vtor->value_binary(h, opaque, node, values[i],
							t, len, key, str) == -1)
						goto error;
					hivex_free(str); str = NULL;
					break;

				case hive_t_multiple_strings:
					strs = hivex_value_multiple_strings(h, values[i]);
					if (strs == NULL) {
						if (hivex_errno != HIVEX_EINVAL) {
							ret = skip_bad ? 0 : -1;
							goto error;
						}
						if (vtor->value_string_invalid_utf16) {
							str = hivex_value_value(h, values[i], &t, &len);
							if (vtor->value_string_invalid_utf16(h, opaque, node, values[i],
								t, len, key, str) == -1)
								goto error;
							hivex_free(str); str = NULL;
						}
						break;
					}
					if (vtor->value_multiple_strings &&
						vtor->value_multiple_strings(h, opaque, node, values[i],
							t, len, key, strs) == -1)
						goto error;
					hivex_free_strings(strs); strs = NULL;
					break;

				case hive_t_resource_list:
				case hive_t_full_resource_description:
				case hive_t_resource_requirements_list:
				default:
					str = hivex_value_value(h, values[i], &t, &len);
					if (str == NULL) {
						ret = skip_bad ? 0 : -1;
						goto error;
					}
					if (vtor->value_other &&
						vtor->value_other(h, opaque, node, values[i],
							t, len, key, str) == -1)
						goto error;
					hivex_free(str); str = NULL;
					break;
				}
			}

			hivex_free(key); key = NULL;
		}

		children = hivex_node_children(h, node);
		if (children == NULL) {
			ret = skip_bad ? 0 : -1;
			goto error;
		}

		for (i = 0; children[i] != 0; ++i) {
			if (h->msglvl >= 2)
				hivex_printf("hivex__visit_node: %s: visiting subkey %d (0x%zx)\n",
					name, i, children[i]);

			if (hivex__visit_node(h, children[i], vtor, unvisited, opaque, flags) == -1)
				goto error;
		}

		if (vtor->node_end && vtor->node_end(h, opaque, node, name) == -1)
			goto error;

		ret = 0;

	error:
		hivex_free(name);
		hivex_free(values);
		hivex_free(children);
		hivex_free(key);
		hivex_free(str);
		hivex_free_strings(strs);
		return ret;
	}

	/*----------------------------------------------------------------------
	* Writing.
	*/

	/* Allocate an hbin (page), extending the malloc'd space if necessary,
	* and updating the hive handle fields (but NOT the hive disk header
	* -- the hive disk header is updated when we commit).  This function
	* also extends the bitmap if necessary.
	*
	* 'allocation_hint' is the size of the block allocation we would like
	* to make.  Normally registry blocks are very small (avg 50 bytes)
	* and are contained in standard-sized pages (4KB), but the registry
	* can support blocks which are larger than a standard page, in which
	* case it creates a page of 8KB, 12KB etc.
	*
	* Returns:
	* > 0 : offset of first usable byte of new page (after page header)
	* 0   : error (hivex_errno set)
	*/
	static hivex_size_t
		allocate_page(hive_h *h, hivex_size_t allocation_hint)
	{
		/* In almost all cases this will be 1. */
		hivex_size_t nr_4k_pages =
			1 + (allocation_hint + sizeof(struct ntreg_hbin_page) - 1) / 4096;
		hivex_assert(nr_4k_pages >= 1);

		/* 'extend' is the number of bytes to extend the file by.  Note that
		* hives found in the wild often contain slack between 'endpages'
		* and the actual end of the file, so we don't always need to make
		* the file larger.
		*/
		hivex_ssize_t extend = h->endpages + nr_4k_pages * 4096 - h->size;

		if (h->msglvl >= 2) {
			hivex_printf("allocate_page: current endpages = 0x%zx,"
				" current size = 0x%zx\n",
				h->endpages, h->size);
			hivex_printf("allocate_page: extending file by %zd bytes"
				" (<= 0 if no extension)\n",
				extend);
		}

		if (extend > 0) {
			hivex_size_t oldsize = h->size;
			hivex_size_t newsize = h->size + extend;
			char *newaddr = (char*)hivex_realloc(h->addr, newsize);
			if (newaddr == NULL)
				return 0;

			hivex_size_t oldbitmapsize = 1 + oldsize / 32;
			hivex_size_t newbitmapsize = 1 + newsize / 32;
			char *newbitmap = (char*)hivex_realloc(h->bitmap, newbitmapsize);
			if (newbitmap == NULL) {
				hivex_free(newaddr);
				return 0;
			}

			h->addr = newaddr;
			h->size = newsize;
			h->bitmap = newbitmap;

			hivex_memset(h->addr + oldsize, 0, newsize - oldsize);
			hivex_memset(h->bitmap + oldbitmapsize, 0, newbitmapsize - oldbitmapsize);
		}

		hivex_size_t offset = h->endpages;
		h->endpages += nr_4k_pages * 4096;

		if (h->msglvl >= 2)
			hivex_printf("allocate_page: new endpages = 0x%zx, new size = 0x%zx\n",
				h->endpages, h->size);

		/* Write the hbin header. */
		struct ntreg_hbin_page *page =
			(struct ntreg_hbin_page *) (h->addr + offset);
		page->magic[0] = 'h';
		page->magic[1] = 'b';
		page->magic[2] = 'i';
		page->magic[3] = 'n';
		page->offset_first = htole32(offset - 0x1000);
		page->page_size = htole32(nr_4k_pages * 4096);
		hivex_memset(page->unknown, 0, sizeof(page->unknown));

		if (h->msglvl >= 2)
			hivex_printf("allocate_page: new page at 0x%zx\n", offset);

		/* Offset of first usable byte after the header. */
		return offset + sizeof(struct ntreg_hbin_page);
	}

	/* Allocate a single block, first allocating an hbin (page) at the end
	* of the current file if necessary.  NB. To keep the implementation
	* simple and more likely to be correct, we do not reuse existing free
	* blocks.
	*
	* seg_len is the size of the block (this INCLUDES the block header).
	* The header of the block is initialized to -seg_len (negative to
	* indicate used).  id[2] is the block ID (type), eg. "nk" for nk-
	* record.  The block bitmap is updated to show this block as valid.
	* The rest of the contents of the block will be zero.
	*
	* **NB** Because allocate_block may reallocate the memory, all
	* pointers into the memory become potentially invalid.  I really
	* love writing in C, can't you tell?
	*
	* Returns:
	* > 0 : offset of new block
	* 0   : error (hivex_errno set)
	*/
	static hivex_size_t
		allocate_block(hive_h *h, hivex_size_t seg_len, const char id[2])
	{
		if (!h->writable) {
			hivex_errno = HIVEX_EROFS;
			return 0;
		}

		if (seg_len < 4) {
			/* The caller probably forgot to include the header.  Note that
			* value lists have no ID field, so seg_len == 4 would be possible
			* for them, albeit unusual.
			*/
			if (h->msglvl >= 2)
				hivex_printf("allocate_block: refusing too small allocation (%zu),"
					" returning HIVEX_ERANGE\n", seg_len);
			hivex_errno = HIVEX_ERANGE;
			return 0;
		}

		/* Refuse really large allocations. */
		if (seg_len > HIVEX_MAX_ALLOCATION) {
			if (h->msglvl >= 2)
				hivex_printf("allocate_block: refusing large allocation (%zu),"
					" returning HIVEX_ERANGE\n", seg_len);
			hivex_errno = HIVEX_ERANGE;
			return 0;
		}

		/* Round up allocation to multiple of 8 bytes.  All blocks must be
		* on an 8 byte boundary.
		*/
		seg_len = (seg_len + 7) & ~7;

		/* Allocate a new page if necessary. */
		if (h->endblocks == 0 || h->endblocks + seg_len > h->endpages) {
			hivex_size_t newendblocks = allocate_page(h, seg_len);
			if (newendblocks == 0)
				return 0;
			h->endblocks = newendblocks;
		}

		hivex_size_t offset = h->endblocks;

		if (h->msglvl >= 2)
			hivex_printf("allocate_block: new block at 0x%zx, size %zu\n",
				offset, seg_len);

		struct ntreg_hbin_block *blockhdr =
			(struct ntreg_hbin_block *) (h->addr + offset);

		hivex_memset(blockhdr, 0, seg_len);

		blockhdr->seg_len = htole32(-(hivex_int32_t)seg_len);
		if (id[0] && id[1] && seg_len >= sizeof(struct ntreg_hbin_block)) {
			blockhdr->id[0] = id[0];
			blockhdr->id[1] = id[1];
		}

		BITMAP_SET(h->bitmap, offset);

		h->endblocks += seg_len;

		/* If there is space after the last block in the last page, then we
		* have to put a dummy free block header here to mark the rest of
		* the page as free.
		*/
		hivex_ssize_t rem = h->endpages - h->endblocks;
		if (rem > 0) {
			if (h->msglvl >= 2)
				hivex_printf("allocate_block: marking remainder of page free"
					" starting at 0x%zx, size %zd\n", h->endblocks, rem);

			hivex_assert(rem >= 4);

			blockhdr = (struct ntreg_hbin_block *) (h->addr + h->endblocks);
			blockhdr->seg_len = htole32((hivex_int32_t)rem);
		}

		return offset;
	}

	/* 'offset' must point to a valid, used block.  This function marks
	* the block unused (by updating the seg_len field) and invalidates
	* the bitmap.  It does NOT do this recursively, so to avoid creating
	* unreachable used blocks, callers may have to recurse over the hive
	* structures.  Also callers must ensure there are no references to
	* this block from other parts of the hive.
	*/
	static void
		mark_block_unused(hive_h *h, hivex_size_t offset)
	{
		hivex_assert(h->writable);
		hivex_assert(IS_VALID_BLOCK(h, offset));

		if (h->msglvl >= 2)
			hivex_printf("mark_block_unused: marking 0x%zx unused\n", offset);

		struct ntreg_hbin_block *blockhdr =
			(struct ntreg_hbin_block *) (h->addr + offset);

		hivex_size_t seg_len = block_len(h, offset, NULL);
		blockhdr->seg_len = htole32(seg_len);

		BITMAP_CLR(h->bitmap, offset);
	}

	/* Delete all existing values at this node. */
	static int
		delete_values(hive_h *h, hive_node_h node)
	{
		hivex_assert(h->writable);

		hive_value_h *values;
		hivex_size_t *blocks;
		if (get_values(h, node, &values, &blocks) == -1)
			return -1;

		hivex_size_t i;
		for (i = 0; blocks[i] != 0; ++i)
			mark_block_unused(h, blocks[i]);

		hivex_free(blocks);

		for (i = 0; values[i] != 0; ++i) {
			struct ntreg_vk_record *vk =
				(struct ntreg_vk_record *) (h->addr + values[i]);

			hivex_size_t len;
			int is_inline;
			len = le32toh(vk->data_len);
			is_inline = !!(len & 0x80000000); /* top bit indicates is inline */
			len &= 0x7fffffff;

			if (!is_inline) {           /* non-inline, so remove data block */
				hivex_size_t data_offset = le32toh(vk->data_offset);
				data_offset += 0x1000;
				mark_block_unused(h, data_offset);
			}

			/* remove vk record */
			mark_block_unused(h, values[i]);
		}

		hivex_free(values);

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);
		nk->nr_values = htole32(0);
		nk->vallist = htole32(0xffffffff);

		return 0;
	}

	int
		hivex_commit(hive_h *h, const char *filename, int flags)
	{
		if (flags != 0) {
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		if (!h->writable) {
			hivex_errno = HIVEX_EROFS;
			return -1;
		}

		filename = filename ? "" : h->filename;
		hivex_file_t fd = hivex_file_open(filename);
		if (fd == 0)
			return -1;

		/* Update the header fields. */
		hivex_uint32_t sequence = le32toh(h->hdr->sequence1);
		sequence++;
		h->hdr->sequence1 = htole32(sequence);
		h->hdr->sequence2 = htole32(sequence);
		/* XXX Ought to update h->hdr->last_modified. */
		h->hdr->blocks = htole32(h->endpages - 0x1000);

		/* Recompute header checksum. */
		hivex_uint32_t sum = header_checksum(h);
		h->hdr->csum = htole32(sum);

		if (h->msglvl >= 2)
			hivex_printf("hivex_commit: new header checksum: 0x%x\n", sum);

		if (hivex_full_write(fd, h->addr, h->size) != h->size) {
			int err = hivex_errno;
			hivex_file_close(fd);
			hivex_errno = err;
			return -1;
		}

		hivex_file_close(fd);

		return 0;
	}

	inline int hivex_toupper(int c)
	{
		if (c >= 'a' && c <= 'z')
			return c - 'a' + 'A';

		return c;
	}
	/* Calculate the hash for a lf or lh record offset.
	*/
	static void
		calc_hash(const char *type, const char *name, char *ret)
	{
		hivex_size_t len = hivex_strlen(name);

		if (STRPREFIX(type, "lf"))
			/* Old-style, not used in current registries. */
			hivex_memcpy(ret, name, len < 4 ? len : 4);
		else {
			/* New-style for lh-records. */
			hivex_size_t i, c;
			hivex_uint32_t h = 0;
			for (i = 0; i < len; ++i) {
				c = hivex_toupper(name[i]);
				h *= 37;
				h += c;
			}
			*((hivex_uint32_t *)ret) = htole32(h);
		}
	}

	/* Create a completely new lh-record containing just the single node. */
	static hivex_size_t
		new_lh_record(hive_h *h, const char *name, hive_node_h node)
	{
		static const char id[2] = { 'l', 'h' };
		hivex_size_t seg_len = sizeof(struct ntreg_lf_record);
		hivex_size_t offset = allocate_block(h, seg_len, id);
		if (offset == 0)
			return 0;

		struct ntreg_lf_record *lh = (struct ntreg_lf_record *) (h->addr + offset);
		lh->nr_keys = htole16(1);
		lh->keys[0].offset = htole32(node - 0x1000);
		calc_hash("lh", name, lh->keys[0].hash);

		return offset;
	}

	/* Insert node into existing lf/lh-record at position.
	* This allocates a new record and marks the old one as unused.
	*/
	static hivex_size_t
		insert_lf_record(hive_h *h, hivex_size_t old_offs, hivex_size_t posn,
			const char *name, hive_node_h node)
	{
		hivex_assert(IS_VALID_BLOCK(h, old_offs));

		/* Work around C stupidity.
		* http://www.redhat.com/archives/libguestfs/2010-February/msg00056.html
		*/
		HIVEX_UNUSED int test = BLOCK_ID_EQ(h, old_offs, "lf") || BLOCK_ID_EQ(h, old_offs, "lh");
		hivex_assert(test);

		struct ntreg_lf_record *old_lf =
			(struct ntreg_lf_record *) (h->addr + old_offs);
		hivex_uint16_t nr_keys = le16toh(old_lf->nr_keys);

		nr_keys++; /* in new record ... */

		hivex_size_t seg_len = sizeof(struct ntreg_lf_record) + (nr_keys - 1) * 8;

		/* Copy the old_lf->id in case it moves during allocate_block. */
		char id[2];
		hivex_memcpy(id, old_lf->id, sizeof id);

		hivex_size_t new_offs = allocate_block(h, seg_len, id);
		if (new_offs == 0)
			return 0;

		/* old_lf could have been invalidated by allocate_block. */
		old_lf = (struct ntreg_lf_record *) (h->addr + old_offs);

		struct ntreg_lf_record *new_lf =
			(struct ntreg_lf_record *) (h->addr + new_offs);
		new_lf->nr_keys = htole16(nr_keys);

		/* Copy the keys until we reach posn, insert the new key there, then
		* copy the remaining keys.
		*/
		hivex_size_t i;
		for (i = 0; i < posn; ++i)
			new_lf->keys[i] = old_lf->keys[i];

		new_lf->keys[i].offset = htole32(node - 0x1000);
		calc_hash(new_lf->id, name, new_lf->keys[i].hash);

		for (i = posn + 1; i < nr_keys; ++i)
			new_lf->keys[i] = old_lf->keys[i - 1];

		/* Old block is unused, return new block. */
		mark_block_unused(h, old_offs);
		return new_offs;
	}

	/* Compare name with name in nk-record. */
	static int
		compare_name_with_nk_name(hive_h *h, const char *name, hive_node_h nk_offs)
	{
		hivex_assert(IS_VALID_BLOCK(h, nk_offs));
		hivex_assert(BLOCK_ID_EQ(h, nk_offs, "nk"));

		/* Name in nk is not necessarily nul-terminated. */
		char *nname = hivex_node_name(h, nk_offs);

		/* Unfortunately we don't have a way to return errors here. */
		if (!nname) {

#ifdef _WIN32
			perror("compare_name_with_nk_name");
#endif
			return 0;
		}

		int r = hivex_strcasecmp(name, nname);
		hivex_free(nname);

		return r;
	}

	hive_node_h
		hivex_node_add_child(hive_h *h, hive_node_h parent, const char *name)
	{
		if (!h->writable) {
			hivex_errno = HIVEX_EROFS;
			return 0;
		}

		if (!IS_VALID_BLOCK(h, parent) || !BLOCK_ID_EQ(h, parent, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		if (name == NULL || hivex_strlen(name) == 0) {
			hivex_errno = HIVEX_EINVAL;
			return 0;
		}

		if (hivex_node_get_child(h, parent, name) != 0) {
			hivex_errno = HIVEX_EEXIST;
			return 0;
		}

		/* Create the new nk-record. */
		static const char nk_id[2] = { 'n', 'k' };
		hivex_size_t seg_len = sizeof(struct ntreg_nk_record) + hivex_strlen(name);
		hive_node_h node = allocate_block(h, seg_len, nk_id);
		if (node == 0)
			return 0;

		if (h->msglvl >= 2)
			hivex_printf("hivex_node_add_child: allocated new nk-record"
				" for child at 0x%zx\n", node);

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);
		nk->flags = htole16(0x0020); /* key is ASCII. */
		nk->parent = htole32(parent - 0x1000);
		nk->subkey_lf = htole32(0xffffffff);
		nk->subkey_lf_volatile = htole32(0xffffffff);
		nk->vallist = htole32(0xffffffff);
		nk->classname = htole32(0xffffffff);
		nk->name_len = htole16((hivex_uint16_t)hivex_strlen(name));
		hivex_strcpy(nk->name, name);

		/* Inherit parent sk. */
		struct ntreg_nk_record *parent_nk =
			(struct ntreg_nk_record *) (h->addr + parent);
		hivex_size_t parent_sk_offset = le32toh(parent_nk->sk);
		parent_sk_offset += 0x1000;
		if (!IS_VALID_BLOCK(h, parent_sk_offset) ||
			!BLOCK_ID_EQ(h, parent_sk_offset, "sk")) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_add_child: returning HIVEX_EFAULT"
					" because parent sk is not a valid block (%zu)\n",
					parent_sk_offset);
			hivex_errno = HIVEX_EFAULT;
			return 0;
		}
		struct ntreg_sk_record *sk =
			(struct ntreg_sk_record *) (h->addr + parent_sk_offset);
		sk->refcount = htole32(le32toh(sk->refcount) + 1);
		nk->sk = htole32(parent_sk_offset - 0x1000);

		/* Inherit parent timestamp. */
		nk->timestamp = parent_nk->timestamp;

		/* What I found out the hard way (not documented anywhere): the
		* subkeys in lh-records must be kept sorted.  If you just add a
		* subkey in a non-sorted position (eg. just add it at the end) then
		* Windows won't see the subkey _and_ Windows will corrupt the hive
		* itself when it modifies or saves it.
		*
		* So use get_children() to get a list of intermediate
		* lf/lh-records.  get_children() returns these in reading order
		* (which is sorted), so we look for the lf/lh-records in sequence
		* until we find the key name just after the one we are inserting,
		* and we insert the subkey just before it.
		*
		* The only other case is the no-subkeys case, where we have to
		* create a brand new lh-record.
		*/
		hive_node_h *unused;
		hivex_size_t *blocks;

		if (get_children(h, parent, &unused, &blocks, 0) == -1)
			return 0;
		hivex_free(unused);

		hivex_size_t i, j;
		hivex_size_t nr_subkeys_in_parent_nk = le32toh(parent_nk->nr_subkeys);
		if (nr_subkeys_in_parent_nk == 0) { /* No subkeys case. */
											/* Free up any existing intermediate blocks. */
			for (i = 0; blocks[i] != 0; ++i)
				mark_block_unused(h, blocks[i]);
			hivex_size_t lh_offs = new_lh_record(h, name, node);
			if (lh_offs == 0) {
				hivex_free(blocks);
				return 0;
			}

			/* Recalculate pointers that could have been invalidated by
			* previous call to allocate_block (via new_lh_record).
			*/
			nk = (struct ntreg_nk_record *) (h->addr + node);
			parent_nk = (struct ntreg_nk_record *) (h->addr + parent);

			if (h->msglvl >= 2)
				hivex_printf("hivex_node_add_child: no keys, allocated new"
					" lh-record at 0x%zx\n", lh_offs);

			parent_nk->subkey_lf = htole32(lh_offs - 0x1000);
		}
		else {                        /* Insert subkeys case. */
			hivex_size_t old_offs = 0, new_offs = 0;
			struct ntreg_lf_record *old_lf = NULL;

			/* Find lf/lh key name just after the one we are inserting. */
			for (i = 0; blocks[i] != 0; ++i) {
				if (BLOCK_ID_EQ(h, blocks[i], "lf") ||
					BLOCK_ID_EQ(h, blocks[i], "lh")) {
					old_offs = blocks[i];
					old_lf = (struct ntreg_lf_record *) (h->addr + old_offs);
					for (j = 0; j < le16toh(old_lf->nr_keys); ++j) {
						hive_node_h nk_offs = le32toh(old_lf->keys[j].offset);
						nk_offs += 0x1000;
						if (compare_name_with_nk_name(h, name, nk_offs) < 0)
							goto insert_it;
					}
				}
			}

			/* Insert it at the end.
			* old_offs points to the last lf record, set j.
			*/
			hivex_assert(old_offs != 0);   /* should never happen if nr_subkeys > 0 */
			j = le16toh(old_lf->nr_keys);

			/* Insert it. */
		insert_it:
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_add_child: insert key in existing"
					" lh-record at 0x%zx, posn %zu\n", old_offs, j);

			new_offs = insert_lf_record(h, old_offs, j, name, node);
			if (new_offs == 0) {
				hivex_free(blocks);
				return 0;
			}

			/* Recalculate pointers that could have been invalidated by
			* previous call to allocate_block (via insert_lf_record).
			*/
			nk = (struct ntreg_nk_record *) (h->addr + node);
			parent_nk = (struct ntreg_nk_record *) (h->addr + parent);

			if (h->msglvl >= 2)
				hivex_printf("hivex_node_add_child: new lh-record at 0x%zx\n",
					new_offs);

			/* If the lf/lh-record was directly referenced by the parent nk,
			* then update the parent nk.
			*/
			if (le32toh(parent_nk->subkey_lf) + 0x1000 == old_offs)
				parent_nk->subkey_lf = htole32(new_offs - 0x1000);
			/* Else we have to look for the intermediate ri-record and update
			* that in-place.
			*/
			else {
				for (i = 0; blocks[i] != 0; ++i) {
					if (BLOCK_ID_EQ(h, blocks[i], "ri")) {
						struct ntreg_ri_record *ri =
							(struct ntreg_ri_record *) (h->addr + blocks[i]);
						for (j = 0; j < le16toh(ri->nr_offsets); ++j)
							if (le32toh(ri->offset[j] + 0x1000) == old_offs) {
								ri->offset[j] = htole32(new_offs - 0x1000);
								goto found_it;
							}
					}
				}

				/* Not found ..  This is an internal error. */
				if (h->msglvl >= 2)
					hivex_printf("hivex_node_add_child: returning HIVEX_ENOTSUP"
						" because could not find ri->lf link\n");
				hivex_errno = HIVEX_ENOTSUP;
				hivex_free(blocks);
				return 0;

			found_it:
				;
			}
		}

		hivex_free(blocks);

		/* Update nr_subkeys in parent nk. */
		nr_subkeys_in_parent_nk++;
		parent_nk->nr_subkeys = htole32(nr_subkeys_in_parent_nk);

		/* Update max_subkey_name_len in parent nk. */
		hivex_uint16_t max = le16toh(parent_nk->max_subkey_name_len);
		if (max < hivex_strlen(name) * 2)  /* *2 because "recoded" in UTF16-LE. */
			parent_nk->max_subkey_name_len = htole16((hivex_uint16_t)hivex_strlen(name) * 2);

		return node;
	}

	/* Decrement the refcount of an sk-record, and if it reaches zero,
	* unlink it from the chain and delete it.
	*/
	static int
		delete_sk(hive_h *h, hivex_size_t sk_offset)
	{
		if (!IS_VALID_BLOCK(h, sk_offset) || !BLOCK_ID_EQ(h, sk_offset, "sk")) {
			if (h->msglvl >= 2)
				hivex_printf("delete_sk: not an sk record: 0x%zx\n", sk_offset);
			hivex_errno = HIVEX_EFAULT;
			return -1;
		}

		struct ntreg_sk_record *sk = (struct ntreg_sk_record *) (h->addr + sk_offset);

		if (sk->refcount == 0) {
			if (h->msglvl >= 2)
				hivex_printf("delete_sk: sk record already has refcount 0: 0x%zx\n",
					sk_offset);
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		sk->refcount--;

		if (sk->refcount == 0) {
			hivex_size_t sk_prev_offset = sk->sk_prev;
			sk_prev_offset += 0x1000;

			hivex_size_t sk_next_offset = sk->sk_next;
			sk_next_offset += 0x1000;

			/* Update sk_prev/sk_next SKs, unless they both point back to this
			* cell in which case we are deleting the last SK.
			*/
			if (sk_prev_offset != sk_offset && sk_next_offset != sk_offset) {
				struct ntreg_sk_record *sk_prev =
					(struct ntreg_sk_record *) (h->addr + sk_prev_offset);
				struct ntreg_sk_record *sk_next =
					(struct ntreg_sk_record *) (h->addr + sk_next_offset);

				sk_prev->sk_next = htole32(sk_next_offset - 0x1000);
				sk_next->sk_prev = htole32(sk_prev_offset - 0x1000);
			}

			/* Refcount is zero so really delete this block. */
			mark_block_unused(h, sk_offset);
		}

		return 0;
	}

	/* Callback from hivex_node_delete_child which is called to delete a
	* node AFTER its subnodes have been visited.  The subnodes have been
	* deleted but we still have to delete any lf/lh/li/ri records and the
	* value list block and values, followed by deleting the node itself.
	*/
	static int
		delete_node(hive_h *h, HIVEX_UNUSED void *opaque, hive_node_h node, HIVEX_UNUSED const char *name)
	{
		/* Get the intermediate blocks.  The subkeys have already been
		* deleted by this point, so tell get_children() not to check for
		* validity of the nk-records.
		*/
		hive_node_h *unused;
		hivex_size_t *blocks;
		if (get_children(h, node, &unused, &blocks, GET_CHILDREN_NO_CHECK_NK) == -1)
			return -1;
		hivex_free(unused);

		/* We don't care what's in these intermediate blocks, so we can just
		* delete them unconditionally.
		*/
		hivex_size_t i;
		for (i = 0; blocks[i] != 0; ++i)
			mark_block_unused(h, blocks[i]);

		hivex_free(blocks);

		/* Delete the values in the node. */
		if (delete_values(h, node) == -1)
			return -1;

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

		/* If the NK references an SK, delete it. */
		hivex_size_t sk_offs = le32toh(nk->sk);
		if (sk_offs != 0xffffffff) {
			sk_offs += 0x1000;
			if (delete_sk(h, sk_offs) == -1)
				return -1;
			nk->sk = htole32(0xffffffff);
		}

		/* If the NK references a classname, delete it. */
		hivex_size_t cl_offs = le32toh(nk->classname);
		if (cl_offs != 0xffffffff) {
			cl_offs += 0x1000;
			mark_block_unused(h, cl_offs);
			nk->classname = htole32(0xffffffff);
		}

		/* Delete the node itself. */
		mark_block_unused(h, node);

		return 0;
	}

	int
		hivex_node_delete_child(hive_h *h, hive_node_h node)
	{
		if (!h->writable) {
			hivex_errno = HIVEX_EROFS;
			return -1;
		}

		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		if (node == hivex_root(h)) {
			if (h->msglvl >= 2)
				hivex_printf("hivex_node_delete_child: cannot delete root node\n");
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		hive_node_h parent = hivex_node_parent(h, node);
		if (parent == 0)
			return -1;

		/* Delete node and all its children and values recursively. */
		//static const struct hivex_visitor visitor = { .node_end = delete_node };
		static struct hivex_visitor visitor; visitor.node_end = delete_node;
		if (hivex_visit_node(h, node, &visitor, sizeof visitor, NULL, 0) == -1)
			return -1;

		/* Delete the link from parent to child.  We need to find the lf/lh
		* record which contains the offset and remove the offset from that
		* record, then decrement the element count in that record, and
		* decrement the overall number of subkeys stored in the parent
		* node.
		*/
		hive_node_h *unused;
		hivex_size_t *blocks;
		if (get_children(h, parent, &unused, &blocks, GET_CHILDREN_NO_CHECK_NK) == -1)
			return -1;

		hivex_free(unused);

		hivex_uint16_t i, j;
		for (i = 0; blocks[i] != 0; ++i) {
			struct ntreg_hbin_block *block =
				(struct ntreg_hbin_block *) (h->addr + blocks[i]);

			if (block->id[0] == 'l' && (block->id[1] == 'f' || block->id[1] == 'h')) {
				struct ntreg_lf_record *lf = (struct ntreg_lf_record *) block;

				hivex_uint16_t nr_subkeys_in_lf = le16toh(lf->nr_keys);

				for (j = 0; j < nr_subkeys_in_lf; ++j)
					if (le32toh(lf->keys[j].offset) + 0x1000 == node) {
						for (; j < nr_subkeys_in_lf - 1; ++j)
							hivex_memcpy(&lf->keys[j], &lf->keys[j + 1], sizeof(lf->keys[j]));
						lf->nr_keys = htole16(nr_subkeys_in_lf - 1);
						goto found;
					}
			}
		}
		if (h->msglvl >= 2)
			hivex_printf("hivex_node_delete_child: could not find parent"
				" to child link\n");
		hivex_errno = HIVEX_ENOTSUP;
		return -1;

	found:;
		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + parent);
		hivex_size_t nr_subkeys_in_nk = le32toh(nk->nr_subkeys);
		nk->nr_subkeys = htole32(nr_subkeys_in_nk - 1);

		if (h->msglvl >= 2)
			hivex_printf("hivex_node_delete_child: updating nr_subkeys"
				" in parent 0x%zx to %zu\n", parent, nr_subkeys_in_nk);

		return 0;
	}

	int
		hivex_node_set_values(hive_h *h, hive_node_h node,
			hivex_size_t nr_values, const hive_set_value *values,
			HIVEX_UNUSED int flags)
	{
		if (!h->writable) {
			hivex_errno = HIVEX_EROFS;
			return -1;
		}

		if (!IS_VALID_BLOCK(h, node) || !BLOCK_ID_EQ(h, node, "nk")) {
			hivex_errno = HIVEX_EINVAL;
			return -1;
		}

		/* Delete all existing values. */
		if (delete_values(h, node) == -1)
			return -1;

		if (nr_values == 0)
			return 0;

		/* Allocate value list node.  Value lists have no id field. */
		static const char nul_id[2] = { 0, 0 };
		hivex_size_t seg_len =
			sizeof(struct ntreg_value_list) + (nr_values - 1) * sizeof(hivex_uint32_t);
		hivex_size_t vallist_offs = allocate_block(h, seg_len, nul_id);
		if (vallist_offs == 0)
			return -1;

		struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);
		nk->nr_values = htole32(nr_values);
		nk->vallist = htole32(vallist_offs - 0x1000);

		struct ntreg_value_list *vallist =
			(struct ntreg_value_list *) (h->addr + vallist_offs);

		hivex_size_t i;
		for (i = 0; i < nr_values; ++i) {
			/* Allocate vk record to store this (key, value) pair. */
			static const char vk_id[2] = { 'v', 'k' };
			seg_len = sizeof(struct ntreg_vk_record) + hivex_strlen(values[i].key);
			hivex_size_t vk_offs = allocate_block(h, seg_len, vk_id);
			if (vk_offs == 0)
				return -1;

			/* Recalculate pointers that could have been invalidated by
			* previous call to allocate_block.
			*/
			nk = (struct ntreg_nk_record *) (h->addr + node);
			vallist = (struct ntreg_value_list *) (h->addr + vallist_offs);

			vallist->offset[i] = htole32(vk_offs - 0x1000);

			struct ntreg_vk_record *vk = (struct ntreg_vk_record *) (h->addr + vk_offs);
			hivex_uint16_t name_len = (hivex_uint16_t)hivex_strlen(values[i].key);
			vk->name_len = htole16(name_len);
			hivex_strcpy(vk->name, values[i].key);
			vk->data_type = htole32(values[i].t);
			hivex_uint32_t len = values[i].len;
			if (len <= 4)               /* store it inline => set MSB flag */
				len |= 0x80000000;
			vk->data_len = htole32(len);
			vk->flags = name_len == 0 ? 0 : 1;

			if (values[i].len <= 4)     /* store it inline */
				hivex_memcpy(&vk->data_offset, values[i].value, values[i].len);
			else {
				hivex_size_t offs = allocate_block(h, values[i].len + 4, nul_id);
				if (offs == 0)
					return -1;

				/* Recalculate pointers that could have been invalidated by
				* previous call to allocate_block.
				*/
				nk = (struct ntreg_nk_record *) (h->addr + node);
				vallist = (struct ntreg_value_list *) (h->addr + vallist_offs);
				vk = (struct ntreg_vk_record *) (h->addr + vk_offs);

				hivex_memcpy(h->addr + offs + 4, values[i].value, values[i].len);
				vk->data_offset = htole32(offs - 0x1000);
			}

			if (((hivex_uint32_t)name_len * 2) > le32toh(nk->max_vk_name_len))
				/* * 2 for UTF16-LE "reencoding" */
				nk->max_vk_name_len = htole32(name_len * 2);
			if (values[i].len > le32toh(nk->max_vk_data_len))
				nk->max_vk_data_len = htole32(values[i].len);
		}

		return 0;
	}

	int
		hivex_node_set_value(hive_h *h, hive_node_h node,
			const hive_set_value *val, HIVEX_UNUSED int flags)
	{
		int i = 0;
		int alloc_ct = 0;
		int idx_of_val = -1;
		hive_set_value* value = 0;

		hive_value_h *prev_values = hivex_node_values(h, node);
		if (prev_values == NULL)
			return -1;

		int retval = -1;

		hivex_size_t nr_values = 0;
		hive_value_h *itr = 0;
		for (itr = prev_values; *itr != 0; ++itr)
			++nr_values;

		hive_set_value *values = (hive_set_value *)hivex_malloc((nr_values + 1) * (sizeof(hive_set_value)));
		if (values == NULL)
			goto leave_prev_values;

		
		hive_value_h *prev_val;
		for (prev_val = prev_values; *prev_val != 0; ++prev_val) {
			hivex_size_t len;
			hive_type t;

			hive_set_value *value = &values[prev_val - prev_values];

			char *valval = hivex_value_value(h, *prev_val, &t, &len);
			if (valval == NULL) goto leave_partial;

			++alloc_ct;
			value->value = valval;
			value->t = t;
			value->len = len;

			char *valkey = hivex_value_key(h, *prev_val);
			if (valkey == NULL) goto leave_partial;

			++alloc_ct;
			value->key = valkey;

			if (STRCASEEQ(valkey, val->key))
				idx_of_val = prev_val - prev_values;
		}

		if (idx_of_val > -1) {
			hivex_free(values[idx_of_val].key);
			hivex_free(values[idx_of_val].value);
		}
		else {
			idx_of_val = nr_values;
			++nr_values;
		}

		value = &values[idx_of_val];

		value->key = hivex_strdup(val->key);
		value->value = (char*)hivex_malloc(val->len);
		value->len = val->len;
		value->t = val->t;

		if (value->key == NULL || value->value == NULL) goto leave_partial;
		hivex_memcpy(value->value, val->value, val->len);

		retval = hivex_node_set_values(h, node, nr_values, values, 0);
		
	leave_partial:
		for (i = 0; i < alloc_ct; i += 2) {
			hivex_free(values[i / 2].value);
			if (i + 1 < alloc_ct && values[i / 2].key != NULL)
				hivex_free(values[i / 2].key);
		}
		hivex_free(values);

	leave_prev_values:
		hivex_free(prev_values);
		return retval;
	}

#ifdef __cplusplus
}
#endif

#endif /* HIVEX_H_ */
