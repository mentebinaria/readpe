/* ssdeep
 * Copyright (C) 2002 Andrew Tridgell <tridge@samba.org>
 * Copyright (C) 2006 ManTech International Corporation
 * Copyright (C) 2013 Helmut Grohne <helmut@subdivi.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Earlier versions of this code were named fuzzy.c and can be found at:
 *     http://www.samba.org/ftp/unpacked/junkcode/spamsum/
 *     http://ssdeep.sf.net/
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include "fuzzy.h"
#include "pe.h"


#if defined(__GNUC__) && __GNUC__ >= 3
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x) x
#define unlikely(x) x
#endif

#define MAX_FUNCTION_NAME 512
#define MAX_DLL_NAME 256

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#define ROLLING_WINDOW 7
#define MIN_BLOCKSIZE 3
#define HASH_PRIME 0x01000193
#define HASH_INIT 0x28021967
#define NUM_BLOCKHASHES 31

struct roll_state {
	unsigned char window[ROLLING_WINDOW];
	uint32_t h1, h2, h3;
	uint32_t n;
};

static void roll_init(/*@out@*/ struct roll_state *self) {
	memset(self, 0, sizeof(struct roll_state));
}

/*
 * a rolling hash, based on the Adler checksum. By using a rolling hash
 * we can perform auto resynchronisation after inserts/deletes

 * internally, h1 is the sum of the bytes in the window and h2
 * is the sum of the bytes times the index

 * h3 is a shift/xor based rolling hash, and is mostly needed to ensure that
 * we can cope with large blocksize values
 */
static void roll_hash(struct roll_state *self, unsigned char c)
{
	self->h2 -= self->h1;
	self->h2 += ROLLING_WINDOW * (uint32_t)c;

	self->h1 += (uint32_t)c;
	self->h1 -= (uint32_t)self->window[self->n % ROLLING_WINDOW];

	self->window[self->n % ROLLING_WINDOW] = c;
	self->n++;

	/* The original spamsum AND'ed this value with 0xFFFFFFFF which
	 * in theory should have no effect. This AND has been removed
	 * for performance (jk) */
	self->h3 <<= 5;
	self->h3 ^= c;
}

static uint32_t roll_sum(const struct roll_state *self)
{
	return self->h1 + self->h2 + self->h3;
}

/* A simple non-rolling hash, based on the FNV hash. */
static uint32_t sum_hash(unsigned char c, uint32_t h)
{
	return (h * HASH_PRIME) ^ c;
}

/* A blockhash contains a signature state for a specific (implicit) blocksize.
 * The blocksize is given by SSDEEP_BS(index). The h and halfh members are the
 * FNV hashes, where halfh stops to be reset after digest is SPAMSUM_LENGTH/2
 * long. The halfh hash is needed be able to truncate digest for the second
 * output hash to stay compatible with ssdeep output. */
struct blockhash_context
{
	uint32_t h, halfh;
	char digest[SPAMSUM_LENGTH];
	unsigned int dlen;
};

struct fuzzy_state
{
	unsigned int bhstart, bhend;
	struct blockhash_context bh[NUM_BLOCKHASHES];
	size_t total_size;
	struct roll_state roll;
};

#define SSDEEP_BS(index) (((uint32_t)MIN_BLOCKSIZE) << (index))

/*@only@*/ /*@null@*/ struct fuzzy_state *fuzzy_new(void)
{
	struct fuzzy_state *self;
	if(NULL == (self = malloc(sizeof(struct fuzzy_state))))
		/* malloc sets ENOMEM */
		return NULL;
	self->bhstart = 0;
	self->bhend = 1;
	self->bh[0].h = HASH_INIT;
	self->bh[0].halfh = HASH_INIT;
	self->bh[0].dlen = 0;
	self->total_size = 0;
	roll_init(&self->roll);
	return self;
}

static void fuzzy_try_fork_blockhash(struct fuzzy_state *self)
{
	struct blockhash_context *obh, *nbh;
	if (self->bhend >= NUM_BLOCKHASHES)
		return;
	assert(self->bhend > 0);
	obh = self->bh + (self->bhend - 1);
	nbh = obh + 1;
	nbh->h = obh->h;
	nbh->halfh = obh->halfh;
	nbh->dlen = 0;
	++self->bhend;
}

static void fuzzy_try_reduce_blockhash(struct fuzzy_state *self) 
{
	assert(self->bhstart < self->bhend);
	if (self->bhend - self->bhstart < 2)
		/* Need at least two working hashes. */
		return;
	if ((size_t)SSDEEP_BS(self->bhstart) * SPAMSUM_LENGTH >=
			self->total_size)
		/* Initial blocksize estimate would select this or a smaller
		 * blocksize. */
		return;
	if (self->bh[self->bhstart + 1].dlen < SPAMSUM_LENGTH / 2)
		/* Estimate adjustment would select this blocksize. */
		return;
	/* At this point we are clearly no longer interested in the
	 * start_blocksize. Get rid of it. */
	++self->bhstart;
}

static const char *b64 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void fuzzy_engine_step(struct fuzzy_state *self, unsigned char c)
{
	size_t h;
	unsigned int i;
	/* At each character we update the rolling hash and the normal hashes.
	 * When the rolling hash hits a reset value then we emit a normal hash
	 * as a element of the signature and reset the normal hash. */
	roll_hash(&self->roll, c);
	h = roll_sum(&self->roll);

	for (i = self->bhstart; i < self->bhend; ++i)
	{
		self->bh[i].h = sum_hash(c, self->bh[i].h);
		self->bh[i].halfh = sum_hash(c, self->bh[i].halfh);
	}

	for (i = self->bhstart; i < self->bhend; ++i)
	{
		/* With growing blocksize almost no runs fail the next test. */
		if (likely(h % SSDEEP_BS(i) != SSDEEP_BS(i) - 1))
			/* Once this condition is false for one bs, it is
			 * automatically false for all further bs. I.e. if
			 * h === -1 (mod 2*bs) then h === -1 (mod bs). */
			break;
		/* We have hit a reset point. We now emit hashes which are
		 * based on all characters in the piece of the message between
		 * the last reset point and this one */
		if (unlikely(0 == self->bh[i].dlen)) {
			/* Can only happen 30 times. */
			/* First step for this blocksize. Clone next. */
			fuzzy_try_fork_blockhash(self);
		}
		if (self->bh[i].dlen < SPAMSUM_LENGTH - 1) {
			/* We can have a problem with the tail overflowing. The
			 * easiest way to cope with this is to only reset the
			 * normal hash if we have room for more characters in
			 * our signature. This has the effect of combining the
			 * last few pieces of the message into a single piece
			 * */
			self->bh[i].digest[self->bh[i].dlen++] =
				b64[self->bh[i].h % 64];
			self->bh[i].h = HASH_INIT;
			if (self->bh[i].dlen < SPAMSUM_LENGTH / 2)
				self->bh[i].halfh = HASH_INIT;
		} else
			fuzzy_try_reduce_blockhash(self);
	}
}

int fuzzy_update(struct fuzzy_state *self,
		const unsigned char *buffer,
		size_t buffer_size) {
	self->total_size += buffer_size;
	for ( ;buffer_size > 0; ++buffer, --buffer_size)
		fuzzy_engine_step(self, *buffer);
	return 0;
}

static int memcpy_eliminate_sequences(char *dst,
		const char *src,
		int n)
{
	const char *srcend = src + n;
	assert(n >= 0);
	if (src < srcend) *dst++ = *src++;
	if (src < srcend) *dst++ = *src++;
	if (src < srcend) *dst++ = *src++;
	while (src < srcend)
		if (*src == dst[-1] && *src == dst[-2] && *src == dst[-3])
		{
			++src;
			--n;
		} else
			*dst++ = *src++;
	return n;
}

#ifdef S_SPLINT_S
extern const int EOVERFLOW;
#endif

// We need some extra help on Win32
#ifdef _WIN32
# define EOVERFLOW 84
# define ftello    ftell
# define fseeko    fseek
#endif

int fuzzy_digest(const struct fuzzy_state *self,
		/*@out@*/ char *result,
		unsigned int flags)
{
	unsigned int bi = self->bhstart;
	uint32_t h = roll_sum(&self->roll);
	int i, remain = FUZZY_MAX_RESULT - 1; /* Exclude terminating '\0'. */
	/* Verify that our elimination was not overeager. */
	assert(bi == 0 || (size_t)SSDEEP_BS(bi) / 2 * SPAMSUM_LENGTH <
			self->total_size);

	/* Initial blocksize guess. */
	while ((size_t)SSDEEP_BS(bi) * SPAMSUM_LENGTH < self->total_size) {
		++bi;
		if (bi >= NUM_BLOCKHASHES) {
			/* The input exceeds data types. */
			errno = EOVERFLOW;
			return -1;
		}
	}
	/* Adapt blocksize guess to actual digest length. */
	while (bi >= self->bhend)
		--bi;
	while (bi > self->bhstart && self->bh[bi].dlen < SPAMSUM_LENGTH / 2)
		--bi;
	assert (!(bi > 0 && self->bh[bi].dlen < SPAMSUM_LENGTH / 2));

	i = snprintf(result, (size_t)remain, "%u:", SSDEEP_BS(bi));
	if (i <= 0)
		/* Maybe snprintf has set errno here? */
		return -1;
	assert(i < remain);
	remain -= i;
	result += i;
	i = (int)self->bh[bi].dlen;
	assert(i <= remain);
	if ((flags & FUZZY_FLAG_ELIMSEQ) != 0)
		i = memcpy_eliminate_sequences(result, self->bh[bi].digest, i);
	else
		memcpy(result, self->bh[bi].digest, (size_t)i);
	result += i;
	remain -= i;
	if (h != 0)
	{
		assert(remain > 0);
		*result = b64[self->bh[bi].h % 64];
		if((flags & FUZZY_FLAG_ELIMSEQ) == 0 || i < 3 ||
				*result != result[-1] ||
				*result != result[-2] ||
				*result != result[-3]) {
			++result;
			--remain;
		}
	}
	assert(remain > 0);
	*result++ = ':';
	--remain;
	if (bi < self->bhend - 1)
	{
		++bi;
		i = (int)self->bh[bi].dlen;
		if ((flags & FUZZY_FLAG_NOTRUNC) == 0 &&
				i > SPAMSUM_LENGTH / 2 - 1)
			i = SPAMSUM_LENGTH / 2 - 1;
		assert(i <= remain);
		if ((flags & FUZZY_FLAG_ELIMSEQ) != 0)
			i = memcpy_eliminate_sequences(result,
					self->bh[bi].digest, i);
		else
			memcpy(result, self->bh[bi].digest, (size_t)i);
		result += i;
		remain -= i;
		if (h != 0) {
			assert(remain > 0);
			h = (flags & FUZZY_FLAG_NOTRUNC) != 0 ? self->bh[bi].h :
				self->bh[bi].halfh;
			*result = b64[h % 64];
			if ((flags & FUZZY_FLAG_ELIMSEQ) == 0 || i < 3 ||
					*result != result[-1] ||
					*result != result[-2] ||
					*result != result[-3])
			{
				++result;
				--remain;
			}
		}
	} else if (h != 0)
	{
		assert(self->bh[bi].dlen == 0);
		assert(remain > 0);
		*result++ = b64[self->bh[bi].h % 64];
		/* No need to bother with FUZZY_FLAG_ELIMSEQ, because this
		 * digest has length 1. */
		--remain;
	}
	*result = '\0';
	return 0;
}

void fuzzy_free(/*@only@*/ struct fuzzy_state *self)
{
	free(self);
}

int fuzzy_hash_buf(const unsigned char *buf,
		uint32_t buf_len,
		/*@out@*/ char *result)
{
	struct fuzzy_state *ctx;
	int ret = -1;
	if (NULL == (ctx = fuzzy_new()))
		return -1;
	if (fuzzy_update(ctx, buf, buf_len) < 0)
		goto out;
	if (fuzzy_digest(ctx, result, 0) < 0)
		goto out;
	ret = 0;
out:
	fuzzy_free(ctx);
	return ret;
}

int fuzzy_hash_stream(FILE *handle, /*@out@*/ char *result)
{
	struct fuzzy_state *ctx;
	unsigned char buffer[4096];
	size_t n;
	int ret = -1;
	if (NULL == (ctx = fuzzy_new()))
		return -1;
	for(;;)
	{
		n = fread(buffer, 1, 4096, handle);
		if (0 == n)
			break;
		if (fuzzy_update(ctx, buffer, n) < 0)
			goto out;
	}
	if (ferror(handle) != 0)
		goto out;
	if (fuzzy_digest(ctx, result, 0) < 0)
		goto out;
	ret = 0;
out:
	fuzzy_free(ctx);
	return ret;
}

#ifdef S_SPLINT_S
typedef size_t off_t;
int fseeko(FILE *, off_t, int);
off_t ftello(FILE *);
#endif

int fuzzy_hash_file(FILE *handle, /*@out@*/ char *result)
{
	off_t fpos;
	int status;
	fpos = ftello(handle);
	if (fseek(handle, 0, SEEK_SET) < 0)
		return -1;
	status = fuzzy_hash_stream(handle, result);
	if (status == 0)
	{
		if (fseeko(handle, fpos, SEEK_SET) < 0)
			return -1;
	}
	return status;
}

int fuzzy_hash_filename(const char *filename, /*@out@*/ char *result)
{
	int status;
	FILE *handle = fopen(filename, "rb");
	if (NULL == handle)
		return -1;
	status = fuzzy_hash_stream(handle, result);
	/* We cannot do anything about an fclose failure. */
	(void)fclose(handle);
	return status;
}

//
// We only accept a match if we have at least one common substring in
// the signature of length ROLLING_WINDOW. This dramatically drops the
// false positive rate for low score thresholds while having
// negligable affect on the rate of spam detection.
//
// return 1 if the two strings do have a common substring, 0 otherwise
//
// eliminate sequences of longer than 3 identical characters. These
// sequences contain very little information so they tend to just bias
// the result unfairly

//
// this is the low level string scoring algorithm. It takes two strings
// and scores them on a scale of 0-100 where 0 is a terrible match and
// 100 is a great match. The block_size is used to cope with very small
// messages.
//

char *calc_hash(const char *alg_name, const unsigned char *data, size_t size, char *output)
{
	OpenSSL_add_all_digests();
	if (strcmp("ssdeep", alg_name) == 0) {
		fuzzy_hash_buf(data, size, output);
		return output;
	}
	const EVP_MD *md = EVP_get_digestbyname(alg_name);
	//assert(md != NULL); // We already checked this in parse_hash_algorithm()
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	// See https://wiki.openssl.org/index.php/1.1_API_Changes
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX md_ctx_auto;
	EVP_MD_CTX *md_ctx = &md_ctx_auto;
#else
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
#endif

	// FIXME: Handle errors - Check return values.
	EVP_MD_CTX_init(md_ctx);
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, data, size);
	EVP_DigestFinal_ex(md_ctx, md_value, &md_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_cleanup(md_ctx);
#else
	EVP_MD_CTX_free(md_ctx);
#endif
	for (unsigned int i=0; i < md_len; i++)
		sprintf(&output[i * 2], "%02x", md_value[i]);
	EVP_cleanup();

	return output;
}

hash_ get_hashes(char *name,const unsigned char *data, size_t data_size) {
	hash_ sample;

	int MD_SIZE = EVP_MAX_MD_SIZE * 2 + 1;
	char hash_value[MD_SIZE];
	sample.name  = name;                             // TODO : allow memory dynamically.
	//sample.name = (char *)malloc(
	sample.md5 = (char *)malloc(MD_SIZE*sizeof(char *));
	sample.sha1 = (char *)malloc(MD_SIZE*sizeof(char *));
	sample.sha256 = (char *)malloc(MD_SIZE*sizeof(char *));
	sample.ssdeep = (char *)malloc(MD_SIZE*sizeof(char *));

	memcpy(sample.md5, calc_hash("md5", data, data_size, hash_value), MD_SIZE * sizeof(char *));
	memcpy(sample.sha1, calc_hash("sha1", data, data_size, hash_value), MD_SIZE * sizeof(char *));
	memcpy(sample.sha256, calc_hash("sha256", data, data_size, hash_value), MD_SIZE * sizeof(char *));
	memcpy(sample.ssdeep, calc_hash("ssdeep", data, data_size, hash_value), MD_SIZE * sizeof(char *));

	return sample;

}

hash_ get_headers_dos_hash(pe_ctx_t *ctx) {
	hash_ dos;
	const IMAGE_DOS_HEADER *dos_sample = pe_dos(ctx);
	const unsigned char *data = (const unsigned char *)dos_sample;
	uint64_t data_size = sizeof(IMAGE_DOS_HEADER);
	dos = get_hashes("IMAGE_DOS_HEADER", data, data_size);
	return dos;
}

hash_ get_headers_coff_hash(pe_ctx_t *ctx) {
	hash_ coff;
	const IMAGE_COFF_HEADER *coff_sample = pe_coff(ctx);
	const unsigned char *data = (const unsigned char *)coff_sample;
	uint64_t data_size = sizeof(IMAGE_COFF_HEADER);
	coff = get_hashes("IMAGE_COFF_HEADER", data, data_size); 
	return coff;
}

hash_ get_headers_optional_hash(pe_ctx_t *ctx) {
	hash_ optional;
	const IMAGE_OPTIONAL_HEADER *optional_sample = pe_optional(ctx);
	const unsigned char *data = (const unsigned char *)optional_sample;
	uint64_t data_size = sizeof(IMAGE_OPTIONAL_HEADER);
	optional = get_hashes("IMAGE_OPTIONAL_HEADER", data, data_size);
	return optional;
}

hdr_ get_headers_hash(pe_ctx_t *ctx) {

	hash_ dos = get_headers_dos_hash(ctx);
	hash_ optional = get_headers_optional_hash(ctx);
	hash_ coff = get_headers_coff_hash(ctx);

	hdr_ sample_hdr;
	sample_hdr.dos = dos;
	sample_hdr.coff = coff;
	sample_hdr.optional = optional;

	return sample_hdr;
}

section_ get_sections_hash(pe_ctx_t *ctx) {
	int c = pe_sections_count(ctx);
	hash_ sample[c];
	const unsigned char *data = NULL;
	uint64_t data_size = 0;
	char *name;
	IMAGE_SECTION_HEADER ** const sections = pe_sections(ctx);
	for (int i=0; i<c; i++) {
		data_size = sections[i]->SizeOfRawData;
		data = LIBPE_PTR_ADD(ctx->map_addr, sections[i]->PointerToRawData);

		if (!pe_can_read(ctx, data, data_size)) {
			//EXIT_ERROR("Unable to read section data");
			fprintf(stderr, "%s\n", "unable to read sections data");
			exit(1);
		}

		if (data_size) {
			name = (char *)sections[i]->Name;
			sample[i] =  get_hashes(name, data, data_size);
		}
	}
	section_ sample_sect;
	sample_sect.sections = (hash_ *)malloc( c * sizeof(hash_));
	sample_sect.sections = sample;
	sample_sect.count = c;
	return sample_sect;
}

hash_ get_file_hash(pe_ctx_t *ctx) {
	const unsigned char *data = ctx->map_addr;
	uint64_t data_size = pe_filesize(ctx);
	hash_ sample;
	char *name = "PEfile hash";
	sample = get_hashes(name, data, data_size);
	return sample;
} 

int get_functions_count( pe_ctx_t *ctx, uint64_t offset) {
	/*printf("from Get Functions count : %s", dllname);
		const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
		printf("%"PRIu32 Print virtual address"\n", dir->VirtualAddress);*/
	uint64_t ofs = offset;

	char hint_str[16];
	char fname[MAX_FUNCTION_NAME];
	int count =0;
	memset(hint_str, 0, sizeof(hint_str));
	memset(fname, 0, sizeof(fname));

	while (1) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
				{
					const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
						// TODO: Should we report something?
						return count;
					}

					// Type punning
					const uint32_t thunk_type = *(uint32_t *)thunk;
					if (thunk_type == 0) {
						return count;
					}

					const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						return count;
					}

					ofs += sizeof(IMAGE_THUNK_DATA32);
					break;
				}
			case MAGIC_PE64:
				{
					const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64))) {
						return count;
					}

					const uint64_t thunk_type = *(uint64_t *)thunk;
					if (thunk_type == 0) {
						return count;
					}

					uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						return count;

					}
					ofs += sizeof(IMAGE_THUNK_DATA64);
					break;
				}
		}
		count++;
	}
	return count;
}

int get_dll_count( pe_ctx_t *ctx) {
	/*const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
		printf("%"PRIu32 Print virtual address"\n ", dir->VirtualAddress);*/
	int count =0;
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		return count;
	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "import directory not found\n");
		return count;
	}
	uint64_t ofs = pe_rva2ofs(ctx, va);

	while (1) {
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			// TODO: Should we report something?
			return count;
		}
		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		const uint64_t aux = ofs; // Store current ofs
		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0)
			break;

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			break;
		}
		count++;
		ofs = aux; // Restore previous ofs
	}
	return count;	
}

function get_imported_functions(pe_ctx_t *ctx, uint64_t offset, int functions_count, char *hint_str, size_t size_hint_str, char *fname, size_t size_fname)
{
	uint64_t ofs = offset;
	function sample;
	sample.count = functions_count;
	char **functions = malloc(functions_count * sizeof(char *)); // create an array of char pointers

	// allocate space for each string.
	for (int i=0; i < functions_count; i++)
		functions[i] = (char *)malloc(MAX_FUNCTION_NAME *sizeof(char *));


	bool is_ordinal;

	for (int i=0;i<functions_count; i++) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
				{
					const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
						// TODO: Should we report something?
						exit(0); // do some thing so the API notifies about the error
					}

					// Type punning
					const uint32_t thunk_type = *(uint32_t *)thunk;
					if (thunk_type == 0)
						exit(0); // DO something so that API notifes about the error

					is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

					if (is_ordinal) {
						snprintf(hint_str, size_hint_str-1, "%"PRIu32,
								thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
					} else {
						const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
						const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
						if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
							// TODO: Should we report something?
							//return NULL;
							exit(0); // Do something so that the API notifes of the error
						}

						snprintf(hint_str, size_hint_str-1, "%d", imp_name->Hint);
						strncpy(fname, (char *)imp_name->Name, size_fname-1);
						// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
						fname[size_fname - 1] = '\0';
						//size_t fname_len = strlen(fname);
					}
					ofs += sizeof(IMAGE_THUNK_DATA32);
					break;
				}
			case MAGIC_PE64:
				{
					const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
					if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64))) {
						// TODO: Should we report something?
						//return NULL;
						exit(0); // DO something so that API notifies of the error
					}

					// Type punning
					const uint64_t thunk_type = *(uint64_t *)thunk;
					if (thunk_type == 0)
						//return NULL;
						exit(0); // DO something so that API notfies of the error

					is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG64) != 0;

					if (is_ordinal) {
						snprintf(hint_str, size_hint_str-1, "%llu",
								thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64);
					} else {
						uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
						const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
						if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
							// TODO: Should we report something?
							//return NULL;
							exit(0); // Do something so that API notifies of the error
						}

						snprintf(hint_str, size_hint_str-1, "%d", imp_name->Hint);
						strncpy(fname, (char *)imp_name->Name, size_fname-1);
						// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
						fname[size_fname - 1] = '\0';
						//size_t fname_len = strlen(fname);
					}
					ofs += sizeof(IMAGE_THUNK_DATA64);
					break;
				}
		}

		if (is_ordinal)
			memcpy(functions[i], hint_str, 16);
		else
			memcpy(functions[i], fname, MAX_FUNCTION_NAME);

	}
	sample.functions = functions;
	return sample;
}
import get_imports(pe_ctx_t *ctx) {
	int dll_count = get_dll_count(ctx);
	//library *libraries = (library *)malloc( dll_count *sizeof(library));
	import imports;
	imports.dll_count = dll_count;
	imports.names = malloc(dll_count *sizeof(imports.names));

	for ( int i=0; i<dll_count; i++)
		imports.names[i] = (char *)malloc(MAX_DLL_NAME*sizeof(char *));

	imports.functions = (function *)malloc(dll_count * sizeof(function));

	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		///EXIT_ERROR("import directory not found")
		// Do something which clearly tells when something get really bad.
		exit(0);

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "import directory not found\n");
		// return something which clearly tell the error
	}
	uint64_t ofs = pe_rva2ofs(ctx, va);

	for (int i=0; i<dll_count; i++) { 
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			// TODO: Should we report something?
			//Areturn;
			// or return an empty struct.
		}

		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		const uint64_t aux = ofs; // Store current ofs

		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0)
			break;

		const char *dll_name_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		// Validate whether it's ok to access at least 1 byte after dll_name_ptr.
		// It might be '\0', for example.
		if (!pe_can_read(ctx, dll_name_ptr, 1)) {
			// TODO: Should we report something?
			break;
		}

		char dll_name[MAX_DLL_NAME];
		strncpy(dll_name, dll_name_ptr, sizeof(dll_name)-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		dll_name[sizeof(dll_name) - 1] = '\0';

		//	imports.names[i] = dll_name;
		memcpy(imports.names[i], dll_name, MAX_DLL_NAME* sizeof(char *));
		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			//            output_close_scope(); // Library
			break;
		}


		// Search for DLL imported functions
		char hint_str[16];
		char fname[MAX_FUNCTION_NAME];
		memset(hint_str, 0, sizeof(hint_str));
		memset(fname, 0, sizeof(fname));
		size_t size_hint_str = sizeof(hint_str);
		size_t size_fname = sizeof(fname);
		//char *imports =
		int functions_count = get_functions_count(ctx, ofs);
		//memcpy(imports.functions[i], get_imported_functions(ctx, ofs, functions_count, hint_str,size_hint_str, fname, size_fname), functions_count* sizeof(function));
		//imports.functions[i] = imp_functions; // DOUBT ==> allocating memory for double pointer. 

		imports.functions[i] = get_imported_functions(ctx, ofs, functions_count, hint_str,size_hint_str, fname, size_fname);


		//printf("imports :%s  \n", imports);
		ofs = aux; // Restore previous ofs
	}

	return imports;
}

double calculate_entropy(const unsigned int counted_bytes[256], const size_t total_length)
{
	static const double log_2 = 1.44269504088896340736;
	double entropy = 0.;

	for (size_t i = 0; i < 256; i++) {
		double temp = (double)counted_bytes[i] / total_length;
		if (temp > 0.)
			entropy += fabs(temp * (log(temp) * log_2));
	}

	return entropy;
}

double calculate_entropy_file(pe_ctx_t *ctx) {
	unsigned int counted_bytes[256];
	memset(counted_bytes, 0, sizeof(counted_bytes));

	const uint8_t *file_bytes = LIBPE_PTR_ADD(ctx->map_addr, 0);
	const uint64_t filesize = pe_filesize(ctx);
	for (uint64_t ofs=0; ofs < filesize; ofs++) {
		const uint8_t byte = file_bytes[ofs];
		counted_bytes[byte]++;
	}

	return calculate_entropy(counted_bytes, (size_t)filesize);
}

bool fpu_trick(pe_ctx_t *ctx) {
	const char *opcode_ptr = ctx->map_addr;

	for (uint32_t i=0, times=0; i < ctx->map_size; i++) {
		if (*opcode_ptr++ == '\xdf') {
			if (++times == 4)
				return true;
		}
		else
			times = 0;
	}

	return false;
}

int cpl_analysis(pe_ctx_t *ctx)
{
	const IMAGE_COFF_HEADER *hdr_coff_ptr = pe_coff(ctx);
	const IMAGE_DOS_HEADER *hdr_dos_ptr = pe_dos(ctx);

	if (hdr_coff_ptr == NULL || hdr_dos_ptr == NULL)
		return 0;

	static const uint16_t characteristics1 =
		( IMAGE_FILE_EXECUTABLE_IMAGE
			| IMAGE_FILE_LINE_NUMS_STRIPPED
			| IMAGE_FILE_LOCAL_SYMS_STRIPPED
			| IMAGE_FILE_BYTES_REVERSED_LO
			| IMAGE_FILE_32BIT_MACHINE
			| IMAGE_FILE_DLL
			| IMAGE_FILE_BYTES_REVERSED_HI);
	static const uint16_t characteristics2 =
		( IMAGE_FILE_EXECUTABLE_IMAGE
			| IMAGE_FILE_LINE_NUMS_STRIPPED
			| IMAGE_FILE_LOCAL_SYMS_STRIPPED
			| IMAGE_FILE_BYTES_REVERSED_LO
			| IMAGE_FILE_32BIT_MACHINE
			| IMAGE_FILE_DEBUG_STRIPPED
			| IMAGE_FILE_DLL
			| IMAGE_FILE_BYTES_REVERSED_HI);
	static const uint16_t characteristics3 =
		( IMAGE_FILE_EXECUTABLE_IMAGE
			| IMAGE_FILE_LINE_NUMS_STRIPPED
			| IMAGE_FILE_32BIT_MACHINE
			| IMAGE_FILE_DEBUG_STRIPPED
			| IMAGE_FILE_DLL);

	if ((hdr_coff_ptr->TimeDateStamp == 708992537 ||
				hdr_coff_ptr->TimeDateStamp > 1354555867)
			&& (hdr_coff_ptr->Characteristics == characteristics1 || // equals 0xa18e
				hdr_coff_ptr->Characteristics == characteristics2 || // equals 0xa38e
				hdr_coff_ptr->Characteristics == characteristics3) // equals 0x2306
			&& hdr_dos_ptr->e_sp == 0xb8
		 )
		return 1;

	return 0;
}

int get_cpl_analysis(pe_ctx_t *ctx) {
	int ret;
	if (pe_is_dll(ctx)) {
		ret = cpl_analysis(ctx);
	} else {
		ret = -1; 
	}
	return ret;
}

const IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(pe_ctx_t *ctx, uint32_t ep)
{
	const uint16_t num_sections = pe_sections_count(ctx);
	if (num_sections == 0)
		return NULL;

	const IMAGE_SECTION_HEADER *section = pe_rva2section(ctx, ep);
	if (section == NULL)
		return NULL;

	if (section->Characteristics & IMAGE_SCN_CNT_CODE)
		return NULL;

	return section;
}

int check_fake_entrypoint(pe_ctx_t *ctx) {
	const IMAGE_OPTIONAL_HEADER *optional = pe_optional(ctx);
	if (optional == NULL)
		return INT_MAX; // Unable to read optional header.
	uint32_t ep = (optional->_32 ? optional->_32->AddressOfEntryPoint :
			(optional->_64 ? optional->_64->AddressOfEntryPoint : 0));

	// fake ep
	int value;

	if (ep == 0) {
		value = -1; // null
	} 
	else if (pe_check_fake_entrypoint(ctx, ep)) {
		value = 1; // fake 
	} 
	else {
		value = 0;       // normal 
	}
	return value;
}

uint32_t pe_get_tls_directory(pe_ctx_t *ctx)
{
	if (ctx->pe.num_directories == 0 || ctx->pe.num_directories > MAX_DIRECTORIES)
		return 0;

	const IMAGE_DATA_DIRECTORY *directory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_TLS);
	if (directory == NULL)
		return 0;

	if (directory->Size == 0)
		return 0;

	return directory->VirtualAddress;
}

int pe_get_tls_callbacks(pe_ctx_t *ctx)
{
	int ret = 0;

	const IMAGE_OPTIONAL_HEADER *optional_hdr = pe_optional(ctx);
	if (optional_hdr == NULL)
		return 0;

	IMAGE_SECTION_HEADER ** const sections = pe_sections(ctx);
	if (sections == NULL)
		return 0;

	const uint64_t tls_addr = pe_get_tls_directory(ctx);
	if (tls_addr == 0)
		return 0;

	const uint16_t num_sections = pe_sections_count(ctx);

	uint64_t ofs = 0;

	// search for tls in all sections
	for (uint16_t i=0, j=0; i < num_sections; i++)
	{
		if (tls_addr >= sections[i]->VirtualAddress &&
				tls_addr < (sections[i]->VirtualAddress + sections[i]->SizeOfRawData))
		{
			ofs = tls_addr - sections[i]->VirtualAddress + sections[i]->PointerToRawData;

			switch (optional_hdr->type) {
				default:
					return 0;
				case MAGIC_PE32:
					{
						const IMAGE_TLS_DIRECTORY32 *tls_dir = LIBPE_PTR_ADD(ctx->map_addr, ofs);
						if (!pe_can_read(ctx, tls_dir, sizeof(IMAGE_TLS_DIRECTORY32))) {
							// TODO: Should we report something?
							return 0;
						}

						if (!(tls_dir->AddressOfCallBacks & optional_hdr->_32->ImageBase))
							break;

						ofs = pe_rva2ofs(ctx, tls_dir->AddressOfCallBacks - optional_hdr->_32->ImageBase);
						break;
					}
				case MAGIC_PE64:
					{
						const IMAGE_TLS_DIRECTORY64 *tls_dir = LIBPE_PTR_ADD(ctx->map_addr, ofs);
						if (!pe_can_read(ctx, tls_dir, sizeof(IMAGE_TLS_DIRECTORY64))) {
							// TODO: Should we report something?
							return 0;
						}

						if (!(tls_dir->AddressOfCallBacks & optional_hdr->_64->ImageBase))
							break;

						ofs = pe_rva2ofs(ctx, tls_dir->AddressOfCallBacks - optional_hdr->_64->ImageBase);
						break;
					}
			}

			ret = -1; // tls directory and section exists

			//char value[MAX_MSG];
			uint32_t funcaddr = 0;

			do
			{
				const uint32_t *funcaddr_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, funcaddr_ptr, sizeof(*funcaddr_ptr))) {
					// TODO: Should we report something?
					return 0;
				}

				uint32_t funcaddr = *funcaddr_ptr;
				if (funcaddr) {
					ret = ++j; // function found
				}
			} while (funcaddr);

			return ret;
		}
	}

	return 0;
}

int get_tls_callback(pe_ctx_t *ctx) {
	int callbacks = pe_get_tls_callbacks(ctx);
	int ret;
	if (callbacks == 0)
		ret = INT_MIN; // not found
	else if (callbacks == -1)
		ret = INT_MAX; // found no functions
	else if (callbacks > 0)
		ret = callbacks;
	return ret;
}

int get_exports_functions_count(pe_ctx_t *ctx) {
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dir == NULL)
		//EXIT_ERROR("export directory not found")
		exit(0); 
	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		//fprintf(stderr, "export directory not found\n");
		// return;
		exit(0);
	}

	uint64_t ofs;

	ofs = pe_rva2ofs(ctx, va);
	const IMAGE_EXPORT_DIRECTORY *exp = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	return exp->NumberOfFunctions;
}

exports *get_exports(pe_ctx_t *ctx)
{
	exports *sample;
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dir == NULL)
		//EXIT_ERROR("export directory not found")
		exit(0); 
	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		//fprintf(stderr, "export directory not found\n");
		// return;
		exit(0);
	}

	uint64_t ofs;

	ofs = pe_rva2ofs(ctx, va);
	const IMAGE_EXPORT_DIRECTORY *exp = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
		// TODO: Should we report something?
		//return;
		exit(0);
	}

	ofs = pe_rva2ofs(ctx, exp->AddressOfNames);
	const uint32_t *rva_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, rva_ptr, sizeof(uint32_t))) {
		// TODO: Should we report something?
		//return;
		exit(0);
	}
	const uint32_t rva = *rva_ptr;

	ofs = pe_rva2ofs(ctx, rva);

	//output_open_scope("Exported functions", OUTPUT_SCOPE_TYPE_ARRAY);
	// If `NumberOfNames == 0` then all functions are exported by ordinal.
	// Otherwise `NumberOfNames` must be equal to `NumberOfFunctions`
	if (exp->NumberOfNames != 0 && exp->NumberOfNames != exp->NumberOfFunctions) {
		// fprintf(stderr, "NumberOfFunctions differs from NumberOfNames\n");
		//output_close_scope(); // Exported functions
		exit(0); // Number of functions difffer for number of names
	}

	uint64_t offset_to_AddressOfFunctions = pe_rva2ofs(ctx, exp->AddressOfFunctions);
	uint64_t offset_to_AddressOfNames = pe_rva2ofs(ctx, exp->AddressOfNames);
	uint64_t offset_to_AddressOfNameOrdinals = pe_rva2ofs(ctx, exp->AddressOfNameOrdinals);

	//
	// The format of IMAGE_EXPORT_DIRECTORY can be seen in http://i.msdn.microsoft.com/dynimg/IC60608.gif
	//

	// We want to use `NumberOfFunctions` for looping as it's the total number of functions/symbols
	// exported by the module. On the other hand, `NumberOfNames` is the number of
	// functions/symbols exported by name only.

	sample = (exports *)malloc(exp->NumberOfFunctions*sizeof(exports *));

	printf("Number Of Functions : %d\n", exp->NumberOfFunctions);
	for (uint32_t i=0; i < exp->NumberOfFunctions; i++) {
		uint64_t entry_ordinal_list_ptr = offset_to_AddressOfNameOrdinals + sizeof(uint16_t) * i;
		uint16_t *entry_ordinal_list = LIBPE_PTR_ADD(ctx->map_addr, entry_ordinal_list_ptr);

		uint64_t entry_va_list_ptr = offset_to_AddressOfFunctions + sizeof(uint32_t) * i;
		uint32_t *entry_va_list = LIBPE_PTR_ADD(ctx->map_addr, entry_va_list_ptr);

		uint64_t entry_name_list_ptr = offset_to_AddressOfNames + sizeof(uint32_t) * i;
		uint32_t *entry_name_list = LIBPE_PTR_ADD(ctx->map_addr, entry_name_list_ptr);

		// printf("ctx->map_addr = %p\n", ctx->map_addr);
		// printf("ctx->map_end = %p\n", ctx->map_end);
		// printf("entry_ordinal_list = %p\n", entry_ordinal_list);
		// printf("entry_va_list = %p\n", entry_va_list);
		// printf("entry_name_list = %p\n", entry_name_list);

		if (!pe_can_read(ctx, entry_ordinal_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		if (!pe_can_read(ctx, entry_va_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		if (!pe_can_read(ctx, entry_name_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		// Add `Base` to the element of `AddressOfNameOrdinals` array to get the correct ordinal..
		//const uint16_t entry_ordinal = exp->Base + *entry_ordinal_list;
		const uint32_t entry_va = *entry_va_list;
		const uint32_t entry_name_rva = *entry_name_list;
		const uint64_t entry_name_ofs = pe_rva2ofs(ctx, entry_name_rva);
		const char *entry_name = LIBPE_PTR_ADD(ctx->map_addr, entry_name_ofs);

		// Validate whether it's ok to access at least 1 byte after entry_name.
		// It might be '\0', for example.
		if (!pe_can_read(ctx, entry_name, 1)) {
			// TODO: Should we report something?
			break;
		}

		//printf("ord=%d, va=%x, name=%s\n", entry_ordinal, entry_va, entry_name);

		// Declared as 11 bytes so that it can store the hexadecimal representation of the maximum
		// possible value of an uint32_t variable, 0xFFFFFFFF.
		sample[i].addr = (char *) malloc(11 *sizeof(char*));
		char addr[11] = { 0 };
		sprintf(addr, "%#x", entry_va);
		memcpy(sample[i].addr, addr, 11);
		printf("%s \n", sample[i].addr);
		char fname[300] = { 0 };
		strncpy(fname, entry_name, sizeof(fname)-1);

		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		fname[sizeof(fname) - 1] = '\0';

		//output_open_scope("Function", OUTPUT_SCOPE_TYPE_OBJECT);

		// Check whether the exported function is forwarded.
		// It's forwarded if its RVA is inside the exports section.
		if (entry_va >= va && entry_va <= va + dir->Size)
		{
			// When a symbol is forwarded, its RVA points to a string containing
			// the name of the DLL and symbol to which it is forwarded.
			const uint64_t fw_entry_name_ofs = pe_rva2ofs(ctx, entry_va);
			const char *fw_entry_name = LIBPE_PTR_ADD(ctx->map_addr, fw_entry_name_ofs);

			// Validate whether it's ok to access at least 1 byte after fw_entry_name.
			// It might be '\0', for example.
			if (!pe_can_read(ctx, fw_entry_name, 1)) {
				// TODO: Should we report something?
				break;
			}

			sample[i].function_name = (char *)malloc( (sizeof(fname) * 2 + 4)*sizeof(char *));
			char fname_forwarded[sizeof(fname) * 2 + 4] = { 0 }; // Twice the size plus " -> ".
			snprintf(fname_forwarded, sizeof(fname_forwarded)-1, "%s -> %s", fname, fw_entry_name);

			memcpy(sample[i].function_name, fname_forwarded, sizeof(fname) * 2 + 4);
			printf(" fname_forwarded : %s ", sample[i].function_name);
		}
		else
		{
			sample[i].function_name = (char *)malloc(300*sizeof(char*));
			memcpy(sample[i].function_name, fname, 300);
		}

	}
	return sample;
}
