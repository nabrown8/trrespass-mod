#include "utils.h"
#include "dram-address.h"
#include "memory.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#define PAGE_BITS 12

#define FLAGS (MAP_PRIVATE | MAP_POPULATE | MAP_HUGETLB | (30<<MAP_HUGE_SHIFT))

char *get_rnd_addr(char *base, size_t m_size, size_t align)
{
	return (char *)((((uint64_t) base) + (rand() % m_size)) &
			(~((uint64_t) align - 1)));
}

int get_rnd_int(int min, int max)
{
	return rand() % (max + 1 - min) + min;
}

double mean(uint64_t * vals, size_t size)
{
	uint64_t avg = 0;
	for (size_t i = 0; i < size; i++) {
		avg += vals[i];
	}
	return ((double)avg) / size;
}

int gt(const void *a, const void *b)
{
	return (*(int *)a - *(int *)b);
}

uint64_t median(uint64_t * vals, size_t size)
{
	qsort(vals, size, sizeof(uint64_t), gt);
	return ((size % 2) ==
		0) ? vals[size / 2] : (vals[(size_t) size / 2] +
				       vals[((size_t) size / 2 + 1)]) / 2;
}

char *bit_string(uint64_t val)
{
	static char bit_str[256];
	char itoa_str[8];
	strcpy(bit_str, "");
	for (int shift = 0; shift < 64; shift++) {
		if ((val >> shift) & 1) {
			if (strcmp(bit_str, "") != 0) {
				strcat(bit_str, "+ ");
			}
			sprintf(itoa_str, "%d ", shift);
			strcat(bit_str, itoa_str);
		}
	}

	return bit_str;
}

char *int_2_bin(uint64_t val)
{
	static char bit_str[256];
	char itoa_str[8];
	strcpy(bit_str, "0b");
	for (int shift = 64 - __builtin_clzl(val); shift >= 0; --shift) {
		sprintf(itoa_str, "%d", (int)(val >> shift) & 1);
		strcat(bit_str, itoa_str);
	}

	return bit_str;
}

typedef struct {
	char *v_addr;
	uint64_t bank;
} BankedAddr;

static int banked_addr_cmp(const void *a, const void *b)
{
	uint64_t ba = ((const BankedAddr *)a)->bank;
	uint64_t bb = ((const BankedAddr *)b)->bank;
	return (ba > bb) - (ba < bb);
}

// Toggles access between a0/a1 for `rounds` iterations, flushing both out of
// cache each round (mirrors the access+clflush+mfence idiom hammer_it uses),
// and returns the average cycles/round.
static uint64_t time_pair(char *a0, char *a1, size_t rounds)
{
	// warm-up: absorb first-touch/TLB effects before the timed loop
	for (size_t w = 0; w < 100; w++) {
		(void)*(volatile char *)a0;
		(void)*(volatile char *)a1;
		clflushopt(a0);
		clflushopt(a1);
		mfence();
	}

	uint64_t t0 = rdtscp();
	for (size_t r = 0; r < rounds; r++) {
		(void)*(volatile char *)a0;
		(void)*(volatile char *)a1;
		clflushopt(a0);
		clflushopt(a1);
		mfence();
	}
	uint64_t t1 = rdtscp();

	return (t1 - t0) / rounds;
}

bool verify_hash_fns(MemoryBuffer * mem, size_t n_addrs, size_t n_pairs,
		      size_t rounds, uint64_t thresh_cycles)
{
	BankedAddr *pool = (BankedAddr *) malloc(sizeof(BankedAddr) * n_addrs);
	for (size_t i = 0; i < n_addrs; i++) {
		char *v = get_rnd_addr(mem->buffer, mem->size, CL_SIZE);
		pool[i].v_addr = v;
		pool[i].bank = phys_2_dram(virt_2_phys(v, mem)).bank;
	}

	// group by bank so adjacent entries make cheap same-bank pairs
	qsort(pool, n_addrs, sizeof(BankedAddr), banked_addr_cmp);

	size_t same_total = 0, same_above = 0;
	size_t diff_total = 0, diff_above = 0;

	for (size_t i = 0; i + 1 < n_addrs && same_total < n_pairs; i++) {
		if (pool[i].bank != pool[i + 1].bank)
			continue;
		uint64_t t = time_pair(pool[i].v_addr, pool[i + 1].v_addr, rounds);
		same_total++;
		if (t > thresh_cycles)
			same_above++;
		fprintf(stderr, "[VERIFY] same-bank(bk%lu): %lu cycles/round\n",
			pool[i].bank, t);
	}

	size_t attempts = 0, max_attempts = n_pairs * 20 + 100;
	while (diff_total < n_pairs && attempts < max_attempts) {
		attempts++;
		size_t i = (size_t) get_rnd_int(0, (int)n_addrs - 1);
		size_t j = (size_t) get_rnd_int(0, (int)n_addrs - 1);
		if (i == j || pool[i].bank == pool[j].bank)
			continue;
		uint64_t t = time_pair(pool[i].v_addr, pool[j].v_addr, rounds);
		diff_total++;
		if (t > thresh_cycles)
			diff_above++;
		fprintf(stderr, "[VERIFY] diff-bank(bk%lu,bk%lu): %lu cycles/round\n",
			pool[i].bank, pool[j].bank, t);
	}

	free(pool);

	double same_pct = same_total ? (100.0 * same_above / same_total) : 0.0;
	double diff_pct = diff_total ? (100.0 * diff_above / diff_total) : 0.0;

	fprintf(stderr,
		"[VERIFY] same-bank pairs above %lu cycles: %.1f%% (%zu/%zu)\n"
		"[VERIFY] diff-bank pairs above %lu cycles: %.1f%% (%zu/%zu)\n",
		thresh_cycles, same_pct, same_above, same_total,
		thresh_cycles, diff_pct, diff_above, diff_total);

	bool likely_correct = (same_total > 0) && (diff_total > 0) &&
			       (same_pct >= 80.0) && (diff_pct <= 20.0);

	fprintf(stderr, "[VERIFY] bank hash functions are %s\n",
		likely_correct ? "PROBABLY CORRECT" : "PROBABLY NOT CORRECT");

	return likely_correct;
}
