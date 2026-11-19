#include "dram-address.h"

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "memory.h"

#define DEBUG_REVERSE_FN 1

extern DRAMLayout g_mem_layout;

// Physical base (of the current 1GB-aligned chunk being addressed) that
// dram_2_phys() ORs into the upper bits of the addresses it builds. Must be
// set via set_dram_base_phys() before dram_2_phys() is called for a given
// hugepage/chunk - separate chunks are not physically contiguous, so this
// has to be updated per-chunk rather than derived once from the whole buffer.
static physaddr_t g_dram_base_phys = 0;

void set_dram_base_phys(physaddr_t base)
{
	g_dram_base_phys = base;
}

// Undoes the hoist: if p_addr was relocated above a reserved region
// (p_addr >= base_value), subtract offset to recover the linear physical
// address the h_fns/row_mask/col_mask were derived against. {0, 0} is a
// no-op, so this is safe to call unconditionally for every phys->DRAM
// lookup, with or without hoisting configured.
static physaddr_t get_linear_phys(physaddr_t p_addr)
{
	if (p_addr >= g_mem_layout.base_value) {
		return p_addr - g_mem_layout.offset;
	}
	return p_addr;
}

// Inverse of get_linear_phys(): re-applies the hoist to a linear address
// built from row/col/h_fns bits so it becomes a real physical address again
// (one usable with virt_2_phys/phys_2_virt page-table lookups). The
// threshold in linear space is base_value - offset, since that's what
// base_value becomes once get_linear_phys() has already been applied to
// it. {0, 0} is again a no-op.
static physaddr_t get_hoisted_phys(physaddr_t lin_addr)
{
	if (lin_addr >= g_mem_layout.base_value - g_mem_layout.offset) {
		return lin_addr + g_mem_layout.offset;
	}
	return lin_addr;
}

uint64_t get_dram_row(physaddr_t p_addr)
{
	p_addr = get_linear_phys(p_addr);
	return (p_addr & g_mem_layout.
		row_mask) >> __builtin_ctzl(g_mem_layout.row_mask);
}

uint64_t get_dram_col(physaddr_t p_addr)
{
	p_addr = get_linear_phys(p_addr);
	return (p_addr & g_mem_layout.
		col_mask) >> __builtin_ctzl(g_mem_layout.col_mask);
}

DRAMAddr phys_2_dram(physaddr_t p_addr)
{

	DRAMAddr res = { 0, 0, 0 };
	physaddr_t lin_addr = get_linear_phys(p_addr);
	for (int i = 0; i < g_mem_layout.h_fns.len; i++) {
		res.bank |=
		    (__builtin_parityl(lin_addr & g_mem_layout.h_fns.lst[i]) <<
		     i);
	}

	res.row = get_dram_row(p_addr);
	res.col = get_dram_col(p_addr);

	return res;
}

#define MAX_FREE_BITS 64

// Picks, among the bits outside row_mask/col_mask, exactly those that are
// set in at least one h_fns entry (the only ones that can ever matter to
// the bank parity equations), in increasing bit-position order.
static int collect_free_bits(int free_bits[MAX_FREE_BITS])
{
	uint64_t free_mask = ~(g_mem_layout.row_mask) & ~(g_mem_layout.col_mask);
	int n_free = 0;

	for (int b = 0; b < 64; b++) {
		if (!((free_mask >> b) & 1)) {
			continue;
		}
		for (int i = 0; i < g_mem_layout.h_fns.len; i++) {
			if ((g_mem_layout.h_fns.lst[i] >> b) & 1) {
				free_bits[n_free++] = b;
				break;
			}
		}
	}
	return n_free;
}

// Sets the bits of *p_addr outside row_mask/col_mask so that every
// h_fns[i] evaluates to bit i of `bank`, given *p_addr already has its
// row/col bits fixed. A naive "flip the lowest free bit per function"
// approach only works if every function has a free bit exclusive to it;
// that's not true for every derived h_fns set (functions can share
// overlapping free bits, so fixing one breaks another already fixed
// earlier in the loop). This instead solves the full linear system over
// GF(2) via Gauss-Jordan elimination, which always finds a correct
// combination of free bits whenever one exists.
static void solve_bank_bits(physaddr_t *p_addr, uint64_t bank)
{
	int free_bits[MAX_FREE_BITS];
	int n_free = collect_free_bits(free_bits);
	int n_fns = g_mem_layout.h_fns.len;

	uint64_t mat[HASH_FN_CNT] = { 0 };
	uint64_t target[HASH_FN_CNT] = { 0 };
	for (int i = 0; i < n_fns; i++) {
		for (int c = 0; c < n_free; c++) {
			if ((g_mem_layout.h_fns.lst[i] >> free_bits[c]) & 1) {
				mat[i] |= (1ULL << c);
			}
		}
		uint64_t base_parity =
		    __builtin_parityl(*p_addr & g_mem_layout.h_fns.lst[i]);
		uint64_t desired = (bank >> i) & 1ULL;
		target[i] = base_parity ^ desired;
	}

	// Full Gauss-Jordan: eliminate each pivot column from every other
	// row (not just rows below it), so by the end every pivot row has a
	// single 1 among all pivot columns -- its own -- making the
	// solution a direct readout with no back-substitution needed.
	int col_pivot_row[MAX_FREE_BITS];
	for (int c = 0; c < n_free; c++) {
		col_pivot_row[c] = -1;
	}

	int rank = 0;
	for (int c = 0; c < n_free && rank < n_fns; c++) {
		int pivot = -1;
		for (int r = rank; r < n_fns; r++) {
			if ((mat[r] >> c) & 1) {
				pivot = r;
				break;
			}
		}
		if (pivot == -1) {
			continue;
		}

		uint64_t tmp = mat[rank];
		mat[rank] = mat[pivot];
		mat[pivot] = tmp;
		tmp = target[rank];
		target[rank] = target[pivot];
		target[pivot] = tmp;

		for (int r = 0; r < n_fns; r++) {
			if (r != rank && ((mat[r] >> c) & 1)) {
				mat[r] ^= mat[rank];
				target[r] ^= target[rank];
			}
		}
		col_pivot_row[c] = rank;
		rank++;
	}

	for (int r = rank; r < n_fns; r++) {
		if (mat[r] == 0 && target[r] != 0) {
			fprintf(stderr,
				"[ERROR] - dram_2_phys: bank 0x%lx is unreachable "
				"with the configured h_fns/row_mask/col_mask\n",
				bank);
		}
	}

	for (int c = 0; c < n_free; c++) {
		if (col_pivot_row[c] != -1 && (target[col_pivot_row[c]] & 1)) {
			*p_addr ^= (1ULL << free_bits[c]);
		}
	}
}

physaddr_t dram_2_phys(DRAMAddr d_addr, MemoryBuffer *mem)
{
	physaddr_t p_addr = 0;

	p_addr = (d_addr.row << __builtin_ctzl(g_mem_layout.row_mask));	// set row bits
	p_addr |= (d_addr.col << __builtin_ctzl(g_mem_layout.col_mask));	// set col bits

	solve_bank_bits(&p_addr, d_addr.bank);

	// g_dram_base_phys is a real (possibly hoisted) physical address, but
	// p_addr built so far is linear, so linearize the base's upper bits
	// before combining them.
	p_addr |= get_linear_phys(g_dram_base_phys) &
	    ~(((uint64_t) PAGE_SIZE - 1));


#if DEBUG_REVERSE_FN
	int correct = 1;
	for (int i = 0; i < g_mem_layout.h_fns.len; i++) {

		if (__builtin_parityl(p_addr & g_mem_layout.h_fns.lst[i]) !=
		    ((d_addr.bank >> i) & 1L)) {
			correct = 0;
			break;
		}
	}
	if (d_addr.row != ((p_addr &
			    g_mem_layout.row_mask) >>
			   __builtin_ctzl(g_mem_layout.row_mask)))
		correct = 0;
	if (!correct)
		fprintf(stderr,
			"[DEBUG] - Mapping function for 0x%lx not respected\n",
			p_addr);

#endif

	return get_hoisted_phys(p_addr);
}

void set_global_dram_layout(DRAMLayout & mem_layout)
{
	g_mem_layout = mem_layout;
}

DRAMLayout *get_dram_layout()
{
	return &g_mem_layout;
}

bool d_addr_eq(DRAMAddr * d1, DRAMAddr * d2)
{
	return (d1->bank == d2->bank) && (d1->row == d2->row)
	    && (d1->col == d2->col);
}

bool d_addr_eq_row(DRAMAddr * d1, DRAMAddr * d2)
{
	return (d1->bank == d2->bank) && (d1->row == d2->row);
}

uint64_t get_banks_cnt()
{
	return 1 << g_mem_layout.h_fns.len;

}

char *dram_2_str(DRAMAddr * d_addr)
{
	static char ret_str[1024];
	sprintf(ret_str, "DRAM(bk: %ld (%s), row: %08ld, col: %08ld)",
		d_addr->bank, int_2_bin(d_addr->bank), d_addr->row,
		d_addr->col);
	return ret_str;
}

char *dramLayout_2_str(DRAMLayout * mem_layout)
{
	static char ret_str[1024];
	sprintf(ret_str, "{0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx} - 0x%lx\n",
		mem_layout->h_fns.lst[0], mem_layout->h_fns.lst[1],
		mem_layout->h_fns.lst[2], mem_layout->h_fns.lst[3],
		mem_layout->h_fns.lst[4], mem_layout->h_fns.lst[5],
		mem_layout->row_mask);
	return ret_str;
}
