#pragma once

#include "types.h"

#define HASH_FN_CNT 7

typedef struct {
	uint64_t lst[HASH_FN_CNT];
	uint64_t len;
} AddrFns;

typedef struct {
	AddrFns h_fns;
	uint64_t row_mask;
	uint64_t col_mask;
	// PCI-hole-style offset hoisting: any physical address >= base_value
	// has been hoisted above a reserved region, so offset must be
	// subtracted from it before it is linear/contiguous again and safe to
	// feed into h_fns/row_mask/col_mask. Addresses below base_value are
	// already linear and pass through unchanged. {0, 0} (the default when
	// omitted from an initializer) is a no-op, since every physaddr_t is
	// >= 0 and subtracting 0 is the identity.
	physaddr_t base_value;
	physaddr_t offset;
} DRAMLayout;

typedef struct {
	/* bank is a simplified addressing of <ch,dimm,rk,bg,bk>
	   where all this will eventually map to a specific bank */
	uint64_t bank;
	uint64_t row;
	uint64_t col;
} DRAMAddr;

physaddr_t dram_2_phys(DRAMAddr d_addr, MemoryBuffer *mem);
void set_dram_base_phys(physaddr_t base);
DRAMAddr phys_2_dram(physaddr_t p_addr);
char *dram_2_str(DRAMAddr * d_addr);
char *dramLayout_2_str(DRAMLayout * mem_layout);
DRAMLayout *get_dram_layout();
uint64_t get_banks_cnt();
bool d_addr_eq(DRAMAddr * d1, DRAMAddr * d2);
bool d_addr_eq_row(DRAMAddr * d1, DRAMAddr * d2);
