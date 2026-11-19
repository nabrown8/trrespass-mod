/*
 * Copyright (c) 2018 Vrije Universiteit Amsterdam
 *
 * This program is licensed under the GPL2+.
 */

#ifndef PARAMS_H
#define PARAMS_H 1

#include <stddef.h>
#include <stdint.h>

#define ROUNDS_std      1000000
#define HUGETLB_std     "/mnt/huge/buff"
#define CONFIG_NAME_std "tmp/s_cfg.bin"
#define O_FILE_std      "DIMM00"
#define ALLOC_SIZE     	1<<30
#define ALIGN_std       2<<20
#define PATT_LEN 		1024
#define AGGR_std		10
#define HUGE_YES

typedef struct ProfileParams {
	uint64_t g_flags 		= 0;
	char 	*g_out_prefix;
	char	*tpat			= (char *)NULL;
	char 	*vpat			= (char *)NULL;
	int		 threshold		= 0;
	int		 phase_sweep	= 0;		// --phase-sweep: with -t/--threshold, vary the post-spike
											// delay each round: 0,20,40,...,2000ns, then wrap to 0
	int 	fuzzing         = 0;		// start fuzzing!!
	size_t   m_size			= ALLOC_SIZE;
	size_t   m_align 		= ALIGN_std;
	size_t   rounds			= ROUNDS_std;
	size_t   base_off 		= 0;
	char     *huge_file		= (char *)HUGETLB_std;
	int		 huge_fd;
	char     *conf_file		= (char *)CONFIG_NAME_std;
	int 	 aggr			= AGGR_std;
	size_t   n_hugepages	= 1;		// default matches single-hugepage ALLOC_SIZE
	int		 sweep_all		= 0;		// --sweep: scan across n_hugepages hugepages
	int		 delayed		= 0;		// --delayed: use staggered_hammer_wrapper (2 delayed aggressors + fast dummies) instead of N_SIDED
	int		 find_aggr		= 0;		// --find-aggressor: run find_aggressor_wrapper instead of N_SIDED
												// (victim/known-aggressor row is hardcoded in find_aggressor_wrapper)
	int		 act_thresh		= 0;		// --act-thresh: run activation_threshold_test instead of N_SIDED
												// (target rows/sweep grid are hardcoded in activation_threshold_test)
	size_t   start_hugepage	= 1;		// --start-hugepage: 1-indexed hugepage to begin sweeping at (skips earlier ones)
	size_t   hint			= 0;		// --hint: 1-indexed hugepage to jump straight to, processing ONLY that one (0 = disabled)
	int		 verify_hash	= 0;		// --verify-hash: run verify_hash_fns() and exit
	size_t   scan_adj		= 1;		// -n/--scan-adj: how many rows beyond the aggressor
											// block to scan for flips, on each side (default: 1)
} ProfileParams;

int process_argv(int argc, char *argv[], ProfileParams *params);

#endif /* params.h */
