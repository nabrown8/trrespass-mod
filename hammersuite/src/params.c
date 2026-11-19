/*
 * Copyright (c) 2016 Andrei Tatar
 * Copyright (c) 2017-2018 Vrije Universiteit Amsterdam
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "include/params.h"
#include "include/utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>

void print_usage(char *bin_name)
{
	fprintf(stderr,
		"[ HELP ] - Usage ./%s [-h] [-r rounds] [-a aggr] [-o o_file] [-v] [--mem mem_size] [--[huge/HUGE] f_name] [--conf f_name] [--align val] [--off val] [--no-overwrite] [--fuzzing] [--start-hugepage N]\n",
		bin_name);
	fprintf(stderr, "\t-h\t\t\t= this help message\n");
	fprintf(stderr, "\t-v\t\t\t= verbose\n\n");
	fprintf(stderr, "\t-r rounds\t\t= number of rounds per tuple\t\t\t(default: %d)\n", ROUNDS_std);
	fprintf(stderr, "\t-a --aggr\t\t= number of aggressors\t\t\t\t(default: %d)\n", AGGR_std);
	fprintf(stderr,	"\t-o --o_file_prefix\t= prefix for output files\t\t\t(default: %s)\n", O_FILE_std);
	fprintf(stderr, "\t--mem mem_size\t\t= allocation size\t\t\t\t(default: %ld)\n",
		(uint64_t) ALLOC_SIZE);
	fprintf(stderr, "\t--huge f_name\t\t= hugetlbfs entry (1GB if HUGE)\t\t\t(default: %s)\n",
		HUGETLB_std);
	fprintf(stderr, "\t--conf f_name\t\t= SessionConfig file\t\t\t\t(default: %s)\n",
		CONFIG_NAME_std);
	fprintf(stderr, "\t--align val\t\t= alignment of the buffer\t\t\t(default: %ld)\n",
		(uint64_t) ALIGN_std);
	fprintf(stderr, "\t--off val\t\t= offset from first row\t\t\t\t(default: 0)\n");
	fprintf(stderr, "\t--no-overwrite\t\t= don't overwrite previous file\n");
	fprintf(stderr, "\t-V --victim-pattern\t= hex value for the victim patter\n");
	fprintf(stderr, "\t-T --target-pattern\t= hex value for the target pattern\n");
	fprintf(stderr, "\t-f --fuzzing\t\t= Start fuzzing (--aggr will be ignored)\n");
	fprintf(stderr, "\t-t --threshold\t\t= Align the hammering to refresh ops,\n\t\t\t\t looking at the memory latency in CPU cycles.\t(default: 0)\n");
	fprintf(stderr, "\t-P --phase-sweep\t= with -t/--threshold set, vary the delay inserted\n\t\t\t\t after each detected refresh spike and before hammering:\n\t\t\t\t 0, 20, 40, ... up to 2000ns, then wraps back to 0\t(default: off)\n");
	fprintf(stderr, "\t-H --hugepages N\t= number of 1GB hugepages to allocate\t\t(default: 1)\n\t\t\t\t (must already be reserved, e.g. via\n\t\t\t\t /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages)\n");
	fprintf(stderr, "\t-s --sweep\t\t= scan across all --hugepages, sampling as much\n\t\t\t\t of each one as possible, instead of the static target list\n");
	fprintf(stderr, "\t-D --delayed\t\t= use the staggered/delayed-aggressor hammer test\n\t\t\t\t (2 aggressors with a delay between activations, --aggr-2\n\t\t\t\t rows stepped through as fast as possible as dummies)\n\t\t\t\t instead of N_SIDED\n");
	fprintf(stderr, "\t-F --find-aggressor\t= run find_aggressor instead of N_SIDED: sweeps candidate\n\t\t\t\t second-aggressor rows against a known one to find which pair\n\t\t\t\t flips fastest (victim/known-aggressor row is hardcoded in\n\t\t\t\t find_aggressor_wrapper in test-suite.c)\n");
	fprintf(stderr, "\t-A --act-thresh\t\t= run activation_threshold_test instead of N_SIDED: for a fixed\n\t\t\t\t target row list, sweeps (total rounds x total wall-clock window)\n\t\t\t\t and reports flip rate out of 50 trials per cell (targets/grid\n\t\t\t\t are hardcoded in activation_threshold_test in test-suite.c)\n");
	fprintf(stderr, "\t--start-hugepage N\t= 1-indexed hugepage to begin --sweep at, skipping\n\t\t\t\t previously scanned ones (must be between 1 and --hugepages)\t(default: 1)\n");
	fprintf(stderr, "\t--hint N\t\t= 1-indexed hugepage to jump straight to, processing\n\t\t\t\t ONLY that one (skips the rest of the sweep entirely);\n\t\t\t\t for re-running a known-good spot without re-scanning\t(default: disabled)\n");
	fprintf(stderr, "\t--verify-hash\t\t= empirically test the bank hash functions via timing,\n\t\t\t\t then exit (uses -r for rounds/pair, -t for the cycle threshold)\n");
	fprintf(stderr, "\t-n --scan-adj N\t\t= how many rows beyond the aggressor block to scan\n\t\t\t\t for flips, on each side\t\t\t(default: 1)\n");
}

static int str2pat(const char *str, char **pat)
{
	char *endp = NULL;
	char tmp[3];
	char *p;
	tmp[2] = '\0';
	size_t len = strlen(str);
	if (len % 2) {
		return EINVAL;
	}
	len /= 2;

	p = (char *)malloc(len);
	for (size_t i = 0; i < len; i++) {
		tmp[0] = str[2 * i];
		tmp[1] = str[2 * i + 1];
		errno = 0;
		((uint8_t *) p)[i] = (uint8_t) strtol(tmp, &endp, 16);
		if (errno) {
			free(p);
			return errno;
		}
		if (*endp != '\0') {
			free(p);
			return EINVAL;
		}
	}
	*pat = p;
	return 0;
}

int process_argv(int argc, char *argv[], ProfileParams *p)
{

	/* Default */
	p->g_flags   = 0;
	p->tpat      = (char *)NULL;
	p->vpat      = (char *)NULL;
	p->threshold = 0;
	p->phase_sweep = 0;
	p->fuzzing   = 0;		// start fuzzing!!
	p->m_size    = ALLOC_SIZE;
	p->m_align   = ALIGN_std;
	p->rounds    = ROUNDS_std;
	p->base_off  = 0;
	p->huge_file = (char *)HUGETLB_std;
	p->conf_file = (char *)CONFIG_NAME_std;
	p->aggr      = AGGR_std;
	p->start_hugepage = 1;
	p->hint      = 0;
	p->scan_adj  = 1;
	p->find_aggr = 0;
	p->act_thresh = 0;


	const struct option long_options[] = {
		/* These options set a flag. */
		{"mem", required_argument, 0, 0},
		{"align", required_argument, 0, 0},
		{"huge", optional_argument, 0, 0},
		{"HUGE", optional_argument, 0, 0},
		{"conf", optional_argument, 0, 0},
		{"off", required_argument, 0, 0},
		{"no-overwrite", no_argument, 0, 0},
		{.name = "target-pattern",.has_arg = required_argument,.flag = NULL,.val='T'},
		{.name = "victim-pattern",.has_arg = required_argument,.flag = NULL,.val = 'V'},
		{.name = "aggr",.has_arg = required_argument,.flag = NULL,.val='a'},
		{.name = "fuzzing", .has_arg = no_argument, .flag = NULL, .val = 'f'},
		{.name = "threshold",.has_arg = required_argument,.flag = NULL,.val = 't'},
		{.name = "phase-sweep",.has_arg = no_argument,.flag = NULL,.val = 'P'},
		{.name = "hugepages",.has_arg = required_argument,.flag = NULL,.val = 'H'},
		{.name = "sweep",.has_arg = no_argument,.flag = NULL,.val = 's'},
		{.name = "delayed",.has_arg = no_argument,.flag = NULL,.val = 'D'},
		{.name = "find-aggressor",.has_arg = no_argument,.flag = NULL,.val = 'F'},
		{.name = "act-thresh",.has_arg = no_argument,.flag = NULL,.val = 'A'},
		{.name = "verify-hash",.has_arg = no_argument,.flag = NULL,.val = 'K'},
		{.name = "start-hugepage",.has_arg = required_argument,.flag = NULL,.val = 'S'},
		{.name = "hint",.has_arg = required_argument,.flag = NULL,.val = 'I'},
		{.name = "scan-adj",.has_arg = required_argument,.flag = NULL,.val = 'n'},
		{0, 0, 0, 0}
	};

	p->g_out_prefix = (char *)O_FILE_std;
	p->g_flags |= F_POPULATE;

	while (1) {
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		int arg = getopt_long(argc, argv, "o:d:r:hvV:T:a:ft:H:sDFAI:Pn:",
				      long_options, &option_index);

		if (arg == -1)
			break;

		switch (arg) {
		case 0:
			switch (option_index) {
			case 0:
				p->m_size = strtoull(optarg, NULL, 10);
				break;
			case 1:
				p->m_align = atoi(optarg);
				break;
			case 2:
				p->g_flags |= F_ALLOC_HUGE_2M;
			case 3:
				p->huge_file = (char *)malloc(sizeof(char) * strlen(optarg));
				strncpy(p->huge_file, optarg, strlen(optarg));
				p->g_flags |= F_ALLOC_HUGE_1G;
				break;
			case 4:
				p->g_flags |= F_CONFIG;
				if (!optarg)
					break;
				p->conf_file = (char *)malloc(sizeof(char) * strlen(optarg));
				strncpy(p->conf_file, optarg, strlen(optarg));
				break;
			case 5:
				p->base_off = atoi(optarg);
				break;
			case 6:
				p->g_flags |= F_NO_OVERWRITE;
				break;
			default:
				break;
			}
			break;
		case 'o':
			p->g_out_prefix = strdup(optarg);
			p->g_flags |= F_EXPORT;
			break;
		case 'r':
			p->rounds = atoi(optarg);
			break;
		case 'v':
			p->g_flags |= F_VERBOSE;
			break;
		case 'a':
			p->aggr = atoi(optarg);
			break;
		case 'T':
			if (str2pat(optarg, &(p->tpat))) {
				fprintf(stderr, "Invalid target fill pattern: %s\n", optarg);
				return -1;
			}
			break;
		case 'V':
			if (str2pat(optarg, &(p->vpat))) {
				fprintf(stderr, "Invalid victim fill pattern: %s\n", optarg);
				return -1;
			}
			break;
		case 'f':
			p->fuzzing = 1;
			break;
		case 't':
			p->threshold = atoi(optarg);
			break;
		case 'P':
			p->phase_sweep = 1;
			break;
		case 'H':
			p->n_hugepages = strtoull(optarg, NULL, 10);
			p->m_size = p->n_hugepages * GB(1);
			break;
		case 's':
			p->sweep_all = 1;
			break;
		case 'D':
			p->delayed = 1;
			break;
		case 'F':
			p->find_aggr = 1;
			break;
		case 'A':
			p->act_thresh = 1;
			break;
		case 'K':
			p->verify_hash = 1;
			break;
		case 'S':
			p->start_hugepage = strtoull(optarg, NULL, 10);
			if (p->start_hugepage < 1) {
				fprintf(stderr, "[ERROR] --start-hugepage must be >= 1\n");
				return -1;
			}
			break;
		case 'I':
			p->hint = strtoull(optarg, NULL, 10);
			if (p->hint < 1) {
				fprintf(stderr, "[ERROR] --hint must be >= 1\n");
				return -1;
			}
			break;
		case 'n':
			p->scan_adj = strtoull(optarg, NULL, 10);
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return -1;
		}
	}

	if (p->start_hugepage > p->n_hugepages) {
		fprintf(stderr,
			"[ERROR] --start-hugepage %zu is beyond --hugepages %zu\n",
			p->start_hugepage, p->n_hugepages);
		return -1;
	}
	if (p->hint > p->n_hugepages) {
		fprintf(stderr,
			"[ERROR] --hint %zu is beyond --hugepages %zu\n",
			p->hint, p->n_hugepages);
		return -1;
	}
#ifdef HUGE_YES
	p->g_flags |= F_ALLOC_HUGE_1G;
#endif

	if (p->g_flags & (F_ALLOC_HUGE_2M | F_ALLOC_HUGE_1G)) {
		if ((p->huge_fd = open(p->huge_file, O_CREAT | O_RDWR, 0755)) == -1) {
			perror("[ERROR] - Unable to open hugetlbfs");
			return -1;
		}
	}
	return 0;
}
