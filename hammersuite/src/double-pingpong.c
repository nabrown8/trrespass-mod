#include "include/hammer-suite.h"

#include "include/memory.h"
#include "include/utils.h"
#include "include/allocator.h"
#include "include/dram-address.h"
#include "include/addr-mapper.h"
#include "include/params.h"

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <time.h>

#define REFRESH_VAL "stdrefi"
#define OUT_HEAD "f_og, f_new, vict_addr, aggr_addr\n"

#define ROW_FIELD 		1
#define COL_FIELD 		1<<1
#define BK_FIELD 		1<<2
#define P_FIELD			1<<3
#define ALL_FIELDS		(ROW_FIELD | COL_FIELD | BK_FIELD)
#define FLIPTABLE

/*
 h_patt		= hammer pattern (e.g., DOUBLE_SIDED)
 d_patt		= data pattern	(e.g., RANDOM)
 vict_addr	= DRAMAddr for the bit flip in format bkXX.XrXXXX.cXXX
 f_og 		= byte original value
 f_new		= byte after bit flip
 f_mask		= bitmask of the bit flip
 base_row	= initial row being hammered *in this round*
 row_cnt	= number of rows being hammered *in this round*
 t_refi		= t_refi
 h_rounds	= number of hammering rounds
 aggr_addr	= addresses of aggressor rows in format bkXX.rXXXX.cXX

 */

// Ping-pong (aggressor_thread/dummy_thread): how many aggressor/dummy
// handoff pairs to run per refresh-spike sync, before the dummy thread
// re-syncs to the next spike. This is independent of (and normally much
// smaller than) the total round count passed in as patt->rounds/a->rounds
// -- that total keeps getting chased across as many refresh-spike bursts
// of this length as it takes.
#define ROUNDS_PER_REFRESH 2

extern ProfileParams *p;

FILE *out_fd            = NULL;
static uint64_t CL_SEED = 0x7bc661612e71168c;

static inline __attribute((always_inline))
char *cl_rand_gen(DRAMAddr * d_addr)
{
	static uint64_t cl_buff[8];
	for (int i = 0; i < 8; i++) {
		cl_buff[i] =
		    __builtin_ia32_crc32di(CL_SEED,
					   (d_addr->row + d_addr->bank +
					    (d_addr->col + i*8)));
	}
	return (char *)cl_buff;
}

typedef struct {
	DRAMAddr *d_lst;
	size_t len;
	size_t rounds;
} HammerPattern;

typedef struct {
	DRAMAddr d_vict;
	uint8_t f_og;
	uint8_t f_new;
	HammerPattern *h_patt;
} FlipVal;

typedef struct {
	MemoryBuffer *mem;
	SessionConfig *cfg;
	DRAMAddr d_base;	// base address for hammering
	ADDRMapper *mapper;	// dram mapper

	int (*hammer_test) (void *self);
} HammerSuite;

bool is_adjacent_to_aggressor(DRAMAddr * d_addr, HammerPattern * h_patt)
{
	for (int i = h_patt->len - 2; i < h_patt->len; i++) {
		if (h_patt->d_lst[i].bank == d_addr->bank &&
		    (h_patt->d_lst[i].row + 1 == d_addr->row ||
		     h_patt->d_lst[i].row - 1 == d_addr->row))
			return true;
	}
	return false;
}

char *dAddr_2_str(DRAMAddr d_addr, uint8_t fields)
{
	static char ret_str[64];
	char tmp_str[10];
	bool first = true;
	memset(ret_str, 0x00, 64);
	if (fields & ROW_FIELD) {
		first = false;
		sprintf(tmp_str, "r%05ld", d_addr.row);
		strcat(ret_str, tmp_str);
	}
	if (fields & BK_FIELD) {
		if (!first) {
			strcat(ret_str, ".");
		}
		sprintf(tmp_str, "bk%02ld", d_addr.bank);
		strcat(ret_str, tmp_str);
		first = false;
	}
	if (fields & COL_FIELD) {
		if (!first) {
			strcat(ret_str, ".");
		}
		sprintf(tmp_str, "col%04ld", d_addr.col);
		strcat(ret_str, tmp_str);
		first = false;
	}
	return ret_str;
}

char *hPatt_2_str(HammerPattern * h_patt, int fields)
{
	static char patt_str[1024];
	char *dAddr_str;

	memset(patt_str, 0x00, 1024);

	for (int i = 0; i < h_patt->len; i++) {
		dAddr_str = dAddr_2_str(h_patt->d_lst[i], fields);
		strcat(patt_str, dAddr_str);
		if (i + 1 != h_patt->len) {
			strcat(patt_str, "/");
		}

	}
	return patt_str;
}

void print_start_attack(HammerPattern *h_patt)
{
	fprintf(out_fd, "%s : ", hPatt_2_str(h_patt, ROW_FIELD | BK_FIELD));
	fflush(out_fd);
}

void print_end_attack()
{
	fprintf(out_fd, "\n");
	fflush(out_fd);
}

void export_flip(FlipVal * flip)
{
	if (p->g_flags & F_VERBOSE) {
		fprintf(stdout, "[FLIP] - (%02x => %02x)\t vict: %s \taggr: %s \n",
				flip->f_og, flip->f_new, dAddr_2_str(flip->d_vict, ALL_FIELDS),
				hPatt_2_str(flip->h_patt, ROW_FIELD | BK_FIELD));
		fflush(stdout);
	}

#ifdef FLIPTABLE
		fprintf(out_fd, "%02x,%02x,%s ", flip->f_og, flip->f_new,
				dAddr_2_str(flip->d_vict, ALL_FIELDS));
#else
		fprintf(out_fd, "%02x,%02x,%s,%s\n", flip->f_og, flip->f_new,
				dAddr_2_str(flip->d_vict, ALL_FIELDS), hPatt_2_str(flip->h_patt,
					ROW_FIELD | BK_FIELD | P_FIELD));
#endif
	fflush(out_fd);
}

void export_cfg(HammerSuite * suite)
{
	SessionConfig *cfg = suite->cfg;

	if (p->g_flags & F_VERBOSE) {
		fprintf(stdout,
			"Config: { h_cfg: %s, d_cfg: %s, h_rows: %ld, h_rounds: %ld, base: %s}\n",
			config_str[cfg->h_cfg], data_str[cfg->d_cfg],
			cfg->h_rows, cfg->h_rounds, dAddr_2_str(suite->d_base,
								ROW_FIELD |
								BK_FIELD));
	}

	fprintf(out_fd,
		"# { h_cfg: %s, d_cfg: %s, h_rows: %ld, h_rounds: %ld, base: %s}\n",
		config_str[cfg->h_cfg], data_str[cfg->d_cfg], cfg->h_rows,
		cfg->h_rounds, dAddr_2_str(suite->d_base,
					   ROW_FIELD | BK_FIELD));
	fflush(out_fd);
}

typedef struct {
    char **v_lst;
    size_t len;
    int rounds;               // TOTAL aggressor/dummy handoff pairs for this call
    size_t rounds_per_refresh;// burst length between refresh-spike re-syncs (<= rounds; 0/>= rounds = one burst for the whole call)
    size_t aggr_cnt;
    uint64_t inner_delay;     // cycles the aggressor waits between a0/a1/...
    uint64_t tsc_freq;        // for calibration
    /* --- synchronization --- */
    pthread_barrier_t barrier_ready;
    pthread_barrier_t barrier_start;
    pthread_barrier_t barrier_stop;
    volatile int shutdown;
    /* --- hot path ping-pong (cache-line aligned to avoid false sharing) --- */
    volatile int token __attribute__((aligned(64))); // 2=not started yet (waiting on dummy's kickoff), 0=aggressor's turn, 1=dummy's turn, -1=done
} HammerThreadArgs;

static HammerThreadArgs g_hammer_args;
static pthread_t        g_t_dummy, g_t_aggr;
static int              g_threads_init = 0;
static void *aggressor_thread(void *arg)
{
    HammerThreadArgs *a = (HammerThreadArgs *)arg;
    while (1) {
        pthread_barrier_wait(&a->barrier_ready);
        if (a->shutdown) break;
        fprintf(stderr, "[AGGR] past barrier_ready\n"); fflush(stderr);
        a->token = 2;          // not started -- wait for the dummy's refresh-spike kickoff
        mfence();
        pthread_barrier_wait(&a->barrier_start);
        fprintf(stderr, "[AGGR] past barrier_start, waiting for dummy's kickoff\n"); fflush(stderr);

        // Total rounds get chased across one or more refresh-aligned
        // bursts of rounds_per_refresh each (see ROUNDS_PER_REFRESH),
        // rather than a single burst spanning the whole round count.
        size_t total = (size_t) a->rounds;
        size_t burst = (a->rounds_per_refresh > 0 && a->rounds_per_refresh < total)
                           ? a->rounds_per_refresh : total;

        size_t done = 0;
        while (done < total) {
            size_t this_burst = (burst < total - done) ? burst : (total - done);

            for (size_t i = 0; i < this_burst; i++) {
                // first round of a burst: blocks until the dummy thread sees
                // its latency spike and hands off. Every later round in this
                // burst: already satisfied by the dummy's handback at the
                // end of the previous round.
                while (a->token != 0)
                    asm volatile("pause");

                mfence();
                // access + flush one aggressor at a time, waiting inner_delay
                // cycles between each activation: a0, wait, a1, wait, ...
                for (size_t j = 0; j < a->aggr_cnt; j++) {
                    (void)*(volatile char *)a->v_lst[j];
                    clflushopt(a->v_lst[j]);

                    if (a->inner_delay > 0) {
                        uint64_t t0 = rdtscp();
                        while ((rdtscp() - t0) < a->inner_delay)
                            asm volatile("pause");
                    }
                }
                asm volatile("sfence" ::: "memory");

                // hand off to the dummy thread and wait for it to finish its pass
                a->token = 1;
                while (a->token != 0)
                    asm volatile("pause");
            }

            done += this_burst;
            // More rounds remain beyond this burst: force a wait for the
            // dummy's next refresh-spike kickoff instead of racing straight
            // into another round off the stale handback token.
            if (done < total)
                a->token = 2;
        }

        a->token = -1;
        pthread_barrier_wait(&a->barrier_stop);
    }
    return NULL;
}

static void *dummy_thread(void *arg)
{
    HammerThreadArgs *a = (HammerThreadArgs *)arg;
    while (1) {
        pthread_barrier_wait(&a->barrier_ready);
        if (a->shutdown) break;
        fprintf(stderr, "[DUMMY] past barrier_ready\n"); fflush(stderr);
        pthread_barrier_wait(&a->barrier_start);
        fprintf(stderr, "[DUMMY] past barrier_start, entering burst loop\n"); fflush(stderr);

        char *first_dummy = a->v_lst[a->aggr_cnt];

        // Mirrors aggressor_thread's burst split so both threads walk the
        // same deterministic sequence of burst sizes in lock-step, purely
        // off the handoff token.
        size_t total = (size_t) a->rounds;
        size_t burst = (a->rounds_per_refresh > 0 && a->rounds_per_refresh < total)
                           ? a->rounds_per_refresh : total;

        size_t done = 0;
        while (done < total) {
            // Kickoff: wait for a refresh-induced latency spike (p->threshold)
            // before doing anything else. The spike-detecting access below IS
            // the activation to the first dummy -- there is no separate access
            // for it once the spike is seen. Runs once per burst, so every
            // burst of rounds_per_refresh rounds re-syncs to a fresh refresh
            // instead of just the very first one for the whole call.
            if (p->threshold > 0) {
                uint64_t t0 = 0, t1 = 0;
                uint64_t spin_iters = 0;
                int64_t max_delta = 0;
                uint64_t wait_start = realtime_now();
                while (llabs((int64_t) t1 - (int64_t) t0) < p->threshold) {
                    t0 = rdtscp();
                    (void)*(volatile char *)first_dummy;
                    t1 = rdtscp();
                    clflushopt(first_dummy);

                    int64_t delta = llabs((int64_t) t1 - (int64_t) t0);
                    if (delta > max_delta) max_delta = delta;
                    spin_iters++;

                    // every ~2M iterations: report whether we're actually
                    // still spinning (vs blocked) and how close the biggest
                    // delta seen so far has come to p->threshold -- if this
                    // never gets close, the threshold is miscalibrated for
                    // this system and the spike this loop waits for will
                    // never be seen.
                    if ((spin_iters & 0x1FFFFF) == 0) {
                        fprintf(stderr,
                            "[DUMMY] still waiting for refresh spike: %lu iters, %lu ms elapsed, "
                            "max_delta=%ld threshold=%d\n",
                            spin_iters, (realtime_now() - wait_start) / 1000000,
                            max_delta, p->threshold);
                        fflush(stderr);
                    }
                }
            } else {
                (void)*(volatile char *)first_dummy;
                clflushopt(first_dummy);
            }
            asm volatile("sfence" ::: "memory");

            // hand off to the aggressor thread so it can hit its aggressor(s)
            a->token = 0;

            size_t this_burst = (burst < total - done) ? burst : (total - done);
            for (size_t i = 0; i < this_burst; i++) {
                // wait for aggressor to hand off after hitting its aggressor(s)
                while (a->token != 1) {
                    if (a->token == -1) goto round_done;
                    asm volatile("pause");
                }

                // step through every remaining dummy, then hit the first dummy
                // again last, closing the loop back to where this round began
                for (size_t j = a->aggr_cnt + 1; j < a->len; j++)
                    (void)*(volatile char *)a->v_lst[j];
                (void)*(volatile char *)first_dummy;
                for (size_t j = a->aggr_cnt + 1; j < a->len; j++)
                    clflushopt(a->v_lst[j]);
                clflushopt(first_dummy);
                asm volatile("sfence" ::: "memory");

                // hand back to aggressor
                a->token = 0;
            }

            done += this_burst;
        }

        round_done:
        pthread_barrier_wait(&a->barrier_stop);
    }
    return NULL;
}

// Ping-pong delayed hammer, refresh-synced: the dummy thread first waits
// for a refresh-induced latency spike (p->threshold) on its first dummy
// row -- that spike-detecting access doubles as the activation to it --
// then hands off to the aggressor thread. The aggressor accesses+flushes
// its aggr_cnt aggressors one at a time (waiting inner_delay cycles
// between each) and hands back; the dummy then steps through every
// remaining dummy row plus the first dummy again (closing the loop) and
// hands back to the aggressor. This repeats for ROUNDS_PER_REFRESH handoff
// pairs, then re-syncs to the next refresh spike and does another
// ROUNDS_PER_REFRESH-pair burst, and so on until patt->rounds total handoff
// pairs have run (ROUNDS_PER_REFRESH is normally much smaller than
// patt->rounds, so one call to hammer_with_delay spans many refreshes).
uint64_t hammer_with_delay(HammerPattern *patt, MemoryBuffer *mem,
                            size_t aggr_cnt, uint64_t inner_delay)
{
    char **v_lst = (char**)malloc(sizeof(char*) * patt->len);
    for (size_t i = 0; i < patt->len; i++)
        v_lst[i] = phys_2_virt(dram_2_phys(patt->d_lst[i], mem), mem);
    if (!g_threads_init) {
        pthread_barrier_init(&g_hammer_args.barrier_ready, NULL, 3);
        pthread_barrier_init(&g_hammer_args.barrier_start, NULL, 3);
        pthread_barrier_init(&g_hammer_args.barrier_stop,  NULL, 3);
        g_hammer_args.shutdown = 0;
        int rc;
        if ((rc = pthread_create(&g_t_aggr,  NULL, aggressor_thread, &g_hammer_args)))
            fprintf(stderr, "[WARN] - pthread_create(aggressor) failed: %s\n", strerror(rc));
        if ((rc = pthread_create(&g_t_dummy, NULL, dummy_thread,     &g_hammer_args)))
            fprintf(stderr, "[WARN] - pthread_create(dummy) failed: %s\n", strerror(rc));
        // Pin aggressor to core 0, dummy to core 1, main to core 2 -- if any
        // of these fail (e.g. fewer than 3 cores available, or the process
        // was started under taskset), the affected thread silently keeps
        // whatever affinity it already had, which can put two of these
        // busy-spinning threads on the same core and make every token
        // handoff wait for an OS context switch instead of a few cycles.
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        if ((rc = pthread_setaffinity_np(g_t_aggr, sizeof(cpu_set_t), &cpuset)))
            fprintf(stderr, "[WARN] - pin aggressor to core 0 failed: %s\n", strerror(rc));
        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        if ((rc = pthread_setaffinity_np(g_t_dummy, sizeof(cpu_set_t), &cpuset)))
            fprintf(stderr, "[WARN] - pin dummy to core 1 failed: %s\n", strerror(rc));
        CPU_ZERO(&cpuset);
        CPU_SET(2, &cpuset);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0)
            fprintf(stderr, "[WARN] - pin main to core 2 failed: %s\n", strerror(errno));
        fflush(stderr);
        g_threads_init = 1;
    }
    g_hammer_args.v_lst             = v_lst;
    g_hammer_args.len               = patt->len;
    g_hammer_args.rounds            = patt->rounds;
    g_hammer_args.rounds_per_refresh = ROUNDS_PER_REFRESH;
    g_hammer_args.aggr_cnt          = aggr_cnt;
    g_hammer_args.inner_delay       = inner_delay;
    fprintf(stderr, "[SYNC] waiting on barrier_ready\n"); fflush(stderr);
    pthread_barrier_wait(&g_hammer_args.barrier_ready);
    fprintf(stderr, "[SYNC] past barrier_ready, waiting on barrier_start\n"); fflush(stderr);
    uint64_t t0 = realtime_now();
    pthread_barrier_wait(&g_hammer_args.barrier_start);
    fprintf(stderr, "[SYNC] past barrier_start, waiting on barrier_stop\n"); fflush(stderr);
    pthread_barrier_wait(&g_hammer_args.barrier_stop);
    fprintf(stderr, "[SYNC] past barrier_stop\n"); fflush(stderr);
    uint64_t t1 = realtime_now();
    free(v_lst);
    return (t1 - t0) / patt->rounds;
}

// DRAMAddr needs to be a copy in order to leave intact the original address
void fill_stripe(DRAMAddr d_addr, uint8_t val, ADDRMapper * mapper)
{
	for (size_t col = 0; col < ROW_SIZE; col += (1 << 6)) {
		d_addr.col = col;
		DRAM_pte d_pte = get_dram_pte(mapper, &d_addr);
		memset(d_pte.v_addr, val, CL_SIZE);
	}

}

void fill_row(HammerSuite *suite, DRAMAddr *d_addr, HammerData data_patt, int reverse)
{
	/* Skip rows that were never registered with init_addr_mapper */
	if (d_addr->row < suite->mapper->base_row ||
	    d_addr->row >= suite->mapper->base_row + suite->cfg->h_rows)
		return;

	if (p->vpat != (void *)NULL && p->tpat != (void *)NULL) {
		uint8_t pat = reverse ? *p->vpat : *p->tpat;
		fill_stripe(*d_addr, pat, suite->mapper);
		return;
	}

	if (reverse) {
		data_patt = (HammerData)((int)data_patt ^(int)REVERSE);
	}

	switch (data_patt) {
	case RANDOM:
		// rows are already filled for random data patt
		break;
	case ONE_TO_ZERO:
		fill_stripe(*d_addr, 0x00, suite->mapper);
		break;
	case ZERO_TO_ONE:
		fill_stripe(*d_addr, 0xff, suite->mapper);
		break;
	default:
		// fprintf(stderr, "[ERROR] - Wrong data pattern %d\n", data_patt);
		// exit(1);
		break;
	}

}

void cl_rand_fill(DRAM_pte * pte)
{
	char *rand_data = cl_rand_gen(&pte->d_addr);
	memcpy(pte->v_addr, rand_data, CL_SIZE);
}

uint64_t cl_rand_comp(DRAM_pte * pte)
{
	char *rand_data = cl_rand_gen(&pte->d_addr);
	uint64_t res = 0;
	for (int i = 0; i < CL_SIZE; i++) {
		if (*(pte->v_addr + i) != rand_data[i]) {
			res |= 1UL<<i;
		}
	}
	return res;
}

// bank < 0 means "every bank" (the original behavior); bank >= 0 restricts
// the fill to just that one bank, so callers that already know which
// single bank they're about to hammer (e.g. an explicit target list) don't
// have to pay for initializing the other get_banks_cnt()-1 banks too.
void init_random_bank(HammerSuite * suite, int bank)
{
	int fd;
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		perror("[ERROR] - Unable to open /dev/urandom");
		exit(1);
	}
	if (CL_SEED == 0) {
		if (read(fd, &CL_SEED, sizeof(CL_SEED)) == -1) {
			perror("[ERROR] - Unable to read /dev/urandom");
			exit(1);
		}
	}
	fprintf(stderr,"#seed: %lx\n", CL_SEED);
	close(fd);
	ADDRMapper *mapper = suite->mapper;
	DRAMAddr d_tmp;
	size_t bk_lo = bank < 0 ? 0 : (size_t)bank;
	size_t bk_hi = bank < 0 ? get_banks_cnt() : (size_t)bank + 1;
	for (size_t bk = bk_lo; bk < bk_hi; bk++) {
		d_tmp.bank = bk;
		for (size_t row = 0; row < suite->cfg->h_rows; row++) {
			d_tmp.row = suite->mapper->base_row + row;
			for (size_t col = 0; col < ROW_SIZE; col += (1 << 6)) {
				d_tmp.col = col;
				DRAM_pte d_pte = get_dram_pte(mapper, &d_tmp);
				cl_rand_fill(&d_pte);
			}
		}
	}
}

void init_random(HammerSuite * suite)
{
	init_random_bank(suite, -1);
}

void init_stripe_bank(HammerSuite * suite, uint8_t val, int bank)
{
	ADDRMapper *mapper = suite->mapper;
	DRAMAddr d_tmp;
	size_t bk_lo = bank < 0 ? 0 : (size_t)bank;
	size_t bk_hi = bank < 0 ? get_banks_cnt() : (size_t)bank + 1;
	for (size_t bk = bk_lo; bk < bk_hi; bk++) {
		d_tmp.bank = bk;
		for (size_t row = 0; row < suite->cfg->h_rows; row++) {

			d_tmp.row = suite->mapper->base_row + row;
			for (size_t col = 0; col < ROW_SIZE; col += (1 << 6)) {
				d_tmp.col = col;
				DRAM_pte d_pte = get_dram_pte(mapper, &d_tmp);

				memset(d_pte.v_addr, val, CL_SIZE);
			}
		}
	}
}

void init_stripe(HammerSuite * suite, uint8_t val)
{
	init_stripe_bank(suite, val, -1);
}

void init_chunk(HammerSuite * suite)
{

	if (p->vpat != (void *)NULL && p->tpat != (void *)NULL) {
		// fprintf(stderr, "init chunk\n");
		init_stripe(suite, (uint8_t) * p->vpat);
		return;
	}


	SessionConfig *cfg = suite->cfg;
	switch (cfg->d_cfg) {
	case RANDOM:
		init_random(suite);
		break;
	case ONE_TO_ZERO:
		init_stripe(suite, 0xff);
		break;
	case ZERO_TO_ONE:
		init_stripe(suite, 0x00);
		break;
	default:
		fprintf(stderr, "[ERROR] - Wrong data pattern %d\n",
			cfg->d_cfg);
		exit(1);
		break;
	}
}

// Same dispatch as init_chunk(), but restricted to one bank -- for
// staggered_hammer's explicit target-list path, which already knows the
// single bank it's about to hammer and has no use for initializing the
// other get_banks_cnt()-1 banks of the chunk.
void init_chunk_bank(HammerSuite * suite, int bank)
{
	if (p->vpat != (void *)NULL && p->tpat != (void *)NULL) {
		init_stripe_bank(suite, (uint8_t) * p->vpat, bank);
		return;
	}

	SessionConfig *cfg = suite->cfg;
	switch (cfg->d_cfg) {
	case RANDOM:
		init_random_bank(suite, bank);
		break;
	case ONE_TO_ZERO:
		init_stripe_bank(suite, 0xff, bank);
		break;
	case ZERO_TO_ONE:
		init_stripe_bank(suite, 0x00, bank);
		break;
	default:
		fprintf(stderr, "[ERROR] - Wrong data pattern %d\n",
			cfg->d_cfg);
		exit(1);
		break;
	}
}

bool scan_random(HammerSuite * suite, HammerPattern * h_patt, size_t adj_rows)
{
	ADDRMapper *mapper = suite->mapper;
	SessionConfig *cfg = suite->cfg;

	DRAMAddr d_tmp;
	FlipVal flip;
	bool flipped = false;

	d_tmp.bank = h_patt->d_lst[0].bank;

	size_t start =
		h_patt->d_lst[h_patt->len - 2].row + 1;

	size_t end =
		h_patt->d_lst[h_patt->len - 1].row;

	for (size_t row = start; row < end; row++) {
		d_tmp.row = row;
		for (size_t col = 0; col < ROW_SIZE; col += (1 << 6)) {
			d_tmp.col = col;
			DRAM_pte pte = get_dram_pte(mapper, &d_tmp);
			clflush(pte.v_addr);
			cpuid();
			uint64_t res = cl_rand_comp(&pte);
			if (res) {
				char *rand_data = cl_rand_gen(&pte.d_addr);
				for (int off = 0; off < CL_SIZE; off++) {
					if (!((res >> off) & 1))
						continue;
					d_tmp.col = col + off;

					flip.d_vict = d_tmp;
					flip.f_og = (uint8_t) rand_data[off];
					flip.f_new = *(uint8_t *) (pte.v_addr + off);
					flip.h_patt = h_patt;
					assert(flip.f_og != flip.f_new);
					if (is_adjacent_to_aggressor(&d_tmp, h_patt)) {
						export_flip(&flip);
						flipped = true;
					}
				}
				memcpy((char *)(pte.v_addr), rand_data, CL_SIZE);
			}
		}
	}
	return flipped;
}

bool in_hPatt(DRAMAddr * d_addr, HammerPattern * h_patt)
{
	for (int i = 0; i < h_patt->len; i++) {
		if (d_addr_eq_row(&h_patt->d_lst[i], d_addr))
			return true;
	}
	return false;
}

// h_patt->d_lst's order is the hammering *access* order and may be any
// permutation (e.g. to try different offsets/orderings within a refresh
// window) -- it does NOT have to be sorted by row. These two helpers
// derive the geometric facts (which rows border the scan, which rows sit
// between aggressors) from the row values themselves rather than from
// list adjacency, so the access order can be anything without corrupting
// victim-row selection or scan bounds.

void hPatt_row_bounds(HammerPattern * h_patt, size_t *lo, size_t *hi)
{
	*lo = *hi = h_patt->d_lst[0].row;
	for (size_t i = 1; i < h_patt->len; i++) {
		if (h_patt->d_lst[i].row < *lo) *lo = h_patt->d_lst[i].row;
		if (h_patt->d_lst[i].row > *hi) *hi = h_patt->d_lst[i].row;
	}
}

uint64_t cl_stripe_cmp(DRAM_pte * pte, uint8_t val)
{
	uint64_t res = 0;
#ifdef POINTER_CHAISING
	for (int_t i = 8; i < CL_SIZE; i++) {
#else
	for (int i = 0; i < CL_SIZE; i++) {
#endif
		if (*(uint8_t*) (pte->v_addr + i) != val) {
			res |= 1UL<<i;
		}
	}
	return res;
}

bool scan_stripe(HammerSuite * suite, HammerPattern * h_patt, size_t adj_rows,
		 uint8_t val)
{
	ADDRMapper *mapper = suite->mapper;
	SessionConfig *cfg = suite->cfg;

	DRAMAddr d_tmp;
	FlipVal flip;
	bool flipped = false;

	d_tmp.bank = h_patt->d_lst[0].bank;
	uint8_t t_val = val;

	// Bounds come from the min/max row actually in h_patt, not
	// d_lst[0]/d_lst[len-1] -- d_lst's order is the hammering access
	// order and may not be sorted (see hPatt_row_bounds).
	size_t row_lo, row_hi;
	hPatt_row_bounds(h_patt, &row_lo, &row_hi);
	size_t start = row_lo - 1; //top lines in both secs to full-test, not just the row between last 2
	size_t end = row_hi + 1;

	for (size_t row = start; row < end; row++) {
		d_tmp.row = row;
		t_val = val;
		if (in_hPatt(&d_tmp, h_patt))
			if (p->tpat != (void *)NULL && p->vpat != (void *)NULL)
				t_val = (uint8_t) * p->tpat;
			else
				t_val ^= 0xff;

		for (size_t col = 0; col < ROW_SIZE; col += (1 << 6)) {
			d_tmp.col = col;
			DRAM_pte pte = get_dram_pte(mapper, &d_tmp);
			clflush(pte.v_addr);
			cpuid();

			uint64_t res = cl_stripe_cmp(&pte, t_val);
			if (res) {
				for (int off = 0; off < CL_SIZE; off++) {
					if (!((res >> off) & 1))
						continue;
					d_tmp.col = col + off;

					flip.d_vict = d_tmp;
					flip.f_og = (uint8_t) t_val;
					flip.f_new = *(uint8_t *) (pte.v_addr + off);
					flip.h_patt = h_patt;
					//if (is_adjacent_to_aggressor(&d_tmp, h_patt)) {
						export_flip(&flip);
						flipped = true;
					//}
					memset(pte.v_addr + off, t_val, 1);
				}
				memset((char *)(pte.v_addr), t_val, CL_SIZE);
			}
		}
	}
	return flipped;
}

// TODO adj_rows should tell how many rows to scan out of the bank. Not currently used
bool scan_rows(HammerSuite * suite, HammerPattern * h_patt, size_t adj_rows)
{
	if (p->vpat != (void *)NULL && p->tpat != (void *)NULL) {
		return scan_stripe(suite, h_patt, adj_rows, (uint8_t) * p->vpat);
	}

	SessionConfig *cfg = suite->cfg;
	switch (cfg->d_cfg) {
	case RANDOM:
		return scan_random(suite, h_patt, adj_rows);
	case ONE_TO_ZERO:
		return scan_stripe(suite, h_patt, adj_rows, 0xff);
	case ZERO_TO_ONE:
		return scan_stripe(suite, h_patt, adj_rows, 0x00);
	default:
		fprintf(stderr, "[ERROR] - Wrong data pattern %d\n",
			cfg->d_cfg);
		exit(1);
		break;
	}
}

// Scans across every reserved 1GB hugepage in mem (mem->size / GB(1) of them),
// treating each as its own independent DRAM-addressing domain (own d_base,
// own ADDRMapper) since separate hugepages are not physically contiguous.
// Within each hugepage, samples as many rows as fit (rows_per_hugepage).
//
// This is the per-hugepage driver for hammer_test: g_dram_base_phys/
// suite->d_base/suite->mapper only ever cover one hugepage's worth of rows
// (see dram_2_phys()'s base-combining logic, which silently corrupts row
// bits once a row crosses a 1GB hugepage boundary), so hammer_test needs
// re-basing per hugepage to safely cover more than rows_per_hugepage rows.
int hugepage_sweep_test(HammerSuite * suite)
{
	MemoryBuffer *mem = suite->mem;
	SessionConfig *cfg = suite->cfg;

	uint64_t banks = get_banks_cnt();
	// NOT GB(1)/(ROW_SIZE*banks): that assumes consecutive row values are
	// exactly ROW_SIZE*banks apart in physical address space, which only
	// holds if row_mask's lowest set bit lines up with that stride. The
	// real row-to-address stride is whatever row_mask's ctz says it is
	// (there can be extra interleaving bits between col_mask and row_mask
	// beyond what bank count alone accounts for), so derive it from
	// row_mask directly or this silently computes too many "rows" per
	// hugepage and walks off the end of the real 1GB allocation.
	uint64_t rows_per_hugepage =
	    GB(1) >> __builtin_ctzl(get_dram_layout()->row_mask);
	cfg->h_rows = rows_per_hugepage;

	size_t n_hugepages = mem->size / GB(1);
	fprintf(stderr, "[SWEEP] %zu hugepage(s), %lu rows/hugepage, %lu banks\n",
		n_hugepages, rows_per_hugepage, banks);

	for (size_t hp = 0; hp < n_hugepages; hp++) {
		// --hint jumps straight to one known hugepage and processes ONLY
		// that one (for re-poking a spot you already found, without
		// re-sweeping everything before it). Takes priority over
		// --start-hugepage, which just skips ones scanned on a prior run
		// but still continues through the rest.
		if (p->hint > 0) {
			if (hp + 1 != p->hint)
				continue;
		} else if (hp + 1 < p->start_hugepage) {
			// --start-hugepage is 1-indexed (matches the "[SWEEP] hugepage N/M"
			// log lines below), so previously scanned hugepages can be skipped.
			continue;
		}
		char *chunk_base = mem->buffer + hp * GB(1);
		physaddr_t chunk_phys = virt_2_phys(chunk_base, mem);

		// phys_2_dram(chunk_phys).row is NOT guaranteed to already be a
		// clean multiple of rows_per_hugepage: chunk_phys is 1GB-aligned,
		// but g_mem_layout's PCI-hole hoist offset isn't a multiple of
		// 1GB (0x20000000 vs 0x40000000 here), so linearizing a hoisted
		// (>= base_value) chunk_phys lands some of its low (fractional)
		// bits inside row_mask -- those bits are real and required (they
		// select *this* physical hugepage), so clearing them would quietly
		// retarget a different, unallocated 1GB region. We shrink how many
		// rows we sweep for this *part* so d_base.row+row never carries
		// into the bits that select a different hugepage -- but that
		// trimmed-off leftover is still real, hammerable rows inside this
		// same hugepage, just reachable from a different real physical
		// base. get_linear_phys()/get_hoisted_phys() are both just a
		// conditional +/- g_mem_layout.offset, so advancing the real phys
		// address by exactly that offset lands precisely on the
		// linear-space boundary this part's trimming stopped short of.
		// Loop over parts until every row in this hugepage has been
		// covered by some part (ordinarily 1 part; 2 when the hoist
		// splits it).
		physaddr_t sub_phys = chunk_phys;
		uint64_t rows_done = 0;
		int part = 0;
		while (rows_done < rows_per_hugepage) {
			set_dram_base_phys(sub_phys);
			DRAMAddr d_base = phys_2_dram(sub_phys);
			d_base.row += cfg->base_off;
			d_base.col = 0;

			uint64_t used = d_base.row & (rows_per_hugepage - 1);
			uint64_t safe_rows = rows_per_hugepage - used;
			uint64_t remaining = rows_per_hugepage - rows_done;
			cfg->h_rows = safe_rows < remaining ? safe_rows : remaining;

			fprintf(stderr,
				"[SWEEP] hugepage %zu/%zu part %d base=%s (%lu safe rows)\n",
				hp + 1, n_hugepages, part,
				dAddr_2_str(d_base, ALL_FIELDS), cfg->h_rows);

			init_addr_mapper(suite->mapper, mem, &d_base, cfg->h_rows);
			suite->d_base = d_base;

			suite->hammer_test(suite);

			tear_down_addr_mapper(suite->mapper);

			rows_done += cfg->h_rows;
			if (rows_done >= rows_per_hugepage)
				break;

			sub_phys += get_dram_layout()->offset;
			part++;
		}

		if (p->hint > 0 && hp + 1 == p->hint)
			break;	// --hint means "just this one hugepage" -- done
	}
	return 0;
}

// Fills aggressor/dummy rows for one aggr_n-wide window and runs it through
// hammer_with_delay (2 real aggressors + the rest stepped as dummies),
// scanning for flips. Shared by staggered_hammer (explicit row list) and
// staggered_hammer_scan (generic sweep) so both stay in sync.
// Returns true if any of the up-to-50 hammer attempts in this window
// found a flip (and stops early as soon as one does -- no need to keep
// re-hammering a spot that already flipped).
static bool staggered_hammer_window(HammerSuite *suite, HammerPattern *h_patt,
                                     uint64_t inner_delay)
{
    SessionConfig *cfg = suite->cfg;

    fprintf(stderr, "[HAMMER] - %s: ",
            hPatt_2_str(h_patt, ROW_FIELD));

#ifdef FLIPTABLE
    print_start_attack(h_patt);
#endif

    /*
     * Fill aggressor rows with aggressor pattern
     */
    for (int idx = 0; idx < h_patt->len; idx++)
        fill_row(suite, &h_patt->d_lst[idx], cfg->d_cfg, 0);

    /*
     * Fill rows between aggressors as victims/dummies
     * (only if same bank and increasing rows)
     */
    for (int idx = 0; idx < h_patt->len - 1; idx++) {

        DRAMAddr lo = h_patt->d_lst[idx];
        DRAMAddr hi = h_patt->d_lst[idx + 1];

        if (lo.bank != hi.bank)
            continue;

        if (hi.row <= lo.row + 1)
            continue;

        for (size_t dummy_row = lo.row + 1;
             dummy_row < hi.row;
             dummy_row++)
        {
            DRAMAddr d_dummy = lo;
            d_dummy.row = dummy_row;

            fill_row(suite, &d_dummy, cfg->d_cfg, 1);
        }
    }

	bool flip_found = false;
	for (int i = 0; i < 50; i++) {
		h_patt->rounds = cfg->h_rounds;

		time_t t_start = time(NULL);
		char start_buf[9], end_buf[9];
		strftime(start_buf, sizeof(start_buf), "%H:%M:%S", localtime(&t_start));
		fprintf(stderr, "[attempt %d/50 start=%s] ", i + 1, start_buf);
		fflush(stderr);

		uint64_t ns_per_round = hammer_with_delay(h_patt, suite->mem, 1, inner_delay);

		time_t t_end = time(NULL);
		strftime(end_buf, sizeof(end_buf), "%H:%M:%S", localtime(&t_end));

		fprintf(stderr, "end=%s %lu ", end_buf, ns_per_round);

		if (scan_rows(suite, h_patt, 0)) {
			flip_found = true;
			break;
		}

		// let the DRAM state settle before the next attempt
		usleep(200000);
    }

    if (!flip_found)
        fprintf(stderr, "\n[ATTEMPTS] - all 50 attempts failed: %s\n",
                hPatt_2_str(h_patt, ROW_FIELD | BK_FIELD));

#ifdef FLIPTABLE
    print_end_attack();
#endif

    fprintf(stderr, "\n");
    return flip_found;
}

// True if every row in this aggr_n-wide window of fixed targets actually
// falls inside the row range suite->mapper is currently set up for (i.e.
// the chunk/hugepage suite->d_base/cfg->h_rows describes right now).
static bool staggered_window_in_range(HammerSuite *suite, const DRAMAddr *window, int aggr_n)
{
    SessionConfig *cfg = suite->cfg;
    for (int i = 0; i < aggr_n; i++) {
        size_t row = window[i].row;
        if (row < suite->d_base.row || row >= suite->d_base.row + cfg->h_rows)
            return false;
    }
    return true;
}

int staggered_hammer(HammerSuite *suite,
                      const DRAMAddr *targets,
                      size_t target_cnt,
                      uint64_t inner_delay)
{
    SessionConfig  *cfg = suite->cfg;

    HammerPattern h_patt;

    if (target_cnt == 0)
        return 0;

    // targets are fixed absolute DRAMAddrs, but hugepage_sweep_test
    // re-bases suite->d_base/cfg->h_rows (and g_dram_base_phys) per
    // hugepage/chunk and calls us once per chunk. dram_2_phys() encodes
    // rows relative to whichever base is currently active, so the same
    // DRAMAddr resolves to a different -- usually out-of-range --
    // physical address on every chunk except the one that actually
    // contains these rows. Bail out before init_chunk()/malloc if none of
    // our windows are reachable from the current chunk, instead of
    // wasting a full pass hammering the wrong physical memory.
    bool any_in_range = false;
    for (size_t start_idx = 0;
         start_idx + cfg->aggr_n <= target_cnt;
         start_idx++)
    {
        if (staggered_window_in_range(suite, &targets[start_idx], cfg->aggr_n)) {
            any_in_range = true;
            break;
        }
    }
    if (!any_in_range)
        return 0;

    h_patt.len    = cfg->aggr_n;
    h_patt.rounds = cfg->h_rounds;
    h_patt.d_lst  = (DRAMAddr *)malloc(sizeof(DRAMAddr) * h_patt.len);

    if (!h_patt.d_lst)
        return 0;

    memset(h_patt.d_lst, 0, sizeof(DRAMAddr) * h_patt.len);

    // All of targets[] is expected to share one bank (that's the whole
    // point of a fixed, deliberately-pinned target list) -- only
    // initialize that bank instead of every bank in the chunk.
    init_chunk_bank(suite, (int)targets[0].bank);
    fprintf(stderr, "CL_SEED: %lx\n", CL_SEED);

    /*
     * Slide a window of aggr_n entries across the user-supplied list.
     *
     * Example:
     * if aggr_n = 3 and targets = [A B C D E]
     * patterns tested:
     *   A B C
     *   B C D
     *   C D E
     *
     * If you want non-overlapping groups instead, replace start_idx++
     * with start_idx += cfg->aggr_n
     *
     * targets is a fixed spot you've deliberately pinned down (unlike the
     * dynamic scan path, which explores many spots and must move on), so
     * keep re-running this same list indefinitely until one of its
     * windows actually flips, instead of giving up after one pass.
     */
    bool flip_found = false;
    while (!flip_found) {
        for (size_t start_idx = 0;
             start_idx + cfg->aggr_n <= target_cnt;
             start_idx++)
        {
            if (!staggered_window_in_range(suite, &targets[start_idx], cfg->aggr_n))
                continue;

            for (int i = 0; i < cfg->aggr_n; i++)
                h_patt.d_lst[i] = targets[start_idx + i];

            if (staggered_hammer_window(suite, &h_patt, inner_delay)) {
                flip_found = true;
                break;
            }
        }
    }

    free(h_patt.d_lst);
	return 0;
}

// Generic fallback for staggered_hammer_wrapper when no explicit row list
// is configured: builds aggr_n-wide, stride-2 windows across every row/bank
// reachable from suite->d_base/cfg->h_rows, so hugepage_sweep_test's
// per-hugepage re-basing still makes this cover the whole buffer, not just
// one chunk.
static int staggered_hammer_scan(HammerSuite *suite, uint64_t inner_delay)
{
    SessionConfig *cfg = suite->cfg;
    DRAMAddr d_base = suite->d_base;
    d_base.col = 0;

    HammerPattern h_patt;
    h_patt.len    = cfg->aggr_n;
    h_patt.rounds = cfg->h_rounds;
    h_patt.d_lst  = (DRAMAddr *) malloc(sizeof(DRAMAddr) * h_patt.len);
    memset(h_patt.d_lst, 0x00, sizeof(DRAMAddr) * h_patt.len);

    init_chunk(suite);
    fprintf(stderr, "CL_SEED: %lx\n", CL_SEED);

    size_t n_rows = cfg->h_rows;
    fprintf(stderr, "Hammering %zu rows per bank\n", n_rows);
    size_t n_r0 = n_rows > 0 ? n_rows - 1 : 0;

    for (size_t i = 0; i < n_r0; i++) {
        size_t r0 = i + 1;

        h_patt.d_lst[0].row = d_base.row + r0;
        int k = 1;
        for (; k < cfg->aggr_n; k++) {
            int stride = 2;
            h_patt.d_lst[k].row = h_patt.d_lst[k - 1].row + stride;
            h_patt.d_lst[k].bank = 0;
        }
        if (h_patt.d_lst[k - 1].row >= d_base.row + cfg->h_rows)
            break;

        for (size_t bk = 0; bk < get_banks_cnt(); bk++) {
            for (int s = 0; s < cfg->aggr_n; s++)
                h_patt.d_lst[s].bank = bk;

            staggered_hammer_window(suite, &h_patt, inner_delay);
        }
    }

    free(h_patt.d_lst);
    return 0;
}

int staggered_hammer_wrapper(HammerSuite *suite)
{
	// Explicit target rows for manual tuning. Leave this empty (the
	// default) to fall back to staggered_hammer_scan, which scans every
	// row/bank reachable from suite->d_base instead of a fixed list.
	static const DRAMAddr targets[] = {
		{.bank = 18, .row = 34499},
		{.bank = 18, .row = 34533},
		{.bank = 18, .row = 34535},
		{.bank = 18, .row = 34537},
		{.bank = 18, .row = 34539},
		{.bank = 18, .row = 34541},
		{.bank = 18, .row = 34543},
		{.bank = 18, .row = 34545},
		{.bank = 18, .row = 34547},
		{.bank = 18, .row = 34549},
		{.bank = 18, .row = 34551},
		{.bank = 18, .row = 34553},
		{.bank = 18, .row = 34555},
		{.bank = 18, .row = 34557},
		{.bank = 18, .row = 34559},
		{.bank = 18, .row = 34561},
		{.bank = 18, .row = 34563},
		{.bank = 18, .row = 34565}, // comment out to try 18-sided hammering
		{.bank = 18, .row = 34567}, // comment out to try 18-sided hammering
		// {.bank = 14, .row = 34539}, // comment out to try 20-sided hammering
		// {.bank = 14, .row = 34541}, // comment out to try 21-sided hammering
		// {.bank = 14, .row = 34543}, // comment out to try 22-sided hammering
	};
	size_t target_cnt = sizeof(targets) / sizeof(targets[0]);

	// cycles the aggressor thread waits between a0/a1/... activations
	uint64_t inner_delay = 0;

	if (target_cnt > 0)
		return staggered_hammer(suite, targets, target_cnt, inner_delay);

	return staggered_hammer_scan(suite, inner_delay);
}

void create_dir(const char* dir_name)
{
	struct stat st = {0};
	if (stat(dir_name, &st) == -1) {
			mkdir(dir_name, 0777);
	}
}

// This build only implements the ping-pong (staggered/delayed) hammer
// method -- see hammer_session/staggered_hammer_wrapper. Kept only as a
// stub so main.c's unconditional "if (p->fuzzing) fuzzing_session(...)"
// still links; -f/--fuzzing isn't supported here.
void fuzzing_session(SessionConfig * cfg, MemoryBuffer * mem)
{
	fprintf(stderr, "[ERROR] - fuzzing mode (-f) isn't supported in this "
			"ping-pong-only build; use -D/--delayed instead\n");
	exit(1);
}

void hammer_session(SessionConfig * cfg, MemoryBuffer * memory)
{
	MemoryBuffer mem = *memory;

	physaddr_t base_phys = virt_2_phys(mem.buffer, &mem);
	set_dram_base_phys(base_phys);
	DRAMAddr d_base = phys_2_dram(base_phys);
	d_base.row += cfg->base_off;
	fprintf(stderr, "base_phys: %lx, base_v: %p, base_d: %s\n",
		base_phys, mem.buffer, dAddr_2_str(d_base, ALL_FIELDS));
 
	create_dir(DATA_DIR);
	char *out_name = (char *)malloc(1024);
	char rows_str[10];
	strcpy(out_name, DATA_DIR);
	strcat(out_name, p->g_out_prefix);
	strcat(out_name, ".");
 
	if (cfg->h_cfg) {
		char config[15];
		sprintf(config, config_str[cfg->h_cfg], cfg->aggr_n);
		strcat(out_name, config);
	} else {
		strcat(out_name, config_str[cfg->h_cfg]);
	}
	strcat(out_name, ".");
	sprintf(rows_str, "%08ld", d_base.row);
	strcat(out_name, rows_str);
	strcat(out_name, ".");
	sprintf(rows_str, "%03ld", cfg->h_rows);
	strcat(out_name, rows_str);
	strcat(out_name, ".");
	sprintf(rows_str, "%ld", cfg->h_rounds);
	strcat(out_name, rows_str);
	strcat(out_name, ".");
	strcat(out_name, REFRESH_VAL);
	strcat(out_name, ".csv");
	if (p->g_flags & F_NO_OVERWRITE) {
		int cnt = 0;
		char *tmp_name = (char *)malloc(1024);
		strncpy(tmp_name, out_name, 1023);
		tmp_name[1023] = '\0';
		while (access(tmp_name, F_OK) != -1) {
			cnt++;
			snprintf(tmp_name, 1024, "%s.%02d", out_name, cnt);
		}
		strncpy(out_name, tmp_name, 1023);
		out_name[1023] = '\0';
		free(tmp_name);
	}
	out_fd = fopen(out_name, "w+");
 
	fprintf(stderr,
		"[LOG] - Hammer session! access pattern: %s\t data pattern: %s\n",
		config_str[cfg->h_cfg], data_str[cfg->d_cfg]);
	fprintf(stderr, "[LOG] - File: %s\n", out_name);
 
	HammerSuite *suite = (HammerSuite *) malloc(sizeof(HammerSuite));
	suite->cfg = cfg;
	suite->mem = &mem;
	suite->d_base = d_base;
	suite->mapper = (ADDRMapper *) malloc(sizeof(ADDRMapper));

	// hugepage_sweep_test builds/tears down suite->mapper fresh per hugepage
	// and re-bases g_dram_base_phys each time, so every hammer_test runs
	// through it rather than against a single mapper/base covering the
	// whole (possibly multi-hugepage, non-contiguous) buffer.
	fprintf(stderr, "done mapping\n");
#ifndef FLIPTABLE
	export_cfg(suite);	// export the configuration of the experiment to file.
	fprintf(out_fd, OUT_HEAD);
#endif
 
	// This build only implements the ping-pong (staggered/delayed) hammer
	// method; every other HammerConfig value (N_SIDED, SWEEP_ALL, etc.)
	// belongs to the other suites (hammer-suite.c/test-suite.c).
	if (cfg->h_cfg != DELAYED) {
		fprintf(stderr, "[ERROR] - this build only supports -D/--delayed "
				"(ping-pong); got h_cfg=%d\n", cfg->h_cfg);
		exit(1);
	}
	suite->hammer_test = (int (*)(void *))staggered_hammer_wrapper;


	hugepage_sweep_test(suite);
	fclose(out_fd);
	free(suite);
}