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
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <stdatomic.h>
#include <limits.h>
#include <time.h>
#include <math.h>

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

#define SHADOW_FLAGS (MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE)
// #define DEBUG

#ifdef DEBUG
// when set, hugepage_sweep_test/sweep_current_mapper only hammers this
// fixed set of row offsets in this fixed bank, instead of sweeping every
// row/bank in the hugepage. Offsets are added to whatever base row the
// current hugepage resolves to (suite->d_base.row, recomputed per-hugepage
// from phys_2_dram), so e.g. 11 always means "base_row+11" even if the
// row-mapping functions change what base row gets reported.
// Which bank hugepage_sweep_test/sweep_current_mapper restricts hammering
// to. -1 disables the filter (every bank, same as the non-DEBUG sweep).
#define DEBUG_BANK -1
static const size_t DEBUG_ROW_OFFSETS[] = { 11 };
#define DEBUG_ROW_OFFSETS_CNT (sizeof(DEBUG_ROW_OFFSETS) / sizeof(DEBUG_ROW_OFFSETS[0]))
// which hugepage (1-indexed, matching the "[SWEEP] hugepage N/M" log lines)
// hugepage_sweep_test should hammer; 0 disables the filter (all hugepages).
#define DEBUG_HUGEPAGE 2
#endif

#define ROUND_STEP 2000
#define THRESH_TRIES 20

#define NOP asm volatile ("NOP":::);
#define NOP10 NOP NOP NOP NOP NOP NOP NOP NOP NOP NOP
#define NOP100 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10
#define NOP1000 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100

#define BIN_THRESH 500
#define BIN_TRIES 50

extern ProfileParams *p;

int g_bk;
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

static uint64_t measure_tsc_hz(void)
{
    struct timespec ts0, ts1;
    uint64_t tsc0, tsc1;

    clock_gettime(CLOCK_MONOTONIC, &ts0);
    tsc0 = rdtscp();
    /* sleep ~100ms */
    struct timespec req = { .tv_sec = 0, .tv_nsec = 100000000 };
    nanosleep(&req, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    tsc1 = rdtscp();

    uint64_t ns_elapsed = (uint64_t)(ts1.tv_sec  - ts0.tv_sec)  * 1000000000ULL
                        + (uint64_t)(ts1.tv_nsec - ts0.tv_nsec);
    uint64_t tsc_elapsed = tsc1 - tsc0;

    /* cycles/sec = tsc_elapsed / (ns_elapsed / 1e9) */
    return tsc_elapsed * 1000000000ULL / ns_elapsed;
}

uint64_t count_activations_in_tREFI(char **v_lst, size_t len, uint64_t tsc_hz)
{
    const uint64_t TREFI_NS        = 7800ULL;
    const uint64_t interval_cycles = tsc_hz / 1000000000ULL * TREFI_NS;

    uint64_t count = 0;
    uint64_t t_end = rdtscp() + interval_cycles;

    while (1) {
        for (size_t j = 0; j < len; j++) {
            if (rdtscp() >= t_end)
                goto done;
            (void)*(volatile char *)v_lst[j];
            clflushopt(v_lst[j]);
            count++;
        }
        mfence();
    }
done:
    mfence();
    printf("activations in 7.8us: %lu\n", count);
    return count;
}

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

#ifdef DEBUG
// remembers the DRAMAddr of the most recently exported flip, so callers can
// look up its physical address (e.g. next to a "[THRESH] min_rounds~" line)
// without threading a return value through scan_rows/scan_stripe/scan_random.
static DRAMAddr g_last_flip_d_addr;
static bool g_last_flip_valid = false;
#endif

void export_flip(FlipVal * flip)
{
#ifdef DEBUG
	g_last_flip_d_addr = flip->d_vict;
	g_last_flip_valid = true;
#endif

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

void swap(char **lst, int i, int j)
{
	char *tmp = lst[i];
	lst[i] = lst[j];
	lst[j] = tmp;
}

int random_int(int min, int max)
{
	int number = min + rand() % (max - min);
	return number;
}

typedef struct {
    char **v_lst;
    size_t len;
    int rounds;
    size_t aggr_cnt;
    uint64_t inner_delay;     // cycles the aggressor waits between a0/a1/...
    uint64_t tsc_freq;        // for calibration
    /* --- synchronization --- */
    pthread_barrier_t barrier_ready;
    pthread_barrier_t barrier_start;
    pthread_barrier_t barrier_stop;
    volatile int shutdown;
    /* --- hot path ping-pong (cache-line aligned to avoid false sharing) --- */
    volatile int token __attribute__((aligned(64))); // 0=aggressor's turn, 1=dummy's turn
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
        a->token = 0;          // reset before both threads enter hot path
        mfence();
        pthread_barrier_wait(&a->barrier_start);

        for (int i = 0; i < a->rounds; i++) {
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

        a->token = -1;
        pthread_barrier_wait(&a->barrier_stop);
    }
    return NULL;
}

static void *dummy_thread(void *arg)
{
	sleep(1);
    HammerThreadArgs *a = (HammerThreadArgs *)arg;
    while (1) {
        pthread_barrier_wait(&a->barrier_ready);
        if (a->shutdown) break;
        pthread_barrier_wait(&a->barrier_start);

        while (1) {
            // wait for aggressor to hand off
            while (a->token != 1) {
                if (a->token == -1) goto round_done;
                asm volatile("pause");
            }

            // step through every dummy once, as fast as possible
            for (size_t j = a->aggr_cnt; j < a->len; j++)
                (void)*(volatile char *)a->v_lst[j];
            for (size_t j = a->aggr_cnt; j < a->len; j++)
                clflushopt(a->v_lst[j]);
            asm volatile("sfence" ::: "memory");

            // hand back to aggressor
            a->token = 0;
        }

        round_done:
        pthread_barrier_wait(&a->barrier_stop);
    }
    return NULL;
}

// Ping-pong delayed hammer: the aggressor thread accesses+flushes its
// aggr_cnt aggressors one at a time (waiting inner_delay cycles between
// each), then hands off to the dummy thread, which steps through every
// remaining row once (+flushes) and hands back immediately -- no delay of
// its own. Repeats for patt->rounds full handoff pairs.
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
        pthread_create(&g_t_aggr,  NULL, aggressor_thread, &g_hammer_args);
        pthread_create(&g_t_dummy, NULL, dummy_thread,     &g_hammer_args);
        // Pin aggressor to core 0, dummy to core 1, main to core 2
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        pthread_setaffinity_np(g_t_aggr, sizeof(cpu_set_t), &cpuset);
        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        pthread_setaffinity_np(g_t_dummy, sizeof(cpu_set_t), &cpuset);
        CPU_ZERO(&cpuset);
        CPU_SET(2, &cpuset);
        sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
        g_threads_init = 1;
    }
    g_hammer_args.v_lst       = v_lst;
    g_hammer_args.len         = patt->len;
    g_hammer_args.rounds      = patt->rounds;
    g_hammer_args.aggr_cnt    = aggr_cnt;
    g_hammer_args.inner_delay = inner_delay;
    pthread_barrier_wait(&g_hammer_args.barrier_ready);
    uint64_t t0 = realtime_now();
    pthread_barrier_wait(&g_hammer_args.barrier_start);
    pthread_barrier_wait(&g_hammer_args.barrier_stop);
    uint64_t t1 = realtime_now();
    free(v_lst);
    return (t1 - t0) / patt->rounds;
}

// inner_delay: cycles to wait *between individual aggressor accesses*
//   within a round (a0, wait, a1, wait, a0, ...). 0 = no per-access wait,
//   and the whole round is issued as the original access-all/flush-all
//   batch instead of one-at-a-time.
// outer_delay: cycles to wait *between rounds* only (a0, a1, ..., wait,
//   a0, a1, ...). 0 = no inter-round wait.
// stop_flag: NULL = run exactly patt->rounds rounds (the original
//   behavior). Non-NULL = ignore patt->rounds and instead loop until
//   *stop_flag becomes nonzero, set by some other thread -- used so the
//   dummy side of hammer_it_delayed keeps stepping through its rows for
//   as long as the aggressor side is still hammering, rather than
//   finishing its own fixed round count early and going idle.
uint64_t hammer_it(HammerPattern* patt, MemoryBuffer* mem,
                    uint64_t inner_delay, uint64_t outer_delay,
                    volatile int *stop_flag, uint64_t *rounds_out) {

	char** v_lst = (char**) malloc(sizeof(char*)*patt->len);
	for (size_t i = 0; i < patt->len; i++) {
		v_lst[i] = phys_2_virt(dram_2_phys(patt->d_lst[i], mem), mem);
		if (v_lst[i] == (char *)NOT_FOUND) {
			fprintf(stderr, "[ERROR] - hammer_it: aggressor %zu (row %lu bank %lu) outside mapped region\n",
				i, patt->d_lst[i].row, patt->d_lst[i].bank);
			free(v_lst);
			return 0;
		}
	}

	for (size_t j = 0; j < patt->len; j++) {
		if (!v_lst[j] || v_lst[j] == (void*)NOT_FOUND) {
			fprintf(stderr, "BAD v_lst[%zu]\n", j);
			abort();
		}
	}

	sched_yield();
	uint64_t round_in_ns = 0;//6600 / 4; // cycles -> ns, 4 GHz
	uint64_t cl0, cl1;
	size_t i;

	// --phase-sweep: walk the delay inserted between the detected refresh
	// spike and the start of hammering, one hammer_it() CALL at a time: all
	// patt->rounds rounds within this call use the same delay (0, 20, 40,
	// ..., 2000ns), and the next call to hammer_it() shifts to the next
	// delay in the sequence, wrapping back to 0. Only meaningful alongside
	// -t/--threshold. g_phase_call_idx persists across calls so the
	// sequence keeps advancing from one attempt to the next.
	//
	const uint64_t PHASE_STEP_NS = 200, PHASE_MAX_NS = 5000;
	const uint64_t PHASE_CYCLE_LEN = PHASE_MAX_NS / PHASE_STEP_NS + 1;
	static uint64_t g_phase_call_idx = 0;
	static uint64_t g_tsc_hz = 0;
	uint64_t phase_delay_cycles = 0;
	if (p->threshold > 0 && p->phase_sweep) {
		if (!g_tsc_hz)
			g_tsc_hz = measure_tsc_hz();
		uint64_t delay_ns = (g_phase_call_idx % PHASE_CYCLE_LEN) * PHASE_STEP_NS;
		g_phase_call_idx++;
		phase_delay_cycles = (g_tsc_hz / 1000000000ULL) * delay_ns;
	}

	cl0 = realtime_now();
	for (i = 0; stop_flag ? !(*stop_flag) : (i < patt->rounds); i++) {
		if (p->threshold > 0) {
			uint64_t t0 = 0, t1 = 0;
			// Threshold value depends on your system
			while (abs((int64_t) t1 - (int64_t) t0) < p->threshold) {
				t0 = rdtscp();
				*(volatile char *)v_lst[0];
				t1 = rdtscp();
				clflushopt(v_lst[0]);
				// fprintf(stderr, "%d\n", t1 - t0);
			}
			if (p->phase_sweep) {
				uint64_t t_wait_end = rdtscp() + phase_delay_cycles;
				while (rdtscp() < t_wait_end)
					asm volatile("pause");
			}
		}
		for (int rds = 0; rds < 2; rds++) {
		mfence();
			if (inner_delay == 0) {
				for (size_t j = 0; j < patt->len; j++) {
					*(volatile char*) v_lst[j];
				}
				for (size_t j = 0; j < patt->len; j++) {
					clflushopt(v_lst[j]);
				}
			} else {
				// one aggressor at a time, waiting inner_delay cycles
				// between each activation: a0, wait, a1, wait, a0, ...
				for (size_t j = 0; j < patt->len; j++) {
					*(volatile char*) v_lst[j];
					clflushopt(v_lst[j]);

					uint64_t t0 = rdtscp();
					while ((rdtscp() - t0) < inner_delay && j < 2)
						asm volatile("pause");
				}
			}
			asm volatile("sfence" ::: "memory");

			if (outer_delay > 0) {
				uint64_t t0 = rdtscp();
				while ((rdtscp() - t0) < outer_delay)
					asm volatile("pause");
			}

		uint64_t next = cl0 + (uint64_t)(i + 1) * round_in_ns;
    	while (realtime_now() < next)
       		asm volatile("pause");
		}
	}
	cl1 = realtime_now();
	usleep(100000); // sleep for 100 ms to ensure no accumulation
	free(v_lst);
	size_t n_rounds = stop_flag ? i : patt->rounds;
	if (n_rounds == 0) n_rounds = 1;
	uint64_t ns_per_round = (cl1-cl0) / n_rounds;
	fprintf(stderr, "[TIMING] hammer_it: %zu rounds, %lu ns total, %lu ns/round\n",
		n_rounds, cl1-cl0, ns_per_round);
	if (rounds_out)
		*rounds_out = n_rounds;
	return ns_per_round;

}

// Two selectable two-thread delayed-hammer modes (see staggered_hammer_window):
//   HAMMER_PING_PONG: aggressor_thread/dummy_thread/hammer_with_delay further
//     down -- strict turn-taking, aggressor hands off to dummy and waits for
//     it to finish one pass before continuing.
//   HAMMER_FULL_SEND: hammer_full_send below -- the two threads run fully
//     independently with no handoff at all; each is paced only by its own
//     inner_delay/outer_delay.
typedef enum { HAMMER_PING_PONG, HAMMER_FULL_SEND } HammerMode;

typedef struct {
    HammerPattern *patt;
    MemoryBuffer  *mem;
    uint64_t       inner_delay;
    uint64_t       outer_delay;
    int            core;
    volatile int  *stop_flag;  // passed to hammer_it as its stop_flag
    int            is_driver;  // 1: run exactly patt->rounds rounds, then
                                // set *stop_flag so the other thread stops
    uint64_t       ret;
    uint64_t       rounds_done; // actual round count hammer_it completed
} FullSendArgs;

static void *full_send_thread(void *arg)
{
    FullSendArgs *a = (FullSendArgs *)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(a->core, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    a->ret = hammer_it(a->patt, a->mem, a->inner_delay, a->outer_delay,
                        a->is_driver ? NULL : a->stop_flag, &a->rounds_done);

    if (a->is_driver)
        *a->stop_flag = 1;

    return NULL;
}

// "Full send": aggressor and dummy threads run fully independently, no
// handoff between them at all. The aggressor thread hammers its aggr_cnt
// rows one at a time (inner_delay between each) and runs exactly
// patt->rounds rounds, driving a shared stop flag. The dummy thread loops
// over the rest with outer_delay between each full pass, ignoring its own
// rounds count, until the aggressor thread hits rounds and sets that flag.
static uint64_t hammer_full_send(HammerSuite *suite, HammerPattern *h_patt,
                                  size_t aggr_cnt,
                                  uint64_t inner_delay, uint64_t outer_delay)
{
    MemoryBuffer *mem = suite->mem;

    HammerPattern aggr_patt = {
        .d_lst  = h_patt->d_lst,
        .len    = aggr_cnt,
        .rounds = h_patt->rounds,
    };
    HammerPattern dummy_patt = {
        .d_lst  = h_patt->d_lst + aggr_cnt,
        .len    = h_patt->len - aggr_cnt,
        .rounds = h_patt->rounds,  // unused: the dummy thread runs off stop_flag instead
    };

    volatile int stop_flag = 0;

    FullSendArgs aggr_args = {
        .patt = &aggr_patt, .mem = mem, .inner_delay = inner_delay,
        .outer_delay = 0, .core = 0, .stop_flag = &stop_flag, .is_driver = 1,
    };
    FullSendArgs dummy_args = {
        .patt = &dummy_patt, .mem = mem, .inner_delay = 0,
        .outer_delay = outer_delay, .core = 1, .stop_flag = &stop_flag, .is_driver = 0,
    };

    pthread_t t_aggr, t_dummy;
    pthread_create(&t_aggr,  NULL, full_send_thread, &aggr_args);
    pthread_create(&t_dummy, NULL, full_send_thread, &dummy_args);

    pthread_join(t_aggr, NULL);
    pthread_join(t_dummy, NULL);

    fprintf(stderr, "[FULL_SEND] aggressor rounds=%lu dummy rounds=%lu\n",
            aggr_args.rounds_done, dummy_args.rounds_done);

    return aggr_args.ret;
}

void __test_fill_random(char *addr, size_t size)
{
	int fd;
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		perror("[ERROR] - Unable to open /dev/urandom");
		exit(1);
	}
	if (read(fd, addr, size) == -1) {
		perror("[ERROR] - Unable to read /dev/urandom");
		exit(1);
	}
	close(fd);

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

int find_flip(HammerSuite * suite, HammerPattern * h_patt, FlipVal *orig)
{
	ADDRMapper *mapper = suite->mapper;
	SessionConfig *cfg = suite->cfg;

	DRAMAddr d_tmp;
	FlipVal flip;;

	d_tmp.bank = orig->d_vict.bank;
	d_tmp.row = orig->d_vict.row;
	d_tmp.col = orig->d_vict.col;

	DRAM_pte pte = get_dram_pte(mapper, &d_tmp);
	clflush(pte.v_addr);
	cpuid();
	int off = cl_rand_comp(&pte);
	if (off != -1) {
		return 1;
	}

	return 0;
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

static int cmp_row_asc(const void *a, const void *b)
{
	size_t ra = *(const size_t *)a;
	size_t rb = *(const size_t *)b;
	return (ra > rb) - (ra < rb);
}

// Fills every row strictly between two row-adjacent aggressors (in sorted
// row order, not list order) with the victim pattern. Does not touch the
// aggressor rows themselves -- callers fill those separately via fill_row.
void fill_victim_rows(HammerSuite * suite, HammerPattern * h_patt)
{
	SessionConfig *cfg = suite->cfg;
	size_t n = h_patt->len;
	size_t *rows = (size_t *) malloc(sizeof(size_t) * n);
	for (size_t i = 0; i < n; i++)
		rows[i] = h_patt->d_lst[i].row;
	qsort(rows, n, sizeof(size_t), cmp_row_asc);

	for (size_t idx = 0; idx + 1 < n; idx++) {
		size_t row_lo = rows[idx];
		size_t row_hi = rows[idx + 1];
		for (size_t dummy_row = row_lo + 1; dummy_row < row_hi; dummy_row++) {
			if (dummy_row >= suite->mapper->base_row + cfg->h_rows) break;
			DRAMAddr d_dummy = h_patt->d_lst[0];
			d_dummy.row = dummy_row;
			fill_row(suite, &d_dummy, cfg->d_cfg, 1);
		}
	}
	free(rows);
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
	// order and may not be sorted (see fill_victim_rows/hPatt_row_bounds).
	size_t row_lo, row_hi;
	hPatt_row_bounds(h_patt, &row_lo, &row_hi);
	// Scan adj_rows rows beyond the aggressor block on each side (not just
	// the row immediately between the outermost two aggressors), so flips
	// further out than the aggressors' immediate neighbors aren't missed.
	size_t start = row_lo - adj_rows;
	size_t end = row_hi + adj_rows + 1;

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

static bool try_flip_n(HammerSuite *suite, HammerPattern *h_patt, MemoryBuffer *mem)
{
    SessionConfig *cfg = suite->cfg;

    for (int t = 0; t < BIN_TRIES; t++) {

        // Refill aggressors
        for (int idx = 0; idx < h_patt->len; idx++)
            fill_row(suite, &h_patt->d_lst[idx], cfg->d_cfg, 0);

        // Refill dummy rows (sorted by row, independent of d_lst's order)
        fill_victim_rows(suite, h_patt);

        uint64_t ttime = hammer_it(h_patt, mem, 0, 0, NULL, NULL);
        if (ttime == 0) return false;  // treat OOB as failure

        if (scan_rows(suite, h_patt, p->scan_adj)) {
			for (int idx = 0; idx < h_patt->len; idx++)
				fill_row(suite, &h_patt->d_lst[idx], cfg->d_cfg, 1);
			fill_victim_rows(suite, h_patt);
			fprintf(stderr, "[DEBUG] flip detected at try %d\n", t);
            return true;  // ANY success → true
		}
		struct timespec req;
		req.tv_sec = 0;
		req.tv_nsec = 64000000; // sleep for 64 ms
		nanosleep(&req, NULL);
    }

	// Restore state
	for (int idx = 0; idx < h_patt->len; idx++)
		fill_row(suite, &h_patt->d_lst[idx], cfg->d_cfg, 1);
	fill_victim_rows(suite, h_patt);

    return false;  // 0/20 flips
}

// Sweeps every row covered by suite->mapper (cfg->h_rows), across every bank,
// building an aggr_n-wide / stride-2 pattern starting at each row offset.
// Used by hugepage_sweep_test to sample as much of the current hugepage's
// mapped row range as possible.
static void sweep_current_mapper(HammerSuite *suite)
{
	MemoryBuffer *mem = suite->mem;
	SessionConfig *cfg = suite->cfg;
	DRAMAddr d_base = suite->d_base;
	d_base.col = 0;

	HammerPattern h_patt;
	h_patt.len = cfg->aggr_n;
	h_patt.rounds = cfg->h_rounds;
	h_patt.d_lst = (DRAMAddr *) malloc(sizeof(DRAMAddr) * h_patt.len);
	memset(h_patt.d_lst, 0x00, sizeof(DRAMAddr) * h_patt.len);

	init_chunk(suite);
	fprintf(stderr, "CL_SEED: %lx\n", CL_SEED);

	h_patt.d_lst[0] = d_base;

	size_t n_rows = cfg->h_rows;
	fprintf(stderr, "Hammering %zu rows per bank\n", n_rows);
#ifdef DEBUG
	size_t n_r0 = DEBUG_ROW_OFFSETS_CNT;
#else
	size_t n_r0 = n_rows > 0 ? n_rows - 1 : 0;
#endif
	for (size_t i = 0; i < n_r0; i++) {
#ifdef DEBUG
		size_t r0 = DEBUG_ROW_OFFSETS[i];
#else
		size_t r0 = i + 1;
#endif
		h_patt.d_lst[0].row = d_base.row + r0;
		int k = 1;
		for (; k < cfg->aggr_n; k++) {
			int stride = 2;
			h_patt.d_lst[k].row = h_patt.d_lst[k - 1].row + stride;
			h_patt.d_lst[k].bank = 0;
		}
		if (h_patt.d_lst[k - 1].row >= d_base.row + cfg->h_rows)
			break;

		fprintf(stderr, "[HAMMER] - %s: ", hPatt_2_str(&h_patt, ROW_FIELD));
		for (size_t bk = 0; bk < get_banks_cnt(); bk++) {
#ifdef DEBUG
			if (DEBUG_BANK >= 0 && bk != (size_t)DEBUG_BANK)
				continue;
#endif

			for (int s = 0; s < cfg->aggr_n; s++) {
				h_patt.d_lst[s].bank = bk;
			}

#ifdef FLIPTABLE
			print_start_attack(&h_patt);
#endif
			// fill all the aggressor rows
			for (int idx = 0; idx < cfg->aggr_n; idx++) {
				fill_row(suite, &h_patt.d_lst[idx], cfg->d_cfg, 0);
			}

			// Reinitialize victim/dummy rows so each round starts from a known state.
			for (int idx = 0; idx < h_patt.len - 1; idx++) {
				size_t row_lo = h_patt.d_lst[idx].row;
				size_t row_hi = h_patt.d_lst[idx + 1].row;
				for (size_t dummy_row = row_lo + 1; dummy_row < row_hi; dummy_row++) {
					if (dummy_row >= suite->mapper->base_row + cfg->h_rows) break;
					DRAMAddr d_dummy = h_patt.d_lst[idx];
					d_dummy.row = dummy_row;
					fill_row(suite, &d_dummy, cfg->d_cfg, 1);
				}
			}

			uint64_t time = hammer_it(&h_patt, mem, 0, 0, NULL, NULL);
			fprintf(stderr, "%ld ", time);

			h_patt.rounds = cfg->h_rounds;
			bool flipped = scan_rows(suite, &h_patt, p->scan_adj);

			// refill aggressors and dummies
			for (int idx = 0; idx < h_patt.len; idx++)
				fill_row(suite, &h_patt.d_lst[idx], cfg->d_cfg, 1);
			for (int idx = 0; idx < h_patt.len - 1; idx++) {
				size_t row_lo = h_patt.d_lst[idx].row;
				size_t row_hi = h_patt.d_lst[idx + 1].row;
				for (size_t dummy_row = row_lo + 1; dummy_row < row_hi; dummy_row++) {
					if (dummy_row >= suite->mapper->base_row + cfg->h_rows) break;
					DRAMAddr d_dummy = h_patt.d_lst[idx];
					d_dummy.row = dummy_row;
					fill_row(suite, &d_dummy, cfg->d_cfg, 1);
				}
			}

			if (flipped) {

			size_t low = 1;
			size_t high = cfg->h_rounds;

			while ((high - low) > BIN_THRESH) {

				size_t mid = (low + high) / 2;
				h_patt.rounds = mid;

				bool success = try_flip_n(suite, &h_patt, mem);

				fprintf(stderr,
					"[BIN] aggr=%s bk%zu low=%zu mid=%zu high=%zu result=%d\n",
					hPatt_2_str(&h_patt, ROW_FIELD),
					bk, low, mid, high, success);

				if (success)
					high = mid;
				else
					low = mid + 1;
			}

			fprintf(out_fd,
				"[THRESH] min_rounds~%zu (+/-%d) aggr=%s bk%zu\n",
				high,
				BIN_THRESH,
				hPatt_2_str(&h_patt, ROW_FIELD),
				bk);
#ifdef DEBUG
			if (g_last_flip_valid) {
				physaddr_t flip_phys = dram_2_phys(g_last_flip_d_addr, mem);
				fprintf(out_fd, "[THRESH] flip_phys=0x%lx (%s)\n",
					flip_phys, dAddr_2_str(g_last_flip_d_addr, ALL_FIELDS));
				g_last_flip_valid = false;
			}
#endif

			h_patt.rounds = cfg->h_rounds;
		}

#ifdef FLIPTABLE
			print_end_attack();
#endif
		}
		fprintf(stderr, "\n");
	}

	free(h_patt.d_lst);
}

// Scans across every reserved 1GB hugepage in mem (mem->size / GB(1) of them),
// treating each as its own independent DRAM-addressing domain (own d_base,
// own ADDRMapper) since separate hugepages are not physically contiguous.
// Within each hugepage, samples as many rows as fit (rows_per_hugepage),
// rather than the fixed 256MB slice n_sided_test's dormant branch used.
//
// This is the general per-hugepage driver for every hammer_test, not just
// SWEEP_ALL's sweep_current_mapper: g_dram_base_phys/suite->d_base/
// suite->mapper only ever cover one hugepage's worth of rows (see
// dram_2_phys()'s base-combining logic, which silently corrupts row bits
// once a row crosses a 1GB hugepage boundary), so every hammer_test needs
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
#ifdef DEBUG
		if (DEBUG_HUGEPAGE != 0 && (hp + 1) != DEBUG_HUGEPAGE)
			continue;
#endif
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

int free_triple_sided_test(HammerSuite * suite)
{
	return 0;
}

int assisted_double_sided_test(HammerSuite * suite)
{
	return 0;
}

int n_sided_test(HammerSuite * suite)
{
	MemoryBuffer *mem = suite->mem;
	SessionConfig *cfg = suite->cfg;
	DRAMAddr d_base = suite->d_base;
	d_base.col = 0;
	/* d_base.row = 20480; */
    /* d_base.row = 16400; */
	HammerPattern h_patt;
 
	h_patt.len = cfg->aggr_n;
	h_patt.rounds = cfg->h_rounds;
 
	h_patt.d_lst = (DRAMAddr *) malloc(sizeof(DRAMAddr) * h_patt.len);
	memset(h_patt.d_lst, 0x00, sizeof(DRAMAddr) * h_patt.len);
 
	init_chunk(suite);
	fprintf(stderr, "CL_SEED: %lx\n", CL_SEED);
 
	h_patt.d_lst[0] = d_base;
	bool static_hammer = true;
	if (static_hammer) {
		// NOTE: must stay sorted ascending by row, stride 2 -- the
		// between-pairs victim-fill loop below walks row_lo+1..row_hi-1
		// between consecutive entries, so an out-of-order entry turns a
		// large gap into a "fill everything in between as victim" and
		// stomps real aggressor rows with vpat.
		static const DRAMAddr targets[] = {
			{.bank = 18, .row = 34499},
			{.bank = 18, .row = 34529},
			{.bank = 18, .row = 34531},
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
			// {.bank = 18, .row = 34537}, // comment out to try 19-sided hammering
			// {.bank = 14, .row = 34539}, // comment out to try 20-sided hammering
			// {.bank = 14, .row = 34541}, // comment out to try 21-sided hammering
			// {.bank = 14, .row = 34543}, // comment out to try 22-sided hammering
		};
		h_patt.len = sizeof(targets) / sizeof(targets[0]);
		h_patt.rounds = cfg->h_rounds;

		h_patt.d_lst = (DRAMAddr*) malloc(sizeof(DRAMAddr) * h_patt.len);
		memcpy(h_patt.d_lst, targets, sizeof(targets));
		#ifdef FLIPTABLE
				print_start_attack(&h_patt);
		#endif
			bool flipped = false;
			// Diagnostic: rotate which target starts the per-round access
			// order across attempts (pairwise adjacency is preserved --
			// 34501 still immediately follows 34499, etc, just wrapped
			// around the end of the list). hammer_it accesses d_lst[0..len)
			// in order every round with no inner delay, so whichever entry
			// is at index 0 is also whichever row is first-activated after
			// the loop's "seam" (restart/flush) each pass -- the one spot
			// most likely to land at a fixed phase relative to DRAM's own
			// (unsynchronized, but highly regular) refresh period.
			// fill_victim_rows/scan_rows are already order-independent
			// (they work off row values, not list position), so rotating
			// here doesn't affect what gets filled or scanned -- only the
			// hammering access order.
			//
			// A first pass of this (rotate-only) found flips *only* at
			// start_idx 0/17/18 -- i.e. only when 34499/34501 land in
			// access positions 0-3 -- and that window never moved across
			// ~10 full rotations. That's consistent with this loop being
			// phase-locked to the chip's refresh cadence (same few
			// positions are "too stale to still be in TRR's sample table
			// by REF time" on every pass), but a software-only artifact
			// at the loop's wrap-around (cold cache line/TLB/branch
			// mispredict right after j=len-1 -> j=0) would produce the
			// exact same signature with no TRR involved at all.
			//
			// phase_shift_inject distinguishes the two: it burns a
			// deliberate, varying delay right before hammer_it() starts
			// each pass, sweeping 0..1000ns in 100ns steps on an 11-step
			// cycle (chosen non-commensurate with the 19-row rotation
			// cycle so (start_idx, shift_ns) keeps exploring new
			// combinations instead of relocking every rotation). If the
			// flip-producing start_idx moves as shift_ns changes, the
			// loop really is phase-locked to REF. If the same start_idx
			// keeps flipping regardless of shift_ns, the effect is tied
			// to the loop's own structure, not DRAM refresh timing.
			static const bool rotate_pattern_start = false;
			static const bool phase_shift_inject   = false;
			static uint64_t ps_tsc_hz = 0;
			const uint64_t PHASE_SHIFT_STEPS = 11;
			const uint64_t PHASE_SHIFT_NS    = 100;
			for (int attempt = 0; attempt < 200; attempt++) {
				size_t rot_off = 0;
				if (rotate_pattern_start) {
					rot_off = (size_t)attempt % h_patt.len;
					for (size_t i = 0; i < h_patt.len; i++)
						h_patt.d_lst[i] = targets[(rot_off + i) % h_patt.len];
				}

				uint64_t shift_ns = 0;
				if (phase_shift_inject) {
					if (!ps_tsc_hz)
						ps_tsc_hz = measure_tsc_hz();
					shift_ns = ((uint64_t)attempt % PHASE_SHIFT_STEPS) * PHASE_SHIFT_NS;
				}

				fprintf(stderr, "[ROTATE] attempt=%d start_idx=%zu shift_ns=%lu first=%s\n",
					attempt, rot_off, shift_ns,
					dAddr_2_str(h_patt.d_lst[0], ROW_FIELD | BK_FIELD));

				// fill all the aggressor rows
				for (int idx = 0; idx < h_patt.len; idx++) {
					fill_row(suite, &h_patt.d_lst[idx], cfg->d_cfg, 0);
				}

				// Reinitialize victim/dummy rows so each round starts from a known state.
				// (sorted by row, independent of d_lst's hammering order)
				fill_victim_rows(suite, &h_patt);

				if (shift_ns > 0) {
					uint64_t delay_cycles = (ps_tsc_hz / 1000000000ULL) * shift_ns;
					uint64_t t_end = rdtscp() + delay_cycles;
					while (rdtscp() < t_end)
						asm volatile("pause");
				}

				uint64_t inner_delay = 0;
				uint64_t outer_delay = 9000;
				uint64_t time = hammer_it(&h_patt, mem, inner_delay, outer_delay, NULL, NULL);
				fprintf(stderr, "%ld ", time);

				h_patt.rounds = cfg->h_rounds;
				if (scan_rows(suite, &h_patt, p->scan_adj)) {
					flipped = true;
					fprintf(stderr, "[ROTATE] flip at attempt=%d start_idx=%zu shift_ns=%lu\n",
						attempt, rot_off, shift_ns);
				}

				// refill aggressors and dummies
				for (int idx = 0; idx < h_patt.len; idx++)
					fill_row(suite, &h_patt.d_lst[idx], cfg->d_cfg, 1);
				fill_victim_rows(suite, &h_patt);
			}

			if (flipped) {

			size_t low = 1;
			size_t high = cfg->h_rounds;

			while ((high - low) > BIN_THRESH) {

				size_t mid = (low + high) / 2;
				h_patt.rounds = mid;

				bool success = try_flip_n(suite, &h_patt, mem);

				fprintf(stderr,
					"[BIN] aggr=%s low=%zu mid=%zu high=%zu result=%d\n",
					hPatt_2_str(&h_patt, ROW_FIELD),
					low, mid, high, success);

				if (success)
					high = mid;
				else
					low = mid + 1;
			}

			fprintf(out_fd,
				"[THRESH] min_rounds~%zu (+/-%d) aggr=%s\n",
				high,
				BIN_THRESH,
				hPatt_2_str(&h_patt, ROW_FIELD)
				);
#ifdef DEBUG
			if (g_last_flip_valid) {
				physaddr_t flip_phys = dram_2_phys(g_last_flip_d_addr, mem);
				fprintf(out_fd, "[THRESH] flip_phys=0x%lx (%s)\n",
					flip_phys, dAddr_2_str(g_last_flip_d_addr, ALL_FIELDS));
				g_last_flip_valid = false;
			}
#endif

			h_patt.rounds = cfg->h_rounds;
		}
 
	#ifdef FLIPTABLE
		print_end_attack();
	#endif
		fprintf(stderr, "\n");
	}
	free(h_patt.d_lst);
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
                                     uint64_t inner_delay, uint64_t outer_delay,
                                     HammerMode mode)
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

    /*
     * CHANGE #1:
     * Dispatch to whichever two-thread delayed-hammer mode is selected:
     * HAMMER_PING_PONG (aggressor hands off to dummy and waits for it each
     * round) or HAMMER_FULL_SEND (both threads run independently, paced
     * only by their own inner_delay/outer_delay).
     */
	bool flip_found = false;
	for (int i = 0; i < 50; i++) {
		h_patt->rounds = cfg->h_rounds;
		uint64_t time = (mode == HAMMER_FULL_SEND)
			? hammer_full_send(suite, h_patt, 1, inner_delay, outer_delay)
			: hammer_with_delay(h_patt, suite->mem, 1, inner_delay);
		fprintf(stderr, "%lu ", time);

		if (scan_rows(suite, h_patt, p->scan_adj)) {
			flip_found = true;
			break;
		}

    }

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
                      uint64_t inner_delay, uint64_t outer_delay,
                      HammerMode mode)
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

            if (staggered_hammer_window(suite, &h_patt, inner_delay, outer_delay, mode)) {
                flip_found = true;
                break;
            }
        }
    }

    free(h_patt.d_lst);
	return 0;
}

// Generic fallback for staggered_hammer_wrapper when no explicit row list
// is configured: builds aggr_n-wide windows (same stride-2 layout
// sweep_current_mapper uses) across every row/bank reachable from
// suite->d_base/cfg->h_rows, so hugepage_sweep_test's per-hugepage
// re-basing still makes this cover the whole buffer, not just one chunk.
static int staggered_hammer_scan(HammerSuite *suite, uint64_t inner_delay,
                                  uint64_t outer_delay, HammerMode mode)
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

            staggered_hammer_window(suite, &h_patt, inner_delay, outer_delay, mode);
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
			{.bank = 18, .row = 34529}, 
			{.bank = 18, .row = 34531},
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
		// {.bank = 14, .row = 34539}, // comment out to try 19-sided hammering
		// {.bank = 14, .row = 34541}, // comment out to try 20-sided hammering
		// {.bank = 14, .row = 34543}, // comment out to try 21-sided hammering
	};
	size_t target_cnt = sizeof(targets) / sizeof(targets[0]);

	// Toggle between the two delayed-hammer modes (see HammerMode):
	//   HAMMER_PING_PONG: aggressor hands off to dummy and waits for it,
	//     strictly alternating every round.
	//   HAMMER_FULL_SEND: aggressor and dummy threads run independently,
	//     no handoff -- aggressor paced by inner_delay, dummy paced by
	//     outer_delay between each full pass over its rows.
	HammerMode mode = HAMMER_FULL_SEND;

	// inner_delay: cycles the aggressor thread waits between a0/a1/...
	// activations. outer_delay: only used by HAMMER_FULL_SEND -- cycles
	// the dummy thread waits between each full pass over its rows.
	uint64_t inner_delay = 15000;
	uint64_t outer_delay = 0;

	if (target_cnt > 0)
		return staggered_hammer(suite, targets, target_cnt, inner_delay, outer_delay, mode);

	return staggered_hammer_scan(suite, inner_delay, outer_delay, mode);
}

void fuzz(HammerSuite *suite, int d, int v)
{
	int i;
	HammerPattern h_patt;
	SessionConfig *cfg = suite->cfg;
	h_patt.rounds = cfg->h_rounds;
	h_patt.len = cfg->aggr_n;

	h_patt.d_lst = (DRAMAddr *) malloc(sizeof(DRAMAddr) * h_patt.len);
	memset(h_patt.d_lst, 0x00, sizeof(DRAMAddr) * h_patt.len);

	init_chunk(suite);
	int offset = random_int(1, 32);

	h_patt.d_lst[0] = suite->d_base;
	h_patt.d_lst[0].row = suite->d_base.row + offset;

	h_patt.d_lst[1] = suite->d_base;
	h_patt.d_lst[1].row = h_patt.d_lst[0].row + v + 1;
	for (i = 2; i < h_patt.len-1; i+=2) {
		h_patt.d_lst[i] = suite->d_base;
		h_patt.d_lst[i].row = h_patt.d_lst[i-1].row + d + 1;
		h_patt.d_lst[i+1] = suite->d_base;
		h_patt.d_lst[i+1].row = h_patt.d_lst[i].row + v + 1;
	}
	if (h_patt.len % 2) {
		h_patt.d_lst[h_patt.len-1] = suite->d_base;
		h_patt.d_lst[h_patt.len-1].row = h_patt.d_lst[h_patt.len-2].row + d + 1;
	}

	fprintf(stderr, "[HAMMER] - %s: ", hPatt_2_str(&h_patt, ROW_FIELD));
	for (int bk = 0; bk < get_banks_cnt(); bk++)
	{
		for (int idx = 0; idx < h_patt.len; idx++) {
			h_patt.d_lst[idx].bank = bk;
		}
#ifdef FLIPTABLE
		print_start_attack(&h_patt);
#endif
		for (int idx = 0; idx < h_patt.len; idx++)
			fill_row(suite, &h_patt.d_lst[idx], suite->cfg->d_cfg, 0);

		uint64_t time = hammer_it(&h_patt, suite->mem, 0, 0, NULL, NULL);
		fprintf(stderr, "%lu ",time);

		scan_rows(suite, &h_patt, p->scan_adj);
		for (int idx = 0; idx<h_patt.len; idx++) {
			fill_row(suite, &h_patt.d_lst[idx], suite->cfg->d_cfg, 1);
		}

#ifdef FLIPTABLE
		print_end_attack();
#endif
	}
	fprintf(stdout, "\n");
	free(h_patt.d_lst);
}

void create_dir(const char* dir_name)
{
	struct stat st = {0};
	if (stat(dir_name, &st) == -1) {
			mkdir(dir_name, 0777);
	}
}

void fuzzing_session(SessionConfig * cfg, MemoryBuffer * mem)
{
	int d, v, aggrs;

	srand(CL_SEED);
	physaddr_t base_phys = virt_2_phys(mem->buffer, mem);
	set_dram_base_phys(base_phys);
	DRAMAddr d_base = phys_2_dram(base_phys);
	fprintf(stdout, "[INFO] d_base.row:%lu\n", d_base.row);

	/* Init FILES */
	create_dir(DATA_DIR);
	char out_name[500];
	char config_buf[32];

	snprintf(config_buf, sizeof(config_buf),
			config_str[cfg->h_cfg],
			cfg->aggr_n);

	snprintf(out_name, sizeof(out_name),
			"%s%s.%s.%08ld.%03ld.%ld.%s.csv",
			DATA_DIR,
			p->g_out_prefix,
			config_buf,
			d_base.row,
			cfg->h_rows,
			cfg->h_rounds,
			REFRESH_VAL);
	if (p->g_flags & F_NO_OVERWRITE) {
		int cnt = 0;
		char tmp_name[500];

		snprintf(tmp_name, sizeof(tmp_name), "%s", out_name);

		while (access(tmp_name, F_OK) != -1) {
			cnt++;
			snprintf(tmp_name, sizeof(tmp_name), "%s.%02d", out_name, cnt);
		}

		snprintf(out_name, sizeof(out_name), "%s", tmp_name);
	}
	out_fd = fopen(out_name, "w+");
	assert(out_fd != NULL);

	HammerSuite *suite = (HammerSuite *) malloc(sizeof(HammerSuite));
	suite->mem = mem;
	suite->cfg = cfg;
	suite->d_base = d_base;
	suite->mapper = (ADDRMapper *) malloc(sizeof(ADDRMapper));
	init_addr_mapper(suite->mapper, mem, &suite->d_base, cfg->h_rows);

	while(1) {
		cfg->aggr_n = random_int(2, 32);
		d = random_int(0, 16);
		v = random_int(1, 4);
		fuzz(suite, d, v);
	}
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
 
	switch (cfg->h_cfg) {
		case ASSISTED_DOUBLE_SIDED:
		{
			suite->hammer_test =
			    (int (*)(void *))assisted_double_sided_test;
			break;
		}
		case FREE_TRIPLE_SIDED:
		{
			suite->hammer_test =
			    (int (*)(void *))free_triple_sided_test;
			break;
		}
		case N_SIDED:
		{
			assert(cfg->aggr_n > 1);
			suite->hammer_test = (int (*)(void *))n_sided_test;
			break;
		}
		case DELAYED:
			suite->hammer_test = (int (*)(void *))staggered_hammer_wrapper;
			break;
		case SWEEP_ALL:
			suite->hammer_test = (int (*)(void *))sweep_current_mapper;
			break;
		default:
		{
			suite->hammer_test = (int (*)(void *))n_sided_test;
		}
	}


	hugepage_sweep_test(suite);
	fclose(out_fd);
	free(suite);
}