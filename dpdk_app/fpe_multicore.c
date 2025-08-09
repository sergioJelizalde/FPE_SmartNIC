/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

 #include <stdio.h>
 #include <string.h>
 #include <stdint.h>
 #include <errno.h>
 #include <sys/queue.h>
 #include <rte_memory.h>
 #include <rte_launch.h>
 #include <rte_eal.h>
 #include <rte_per_lcore.h>
 #include <rte_lcore.h>
 #include <rte_debug.h>
 #include <stdalign.h>
 #include <stdint.h>
 #include <stdlib.h>
 #include <inttypes.h>
 #include <getopt.h>
 #include <rte_eal.h>
 #include <rte_ethdev.h>
 #include <rte_cycles.h>
 #include <rte_lcore.h>
 #include <rte_mbuf.h>
 #include <rte_mbuf_dyn.h>
 #include <fcntl.h>
 #include <rte_version.h>

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include <stdarg.h>
 #include <ctype.h>
 #include <errno.h>
 #include <getopt.h>
 #include <signal.h>
 
 #include <rte_eal.h>
 #include <rte_common.h>
 #include <rte_malloc.h>
 #include <rte_mempool.h>
 #include <rte_mbuf.h>
 #include <rte_cycles.h>

 #include <rte_hash.h>
 #include <rte_jhash.h>
 
 #include <rte_flow.h>
 
 //for bluefield2

#include <arm_neon.h>

#if defined(__aarch64__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191*2 

 // #define BURST_SIZE (1 << 9)
 
 #define QUEUE_SIZE 256
 
 #define BURST_SIZE 32
 
 // #define QUEUE_SIZE (1 << 6)
 
 #define MBUF_CACHE_SIZE 512
 
 //#define HASH_TABLE_SIZE (1 << 15) 
 
#define ALIGN16 __attribute__((aligned(16)))

//#define MAX_SAMPLES 10000
//static uint64_t *latency_cycles;
//static size_t    latency_count = 0;

#define N_PACKETS 8
#define INVALID_INDEX   UINT32_MAX

#define MAX_FLOWS_PER_CORE 8192*2
#define MAX_CORES       RTE_MAX_LCORE

#define MAX_SAMPLES 10000

static uint64_t aes_lat_cycles[MAX_SAMPLES];
static size_t   aes_lat_count = 0;

struct worker_args {
    struct rte_mempool *mbuf_pool;
    struct rte_hash    *flow_table;
    struct flow_entry  *flow_pool; 
    uint16_t            queue_id;    
    uint32_t            next_free;
    uint16_t port_id;
};

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_entry {
    uint64_t first_timestamp;
    uint64_t last_timestamp;

    uint16_t pkt_count;

    /* packet‐length stats */
    uint32_t len_min;
    uint32_t len_max;
    uint64_t len_sum;      // for computing mean

    /* inter‐arrival time (IAT) stats */
    uint64_t iat_min;
    uint64_t iat_max;
    uint64_t iat_sum;      // for computing mean

    /* total bytes in flow (you already had: total_len) */
    uint64_t total_len;

    /* sum of '1' bits in the TCP flags field */
    uint32_t flag_bits_sum;
};

/* Statically allocate pools for every possible lcore */
static struct flow_entry flow_pools[MAX_CORES][MAX_FLOWS_PER_CORE];
static struct rte_hash *flow_tables[MAX_CORES];

 /* >8 End of launching function on lcore. */
 static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t number_rings)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    uint16_t nb_queue_pairs, rx_rings, tx_rings;
    int retval;
    uint16_t q;

    /* Fetch device info */
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info for port %u: %s\n",
               port, strerror(-retval));
        return retval;
    }

    printf("Port %u: max_rx_queues=%u, max_tx_queues=%u, rx_offload_capa=0x%016" PRIx64 ", flow_type=0x%08x\n",
           port, dev_info.max_rx_queues, dev_info.max_tx_queues,
           dev_info.rx_offload_capa, dev_info.flow_type_rss_offloads);

    /* Cap number_rings to NIC capabilities */
    nb_queue_pairs = number_rings;
    if (nb_queue_pairs > dev_info.max_rx_queues) {
        printf("  -> Capping RX queues from %u to %u\n", nb_queue_pairs, dev_info.max_rx_queues);
        nb_queue_pairs = dev_info.max_rx_queues;
    }
    if (nb_queue_pairs > dev_info.max_tx_queues) {
        printf("  -> Capping TX queues from %u to %u\n", nb_queue_pairs, dev_info.max_tx_queues);
        nb_queue_pairs = dev_info.max_tx_queues;
    }
    rx_rings = nb_queue_pairs;
    tx_rings = nb_queue_pairs;

    /* Build port_conf with safe defaults */
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode  = RTE_ETH_MQ_RX_RSS,
            .offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP, /* we'll clear below if unsupported */
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf  = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP,
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };

    /* Remove unsupported offloads */
    if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
        printf("  -> NIC does not support RX_TIMESTAMP. Disabling offload.\n");
        port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    }

    /* Mask RSS hash types */
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
        printf("  -> WARNING: NIC does not support requested RSS hash types. Disabling RSS.\n");
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    }

    /* Configure the device */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0)
        return retval;

    /* Adjust descriptors */
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval < 0)
        return retval;

    /* Setup RX queues */
    rxconf = dev_info.default_rxconf;
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port),
                                        &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Setup TX queues */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port),
                                        &txconf);
        if (retval < 0)
            return retval;
    }

    /* Start the device */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable promiscuous mode */
    rte_eth_promiscuous_enable(port);

    printf("Port %u successfully initialized with %u RX/TX queues.\n",
           port, nb_queue_pairs);
    return 0;
}

 
 
 
 // Start of HW timestamps
 static inline bool
is_timestamp_enabled(const struct rte_mbuf *mbuf)
{
    static uint64_t timestamp_rx_dynflag;
    int timestamp_rx_dynflag_offset;

    if (timestamp_rx_dynflag == 0) {
        timestamp_rx_dynflag_offset = rte_mbuf_dynflag_lookup(
                RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, NULL);
        if (timestamp_rx_dynflag_offset < 0)
            return false;
        timestamp_rx_dynflag = RTE_BIT64(timestamp_rx_dynflag_offset);
    }

    return (mbuf->ol_flags & timestamp_rx_dynflag) != 0;
}

static inline rte_mbuf_timestamp_t
get_hw_timestamp(const struct rte_mbuf *mbuf)
{
    static int timestamp_dynfield_offset = -1;

    if (timestamp_dynfield_offset < 0) {
        timestamp_dynfield_offset = rte_mbuf_dynfield_lookup(
                RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
        if (timestamp_dynfield_offset < 0)
            return 0;
    }

    return *RTE_MBUF_DYNFIELD(mbuf,
            timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

// End of HW timetamps


// Starting encryption functions ------------------------------------------------
#ifdef USE_ARM_AES
#include <arm_neon.h>
#endif

// ---------- AES-128 key schedule (portable C) ----------
static void aes128_key_expand(const uint8_t key[16], uint8_t round_keys[176]) {
    static const uint8_t rcon[10] =
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

    memcpy(round_keys, key, 16);
    uint8_t t[4];
    for (int i = 16, r = 0; i < 176; i += 4) {
        t[0] = round_keys[i - 4];
        t[1] = round_keys[i - 3];
        t[2] = round_keys[i - 2];
        t[3] = round_keys[i - 1];

        if (i % 16 == 0) {
            // RotWord
            uint8_t tmp = t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;
            // SubWord (AES S-box)
            static const uint8_t sbox[256] = {
                0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
                0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
                0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
                0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
                0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
                0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
                0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
                0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
                0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
                0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
                0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
                0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
                0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
                0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
                0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
                0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
            };
            t[0] = sbox[t[0]]; t[1] = sbox[t[1]]; t[2] = sbox[t[2]]; t[3] = sbox[t[3]];
            t[0] ^= rcon[r++];
        }

        round_keys[i + 0] = round_keys[i - 16] ^ t[0];
        round_keys[i + 1] = round_keys[i - 15] ^ t[1];
        round_keys[i + 2] = round_keys[i - 14] ^ t[2];
        round_keys[i + 3] = round_keys[i - 13] ^ t[3];
    }
}

// ---------- AES-128 encrypt 1 block with ARMv8 Crypto Extensions ----------
#ifdef USE_ARM_AES
static inline void aes128_encrypt_block_neon(const uint8_t in[16],
                                             const uint8_t rk_bytes[176],
                                             uint8_t out[16]) {
    const uint8x16_t *rk = (const uint8x16_t *)rk_bytes;

    // ---- Round 0: initial whitening ----
    // x = plaintext ^ K0
    uint8x16_t x = veorq_u8(vld1q_u8(in), rk[0]);

    // ---- Rounds 1..9 ----
    for (int r = 1; r < 10; r++) {
        // AESE with zero "key": SubBytes + ShiftRows (no AddRoundKey)
        x = vaeseq_u8(x, vdupq_n_u8(0));

        // MixColumns
        x = vaesmcq_u8(x);

        // AddRoundKey AFTER MixColumns (correct AES order)
        x = veorq_u8(x, rk[r]);
    }

    // ---- Round 10 (final) ----
    // SubBytes + ShiftRows
    x = vaeseq_u8(x, vdupq_n_u8(0));

    // AddRoundKey (no MixColumns in final round)
    x = veorq_u8(x, rk[10]);

    // store result
    vst1q_u8(out, x);
}

#endif

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}
// Known-answer test from FIPS-197:
// Key:        000102030405060708090a0b0c0d0e0f
// Plaintext:  00112233445566778899aabbccddeeff
// Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
static int aes_selftest_neon(void) {

    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const uint8_t pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const uint8_t expect[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    uint8_t rk[176];
    aes128_key_expand(key, rk);

    uint8_t ct[16];
    aes128_encrypt_block_neon(pt, rk, ct);

    int ok = (memcmp(ct, expect, 16) == 0);
    print_hex("AES-128 PT : ", pt, 16);
    print_hex("AES-128 CT : ", ct, 16);
    print_hex("AES-128 EXP: ", expect, 16);
    printf("AES-128 NEON selftest: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : -1;
}

// End of encryption functions
//--------------------------------------------------------------------------


static inline uint64_t rdtsc_now(void) {
    return rte_rdtsc_precise();
}

// runs N encryptions and records per-op latency in cycles
static void benchmark_aes_neon(size_t iters, double tsc_hz) {
#ifdef USE_ARM_AES
    const uint8_t key[16] = {0};
    uint8_t rk[176];
    aes128_key_expand(key, rk);

    // start with some PT in regs
    uint8x16_t pt = vdupq_n_u8(0xA5);
    // 128-bit counter to mutate PT each iter
    uint64x2_t ctr = {1, 0x9E3779B97F4A7C15ULL}; // golden-ratio step

    // warmup
    uint8_t ct_tmp[16];
    for (int i=0;i<1000;i++) {
        uint8x16_t ptv = vreinterpretq_u8_u64(
            veorq_u64(vreinterpretq_u64_u8(pt), ctr));
        uint8_t pt_bytes[16];
        vst1q_u8(pt_bytes, ptv);
        aes128_encrypt_block_neon(pt_bytes, rk, ct_tmp);
        // advance the counter and rotate/mix a bit
        ctr = vaddq_u64(ctr, (uint64x2_t){1,1});
        pt = veorq_u8(pt, vqtbl1q_u8(pt, vld1q_u8((uint8_t[16]){1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0})));
    }

    // measure per-iteration latency (still affected by loop overhead)
    uint64_t *samples = malloc(sizeof(uint64_t) * iters);
    if (!samples) { perror("malloc"); return; }

    for (size_t i=0; i<iters; i++) {
        uint8x16_t ptv = vreinterpretq_u8_u64(
            veorq_u64(vreinterpretq_u64_u8(pt), ctr));
        uint8_t pt_bytes[16];
        vst1q_u8(pt_bytes, ptv);

        uint64_t t0 = rte_rdtsc_precise();
        aes128_encrypt_block_neon(pt_bytes, rk, ct_tmp);
        uint64_t t1 = rte_rdtsc_precise();

        samples[i] = t1 - t0;

        ctr = vaddq_u64(ctr, (uint64x2_t){0x10001,0x9E37});
        pt  = veorq_u8(pt, vrev64q_u8(pt)); // keep mutating PT in regs
    }


    // Write CSV
    FILE *f = fopen("aes_latencies.csv", "w");
    if (!f) { perror("fopen"); return; }
    fprintf(f, "# tsc_hz,%.0f\n", tsc_hz);
    fprintf(f, "iter,cycles,ns\n");
    for (size_t i=0;i<aes_lat_count;i++) {
        double ns = (double)aes_lat_cycles[i] * 1e9 / tsc_hz;
        fprintf(f, "%zu,%" PRIu64 ",%.3f\n", i, aes_lat_cycles[i], ns);
    }
    fclose(f);

    // Quick summary
    uint64_t min=UINT64_MAX, max=0, sum=0;
    for (size_t i=0;i<aes_lat_count;i++){ uint64_t c=aes_lat_cycles[i]; if(c<min)min=c; if(c>max)max=c; sum+=c; }
    double avg_ns = ((double)sum/aes_lat_count) * 1e9 / tsc_hz;
    printf("AES bench: samples=%zu  min=%" PRIu64 " cyc  max=%" PRIu64 " cyc  avg=%.2f ns\n",
           aes_lat_count, min, max, avg_ns);
#else
    (void)iters; (void)tsc_hz;
    printf("AES bench skipped: USE_ARM_AES not defined.\n");
#endif
}






static inline uint32_t
allocate_entry_per_core(struct worker_args *w)
{
    if (w->next_free >= MAX_FLOWS_PER_CORE){
        printf("invalid index");
        return INVALID_INDEX;
    }
        
    /* grab the next slot; it’s already zeroed at startup */
    return w->next_free++;
}


static inline void
reset_entry_per_core(struct worker_args *w, uint32_t idx)
{
    struct flow_entry *e = &w->flow_pool[idx];

    // Clear everything
    memset(e, 0, sizeof(*e));

    // Set initial “min” values so first packet always replaces them
    e->len_min = UINT32_MAX;
    e->iat_min = UINT64_MAX;
}


static inline uint8_t
count_bits(uint8_t x) {
    // GCC/Clang builtin popcount
    return __builtin_popcount(x);
}

void update_flow_entry(struct flow_entry *e,
                       uint16_t    pkt_len,
                       uint64_t    now_cycles,
                       uint8_t     tcp_flags_count)
{
    uint64_t iat = (e->pkt_count > 0)
                   ? (now_cycles - e->last_timestamp)
                   : 0;

    if (e->pkt_count == 0) {
        e->len_min   = pkt_len;
        e->len_max   = pkt_len;
        e->len_sum   = pkt_len;

        e->iat_min   = UINT64_MAX;
        e->iat_max   = 0;
        e->iat_sum   = 0;

        e->first_timestamp = now_cycles;
        e->total_len       = pkt_len;

        e->flag_bits_sum   = tcp_flags_count;
    } else {
        /* length stats */
        if (pkt_len < e->len_min) e->len_min = pkt_len;
        if (pkt_len > e->len_max) e->len_max = pkt_len;
        e->len_sum += pkt_len;

        /* IAT stats */
        if (iat < e->iat_min) e->iat_min = iat;
        if (iat > e->iat_max) e->iat_max = iat;
        e->iat_sum += iat;

        /* total bytes */
        e->total_len += pkt_len;

        /* flag bits sum */
        e->flag_bits_sum += tcp_flags_count;
    }

    e->last_timestamp = now_cycles;
    e->pkt_count++;
}


static inline void
handle_packet(struct flow_key   *key,
              uint16_t           pkt_len,
              uint64_t           now,
              uint8_t            flags_count,
              struct worker_args *w)
{
    void    *data_ptr = NULL;
    int      ret      = rte_hash_lookup_data(w->flow_table, key, &data_ptr);
    uint32_t index;

    if (ret < 0) {
        // not found: grab a new slot
        index = allocate_entry_per_core(w);
        if (index == INVALID_INDEX)
            return;  // table full

        ret = rte_hash_add_key_data(w->flow_table,
                                    key,
                                    (void*)(uintptr_t)index);
        if (ret < 0) {
            // failed to insert: rewind allocator
            w->next_free--;
            return;
        }
    } else {
        // found: unwrap the stored index
        index = (uint32_t)(uintptr_t)data_ptr;
    }

    struct flow_entry *e = &w->flow_pool[index];

    // update per‐flow stats
    update_flow_entry(e, pkt_len, now, flags_count);

    // once N_PACKETS seen, build features & (optionally) predict
    if (e->pkt_count >= N_PACKETS) {
        double hz = (double)rte_get_tsc_hz();

        float mean_len = (float)(e->len_sum   / (double)e->pkt_count);
        float mean_iat = (float)(e->iat_sum   / (double)(e->pkt_count - 1))
                         * 1e6f / hz;

        ALIGN16 float features[8] = {
            (float)e->len_min,
            (float)e->len_max,
            mean_len,
            (float)(e->iat_min / hz * 1e6),
            (float)(e->iat_max / hz * 1e6),
            mean_iat,
            (float)e->total_len,
            (float)e->flag_bits_sum
        };

        // cleanup flows
        //rte_hash_del_key(w->flow_table, key);
        reset_entry_per_core(w, index);
    }
}


static struct worker_args worker_args[MAX_CORES];


 double right_predictions=0;
 double wrong_predictions=0;
 
 double received_packets=0;
 double processed_packets=0;
 

 static int lcore_main(void *args)
 {
    struct worker_args *w = (struct worker_args *)args;

    struct rte_mempool *mbuf_pool = w->mbuf_pool;
    struct rte_hash    *flow_table = w->flow_table;

     uint16_t port;
     uint16_t ret;
     uint16_t queue_id = w->queue_id;

     struct flow_key key;
     struct flow_entry entry;
 
     double sample[5];
 
     RTE_ETH_FOREACH_DEV(port)
     if (rte_eth_dev_socket_id(port) >= 0 &&
         rte_eth_dev_socket_id(port) !=
             (int)rte_socket_id())
         printf("WARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.\n",
                port);
 
     printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
            rte_lcore_id());
 
 
     uint32_t pkt_count = 0;

     for (;;)
     {

            struct rte_mbuf *bufs[BURST_SIZE];
            
            uint16_t nb_rx = rte_eth_rx_burst(w->port_id, w->queue_id, bufs, BURST_SIZE);
            //printf(" -> burst returned %u pkts\n", nb_rx);
            if (unlikely(nb_rx == 0)) continue;

            // break;
            if (nb_rx > 0)
            {
                uint64_t start_cycles = rte_rdtsc_precise();

            
                received_packets+=nb_rx;
                struct rte_ether_hdr *ethernet_header; 
                struct rte_ipv4_hdr *pIP4Hdr;
                struct rte_tcp_hdr *pTcpHdr;
            
                u_int16_t ethernet_type;
                for (int i = 0; i < nb_rx; i++)
                {
                    // pkt_count +=1;
                    ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                    ethernet_type = ethernet_header->ether_type;
                    ethernet_type = rte_cpu_to_be_16(ethernet_type);

                    //swap
                    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                    struct rte_ether_addr tmp;
                    rte_ether_addr_copy(&eth->src_addr, &tmp);
                    rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
                    rte_ether_addr_copy(&tmp,         &eth->dst_addr);
                    if (ethernet_type == 2048)
                    {
                        uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);

                        pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, ipdata_offset);
                        uint32_t src_ip = rte_be_to_cpu_32(pIP4Hdr->src_addr);
                        uint32_t dst_ip = rte_be_to_cpu_32(pIP4Hdr->dst_addr);
                        uint8_t IPv4NextProtocol = pIP4Hdr->next_proto_id;
                        ipdata_offset += (pIP4Hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

                        if (IPv4NextProtocol == 6)
                        {

                            pTcpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, ipdata_offset);
                            uint16_t dst_port = rte_be_to_cpu_16(pTcpHdr->dst_port);
                            uint16_t src_port = rte_be_to_cpu_16(pTcpHdr->src_port);
                            uint8_t tcp_dataoffset = pTcpHdr->data_off >> 4;
                            uint32_t tcpdata_offset = ipdata_offset + sizeof(struct rte_tcp_hdr) + (tcp_dataoffset - 5) * 4;
                            /* figure out how many ‘1’ bits are set in TCP flags, or 0 otherwise */
                            // integrate code below with down code
                        uint8_t flags_count = __builtin_popcount(pTcpHdr->tcp_flags);


                        //printf("This is a application data packet");
                        key.src_ip = dst_ip;  
                        key.dst_ip = src_ip; 
                        key.src_port = dst_port;
                        key.dst_port = src_port;
                        key.protocol = IPv4NextProtocol;

                        uint16_t pkt_len = pIP4Hdr->total_length;
                        uint64_t pkt_time = is_timestamp_enabled(bufs[i]) ? get_hw_timestamp(bufs[i]) : 0; 
                        
                        //printf("Pkt time: %" PRIu64 " cycles\n", pkt_time);
                        // printf("TSC frequency: %lu Hz\n", hz);
                        
                        // int prediction = predict_mlp(features);
                        // uint64_t start_cycles = rte_rdtsc_precise();

                        //handle_packet(&key, pkt_len, pkt_time, flags_count, w);
    
                        // uint64_t end_cycles = rte_rdtsc_precise();
                        // uint64_t inference_cycles = end_cycles - start_cycles;

                        // // Convert to nanoseconds
                        // double latency_ns = ((double)inference_cycles / hz) * 1e9;

                        // printf("Latency: %.2f ns (%lu cycles)\n", latency_ns, inference_cycles);                                       
                        
                    }
                }
            }
            
            //uint64_t end_cycles = rte_rdtsc_precise();
            //if (latency_count < MAX_SAMPLES) latency_cycles[latency_count++] = end_cycles - start_cycles;
            
            /*
            //for testing number flows in every flow table per core
            static uint64_t stats_counter = 0;
            stats_counter += nb_rx;  // or just ++stats_counter for per‐packet

            if (stats_counter >= 10000) {   // every 10k packets…
                uint32_t used = rte_hash_count(w->flow_table);
                printf("Core %u: %u active flows\n",
                    rte_lcore_id(), used);
                stats_counter = 0;
            }
            */

            if (unlikely(nb_rx == 0))
                continue;
            //printf("Core %u: about to burst %u pkts on port %u queue %u\n",
                //rte_lcore_id(), nb_rx, w->port_id, w->queue_id);

            
            uint16_t nb_tx = rte_eth_tx_burst(w->port_id, w->queue_id, bufs, nb_rx);

            //printf("Core %u: burst returned %u (dropped %u)\n",
                //rte_lcore_id(), nb_tx, nb_rx - nb_tx);

            //const uint16_t nb_tx = rte_eth_tx_burst(w->port_id, w->queue_id, bufs, nb_rx);

            processed_packets += nb_tx;

            if (unlikely(nb_tx < nb_rx))
            {
                uint16_t buf;

                // printf("SOme packets are not processed\n");

                for (buf = nb_tx; buf < nb_rx; buf++)
                    rte_pktmbuf_free(bufs[buf]); 
            }

            // printf("Core %u proceesed %u packets\n",core_id,*packet_counter);

            }
         
     }
 
     return 0;
 }
 

 static void close_ports(void);
 static void close_ports(void)
 {
     uint16_t portid;
     int ret;
     uint16_t nb_ports;
     nb_ports = rte_eth_dev_count_avail();
     for (portid = 0; portid < nb_ports; portid++)
     {
         printf("Closing port %d...", portid);
         ret = rte_eth_dev_stop(portid);
         if (ret != 0)
             rte_exit(EXIT_FAILURE, "rte_eth_dev_stop: err=%s, port=%u\n",
                      strerror(-ret), portid);
         rte_eth_dev_close(portid);
         printf(" Done\n");
     }
 }
 



 /* Initialization of Environment Abstraction Layer (EAL). 8< */
 int main(int argc, char **argv)
 {
     struct rte_mempool *mbuf_pool;
     uint16_t nb_ports;
     uint16_t portid;
     unsigned lcore_id;
     int ret;
     // int packet_counters[10] = {0};
    

     ret = rte_eal_init(argc, argv);
     if (ret < 0)
         rte_panic("Cannot init EAL\n");

    printf("DPDK version: %s\n", rte_version());

    unsigned total_lcores = rte_lcore_count();

    
    struct rte_hash_parameters p = {
    .entries           = MAX_FLOWS_PER_CORE,
    .key_len           = sizeof(struct flow_key),
    .hash_func         = rte_jhash,
    .hash_func_init_val= 0,
    .socket_id         = rte_socket_id(),
    };
    for (unsigned core = 0; core < total_lcores; core++) {
    char name[32];
    snprintf(name, sizeof(name), "ftbl_%u", core);
    p.name = name;
    flow_tables[core] = rte_hash_create(&p);
    if (!flow_tables[core])
        rte_exit(EXIT_FAILURE, "Cannot create hash for core %u\n", core);
    }

     argc -= ret;
     argv += ret;
 
     nb_ports = rte_eth_dev_count_avail();
 
     mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                         NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                         RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
     if (mbuf_pool == NULL)
         rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

     RTE_ETH_FOREACH_DEV(portid)
     if (port_init(portid, mbuf_pool,total_lcores) != 0)
     {
         rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                  portid);
     }
     else{
         printf("port %u initialized\n",portid);
     };


    double tsc_hz = (double)rte_get_tsc_hz();
    benchmark_aes_neon(100000, tsc_hz);
    printf("Wrote aes_latencies.csv (cycles + ns)\n");
    
    uint16_t queue_id = 0;
    uint16_t base_port = 0;  // your only port

    for (unsigned core_id = 0; core_id < total_lcores; core_id++) {
        struct worker_args *w = &worker_args[core_id];

        // 1) Shared resources
        w->mbuf_pool  = mbuf_pool;
        w->flow_table = flow_tables[core_id];
        w->flow_pool  = flow_pools[core_id];
        w->port_id  = base_port;


        // 2) Per-core state
        w->next_free  = 0;            // start allocating at slot 0
        w->queue_id   = queue_id++;   // one RX queue per core

        // 4) Launch worker on that core (skip core 0 if you plan to use it as master below)
        if (core_id != rte_get_main_lcore()) {
            rte_eal_remote_launch(lcore_main, w, core_id);
        }
    }

    // Finally, run master on its own core (often core 0)
    unsigned master = rte_get_main_lcore();
    struct worker_args *w_master = &worker_args[master];
    // (mbuf_pool, flow_table, flow_pool, next_free, queue_id already set above)
    lcore_main(w_master);

   
    

     char command[50];
     
     while (1) {
         printf("Enter command: ");
         scanf("%20s", command);
         // printf("The input command is %s\n",command);
 
         if (strcmp(command, "get_stats") == 0) {
             RTE_LCORE_FOREACH_WORKER(lcore_id)
             {
 
                 char output_file[50]; //= "../datasets/DoHBrw/predictions.txt";
                 
                 printf("Enter file name: ");
                 scanf("%20s", output_file);   
 
                 FILE *file = fopen(output_file, "w");
 
                 if (file == NULL) {
                     printf("Error opening the file.\n");
                     return -1;
                 }
 
                 fprintf(file, "Reeived Processed Dropped\n");
                 // printf("Core %u processed %u packets\n",lcore_id,packet_counters[lcore_id]);
                 fprintf(file, "%f %f %.3f \n",received_packets,processed_packets,(double)(processed_packets/received_packets));
                 right_predictions = 0;
                 wrong_predictions = 0;
                 received_packets = 0;
                 processed_packets = 0;
 
                 fclose(file);
                 // packet_counters[lcore_id] = 0;
             }
              //break;
         }
     }
 
 
     rte_eal_mp_wait_lcore();
 
     // free each per-core hash table
    for (unsigned core_id = 0; core_id < total_lcores; core_id++) {
        if (flow_tables[core_id]) {
            rte_hash_free(flow_tables[core_id]);
            flow_tables[core_id] = NULL;
        }
    }
 
     close_ports();
 
     /* clean up the EAL */
     rte_eal_cleanup();
 
     return 0;
 }