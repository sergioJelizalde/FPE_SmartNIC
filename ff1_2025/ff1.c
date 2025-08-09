// ff1_aes_neon.c
// AES-FF1 (NIST SP 800-38G Rev.1, 2nd public draft, Feb 2025)
// Encrypt + Decrypt; AES-128 via ARMv8 AES/NEON.
// Build: clang -O3 -march=armv8-a+crypto -std=c11 ff1_aes_neon.c -o ff1

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arm_neon.h>
#include <rte_cycles.h>
// ---------------- AES-128 key schedule (portable) ----------------
static void aes128_key_expand(const uint8_t key[16], uint8_t rk[176]) {
    static const uint8_t rcon[10] =
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};
    memcpy(rk, key, 16);
    uint8_t t[4];
    for (int i = 16, r = 0; i < 176; i += 4) {
        t[0]=rk[i-4]; t[1]=rk[i-3]; t[2]=rk[i-2]; t[3]=rk[i-1];
        if (i % 16 == 0) {
            uint8_t tmp=t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;
            static const uint8_t sbox[256]={
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
            t[0]=sbox[t[0]]; t[1]=sbox[t[1]]; t[2]=sbox[t[2]]; t[3]=sbox[t[3]];
            t[0]^=rcon[r++];
        }
        rk[i+0]=rk[i-16]^t[0];
        rk[i+1]=rk[i-15]^t[1];
        rk[i+2]=rk[i-14]^t[2];
        rk[i+3]=rk[i-13]^t[3];
    }
}

// ---------------- AES-128 encrypt one block (ARMv8 AES/NEON) ----------------
static inline void aes128_encrypt_block_neon(const uint8_t in[16],
                                             const uint8_t rk[176],
                                             uint8_t out[16]) {
    const uint8x16_t *rks = (const uint8x16_t*)rk; // 11 round keys
    uint8x16_t x = veorq_u8(vld1q_u8(in), rks[0]); // AddRoundKey
    for (int r=1; r<10; r++) {
        x = vaeseq_u8(x, vdupq_n_u8(0));
        x = vaesmcq_u8(x);
        x = veorq_u8(x, rks[r]);
    }
    x = vaeseq_u8(x, vdupq_n_u8(0));
    x = veorq_u8(x, rks[10]);
    vst1q_u8(out, x);
}

// ---------------- PRF (CBC-MAC with zero IV) -------------------
static void prf_cbc_mac_neon(const uint8_t *rk,
                             const uint8_t *X, size_t nblocks,
                             uint8_t out[16]) {
    uint8_t Y[16] = {0};
    for (size_t j=0; j<nblocks; j++) {
        uint8_t blk[16];
        const uint8_t *p = X + 16*j;
        for (int i=0;i<16;i++) blk[i] = Y[i] ^ p[i];
        aes128_encrypt_block_neon(blk, rk, Y);
    }
    memcpy(out, Y, 16);
}

// ---------------- Utilities (NUM/STR in base 'radix') -----------------------
static void encode_uint32_be(uint32_t v, uint8_t out[4]){
    out[0]=v>>24; out[1]=v>>16; out[2]=v>>8; out[3]=v;
}

static uint32_t ceil_div(uint32_t a, uint32_t b){ return (a + b - 1)/b; }

// Convert big-endian byte string Y (length ylen) into base-radix digits modulo radix^m.
// D gets m digits, most significant at index 0.
static void bytes_mod_radixm(const uint8_t *Y, size_t ylen,
                             uint32_t *D, size_t m, uint32_t radix) {
    memset(D, 0, m*sizeof(uint32_t));
    for (size_t k=0; k<ylen; k++) {
        uint64_t carry = Y[k];
        for (ssize_t i=(ssize_t)m-1; i>=0; i--) {
            uint64_t v = (uint64_t)D[i]*256 + carry;
            D[i] = (uint32_t)(v % radix);
            carry = v / radix;
        }
    }
}

static void add_radixm(const uint32_t *A, const uint32_t *Z,
                       uint32_t *C, size_t m, uint32_t radix) {
    int64_t carry = 0;
    for (ssize_t i=(ssize_t)m-1; i>=0; i--) {
        int64_t v = (int64_t)A[i] + Z[i] + carry;
        carry = v / (int64_t)radix;
        int64_t rem = v % (int64_t)radix;
        if (rem < 0) { rem += radix; carry--; }
        C[i] = (uint32_t)rem;
    }
    // carry discarded (mod r^m)
}

// NEW: modular subtraction C = (A - Z) mod radix^m
static void sub_radixm(const uint32_t *A, const uint32_t *Z,
                       uint32_t *C, size_t m, uint32_t radix) {
    int64_t borrow = 0;
    for (ssize_t i=(ssize_t)m-1; i>=0; i--) {
        int64_t v = (int64_t)A[i] - Z[i] - borrow;
        if (v < 0) { v += radix; borrow = 1; } else borrow = 0;
        C[i] = (uint32_t)v;
    }
    // modulo r^m -> ignore final borrow (wrap already applied)
}

// ---------------- FF1 parameters -------------------------------------------
typedef struct {
    uint32_t radix;      // 2..65536
    uint32_t minlen;     // >=2, and radix^minlen >= 1,000,000
    uint32_t maxlen;     // practical upper bound
    uint32_t maxTlen;    // tweak bytes limit
} ff1_params;

// Helper to compute b and d from v (per draft)
static void compute_b_d(uint32_t radix, uint32_t v, uint32_t *b, uint32_t *d){
    // bitlen(radix^v - 1) == ceil(v * log2(radix)), but avoid FP:
    // find smallest s with radix^v <= 2^s using 128-bit.
    __uint128_t r = 1;
    uint64_t s = 0;
    for (uint32_t i=0;i<v;i++){
        r *= radix;
        while (r > (((__uint128_t)1)<<s)) s++;
    }
    *b = (uint32_t)ceil_div((uint32_t)s, 8);
    *d = 4*ceil_div(*b,4) + 4;
}

// Build the 16-byte P block (Step 5)
static void build_P(uint8_t Pblk[16], uint32_t radix, uint32_t u, uint32_t n, uint32_t t){
    memset(Pblk, 0, 16);
    Pblk[0]=0x01; Pblk[1]=0x02; Pblk[2]=0x01;
    Pblk[3]=(radix>>16)&0xFF; Pblk[4]=(radix>>8)&0xFF; Pblk[5]=radix&0xFF;
    Pblk[6]=0x0A;
    Pblk[7]=(uint8_t)(u & 0xFF);
    encode_uint32_be(n, &Pblk[8]);
    encode_uint32_be(t, &Pblk[12]);
}

// Encode NUM_radix(B) into b bytes big-endian.
// B has lenB digits in base radix (MSD first). Work via repeated div by 256.
static void encode_NUMradix_to_b(const uint32_t *B, uint32_t lenB,
                                 uint32_t radix, uint32_t b, uint8_t *Nb_out){
    uint32_t *tmp = (uint32_t*)alloca(lenB*sizeof(uint32_t));
    memcpy(tmp, B, lenB*sizeof(uint32_t));
    memset(Nb_out, 0, b);
    for (int bi=(int)b-1; bi>=0; bi--) {
        uint64_t rem = 0;
        for (uint32_t di=0; di<lenB; di++) {
            uint64_t cur = tmp[di] + rem*(uint64_t)radix;
            tmp[di] = (uint32_t)(cur / 256);
            rem = cur % 256;
        }
        Nb_out[bi] = (uint8_t)rem;
    }
}

// ---------------- FF1.Encrypt ----------------------------------------------
int ff1_encrypt_aes_neon(const ff1_params *P,
                         const uint8_t key[16],
                         const uint8_t *T, uint32_t t,
                         const uint32_t *X, uint32_t n,
                         uint32_t *Y)
{
    if (!P || !X || !Y) return -1;
    if (P->radix < 2 || P->radix > 65536) return -2;
    if (n < P->minlen || n > P->maxlen) return -3;
    if (t > P->maxTlen) return -4;

    const uint32_t radix = P->radix;
    uint32_t u = n/2, v = n - u;

    const uint32_t *A0 = X;
    const uint32_t *B0 = X + u;

    uint32_t b, d; compute_b_d(radix, v, &b, &d);

    uint8_t Pblk[16]; build_P(Pblk, radix, u, n, t);

    uint8_t rk[176]; aes128_key_expand(key, rk);

    uint32_t *A = (uint32_t*)malloc(n*sizeof(uint32_t));
    uint32_t *B = A + 0;
    memcpy(A, A0, u*sizeof(uint32_t));
    memcpy(A+u, B0, v*sizeof(uint32_t));
    uint32_t *Aptr = A;
    uint32_t *Bptr = A + u;

    uint8_t *Q = (uint8_t*)malloc(t + ((16 - (t + 1 + b)%16)%16) + 1 + b);

    for (uint32_t i=0; i<10; i++) {
        uint32_t qlen = 0;
        memcpy(Q + qlen, T, t); qlen += t;
        uint32_t pad = (uint32_t)((16 - ((t + 1 + b) % 16)) % 16);
        memset(Q + qlen, 0, pad); qlen += pad;
        Q[qlen++] = (uint8_t)i;

        uint32_t lenB = (i%2==0) ? v : u;
        encode_NUMradix_to_b((i%2==0)? Bptr : Aptr, lenB, radix, b, Q + qlen);
        qlen += b;

        uint32_t pqlen = 16 + qlen;
        uint8_t *PQ = (uint8_t*)alloca(pqlen);
        memcpy(PQ, Pblk, 16);
        memcpy(PQ+16, Q, qlen);
        uint8_t R[16]; prf_cbc_mac_neon(rk, PQ, pqlen/16, R);

        uint32_t so = 0;
        uint8_t *S = (uint8_t*)alloca(d);
        uint32_t take = (d - so > 16) ? 16 : (d - so);
        memcpy(S+so, R, take); so += take;
        for (uint32_t ctr=1; so<d; ctr++) {
            uint8_t blk[16]; memcpy(blk, R, 16);
            blk[15]^=(uint8_t)(ctr&0xFF);
            blk[14]^=(uint8_t)((ctr>>8)&0xFF);
            blk[13]^=(uint8_t)((ctr>>16)&0xFF);
            blk[12]^=(uint8_t)((ctr>>24)&0xFF);
            uint8_t out[16]; aes128_encrypt_block_neon(blk, rk, out);
            take = (d - so > 16) ? 16 : (d - so);
            memcpy(S+so, out, take); so += take;
        }

        uint32_t m = (i%2==0) ? u : v;
        uint32_t *Ymod = (uint32_t*)alloca(m*sizeof(uint32_t));
        bytes_mod_radixm(S, d, Ymod, m, radix);

        uint32_t *C = (uint32_t*)alloca(m*sizeof(uint32_t));
        const uint32_t *Acur = (i%2==0) ? Aptr : Bptr;
        add_radixm(Acur, Ymod, C, m, radix);

        if (i%2==0) { // lengths swap
            memcpy(Aptr, Bptr, v*sizeof(uint32_t));
            memcpy(Bptr, C,   u*sizeof(uint32_t));
        } else {
            memcpy(Aptr, Bptr, u*sizeof(uint32_t));
            memcpy(Bptr, C,   v*sizeof(uint32_t));
        }
    }

    memcpy(Y, Aptr, u*sizeof(uint32_t));
    memcpy(Y+u, Bptr, v*sizeof(uint32_t));
    free(A); free(Q);
    return 0;
}

// ---------------- FF1.Decrypt ----------------------------------------------
int ff1_decrypt_aes_neon(const ff1_params *P,
                         const uint8_t key[16],
                         const uint8_t *T, uint32_t t,
                         const uint32_t *Y, uint32_t n,
                         uint32_t *Xout)
{
    if (!P || !Y || !Xout) return -1;
    if (P->radix < 2 || P->radix > 65536) return -2;
    if (n < P->minlen || n > P->maxlen) return -3;
    if (t > P->maxTlen) return -4;

    const uint32_t radix = P->radix;
    uint32_t u = n/2, v = n - u;

    // Final (A10,B10) comes from Y
    const uint32_t *A10 = Y;
    const uint32_t *B10 = Y + u;

    uint32_t b, d; compute_b_d(radix, v, &b, &d);
    uint8_t Pblk[16]; build_P(Pblk, radix, u, n, t);

    uint8_t rk[176]; aes128_key_expand(key, rk);

    // Work buffers that we’ll walk backwards: hold A_{i+1}, B_{i+1}
    uint32_t *A = (uint32_t*)malloc(n*sizeof(uint32_t));
    uint32_t *B = A + 0;
    memcpy(A, A10, u*sizeof(uint32_t));
    memcpy(A+u, B10, v*sizeof(uint32_t));
    uint32_t *Aip1 = A;          // A_{i+1}
    uint32_t *Bip1 = A + u;      // B_{i+1}

    uint8_t *Q = (uint8_t*)malloc(t + ((16 - (t + 1 + b)%16)%16) + 1 + b);

    for (int i=9; i>=0; i--) {
        // Inverse round: we *know* B_i = A_{i+1}. Compute y from B_i.
        uint32_t qlen = 0;
        memcpy(Q + qlen, T, t); qlen += t;
        uint32_t pad = (uint32_t)((16 - ((t + 1 + b) % 16)) % 16);
        memset(Q + qlen, 0, pad); qlen += pad;
        Q[qlen++] = (uint8_t)i;

        uint32_t lenBi = (i%2==0) ? v : u; // length of B_i
        encode_NUMradix_to_b(Aip1, lenBi, radix, b, Q + qlen); // B_i == A_{i+1}
        qlen += b;

        uint32_t pqlen = 16 + qlen;
        uint8_t *PQ = (uint8_t*)alloca(pqlen);
        memcpy(PQ, Pblk, 16);
        memcpy(PQ+16, Q, qlen);
        uint8_t R[16]; prf_cbc_mac_neon(rk, PQ, pqlen/16, R);

        uint32_t so = 0;
        uint8_t *S = (uint8_t*)alloca(d);
        uint32_t take = (d - so > 16) ? 16 : (d - so);
        memcpy(S+so, R, take); so += take;
        for (uint32_t ctr=1; so<d; ctr++) {
            uint8_t blk[16]; memcpy(blk, R, 16);
            blk[15]^=(uint8_t)(ctr&0xFF);
            blk[14]^=(uint8_t)((ctr>>8)&0xFF);
            blk[13]^=(uint8_t)((ctr>>16)&0xFF);
            blk[12]^=(uint8_t)((ctr>>24)&0xFF);
            uint8_t out[16]; aes128_encrypt_block_neon(blk, rk, out);
            take = (d - so > 16) ? 16 : (d - so);
            memcpy(S+so, out, take); so += take;
        }

        // y mod r^m where m is len(A_i)
        uint32_t m = (i%2==0) ? u : v;
        uint32_t *Ymod = (uint32_t*)alloca(m*sizeof(uint32_t));
        bytes_mod_radixm(S, d, Ymod, m, radix);

        // Recover A_i = (B_{i+1} - y) mod r^m
        uint32_t *Ai = (uint32_t*)alloca(m*sizeof(uint32_t));
        sub_radixm((i%2==0)? Bip1 : Bip1, Ymod, Ai, m, radix); // Bip1 has length m here:
        // (when i even, m=u => Bip1 length is u; when i odd, m=v => Bip1 length is v)

        // Now B_i = A_{i+1} (already have it)
        // Prepare (A_i, B_i) for next iteration (i-1):
        if (i%2==0) {
            // At i even, A_i has length u, B_i has length v.
            // Next loop wants A_{i} as A_{i+1} and B_{i} as B_{i+1} in its variables.
            memcpy(Bip1, Aip1, v*sizeof(uint32_t)); // B_i
            memcpy(Aip1, Ai,   u*sizeof(uint32_t)); // A_i
        } else {
            // At i odd, A_i has length v, B_i has length u.
            memcpy(Bip1, Aip1, u*sizeof(uint32_t)); // B_i
            memcpy(Aip1, Ai,   v*sizeof(uint32_t)); // A_i
        }
    }

    // After i == -1, (Aip1,Bip1) hold (A0,B0)
    memcpy(Xout, Aip1, u*sizeof(uint32_t));
    memcpy(Xout+u, Bip1, v*sizeof(uint32_t));

    free(A); free(Q);
    return 0;
}

// ---------------- demo / quick check ---------------------------------------
#ifdef TEST_FF1
static void print_digits(const uint32_t *X, uint32_t n){
    for(uint32_t i=0;i<n;i++) printf("%u", X[i]); puts("");
}
int main(void){
    ff1_params params = {.radix=10, .minlen=6, .maxlen=64, .maxTlen=64};
    uint8_t K[16]={0};
    const uint8_t tweak[]="demo";
    uint32_t X[] = {1,2,3,4,5,6,7,8,9,0};
    uint32_t n = sizeof(X)/sizeof(X[0]);
    uint32_t C[sizeof(X)/sizeof(X[0])];
    uint32_t P2[sizeof(X)/sizeof(X[0])];

    uint64_t t0 = rte_rdtsc_precise();
    if (ff1_encrypt_aes_neon(&params, K, tweak, sizeof(tweak)-1, X, n, C)!=0) {
        puts("encrypt failed"); return 1;
    }
    uint64_t t1 = rte_rdtsc_precise();
    double ns_enc = (double)(t1 - t0) * 1e9 / hz;

    t0 = rte_rdtsc_precise();
    if (ff1_decrypt_aes_neon(&params, K, tweak, sizeof(tweak)-1, C, n, P2)!=0) {
        puts("decrypt failed"); return 1;
    }
    t1 = rte_rdtsc_precise();
    double ns_dec = (double)(t1 - t0) * 1e9 / hz;
    fprintf(out, "%d,%.2f,%.2f\n", it, ns_enc, ns_dec);

    printf("PT : "); print_digits(X,n);
    printf("CT : "); print_digits(C,n);
    printf("PT' : "); print_digits(P2,n);
    return 0;
}
#endif
