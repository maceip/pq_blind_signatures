#ifndef FAEST_KEYS_INC
#define FAEST_KEYS_INC

#include "aes.hpp"
#include "constants.hpp"
#include "faest_keys.hpp"
#include "gfsmall.hpp"
#include "parameters.hpp"
#include <vector>

namespace faest
{

static inline uint8_t mul_gf16(uint8_t a, uint8_t b) {

    size_t c = 0;
    while (b) {
        if (b & 1) {
            c ^= a;
        }
        a <<= 1;
        b >>= 1;
    }

    for(size_t i = 7; i > 3; i--) {
        if ((c >> i) & 1) {
            c ^= VOLEMAYO_MOD << (i - 4);
        }
    }
    return (uint8_t)c;
}

static inline uint64_t gf16v_mul_u64( uint64_t a, uint8_t b ) {
    uint64_t mask_msb = 0x8888888888888888ULL;
    uint64_t a_msb;
    uint64_t a64 = a;
    uint64_t b32 = b;
    uint64_t r64 = a64 * (b32 & 1);

    a_msb = a64 & mask_msb; // MSB, 3rd bits
    a64 ^= a_msb;   // clear MSB
    a64 = (a64 << 1) ^ ((a_msb >> 3) * 3);
    r64 ^= (a64) * ((b32 >> 1) & 1);

    a_msb = a64 & mask_msb; // MSB, 3rd bits
    a64 ^= a_msb;   // clear MSB
    a64 = (a64 << 1) ^ ((a_msb >> 3) * 3);
    r64 ^= (a64) * ((b32 >> 2) & 1);

    a_msb = a64 & mask_msb; // MSB, 3rd bits
    a64 ^= a_msb;   // clear MSB
    a64 = (a64 << 1) ^ ((a_msb >> 3) * 3);
    r64 ^= (a64) * ((b32 >> 3) & 1);

    return r64;
}


template <typename P>
static inline void apply_e_p(uint64_t* data, size_t number_of_vecs){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;
    static constexpr size_t elements_in_last_uint = m - (uint64s_per_vec - 1) * 16;

    uint64_t last_mask = (((uint64_t)1) << (elements_in_last_uint * 4)) - 1;
    if (elements_in_last_uint == 16) {
        last_mask = 0xffffffffffffffff;
    }

    uint32_t tail_multiples[16];
    for (size_t i = 0; i < 16; i++) {
        tail_multiples[i] = 0;
        for (size_t j = 0; j < 4; j++) {
            tail_multiples[i] ^= mul_gf16(i, VOLEMAYO_F_TAIL<P::secpar_v>[j]) << (j * 4);
        }
    }

    for (size_t idx = 0; idx < number_of_vecs; idx++) {
        char top_nibble = data[(idx+1) * uint64s_per_vec - 1] >> (((m-1) % 16) * 4);
        
        // shift up by 4 bits
        for (size_t i = uint64s_per_vec - 1; i > 0; i--) {
            data[idx * uint64s_per_vec + i] = (data[idx * uint64s_per_vec + i] << 4) |
                                              (data[idx * uint64s_per_vec + i - 1] >> 60);
        }
        data[idx * uint64s_per_vec] <<= 4;
        data[(idx+1) * uint64s_per_vec - 1] &= last_mask;
        // reduction mod f(X)
        data[idx * uint64s_per_vec] ^= tail_multiples[top_nibble];
    }
}


template <typename P>
static void combineP1_P2_P3(const unsigned char * in, uint64_t *out){
    size_t i,j;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t v = VOLEMAYO_V<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;

    const unsigned char* P1 = in;
    const unsigned char* P2 = in + v*(v+1)/2*uint64s_per_vec*sizeof(uint64_t);
    const unsigned char* P3 = P2 + v*o*uint64s_per_vec*sizeof(uint64_t);

    memset((unsigned char *) out, 0, n * (n + 1) / 2 * uint64s_per_vec * sizeof(uint64_t));

    // load and mix P1 and P2
    for (i = 0; i < v; i++) {
        for (j = i; j < v; j++) {
            memcpy((void *) out , P1, m / 2);
            P1 += uint64s_per_vec * sizeof(uint64_t);
            out += uint64s_per_vec;
        }
        for (; j < n; j++) {
            memcpy((void *) out , P2, m / 2);
            P2 += uint64s_per_vec * sizeof(uint64_t);
            out += uint64s_per_vec;
        }
    }
    // load P3
    memcpy((void *) out , P3, o*(o+1)/2*uint64s_per_vec*sizeof(uint64_t));
}

template <typename P> inline void get_mayo_r(const uint8_t* _pk, const uint8_t* hbytes, const uint8_t* sbytes, uint8_t* rbytes) {

    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t n_minus_o = VOLEMAYO_N_MINUS_O<P::secpar_v>;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t k = VOLEMAYO_K<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;

    // witness s
    constexpr size_t s_elem_size = VOLEMAYO_K<P::secpar_v> * VOLEMAYO_N<P::secpar_v>;
    std::vector<uint8_t> su8(s_elem_size);
    for (size_t idx = 0; idx < s_elem_size; idx++) {
        su8[idx] = (sbytes[idx/VOLEMAYO_FIELD_IN_UINT8] >> (idx%VOLEMAYO_FIELD_IN_UINT8)*4) & 0xf;
    }

    // the trapdoor part 
    std::vector<uint64_t> pk(VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>);
    combineP1_P2_P3<P>(_pk, pk.data());

    std::vector<uint64_t> u(uint64s_per_vec, 0);    
    for (int i = 0; i < k; i++) {
        for (int j = k-1; j >= i; j--) {
            
            // multiply by 'E'
            if (i != 0 || j != k-1){
                apply_e_p<P>(pk.data(), n*(n+1)/2);
            }

            size_t ctr = 0;
            for (size_t a = 0; a < n; a++) {
                for (size_t b = a; b < n; b++) {
                    unsigned char s_i_times_s_j = mul_gf16(su8[i * n + a], su8[j * n + b]);
                    unsigned char s_i_times_s_j_prime = mul_gf16(su8[j * n + a], su8[i * n + b]);
                    for (size_t idx = 0; idx < uint64s_per_vec; idx++) {
                        u[idx] ^= gf16v_mul_u64(pk[ctr * uint64s_per_vec + idx], s_i_times_s_j);
                        if(i != j){
                            u[idx] ^= gf16v_mul_u64(pk[ctr * uint64s_per_vec + idx], s_i_times_s_j_prime);
                        }
                    }
                    ctr++;
                }    
            }
        }
    }

    // u - h = r 
    uint8_t* uu8 = (uint8_t*) u.data();
    constexpr size_t r_bytes_size = VOLEMAYO_M<P::secpar_v>/VOLEMAYO_FIELD_IN_UINT8;
    for (size_t idx = 0; idx < r_bytes_size; idx++) {     // 1 byte has 2 elements
        rbytes[idx] = hbytes[idx] ^ uu8[idx];
    }
}

template <typename P> inline void get_mayo_h(const uint8_t* _pk, uint8_t* hbytes, const uint8_t* sbytes, const uint8_t* rbytes) {

    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t n_minus_o = VOLEMAYO_N_MINUS_O<P::secpar_v>;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t k = VOLEMAYO_K<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;

    // witness s
    constexpr size_t s_elem_size = VOLEMAYO_K<P::secpar_v> * VOLEMAYO_N<P::secpar_v>;
    std::vector<uint8_t> su8(s_elem_size);
    for (size_t idx = 0; idx < s_elem_size; idx++) {
        su8[idx] = (sbytes[idx/VOLEMAYO_FIELD_IN_UINT8] >> (idx%VOLEMAYO_FIELD_IN_UINT8)*4) & 0xf;
    }

    // the trapdoor part 
    std::vector<uint64_t> pk(VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>);
    combineP1_P2_P3<P>(_pk, pk.data());

    std::vector<uint64_t> u(uint64s_per_vec, 0);    
    for (int i = 0; i < k; i++) {
        for (int j = k-1; j >= i; j--) {
            
            // multiply by 'E'
            if (i != 0 || j != k-1){
                apply_e_p<P>(pk.data(), n*(n+1)/2);
            }

            size_t ctr = 0;
            for (size_t a = 0; a < n; a++) {
                for (size_t b = a; b < n; b++) {
                    unsigned char s_i_times_s_j = mul_gf16(su8[i * n + a], su8[j * n + b]);
                    unsigned char s_i_times_s_j_prime = mul_gf16(su8[j * n + a], su8[i * n + b]);
                    for (size_t idx = 0; idx < uint64s_per_vec; idx++) {
                        u[idx] ^= gf16v_mul_u64(pk[ctr * uint64s_per_vec + idx], s_i_times_s_j);
                        if(i != j){
                            u[idx] ^= gf16v_mul_u64(pk[ctr * uint64s_per_vec + idx], s_i_times_s_j_prime);
                        }
                    }
                    ctr++;
                }    
            }
        }
    }

    // u - r = h 
    uint8_t* uu8 = (uint8_t*) u.data();
    constexpr size_t r_bytes_size = VOLEMAYO_M<P::secpar_v>/VOLEMAYO_FIELD_IN_UINT8;
    for (size_t idx = 0; idx < r_bytes_size; idx++) {     // 1 byte has 2 elements
        hbytes[idx] = rbytes[idx] ^ uu8[idx];
    }
}

template <typename P> bool faest_unpack_secret_key(secret_key<P>* unpacked, const uint8_t* packed)
{
    size_t sk_offset_bytes = 0;
    // getting the public part
    memcpy((unsigned char *) unpacked->pk.mayo_expanded_pk, packed, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
    sk_offset_bytes += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

    memcpy(&unpacked->pk.h[0], packed + sk_offset_bytes, VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>);
    sk_offset_bytes += VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>;

    // getting the secret part
    memcpy(&unpacked->sk[0], packed + sk_offset_bytes, VOLEMAYO_WITNESS_SIZE_BYTES<P::secpar_v>);       // contains the s and r
    memcpy(&unpacked->witness[0], packed + sk_offset_bytes, VOLEMAYO_WITNESS_SIZE_BYTES<P::secpar_v>);    // basically copying the same thing here as sk

    /*
    // check validity
    unsigned char r[VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>] = {0};
    unsigned char *sk_r = ((unsigned char *) &unpacked->sk[0]) + VOLEMAYO_K<P::secpar_v>*VOLEMAYO_N<P::secpar_v>/2;

    get_mayo_r<P>((unsigned char *) unpacked->pk.mayo_expanded_pk, (unsigned char *) &unpacked->pk.h[0], (unsigned char *) &unpacked->sk[0], r);

    for (size_t idx = 0; idx < sizeof(r); idx++) {
        if (r[idx] != sk_r[idx]) {
            std::cout << static_cast<int>(r[idx]) << " vs " << static_cast<int>(sk_r[idx]) << "\n";
        }
    }

    for (size_t idx = 0; idx < sizeof(r); idx++) {
        if (r[idx] != sk_r[idx]) {
            std::cout << "sk is not valid!" << std::endl;
            return false;
        }
    }

    std::cout << "sk is valid" << std::endl;
    */

    return true;
}

template <typename P> void faest_pack_public_key(uint8_t* packed, const public_key<P>* unpacked)
{
    memcpy(packed, (unsigned char *) unpacked->mayo_expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
    packed += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;
    memcpy(packed, &unpacked->h, VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>);   
}

template <typename P> void faest_unpack_public_key(public_key<P>* unpacked, const uint8_t* packed)
{
    size_t sk_offset_bytes = 0;
    memcpy((unsigned char *) unpacked->mayo_expanded_pk, packed, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
    sk_offset_bytes += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

    memcpy(&unpacked->h[0], packed + sk_offset_bytes, VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>);
}

template <typename P> bool faest_compute_witness(secret_key<P>* sk)
{
    return true;
}

template <typename P>
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key<P>* sk)
{
    if (!faest_unpack_secret_key(sk, sk_packed))
        return false;

    faest_pack_public_key(pk_packed, &sk->pk);
    return true;
}

} // namespace faest

#endif
