#ifndef OWF_PROOF_INC
#define OWF_PROOF_INC

#include "aes.hpp"
#include "hash.hpp"
#include "constants.hpp"
#include "faest_keys.hpp"
#include "owf_proof.hpp"
#include "owf_proof_tools.hpp"
#include "parameters.hpp"
#include "quicksilver.hpp"
#include <iostream>
#include <vector>
#include <stdio.h>
#include <sys/time.h>

namespace faest
{

template <secpar S> constexpr static std::size_t N_WD = secpar_to_bits(S) / 32;

template <secpar S, owf O> constexpr static std::size_t S_ENC = OWF_CONSTANTS<S, O>::OWF_ENC_SBOXES;

template <secpar S, owf O> using owf_block = OWF_CONSTANTS<S, O>::block_t;

template <typename QS>
static inline quicksilver_gfsecpar<QS, 0> load_const_4_bits_and_combine(const QS* state,
                                                                        const void* s, bool msb_4_bits)
{
    auto input_bits = state->template const_gf2_array<4, 0>();
    size_t bit_offset = 0;
    if (msb_4_bits) {
        bit_offset = 4;
    }
    for (size_t bit_j = 0; bit_j < 4; ++bit_j)
        input_bits[bit_j] = quicksilver_gf2<QS, 0>(poly1::load(*(uint8_t*)s, bit_j + bit_offset), state);
    return quicksilver_gfsecpar<QS, 0>::combine_4_bits(input_bits.data());
}

static inline uint8_t _mul_gf16(uint8_t a, uint8_t b) {

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

template <typename P>
static inline void _apply_e_p(uint64_t* data, size_t number_of_vecs){
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
            tail_multiples[i] ^= _mul_gf16(i, VOLEMAYO_F_TAIL<P::secpar_v>[j]) << (j * 4);
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
static void _combineP1_P2_P3(const unsigned char * in, uint64_t *out){
    size_t i,j;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t v = VOLEMAYO_V<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;

    const unsigned char* P1 = in;
    const unsigned char* P2 = in + v*(v+1)/2*uint64s_per_vec*sizeof(uint64_t);
    const unsigned char* P3 = P2 + v*o*uint64s_per_vec*sizeof(uint64_t);

    memset(out, 0, n * (n + 1) / 2 * uint64s_per_vec * sizeof(uint64_t));

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

template <typename P>
static void sample_random_embedding(std::vector<poly_secpar<P::secpar_v>> &embedding_table, unsigned char * chall2){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    constexpr secpar S = P::secpar_v;
    static constexpr size_t security_bits = secpar_to_bits(S);

    
    embedding_table.resize(m*16);

    unsigned char randomness[m*sizeof(poly_secpar<S>)];

    hash_state hasher;

    // mu <- H_2^0(pk || msg)
    hasher.init(S);
    hasher.update(chall2, secpar_to_bits(S) / 4); // hash 2*lambda bits of chall2
    hasher.finalize(randomness, m*sizeof(poly_secpar<S>));

    const unsigned char (*gf4_in_gf_secpar)[security_bits/8]; 
    if constexpr (security_bits == 128) {
        gf4_in_gf_secpar = gf4_in_gf128;
    } else if constexpr (security_bits == 192) {
        gf4_in_gf_secpar = gf4_in_gf192;
    } else if constexpr (security_bits == 256) {
        gf4_in_gf_secpar = gf4_in_gf256;
    }

    poly_secpar<S> x   = poly_secpar<S>::load_dup(gf4_in_gf_secpar[0]);
    poly_secpar<S> xx  = poly_secpar<S>::load_dup(gf4_in_gf_secpar[1]);
    poly_secpar<S> xxx = poly_secpar<S>::load_dup(gf4_in_gf_secpar[2]);

    for (size_t i = 0; i < m; i++) {
        embedding_table[i*16 + 0] = poly_secpar<S>::set_zero();
        embedding_table[i*16 + 1] = poly_secpar<S>::load_dup(randomness + i*sizeof(poly_secpar<S>));
        embedding_table[i*16 + 2] = (x   * embedding_table[i*16 + 1]).template reduce_to<security_bits>();
        embedding_table[i*16 + 4] = (xx  * embedding_table[i*16 + 1]).template reduce_to<security_bits>();
        embedding_table[i*16 + 8] = (xxx * embedding_table[i*16 + 1]).template reduce_to<security_bits>();

        embedding_table[i*16 + 3] = embedding_table[i*16 + 2] + embedding_table[i*16 + 1];
        
        embedding_table[i*16 + 5] = embedding_table[i*16 + 4] + embedding_table[i*16 + 1];
        embedding_table[i*16 + 6] = embedding_table[i*16 + 4] + embedding_table[i*16 + 2];
        embedding_table[i*16 + 7] = embedding_table[i*16 + 4] + embedding_table[i*16 + 3];

        embedding_table[i*16 + 9]  = embedding_table[i*16 + 8] + embedding_table[i*16 + 1];
        embedding_table[i*16 + 10] = embedding_table[i*16 + 8] + embedding_table[i*16 + 2];
        embedding_table[i*16 + 11] = embedding_table[i*16 + 8] + embedding_table[i*16 + 3];
        embedding_table[i*16 + 12] = embedding_table[i*16 + 8] + embedding_table[i*16 + 4];
        embedding_table[i*16 + 13] = embedding_table[i*16 + 8] + embedding_table[i*16 + 5];
        embedding_table[i*16 + 14] = embedding_table[i*16 + 8] + embedding_table[i*16 + 6];
        embedding_table[i*16 + 15] = embedding_table[i*16 + 8] + embedding_table[i*16 + 7];
    }
}


template <typename P>
static void embed_gf16_vec(std::vector<poly_secpar<P::secpar_v>> embedding_table, const uint8_t* vec, poly_secpar<P::secpar_v> &poly){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;

    poly = poly_secpar<P::secpar_v>::set_zero();
    for (size_t i = 0; i < m; i+=2)
    {
        unsigned char nibble_low = vec[i/2] & 0xf;
        unsigned char nibble_high = (vec[i/2] >> 4) & 0xf;
        poly += embedding_table[i * 16 + nibble_low];
        poly += embedding_table[(i+1) * 16 + nibble_high];
    }
}


template <typename QS, typename P, owf O>
static void
enc_constraints(QS* qs_state, const public_key<P>* pk, unsigned char *chal2)
{
    constexpr secpar S = QS::secpar_v;
    using OC = OWF_CONSTANTS<S, O>;

    const uint8_t* hbytes = (uint8_t*)&pk->h;

    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t n_minus_o = VOLEMAYO_N_MINUS_O<P::secpar_v>;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t k = VOLEMAYO_K<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = VOLEMAYO_u64s_per_m_vec<S>;

    // sample challenge embedding
    std::vector<poly_secpar<S>> embedding_table;
    sample_random_embedding<P>(embedding_table, chal2);

    // witness r
    size_t witness_offset_bits_idx = 0;
    constexpr size_t r_elem_size = VOLEMAYO_M<P::secpar_v>;
    std::vector<quicksilver_gfsecpar<QS, 1>> r(r_elem_size);
    for (size_t idx = 0; idx < r_elem_size; idx++) {   
        r[idx] = qs_state->load_witness_4_bits_and_combine(witness_offset_bits_idx); 
        witness_offset_bits_idx += 4;
    }

    quicksilver_gfsecpar<QS, 0> generator(poly_secpar<S>::set_low32(2), r[0]);
    
    // embed r
    quicksilver_gfsecpar<QS, 1> r_embedded(0, qs_state);
    for (int i = 0; i < m; i++)
    {
        r_embedded +=  embedding_table[16*i + 1] * r[i];
    }

    // witness s
    constexpr size_t s_elem_size = VOLEMAYO_K<P::secpar_v> * VOLEMAYO_N<P::secpar_v>;
    std::vector<quicksilver_gfsecpar<QS, 1>> s(s_elem_size);
    for (size_t idx = 0; idx < s_elem_size; idx++) {
        s[idx] = qs_state->load_witness_4_bits_and_combine(witness_offset_bits_idx);
        witness_offset_bits_idx += 4;
    }
    
    // embedded h
    poly_secpar<S> h_embedded;
    embed_gf16_vec<P>(embedding_table, hbytes, h_embedded);

    // t = h + r
    quicksilver_gfsecpar<QS, 1> t_embedded(0, qs_state);
    t_embedded = quicksilver_gfsecpar<QS,1>(h_embedded, qs_state) + r_embedded;

    quicksilver_gfsecpar<QS, 2> u(0,qs_state);
    poly_secpar<S> embedded_column;

    std::vector<uint64_t> _expanded_pk(VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>);
    uint64_t* expanded_pk = _expanded_pk.data();
    _combineP1_P2_P3<P>((unsigned char*) pk->mayo_expanded_pk, expanded_pk);

    std::vector<quicksilver_gfsecpar<QS, 1>> As(n);

    for (int i = 0; i < k; i++) {
        for (int j = k-1; j >= i; j--) {
            // multiply by 'E'
            if (i != 0 || j != k-1){
                _apply_e_p<P>(expanded_pk, n*(n+1)/2);
            }

            for (size_t a = 0 ; a<n; a++){
                As[a] = quicksilver_gfsecpar<QS, 1>(0, qs_state); 
            }

            // compute As = A * s_j         (if i == j)
            // or      As = (A + A^t) * s_j (if i != j)
            size_t ctr = 0;
            for (size_t a = 0; a < n; a++) {
                // skip i != j and a == b case
                ctr += (i != j);
                for (size_t b = a + (i != j); b < n; b++) {
                    embed_gf16_vec<P>(embedding_table, (unsigned char*) &expanded_pk[(ctr++) * uint64s_per_vec], embedded_column);
                
                    As[a] += embedded_column * s[j*n + b];
                    if (i != j){
                        As[b] += embedded_column * s[j*n + a];
                    }
                }    
            }

            // u += s_i * As
            for (size_t a = 0; a < n; a++) {
                u += As[a] * s[i * n + a];
            }
        }
    }

    qs_state->add_constraint(u + t_embedded);
}


template <typename P, bool verifier>
void owf_constraints(quicksilver_state<P::secpar_v, verifier, P::OWF_CONSTS::QS_DEGREE>* state,
                     const public_key<P>* pk, unsigned char *chal2)
{
    using QS = quicksilver_state<P::secpar_v, verifier, P::OWF_CONSTS::QS_DEGREE>;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;
    constexpr auto O = P::owf_v;

    enc_constraints<QS, P, O>(state, pk, chal2);
}

} // namespace faest

#endif
