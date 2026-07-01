#ifndef TEST_TEST_HPP
#define TEST_TEST_HPP

#include "constants.hpp"
#include "debug.hpp"
#include "faest_keys.inc"
#include "polynomials.hpp"
#include "quicksilver.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace faest;

// Some of the test code still uses POLY_VEC_LEN
constexpr std::size_t POLY_VEC_LEN_SHIFT = 0;
constexpr std::size_t POLY_VEC_LEN = 1 << POLY_VEC_LEN_SHIFT;

struct secpar128_t
{
    constexpr static secpar value = secpar::s128;
};
struct secpar192_t
{
    constexpr static secpar value = secpar::s192;
};
struct secpar256_t
{
    constexpr static secpar value = secpar::s256;
};

#define REQUIRE_POLYVEC_EQ(a, b)                                                                   \
    {                                                                                              \
        INFO("Requiring: " << poly_to_string(a) << " == " << poly_to_string(b));                   \
        REQUIRE(a == b);                                                                           \
    }
#define REQUIRE_POLYVEC_NEQ(a, b)                                                                  \
    {                                                                                              \
        INFO("Requiring: " << poly_to_string(a) << " != " << poly_to_string(b));                   \
        REQUIRE(a != b);                                                                           \
    }

inline std::ostream& operator<<(std::ostream& o, const std::vector<uint8_t>& array)
{
    o << "{ ";
    for (size_t i = 0; i < array.size(); ++i)
    {
        if (i)
            o << ", ";
        o << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)array[i];
    }
    return o << " }";
}

template <size_t N>
inline std::ostream& operator<<(std::ostream& o, const std::array<uint8_t, N>& array)
{
    return o << std::vector(array.begin(), array.end());
}

template <typename T> inline T rand()
{
    static std::mt19937_64 rd(42);
    std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
    return dist(rd);
}

template <> inline block128 rand<block128>()
{
    std::array<uint64_t, 2> data;
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = rand<uint64_t>();

    block128 output;
    memcpy(&output, &data[0], sizeof(output));
    return output;
}

template <> inline block192 rand<block192>()
{
    std::array<uint64_t, 3> data;
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = rand();

    block192 output;
    memcpy(&output, &data[0], sizeof(output));
    return output;
}

template <> inline block256 rand<block256>()
{
    std::array<uint64_t, 4> data;
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = rand();

    block256 output;
    memcpy(&output, &data[0], sizeof(output));
    return output;
}

template <typename T> inline std::vector<T> random_vector(std::size_t size)
{
    std::vector<T> v(size);
    std::generate(v.begin(), v.end(), rand<T>);
    return v;
}

template <secpar S>
std::pair<std::vector<block_secpar<S>>, std::vector<block_secpar<S>>> inline gen_vole_correlation(
    size_t n, const uint8_t* witness, block_secpar<S> delta)
{
    const auto keys = random_vector<block_secpar<S>>(n);
    auto tags = keys;
    for (size_t i = 0; i < n; ++i)
    {
        if ((witness[i / 8] >> (i % 8)) & 1)
        {
            tags[i] = tags[i] ^ delta;
        }
    }
    return std::make_pair(keys, tags);
}

template <secpar S, size_t max_deg> struct quicksilver_test_state_pre_quicksilver
{
    using QS_CONS = QS_CONSTANTS<S, max_deg>;

    std::vector<uint8_t> witness;
    std::vector<block_secpar<S>> tags;
    std::vector<block_secpar<S>> keys;
    std::array<uint8_t, QS_CONS::CHALLENGE_BYTES> challenge;

    quicksilver_test_state_pre_quicksilver(const uint8_t* witness_in, size_t witness_bits,
                                           block_secpar<S> delta)
        : witness(witness_in, witness_in + witness_bits / 8)
    {
        auto witness_mask = random_vector<uint8_t>((max_deg - 1) * secpar_to_bytes(S));
        witness.insert(witness.end(), witness_mask.begin(), witness_mask.end());

        auto correlation = gen_vole_correlation<S>(witness_bits + (max_deg - 1) * secpar_to_bits(S),
                                                   witness.data(), delta);
        keys = std::move(correlation.first);
        tags = std::move(correlation.second);

        std::generate(challenge.begin(), challenge.end(), rand<uint8_t>);
    }
};

template <secpar S, size_t max_deg = 2>
struct quicksilver_test_state : public quicksilver_test_state_pre_quicksilver<S, max_deg>
{
    using base = quicksilver_test_state_pre_quicksilver<S, max_deg>;
    using QS_CONS = base::QS_CONS;
    using QSP = quicksilver_state<S, false, max_deg>;
    using QSV = quicksilver_state<S, true, max_deg>;

    QSP prover_state;
    QSV verifier_state;

    quicksilver_test_state(size_t num_constraints, const uint8_t* witness_in, size_t witness_bits,
                           block_secpar<S> delta)
        : base(witness_in, witness_bits, delta),
          prover_state(this->witness.data(), this->tags.data(), num_constraints,
                       this->challenge.data()),
          verifier_state(this->keys.data(), num_constraints, delta, this->challenge.data())
    {
    }

    template <size_t deg>
        requires(deg <= QSP::max_degree)
    bool check_mac(const quicksilver_gf2<QSP, deg>& x_p, const quicksilver_gf2<QSV, deg>& x_v) const
    {
        auto z = poly_secpar<S>::from_1(x_p.value());
        const auto delta = verifier_state.delta();
        for (size_t i = 1; i <= deg; ++i)
        {
            z = (z * delta).template reduce_to<secpar_to_bits(S)>();
            z += x_p.mac.coeffs[deg - i];
        }

        return z == x_v.mac;
    }

    template <size_t deg>
        requires(deg <= QSP::max_degree)
    bool check_mac(const quicksilver_gfsecpar<QSP, deg>& x_p,
                   const quicksilver_gfsecpar<QSV, deg>& x_v) const
    {
        auto z = x_p.value();
        const auto delta = verifier_state.delta();
        for (size_t i = 1; i <= deg; ++i)
        {
            z = (z * delta).template reduce_to<secpar_to_bits(S)>();
            z += x_p.mac.coeffs[deg - i];
        }

        return z == x_v.mac;
    }

    std::array<std::array<uint8_t, QS_CONS::CHECK_BYTES>, 2> compute_check() const
    {
        std::array<uint8_t, QS_CONS::PROOF_BYTES> proof;
        std::array<uint8_t, QS_CONS::CHECK_BYTES> check_prover, check_verifier;

        size_t witness_bits = 8 * this->witness.size() - (max_deg - 1) * secpar_to_bits(S);
        prover_state.prove(witness_bits, proof.data(), check_prover.data());
        verifier_state.verify(witness_bits, proof.data(), check_verifier.data());

        return {check_prover, check_verifier};
    }
};

// --- START ---


inline uint8_t mul_gf16(uint8_t a, uint8_t b) {
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

inline void memset_rand(unsigned char* in, size_t byte_size) {
    for (size_t i = 0; i < byte_size; i++) {
        in[i] = rand();
    }
}

// This generates random bytes and set the pk
template <typename P> inline void set_pk(unsigned char* pk) {

    size_t pk_offset = 0;    

    constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    constexpr size_t m_vecs = n*(n+1)/2;
    constexpr size_t uint64s_per_vec = VOLEMAYO_u64s_per_m_vec<P::secpar_v>;

    memset(pk, 0x00, m_vecs * uint64s_per_vec * sizeof(uint64_t));
    // only choose the m_vec bytes at random, not the intermediate stuff
    for (size_t i = 0; i < m_vecs; i++) {
        memset_rand(pk + i * uint64s_per_vec * sizeof(uint64_t), m/2);
    }

    //memset(temp_pk.data(), 0x00, bytes);
    pk_offset += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

    // NOTE: h + r pre-image is generated from MAYO.SamplePre
    memset_rand(pk + pk_offset, VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>);
    //memset(pk + pk_offset, 0x00, VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>);
    //pk[pk_offset] = 2;
}
// This generates random bytes and set the sk
template <typename P> inline void set_sk(unsigned char* sk, unsigned char* pk) {

    // set_pk<P>(sk);
    memcpy(sk, pk, VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
    size_t sk_offset = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

    uint8_t* h = sk + VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;
    assert(h + VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v> == sk + sk_offset);

    uint8_t* s = sk + sk_offset;
    memset_rand(s, VOLEMAYO_S_BYTES<P::secpar_v>);
    sk_offset += VOLEMAYO_S_BYTES<P::secpar_v>;

    uint8_t* r = sk + sk_offset;
    get_mayo_r<P>(pk, h, s, r);       // Setting the r (4 * M bits)
}

template <typename P> inline void set_sk_pk(unsigned char* sk, unsigned char* pk, unsigned char* u_r) {

    // Setting the sk part of sk
    size_t sk_offset = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

    // TODO: Remove this!
    // uint8_t* r = sk + sk_offset;
    // memcpy(r, u_r, VOLEMAYO_R_BYTES<P::secpar_v>);
    //////////////////////////

    sk_offset += VOLEMAYO_R_BYTES<P::secpar_v>;
    uint8_t* s = sk + sk_offset;
    memset_rand(s, VOLEMAYO_S_BYTES<P::secpar_v>);

    // for (size_t i = 0; i < 16; i++) {
    //     std::cout << static_cast<int>(s[i]) << " ";
    // }
    // std::cout << "\n\n";

    // Setting pk
    size_t pk_offset = 0;    
    constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    constexpr size_t m_vecs = n*(n+1)/2;
    constexpr size_t uint64s_per_vec = VOLEMAYO_u64s_per_m_vec<P::secpar_v>;
    memset(pk, 0x00, m_vecs * uint64s_per_vec * sizeof(uint64_t));
    // only choose the m_vec bytes at random, not the intermediate stuff
    for (size_t i = 0; i < m_vecs; i++) {
        memset_rand(pk + i * uint64s_per_vec * sizeof(uint64_t), m/2);
    }
    //memset(temp_pk.data(), 0x00, bytes);
    pk_offset += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

    // Back calculating the h from u_r
    uint8_t h[VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>];
    get_mayo_h<P>(pk, h, s, u_r);
    // Setting h to pk
    memcpy(pk + pk_offset, h, VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>);

    // Setting the pk part of the sk
    memcpy(sk, pk, VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);


}

template <typename P> inline void test_gen_keypair(unsigned char* pk, unsigned char* sk, unsigned char* u_r)
{

    set_sk_pk<P>(sk, pk, u_r);

    // set_pk<P>(pk);      // setting the pk part
    // set_sk<P>(sk, pk);  // setting the pk part of the sk and sk part in sk
    
}
// --- END ---

#endif
