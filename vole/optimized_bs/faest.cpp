#include "faest.inc"

// VOLE STUFF
#include "../parameters.hpp"
#include <memory>

namespace faest
{

    // clang-format off

template bool faest_unpack_secret_key(secret_key<v1::mayo_128_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::mayo_128_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::mayo_192_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::mayo_192_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::mayo_256_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::mayo_256_f>*, const uint8_t*);

template bool faest_unpack_secret_key(secret_key<v2::mayo_128_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::mayo_128_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::mayo_192_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::mayo_192_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::mayo_256_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::mayo_256_f>*, const uint8_t*);

template void faest_pack_public_key(uint8_t*, const public_key<v1::mayo_128_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::mayo_128_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::mayo_192_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::mayo_192_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::mayo_256_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::mayo_256_f>*);

template void faest_pack_public_key(uint8_t*, const public_key<v2::mayo_128_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::mayo_128_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::mayo_192_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::mayo_192_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::mayo_256_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::mayo_256_f>*);

template void faest_unpack_public_key(public_key<v1::mayo_128_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::mayo_128_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::mayo_192_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::mayo_192_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::mayo_256_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::mayo_256_f>*, const uint8_t*);

template void faest_unpack_public_key(public_key<v2::mayo_128_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::mayo_128_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::mayo_192_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::mayo_192_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::mayo_256_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::mayo_256_f>*, const uint8_t*);

// THE VOLE STUFF

// mayo functions
template bool vole_prove_1
<faest::v1::mayo_128_s>
(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<faest::v1::mayo_128_s::secpar_v>* forest, 
    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof,
    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional);

template bool vole_prove_2
<faest::v1::mayo_128_s>
(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, faest::block128* iv_pre, size_t iv_pre_size,
                        faest::block_secpar<faest::v1::mayo_128_s::secpar_v>* forest, unsigned char* hashed_leaves, 
                        uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional);
template bool vole_verify
<faest::v1::mayo_128_s>
(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional);


template bool vole_prove_1
<faest::v1::mayo_128_f>
(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<faest::v1::mayo_128_f::secpar_v>* forest, 
    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof, 
    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional);
template bool vole_prove_2
<faest::v1::mayo_128_f>
(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, faest::block128* iv_pre, size_t iv_pre_size, 
                        faest::block_secpar<faest::v1::mayo_128_f::secpar_v>* forest, unsigned char* hashed_leaves, 
                        uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional);
template bool vole_verify
<faest::v1::mayo_128_f>
(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional);


template bool vole_prove_1
<faest::v1::mayo_192_s>
(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<faest::v1::mayo_192_s::secpar_v>* forest, 
    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof, 
    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional);
template bool vole_prove_2
<faest::v1::mayo_192_s>
(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, faest::block128* iv_pre, size_t iv_pre_size, 
                        faest::block_secpar<faest::v1::mayo_192_s::secpar_v>* forest, unsigned char* hashed_leaves, 
                        uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional);
template bool vole_verify
<faest::v1::mayo_192_s>
(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional);


template bool vole_prove_1
<faest::v1::mayo_192_f>
(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<faest::v1::mayo_192_f::secpar_v>* forest, 
    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof, 
    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional);
template bool vole_prove_2
<faest::v1::mayo_192_f>
(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, faest::block128* iv_pre, size_t iv_pre_size, 
                        faest::block_secpar<faest::v1::mayo_192_f::secpar_v>* forest, unsigned char* hashed_leaves, 
                        uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional);
template bool vole_verify
<faest::v1::mayo_192_f>
(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional);


template bool vole_prove_1
<faest::v1::mayo_256_s>
(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<faest::v1::mayo_256_s::secpar_v>* forest, 
    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof, 
    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional);

template bool vole_prove_2
<faest::v1::mayo_256_s>
(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, faest::block128* iv_pre, size_t iv_pre_size, 
                        faest::block_secpar<faest::v1::mayo_256_s::secpar_v>* forest, unsigned char* hashed_leaves, 
                        uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional);
template bool vole_verify
<faest::v1::mayo_256_s>
(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional);


template bool vole_prove_1
<faest::v1::mayo_256_f>
(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<faest::v1::mayo_256_f::secpar_v>* forest, 
    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof, 
    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional);

template bool vole_prove_2
<faest::v1::mayo_256_f>
(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, faest::block128* iv_pre, size_t iv_pre_size, 
                        faest::block_secpar<faest::v1::mayo_256_f::secpar_v>* forest, unsigned char* hashed_leaves, 
                        uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional);
template bool vole_verify
<faest::v1::mayo_256_f>
(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional);



template <typename P> 
void serialize_pk(uint8_t* pk, const uint8_t* seed, const uint8_t* p1, const uint8_t* p2, const uint8_t* p3, const uint8_t* h);

template <typename P> 
void serialize_sk(uint8_t* sk,  const uint8_t* pk, const uint8_t* s, const uint8_t* r);



// THE RUST WRAPPER FUNCTIONS

// v1 serialize function
extern "C" {
    // 128_s
    void mayo_128_s_v1_serialize_pk(uint8_t* pk, size_t pk_size,
                            const uint8_t* seed, size_t seed_size,
                            const uint8_t* p1, size_t p1_size,
                            const uint8_t* p2, size_t p2_size,
                            const uint8_t* p3, size_t p3_size,
                            const uint8_t* h, size_t h_size) {
        using P = faest::v1::mayo_128_s;
        constexpr auto S = P::secpar_v;
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(seed_size == VOLEMAYO_PK_SEED_BYTES<S>);
        assert(p1_size == VOLEMAYO_P1_SIZE_BYTES<S>);
        assert(p2_size == VOLEMAYO_P2_SIZE_BYTES<S>);
        assert(p3_size == VOLEMAYO_P3_SIZE_BYTES<S>);
        assert(h_size == VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>);

        serialize_pk<P>(pk, seed, p1, p2, p3, h);
    }
    void mayo_128_s_v1_serialize_sk(uint8_t* sk, size_t sk_size,
                            const uint8_t* pk, size_t pk_size,
                            const uint8_t* s, size_t s_size,
                            const uint8_t* r, size_t r_size) {
        using P = faest::v1::mayo_128_s;
        constexpr auto S = P::secpar_v;
        assert(sk_size == VOLEMAYO_SECRET_SIZE_BYTES<S>);
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(s_size == VOLEMAYO_S_BYTES<S>);
        assert(r_size == VOLEMAYO_R_BYTES<S>);

        serialize_sk<P>(sk, pk, s, r);
    }

    // 128_f
    void mayo_128_f_v1_serialize_pk(uint8_t* pk, size_t pk_size,
                            const uint8_t* seed, size_t seed_size,
                            const uint8_t* p1, size_t p1_size,
                            const uint8_t* p2, size_t p2_size,
                            const uint8_t* p3, size_t p3_size,
                            const uint8_t* h, size_t h_size) {
        using P = faest::v1::mayo_128_f;
        constexpr auto S = P::secpar_v;
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(seed_size == VOLEMAYO_PK_SEED_BYTES<S>);
        assert(p1_size == VOLEMAYO_P1_SIZE_BYTES<S>);
        assert(p2_size == VOLEMAYO_P2_SIZE_BYTES<S>);
        assert(p3_size == VOLEMAYO_P3_SIZE_BYTES<S>);
        assert(h_size == VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>);

        serialize_pk<P>(pk, seed, p1, p2, p3, h);
    }
    void mayo_128_f_v1_serialize_sk(uint8_t* sk, size_t sk_size,
                            const uint8_t* pk, size_t pk_size,
                            const uint8_t* s, size_t s_size,
                            const uint8_t* r, size_t r_size) {
        using P = faest::v1::mayo_128_f;
        constexpr auto S = P::secpar_v;
        assert(sk_size == VOLEMAYO_SECRET_SIZE_BYTES<S>);
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(s_size == VOLEMAYO_S_BYTES<S>);
        assert(r_size == VOLEMAYO_R_BYTES<S>);

        serialize_sk<P>(sk, pk, s, r);
    }


    // 192_s
    void mayo_192_s_v1_serialize_pk(uint8_t* pk, size_t pk_size,
                            const uint8_t* seed, size_t seed_size,
                            const uint8_t* p1, size_t p1_size,
                            const uint8_t* p2, size_t p2_size,
                            const uint8_t* p3, size_t p3_size,
                            const uint8_t* h, size_t h_size) {
        using P = faest::v1::mayo_192_s;
        constexpr auto S = P::secpar_v;
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(seed_size == VOLEMAYO_PK_SEED_BYTES<S>);
        assert(p1_size == VOLEMAYO_P1_SIZE_BYTES<S>);
        assert(p2_size == VOLEMAYO_P2_SIZE_BYTES<S>);
        assert(p3_size == VOLEMAYO_P3_SIZE_BYTES<S>);
        assert(h_size == VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>);

        serialize_pk<P>(pk, seed, p1, p2, p3, h);
    }
    void mayo_192_s_v1_serialize_sk(uint8_t* sk, size_t sk_size,
                            const uint8_t* pk, size_t pk_size,
                            const uint8_t* s, size_t s_size,
                            const uint8_t* r, size_t r_size) {
        using P = faest::v1::mayo_192_s;
        constexpr auto S = P::secpar_v;
        assert(sk_size == VOLEMAYO_SECRET_SIZE_BYTES<S>);
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(s_size == VOLEMAYO_S_BYTES<S>);
        assert(r_size == VOLEMAYO_R_BYTES<S>);

        serialize_sk<P>(sk, pk, s, r);
    }

    // 192_f
    void mayo_192_f_v1_serialize_pk(uint8_t* pk, size_t pk_size,
                            const uint8_t* seed, size_t seed_size,
                            const uint8_t* p1, size_t p1_size,
                            const uint8_t* p2, size_t p2_size,
                            const uint8_t* p3, size_t p3_size,
                            const uint8_t* h, size_t h_size) {
        using P = faest::v1::mayo_192_f;
        constexpr auto S = P::secpar_v;
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(seed_size == VOLEMAYO_PK_SEED_BYTES<S>);
        assert(p1_size == VOLEMAYO_P1_SIZE_BYTES<S>);
        assert(p2_size == VOLEMAYO_P2_SIZE_BYTES<S>);
        assert(p3_size == VOLEMAYO_P3_SIZE_BYTES<S>);
        assert(h_size == VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>);

        serialize_pk<P>(pk, seed, p1, p2, p3, h);
    }
    void mayo_192_f_v1_serialize_sk(uint8_t* sk, size_t sk_size,
                            const uint8_t* pk, size_t pk_size,
                            const uint8_t* s, size_t s_size,
                            const uint8_t* r, size_t r_size) {
        using P = faest::v1::mayo_192_f;
        constexpr auto S = P::secpar_v;
        assert(sk_size == VOLEMAYO_SECRET_SIZE_BYTES<S>);
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(s_size == VOLEMAYO_S_BYTES<S>);
        assert(r_size == VOLEMAYO_R_BYTES<S>);

        serialize_sk<P>(sk, pk, s, r);
    }


    // 256_s
    void mayo_256_s_v1_serialize_pk(uint8_t* pk, size_t pk_size,
                            const uint8_t* seed, size_t seed_size,
                            const uint8_t* p1, size_t p1_size,
                            const uint8_t* p2, size_t p2_size,
                            const uint8_t* p3, size_t p3_size,
                            const uint8_t* h, size_t h_size) {
        using P = faest::v1::mayo_256_s;
        constexpr auto S = P::secpar_v;
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(seed_size == VOLEMAYO_PK_SEED_BYTES<S>);
        assert(p1_size == VOLEMAYO_P1_SIZE_BYTES<S>);
        assert(p2_size == VOLEMAYO_P2_SIZE_BYTES<S>);
        assert(p3_size == VOLEMAYO_P3_SIZE_BYTES<S>);
        assert(h_size == VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>);

        serialize_pk<P>(pk, seed, p1, p2, p3, h);
    }
    void mayo_256_s_v1_serialize_sk(uint8_t* sk, size_t sk_size,
                            const uint8_t* pk, size_t pk_size,
                            const uint8_t* s, size_t s_size,
                            const uint8_t* r, size_t r_size) {
        using P = faest::v1::mayo_256_s;
        constexpr auto S = P::secpar_v;
        assert(sk_size == VOLEMAYO_SECRET_SIZE_BYTES<S>);
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(s_size == VOLEMAYO_S_BYTES<S>);
        assert(r_size == VOLEMAYO_R_BYTES<S>);

        serialize_sk<P>(sk, pk, s, r);
    }

    // 256_f
    void mayo_256_f_v1_serialize_pk(uint8_t* pk, size_t pk_size,
                            const uint8_t* seed, size_t seed_size,
                            const uint8_t* p1, size_t p1_size,
                            const uint8_t* p2, size_t p2_size,
                            const uint8_t* p3, size_t p3_size,
                            const uint8_t* h, size_t h_size) {
        using P = faest::v1::mayo_256_f;
        constexpr auto S = P::secpar_v;
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(seed_size == VOLEMAYO_PK_SEED_BYTES<S>);
        assert(p1_size == VOLEMAYO_P1_SIZE_BYTES<S>);
        assert(p2_size == VOLEMAYO_P2_SIZE_BYTES<S>);
        assert(p3_size == VOLEMAYO_P3_SIZE_BYTES<S>);
        assert(h_size == VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>);

        serialize_pk<P>(pk, seed, p1, p2, p3, h);
    }
    void mayo_256_f_v1_serialize_sk(uint8_t* sk, size_t sk_size,
                            const uint8_t* pk, size_t pk_size,
                            const uint8_t* s, size_t s_size,
                            const uint8_t* r, size_t r_size) {
        using P = faest::v1::mayo_256_f;
        constexpr auto S = P::secpar_v;
        assert(sk_size == VOLEMAYO_SECRET_SIZE_BYTES<S>);
        assert(pk_size == VOLEMAYO_PUBLIC_SIZE_BYTES<S>);
        assert(s_size == VOLEMAYO_S_BYTES<S>);
        assert(r_size == VOLEMAYO_R_BYTES<S>);

        serialize_sk<P>(sk, pk, s, r);
    }

}


// v1 Parameter getter
extern "C" {
    void get_mayo128sv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {
        using P = faest::v1::mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        *r_size = VOLEMAYO_R_BYTES<S>;
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        *h_size =  VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>;
        *s_size =  VOLEMAYO_S_BYTES<S>;

    }
        void get_mayo128fv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        *r_size = VOLEMAYO_R_BYTES<S>;
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        *h_size =  VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>;
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_mayo192sv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        *r_size = VOLEMAYO_R_BYTES<S>;
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        *h_size =  VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>;
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_mayo192fv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        *r_size = VOLEMAYO_R_BYTES<S>;
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        *h_size =  VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>;
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_mayo256sv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        *r_size = VOLEMAYO_R_BYTES<S>;
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        *h_size =  VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>;
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_mayo256fv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        *r_size = VOLEMAYO_R_BYTES<S>;
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        *h_size =  VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>;
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
    
}


// V1
// 128s/f
extern "C" {
    bool mayo128sv1_prove_1(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* r, size_t r_size,
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            const uint8_t* random_seed, size_t random_seed_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(r_size == VOLEMAYO_R_BYTES<S>);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        return vole_prove_1<P>(chal1, r, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block_secpar<P::secpar_v>*)forest, 
                        (faest::block128*)iv_pre, (unsigned char*)hashed_leaves, proof, random_seed, random_seed_size, r_additional);
    }
    bool mayo128sv1_prove_2(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            uint8_t* packed_pk, size_t packed_pk_size,
                            const uint8_t* packed_sk, size_t packed_sk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        assert(packed_sk_size == faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>);
        return vole_prove_2<P>(proof, chal1, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block128*)iv_pre, iv_pre_size, (faest::block_secpar<P::secpar_v>*)forest, 
                            (unsigned char*)hashed_leaves, packed_pk, packed_sk, r_additional);
    }
    bool mayo128sv1_verify( const uint8_t* proof, size_t proof_size,
                            const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        
        return vole_verify<P>(proof, proof_size, packed_pk, packed_pk_size, r_additional);
    }


    bool mayo128fv1_prove_1(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* r, size_t r_size,
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            const uint8_t* random_seed, size_t random_seed_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(r_size == VOLEMAYO_R_BYTES<S>);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        
        return vole_prove_1<P>(chal1, r, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block_secpar<P::secpar_v>*)forest, 
                        (faest::block128*)iv_pre, (unsigned char*)hashed_leaves, proof, random_seed, random_seed_size, r_additional);
    }
    bool mayo128fv1_prove_2(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            uint8_t* packed_pk, size_t packed_pk_size,
                            const uint8_t* packed_sk, size_t packed_sk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        assert(packed_sk_size == faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>);
        return vole_prove_2<P>(proof, chal1, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block128*)iv_pre, iv_pre_size, (faest::block_secpar<P::secpar_v>*)forest, 
                            (unsigned char*)hashed_leaves, packed_pk, packed_sk, r_additional);
    }
    bool mayo128fv1_verify( const uint8_t* proof, size_t proof_size,
                            const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        
        return vole_verify<P>(proof, proof_size, packed_pk, packed_pk_size, r_additional);
    }
}
// 192s/f
extern "C" {
    bool mayo192sv1_prove_1(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* r, size_t r_size,
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            const uint8_t* random_seed, size_t random_seed_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(r_size == VOLEMAYO_R_BYTES<S>);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        
        return vole_prove_1<P>(chal1, r, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block_secpar<P::secpar_v>*)forest, 
                        (faest::block128*)iv_pre, (unsigned char*)hashed_leaves, proof, random_seed, random_seed_size, r_additional);
    }
    bool mayo192sv1_prove_2(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            uint8_t* packed_pk, size_t packed_pk_size,
                            const uint8_t* packed_sk, size_t packed_sk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        assert(packed_sk_size == faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>);
        return vole_prove_2<P>(proof, chal1, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block128*)iv_pre, iv_pre_size, (faest::block_secpar<P::secpar_v>*)forest, 
                            (unsigned char*)hashed_leaves, packed_pk, packed_sk, r_additional);
    }
    bool mayo192sv1_verify( const uint8_t* proof, size_t proof_size,
                            const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        
        return vole_verify<P>(proof, proof_size, packed_pk, packed_pk_size, r_additional);
    }


    bool mayo192fv1_prove_1(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* r, size_t r_size,
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            const uint8_t* random_seed, size_t random_seed_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(r_size == VOLEMAYO_R_BYTES<S>);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        
        return vole_prove_1<P>(chal1, r, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block_secpar<P::secpar_v>*)forest, 
                        (faest::block128*)iv_pre, (unsigned char*)hashed_leaves, proof, random_seed, random_seed_size, r_additional);
    }
    bool mayo192fv1_prove_2(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            uint8_t* packed_pk, size_t packed_pk_size,
                            const uint8_t* packed_sk, size_t packed_sk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        assert(packed_sk_size == faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>);
        return vole_prove_2<P>(proof, chal1, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block128*)iv_pre, iv_pre_size, (faest::block_secpar<P::secpar_v>*)forest, 
                            (unsigned char*)hashed_leaves, packed_pk, packed_sk, r_additional);
    }
    bool mayo192fv1_verify( const uint8_t* proof, size_t proof_size,
                            const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        
        return vole_verify<P>(proof, proof_size, packed_pk, packed_pk_size, r_additional);
    }
}
// 256s/f
extern "C" {
    bool mayo256sv1_prove_1(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* r, size_t r_size,
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            const uint8_t* random_seed, size_t random_seed_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(r_size == VOLEMAYO_R_BYTES<S>);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        
        return vole_prove_1<P>(chal1, r, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block_secpar<P::secpar_v>*)forest, 
                        (faest::block128*)iv_pre, (unsigned char*)hashed_leaves, proof, random_seed, random_seed_size, r_additional);
    }
    bool mayo256sv1_prove_2(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            uint8_t* packed_pk, size_t packed_pk_size,
                            const uint8_t* packed_sk, size_t packed_sk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        assert(packed_sk_size == faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>);
        return vole_prove_2<P>(proof, chal1, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block128*)iv_pre, iv_pre_size, (faest::block_secpar<P::secpar_v>*)forest, 
                            (unsigned char*)hashed_leaves, packed_pk, packed_sk, r_additional);
    }
    bool mayo256sv1_verify( const uint8_t* proof, size_t proof_size,
                            const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        
        return vole_verify<P>(proof, proof_size, packed_pk, packed_pk_size, r_additional);
    }


    bool mayo256fv1_prove_1(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* r, size_t r_size,
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            const uint8_t* random_seed, size_t random_seed_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(r_size == VOLEMAYO_R_BYTES<S>);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        
        return vole_prove_1<P>(chal1, r, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block_secpar<P::secpar_v>*)forest, 
                        (faest::block128*)iv_pre, (unsigned char*)hashed_leaves, proof, random_seed, random_seed_size, r_additional);
    }
    bool mayo256fv1_prove_2(uint8_t* chal1, size_t chal1_size, 
                            uint8_t* u, size_t u_size, 
                            uint8_t* v, size_t v_size, 
                            uint8_t* forest, size_t forest_size,
                            uint8_t* iv_pre, size_t iv_pre_size,
                            uint8_t* hashed_leaves, size_t hashed_leaves_size,
                            uint8_t* proof, size_t proof_size,
                            uint8_t* packed_pk, size_t packed_pk_size,
                            const uint8_t* packed_sk, size_t packed_sk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(chal1_size == CP::VOLE_CHECK::CHALLENGE_BYTES);
        assert(u_size == CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(v_size == P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block));
        assert(forest_size == P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>));
        assert(iv_pre_size == sizeof(faest::block128));
        assert(hashed_leaves_size == P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        assert(packed_sk_size == faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>);
        return vole_prove_2<P>(proof, chal1, (faest::vole_block*)u, (faest::vole_block*)v, (faest::block128*)iv_pre, iv_pre_size, (faest::block_secpar<P::secpar_v>*)forest, 
                            (unsigned char*)hashed_leaves, packed_pk, packed_sk, r_additional);
    }
    bool mayo256fv1_verify( const uint8_t* proof, size_t proof_size,
                            const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional) {
        using P = faest::v1::mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);
        assert(packed_pk_size == faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        
        return vole_verify<P>(proof, proof_size, packed_pk, packed_pk_size, r_additional);
    }
}

} // namespace faest
