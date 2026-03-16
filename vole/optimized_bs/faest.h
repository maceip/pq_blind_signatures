#ifndef FAEST_H
#define FAEST_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // getters for the parameters
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
                                   size_t *s_size);
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
                                   size_t *s_size);
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
                                   size_t *s_size);
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
                                   size_t *s_size);
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
                                   size_t *s_size);
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
                                   size_t *s_size);

    // 128_s
    void mayo_128_s_v1_serialize_pk(uint8_t *pk, size_t pk_size,
                                    const uint8_t *seed, size_t seed_size,
                                    const uint8_t *p1, size_t p1_size,
                                    const uint8_t *p2, size_t p2_size,
                                    const uint8_t *p3, size_t p3_size,
                                    const uint8_t *h, size_t h_size);

    void mayo_128_s_v1_serialize_sk(uint8_t *sk, size_t sk_size,
                                    const uint8_t *pk, size_t pk_size,
                                    const uint8_t *s, size_t s_size,
                                    const uint8_t *r, size_t r_size);

    // 128_f
    void mayo_128_f_v1_serialize_pk(uint8_t *pk, size_t pk_size,
                                    const uint8_t *seed, size_t seed_size,
                                    const uint8_t *p1, size_t p1_size,
                                    const uint8_t *p2, size_t p2_size,
                                    const uint8_t *p3, size_t p3_size,
                                    const uint8_t *h, size_t h_size);

    void mayo_128_f_v1_serialize_sk(uint8_t *sk, size_t sk_size,
                                    const uint8_t *pk, size_t pk_size,
                                    const uint8_t *s, size_t s_size,
                                    const uint8_t *r, size_t r_size);

    // 192_s
    void mayo_192_s_v1_serialize_pk(uint8_t *pk, size_t pk_size,
                                    const uint8_t *seed, size_t seed_size,
                                    const uint8_t *p1, size_t p1_size,
                                    const uint8_t *p2, size_t p2_size,
                                    const uint8_t *p3, size_t p3_size,
                                    const uint8_t *h, size_t h_size);

    void mayo_192_s_v1_serialize_sk(uint8_t *sk, size_t sk_size,
                                    const uint8_t *pk, size_t pk_size,
                                    const uint8_t *s, size_t s_size,
                                    const uint8_t *r, size_t r_size);

    // 192_f
    void mayo_192_f_v1_serialize_pk(uint8_t *pk, size_t pk_size,
                                    const uint8_t *seed, size_t seed_size,
                                    const uint8_t *p1, size_t p1_size,
                                    const uint8_t *p2, size_t p2_size,
                                    const uint8_t *p3, size_t p3_size,
                                    const uint8_t *h, size_t h_size);

    void mayo_192_f_v1_serialize_sk(uint8_t *sk, size_t sk_size,
                                    const uint8_t *pk, size_t pk_size,
                                    const uint8_t *s, size_t s_size,
                                    const uint8_t *r, size_t r_size);

    // 256_s
    void mayo_256_s_v1_serialize_pk(uint8_t *pk, size_t pk_size,
                                    const uint8_t *seed, size_t seed_size,
                                    const uint8_t *p1, size_t p1_size,
                                    const uint8_t *p2, size_t p2_size,
                                    const uint8_t *p3, size_t p3_size,
                                    const uint8_t *h, size_t h_size);

    void mayo_256_s_v1_serialize_sk(uint8_t *sk, size_t sk_size,
                                    const uint8_t *pk, size_t pk_size,
                                    const uint8_t *s, size_t s_size,
                                    const uint8_t *r, size_t r_size);

    // 256_f
    void mayo_256_f_v1_serialize_pk(uint8_t *pk, size_t pk_size,
                                    const uint8_t *seed, size_t seed_size,
                                    const uint8_t *p1, size_t p1_size,
                                    const uint8_t *p2, size_t p2_size,
                                    const uint8_t *p3, size_t p3_size,
                                    const uint8_t *h, size_t h_size);

    void mayo_256_f_v1_serialize_sk(uint8_t *sk, size_t sk_size,
                                    const uint8_t *pk, size_t pk_size,
                                    const uint8_t *s, size_t s_size,
                                    const uint8_t *r, size_t r_size);


    // v1 128
    bool mayo128sv1_prove_1(uint8_t *chal1, size_t chal1_size,
                            uint8_t *r, size_t r_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            const uint8_t *random_seed, size_t random_seed_len, uint8_t* r_additional);

    bool mayo128sv1_prove_2(uint8_t *chal1, size_t chal1_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            uint8_t *packed_pk, size_t packed_pk_size,
                            const uint8_t *packed_sk, size_t packed_sk_size, uint8_t* r_additional);

    bool mayo128sv1_verify(const uint8_t *proof, size_t proof_size,
                           const uint8_t *packed_pk, size_t packed_pk_size, uint8_t* r_additional);

    bool mayo128fv1_prove_1(uint8_t *chal1, size_t chal1_size,
                            uint8_t *r, size_t r_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            const uint8_t *random_seed, size_t random_seed_size, uint8_t* r_additional);

    bool mayo128fv1_prove_2(uint8_t *chal1, size_t chal1_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            uint8_t *packed_pk, size_t packed_pk_size,
                            const uint8_t *packed_sk, size_t packed_sk_size, uint8_t* r_additional);

    bool mayo128fv1_verify(const uint8_t *proof, size_t proof_size,
                           const uint8_t *packed_pk, size_t packed_pk_size, uint8_t* r_additional);

    bool mayo192sv1_prove_1(uint8_t *chal1, size_t chal1_size,
                            uint8_t *r, size_t r_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            const uint8_t *random_seed, size_t random_seed_size, uint8_t* r_additional);

    // v1 192
    bool mayo192sv1_prove_2(uint8_t *chal1, size_t chal1_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            uint8_t *packed_pk, size_t packed_pk_size,
                            const uint8_t *packed_sk, size_t packed_sk_size, uint8_t* r_additional);

    bool mayo192sv1_verify(const uint8_t *proof, size_t proof_size,
                           const uint8_t *packed_pk, size_t packed_pk_size, uint8_t* r_additional);

    bool mayo192fv1_prove_1(uint8_t *chal1, size_t chal1_size,
                            uint8_t *r, size_t r_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            const uint8_t *random_seed, size_t random_seed_size, uint8_t* r_additional);

    bool mayo192fv1_prove_2(uint8_t *chal1, size_t chal1_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            uint8_t *packed_pk, size_t packed_pk_size,
                            const uint8_t *packed_sk, size_t packed_sk_size, uint8_t* r_additional);

    bool mayo192fv1_verify(const uint8_t *proof, size_t proof_size,
                           const uint8_t *packed_pk, size_t packed_pk_size, uint8_t* r_additional);

    // v1 256
    bool mayo256sv1_prove_1(uint8_t *chal1, size_t chal1_size,
                            uint8_t *r, size_t r_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            const uint8_t *random_seed, size_t random_seed_size, uint8_t* r_additional);

    bool mayo256sv1_prove_2(uint8_t *chal1, size_t chal1_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            uint8_t *packed_pk, size_t packed_pk_size,
                            const uint8_t *packed_sk, size_t packed_sk_size, uint8_t* r_additional);

    bool mayo256sv1_verify(const uint8_t *proof, size_t proof_size,
                           const uint8_t *packed_pk, size_t packed_pk_size, uint8_t* r_additional);

    bool mayo256fv1_prove_1(uint8_t *chal1, size_t chal1_size,
                            uint8_t *r, size_t r_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            const uint8_t *random_seed, size_t random_seed_size, uint8_t* r_additional);

    bool mayo256fv1_prove_2(uint8_t *chal1, size_t chal1_size,
                            uint8_t *u, size_t u_size,
                            uint8_t *v, size_t v_size,
                            uint8_t *forest, size_t forest_size,
                            uint8_t *iv_pre, size_t iv_pre_size,
                            uint8_t *hashed_leaves, size_t hashed_leaves_size,
                            uint8_t *proof, size_t proof_size,
                            uint8_t *packed_pk, size_t packed_pk_size,
                            const uint8_t *packed_sk, size_t packed_sk_size, uint8_t* r_additional);

    bool mayo256fv1_verify(const uint8_t *proof, size_t proof_size,
                           const uint8_t *packed_pk, size_t packed_pk_size, uint8_t* r_additional);


#ifdef __cplusplus
}
#endif

#endif