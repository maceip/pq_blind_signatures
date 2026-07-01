#ifndef FAEST_INC
#define FAEST_INC

#include "faest.hpp"
#include "faest_keys.inc"

#include "hash.hpp"
#include "owf_proof.hpp"
#include "quicksilver.hpp"
#include "small_vole.hpp"
#include "transpose_secpar.hpp"
#include "util.hpp"
#include "vector_com.inc"
#include "vole_check.hpp"
#include "vole_commit.hpp"
#include <cassert>
#include <cstdalign>
#include <cstdlib>

namespace faest
{

// NOTE: This will be called in BS Sign_1 algorithm. Generates the initial vole commitments with the mayo pk and random h
// Taking the shell from faest sign, replacing the signature part and keeping just the voleith proof part
// Algorithm 2:: Optimized BS::4
template <typename P>
bool vole_prove_1(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<P::secpar_v>* forest, 
                    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof, 
                    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional) {

    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    // SHAKE hash state the we will keep reusing.
    faest::hash_state hasher;

    // (r, iv^pre) <- H_3(mu || r)
    faest::block_secpar<S> seed; // r
    faest::block128 iv;
    std::array<uint8_t, sizeof(seed) + sizeof(iv)> seed_iv_pre;
    hasher.init(S);
    if (random_seed) // rho (NB: spec assumes rho is always given and \lambda bit long)
            hasher.update(random_seed, random_seed_len);
    hasher.update_byte(3);
    hasher.finalize(seed_iv_pre.data(), sizeof(seed_iv_pre));
    memcpy(&seed, seed_iv_pre.data(), sizeof(seed));
    memcpy(iv_pre, &seed_iv_pre[sizeof(seed)], sizeof(iv));

    // for (size_t i = 0; i < sizeof(iv); i++) {
    //     std::cout << "vole_prove_1 iv_pre 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(iv_pre)[i] << "\n";
    // }

    // iv <- H_4(iv^pre)
    hasher.init(S);
    hasher.update(iv_pre, sizeof(iv));
    hasher.update_byte(4);
    hasher.finalize(reinterpret_cast<uint8_t*>(&iv), sizeof(iv));

    // std::cout << "vole_prove_1 iv 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(&iv)[0] << "\n";

    uint8_t vole_commit_check[CP::VOLE_COMMIT_CHECK_SIZE];

    vole_commit<P>(seed, iv, forest, hashed_leaves, u, v, proof, vole_commit_check);

    // copying the r part from the u
    memcpy(r, (uint8_t*)&u[0], VOLEMAYO_R_BYTES<P::secpar_v>);

    // for (size_t i = 0; i < 16; i++) {
    //     std::cout << static_cast<int>(r[i]) << " ";
    // }
    // std::cout << "\n\n";

    // std::cout << "vole_prove_1 vole_commit_check 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)vole_commit_check[0] << "\n";
    // std::cout << "vole_prove_1 proof 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)proof[0] << "\n";

    // Getting the additional r
    hasher.init(S);
    hasher.update(r_additional, 32);
    std::array<uint8_t, 32> r_additional_hash_out;
    hasher.finalize(r_additional_hash_out.data(), 32);

    // chall_1 <- H_2^1(mu || com || c_1 || ... || c_\tau-1 || iv)
    hasher.init(S);
    hasher.update(r_additional_hash_out.data(), 32);
    hasher.update(vole_commit_check, CP::VOLE_COMMIT_CHECK_SIZE);
    hasher.update(proof, CP::VOLE_COMMIT_SIZE);
    hasher.update(&iv, sizeof(iv));
    hasher.update_byte(8 + 1);
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES + VOLEMAYO_R_BYTES<S>> out;
    hasher.finalize(out.data(), CP::VOLE_CHECK::CHALLENGE_BYTES + VOLEMAYO_R_BYTES<S>);
    memcpy(chal1, out.data(), CP::VOLE_CHECK::CHALLENGE_BYTES);      // getting the challenge
    
    return true;

}

// NOTE: Here we continue with the vole proof after Sign_2
template <typename P>
bool vole_prove_2(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, 
                        faest::block128* iv_pre, size_t iv_pre_size, faest::block_secpar<P::secpar_v>* forest, 
                        unsigned char* hashed_leaves, uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional)
{
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    faest::secret_key<P> sk;
    static_assert(faest::FAEST_PUBLIC_KEY_BYTES<P> > 0);
    uint8_t pk_packed[faest::FAEST_PUBLIC_KEY_BYTES<P>];
    if (!faest_unpack_sk_and_get_pubkey<P>(packed_pk, packed_sk, &sk))
        return false;

    // SHAKE hash state the we will keep reusing.
    faest::hash_state hasher;

    // chall_2 <- H_2^2(chall_1 || \tilde{u} || h_V || d)
    std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
    hasher.init(S);
    hasher.update(r_additional, 32);
    hasher.update(chal1, CP::VOLE_CHECK::CHALLENGE_BYTES);

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - ((proof + faest::VOLE_PROOF_BYTES<P>) 
    //     - P::grinding_counter_size
    //     - sizeof(*iv_pre)
    //     - sizeof(faest::block_secpar<S>)
    //     - P::bavc_t::OPEN_SIZE
    //     - CP::QS::PROOF_BYTES
    //     - (OC::WITNESS_BITS + 7) / 8
    //     - P::CONSTS::VOLE_CHECK::PROOF_BYTES) << "\n";

    FAEST_ASSERT(proof
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(*iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8
        - P::CONSTS::VOLE_CHECK::PROOF_BYTES
        - CP::VOLE_COMMIT_SIZE);


    uint8_t* vole_check_proof = proof + CP::VOLE_COMMIT_SIZE;

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - ((proof + faest::VOLE_PROOF_BYTES<P>) 
    //     - P::grinding_counter_size
    //     - sizeof(*iv_pre)
    //     - sizeof(faest::block_secpar<S>)
    //     - P::bavc_t::OPEN_SIZE
    //     - CP::QS::PROOF_BYTES
    //     - (OC::WITNESS_BITS + 7) / 8
    //     - P::CONSTS::VOLE_CHECK::PROOF_BYTES) << "\n";
    
    FAEST_ASSERT(proof + CP::VOLE_COMMIT_SIZE
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(*iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8
        - P::CONSTS::VOLE_CHECK::PROOF_BYTES);

    // vole_check_sender hashes u_tilde and V_tilde
    vole_check_sender<P>(u, v, (uint8_t*)chal1, vole_check_proof, hasher);

    uint8_t* correction = vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES;
    FAEST_ASSERT(vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(*iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8);

    // To make life easy
    assert(VOLEMAYO_R_BITS<P::secpar_v>%8 == 0);
    assert(OC::WITNESS_BITS%8 == 0);

    size_t remainder = ((OC::WITNESS_BITS + 7) / 8) % (16 * CP::VOLE_BLOCK);
    size_t r_byte_counter = 0;
    for (size_t i = 0; i < CP::WITNESS_BLOCKS - (remainder != 0); ++i)
    {
        faest::vole_block correction_i;
        memset(&correction_i, 0x00, sizeof(faest::vole_block));
        uint8_t correction_made = 0;
        for (size_t b_idx = 0; b_idx < sizeof(faest::vole_block); b_idx++) {
            if (r_byte_counter >= VOLEMAYO_R_BYTES<P::secpar_v>) {
                ((uint8_t*)&correction_i)[b_idx] = ((uint8_t*)&u[i])[b_idx] ^ ((uint8_t*)&sk.witness[i])[b_idx];
            }
            r_byte_counter++;
        }
        // faest::vole_block correction_i = u[i] ^ sk.witness[i];
        memcpy(correction + (i * sizeof(faest::vole_block)), &correction_i, sizeof(faest::vole_block)); // ZERO correction for less than r bytes
    }
    if (remainder)
    {
        faest::vole_block correction_i;
        for (size_t b_idx = 0; b_idx < remainder; b_idx++) {
            ((uint8_t*)&correction_i)[b_idx] = ((uint8_t*)&u[CP::WITNESS_BLOCKS - 1])[b_idx] ^ ((uint8_t*)&sk.witness[CP::WITNESS_BLOCKS - 1])[b_idx];
        }
        // faest::vole_block correction_i = u[CP::WITNESS_BLOCKS - 1] ^ sk.witness[CP::WITNESS_BLOCKS - 1];
        memcpy(correction + ((CP::WITNESS_BLOCKS - 1) * sizeof(faest::vole_block)), &correction_i, remainder);
    }

    // for (size_t i = 0; i < 16; i++) {
    //     std::cout << static_cast<int>(correction[i]) << " ";
    // }
    // std::cout << "\n\n";

    // continue with H_2^2
    hasher.update(correction, (OC::WITNESS_BITS + 7) / 8); // There are only S bytes of correction!
    hasher.update_byte(8 + 2);
    hasher.finalize(chal2.data(), sizeof(chal2));

    // for (size_t i = 0; i < 1; i++) {
    //     std::cout << "vole_prove_1 chal2 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal2[i] << std::endl;
    // }

    // faest::block_secpar<S>* macs = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(
    //     alignof(faest::block_secpar<S>), CP::QUICKSILVER_ROWS_PADDED * sizeof(faest::block_secpar<S>)));
    faest::block_secpar<S>* macs = (faest::block_secpar<S>*)malloc(CP::QUICKSILVER_ROWS_PADDED * sizeof(faest::block_secpar<S>));

    // not touching the r part of the u
    size_t b_idx = VOLEMAYO_R_BYTES<P::secpar_v>;
    memcpy(&(((uint8_t*)&u[b_idx/sizeof(faest::vole_block)])[b_idx%sizeof(faest::vole_block)]), 
                    &(((uint8_t*)&sk.witness[b_idx/sizeof(faest::vole_block)])[b_idx%sizeof(faest::vole_block)]), (OC::WITNESS_BITS + 7) / 8 - b_idx); 
    
    // for (size_t i = 0; i < 16; i++) {
    //     std::cout << static_cast<int>(((uint8_t*)&u[0])[i]) << " ";
    // }
    // std::cout << "\n\n";

    // for (size_t i = VOLEMAYO_R_BYTES<P::secpar_v>; i < VOLEMAYO_R_BYTES<P::secpar_v> + 16; i++) {
    //     std::cout << static_cast<int>(((uint8_t*)&sk.witness[i/sizeof(faest::vole_block)])[i%sizeof(faest::vole_block)]) << " ";
    // }
    // std::cout << "\n\n";

    // memcpy(&u[0], &sk.witness[0], (OC::WITNESS_BITS + 7) / 8);
    static_assert(CP::QUICKSILVER_ROWS_PADDED % faest::TRANSPOSE_BITS_ROWS == 0, "");
    transpose_secpar<S>(v, macs, CP::VOLE_COL_STRIDE, CP::QUICKSILVER_ROWS_PADDED);
    // free(v);

    faest::quicksilver_state<S, false, OC::QS_DEGREE> qs((uint8_t*)&u[0], macs, OC::OWF_NUM_CONSTRAINTS, chal2.data());

    faest::owf_constraints<P, false>(&qs, &sk.pk, chal2.data());

    uint8_t* qs_proof = correction + (OC::WITNESS_BITS + 7) / 8;
    FAEST_ASSERT(correction + (OC::WITNESS_BITS + 7) / 8
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(*iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES);

    std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
    qs.prove(OC::WITNESS_BITS, qs_proof, qs_check.data());
    // free(macs);
    // free(u);

    uint8_t* veccom_open_start = qs_proof + CP::QS::PROOF_BYTES;
    FAEST_ASSERT(qs_proof + CP::QS::PROOF_BYTES 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(*iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE);

    uint8_t* delta = veccom_open_start + P::bavc_t::OPEN_SIZE;
    FAEST_ASSERT(veccom_open_start + P::bavc_t::OPEN_SIZE 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(*iv_pre)
        - sizeof(faest::block_secpar<S>));

    uint8_t* iv_pre_dst = delta + sizeof(faest::block_secpar<S>);
    FAEST_ASSERT(delta + sizeof(faest::block_secpar<S>) 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(*iv_pre));

    memcpy(iv_pre_dst, iv_pre, sizeof(faest::block128));
    uint8_t* grinding_counter_dst = iv_pre_dst + sizeof(*iv_pre);

    FAEST_ASSERT(iv_pre_dst + sizeof(*iv_pre) 
    == proof + faest::VOLE_PROOF_BYTES<P> - P::grinding_counter_size);

    if constexpr (!P::use_grinding)
    {
        // chall_3 <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2)
        hasher.init(S);
        hasher.update(chal2.data(), sizeof(chal2));
        hasher.update(qs_check.data(), CP::QS::CHECK_BYTES);
        hasher.update(qs_proof, CP::QS::PROOF_BYTES);
        hasher.update_byte(8 + 3);
        hasher.finalize(delta, sizeof(faest::block_secpar<S>));

        std::array<uint8_t, P::delta_bits_v> delta_bytes;
        faest::expand_bits_to_bytes(delta_bytes.data(), P::delta_bits_v, delta);

        P::bavc_t::open(forest, hashed_leaves, delta_bytes.data(), veccom_open_start);
    }
    else
    {
        // chall_3 <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2 || ctr)
        // Initialize a 4x hasher and hash the common input prefix.
        faest::hash_state_x4 grinding_hasher;
        grinding_hasher.init(S);
        grinding_hasher.update_1(chal2.data(), sizeof(chal2));
        grinding_hasher.update_1(qs_check.data(), CP::QS::CHECK_BYTES);
        grinding_hasher.update_1(qs_proof, CP::QS::PROOF_BYTES);
        uint32_t counter;
        bool open_success = grind_and_open<typename P::bavc_t>(
            forest, hashed_leaves, delta, veccom_open_start, &grinding_hasher, &counter);
        // Opening fails with a negligible probability, so we can assume it succeeds.
        FAEST_ASSERT(open_success);
        if (!open_success) return false;
        // Store counter in the signature.
        grinding_counter_dst[0] = counter;
        grinding_counter_dst[1] = counter >> 8;
        grinding_counter_dst[2] = counter >> 16;
        grinding_counter_dst[3] = counter >> 24;
    }

    // free(forest);
    // free(hashed_leaves);

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - grinding_counter_dst + P::grinding_counter_size << "\n";
    FAEST_ASSERT(grinding_counter_dst + P::grinding_counter_size == proof + faest::VOLE_PROOF_BYTES<P>);

    return true;
}

template <typename P>
bool vole_verify(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional)
{

    // std::cout << "vole_verify!!! \n" << std::flush;
    
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    // SHAKE hash state the we will keep reusing.
    faest::hash_state hasher;

    // mu <- H_2^0(pk || msg)
    // faest::block_2secpar<S> mu;
    // hasher.init(S);
    // hasher.update(packed_pk, packed_pk_size);
    // hasher.update(commit_mu, commit_mu_size);
    // hasher.update_byte(8 + 0);
    // hasher.finalize(&mu, sizeof(mu));

    faest::block128 iv;

    const uint8_t* vole_check_proof = proof + CP::VOLE_COMMIT_SIZE;
    const uint8_t* correction = vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES;
    const uint8_t* qs_proof = correction + (OC::WITNESS_BITS + 7) / 8;
    const uint8_t* veccom_open_start = qs_proof + CP::QS::PROOF_BYTES;
    const uint8_t* delta = veccom_open_start + P::bavc_t::OPEN_SIZE;
    const uint8_t* iv_pre_ptr = delta + sizeof(faest::block_secpar<S>);
    const uint8_t* counter = iv_pre_ptr + sizeof(iv);

    // for (size_t i = 0; i < sizeof(iv); i++) {
    //     std::cout << "vole_verify iv_pre_ptr 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)iv_pre_ptr[i] << "\n";
    // }
    // std::cout << "vole_verify counter 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)counter[0] << "\n";

    // Check that the prover actually did its grinding.
    for (size_t i = secpar_to_bits(S) - 1; i >= CP::VEC_COM::delta_bits_v; --i)
        if ((delta[i / 8] >> (i % 8)) & 1)
            return false;

    // iv <- H_4(iv^pre)
    hasher.init(S);
    hasher.update(iv_pre_ptr, sizeof(iv));
    hasher.update_byte(4);
    hasher.finalize(reinterpret_cast<uint8_t*>(&iv), sizeof(iv));

    // std::cout << "vole_verify iv 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(&iv)[0] << "\n";

    std::array<uint8_t, P::delta_bits_v> delta_bytes;
    faest::expand_bits_to_bytes(delta_bytes.data(), P::delta_bits_v, delta);

    faest::vole_block* q = reinterpret_cast<faest::vole_block*>(aligned_alloc(
        alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    uint8_t vole_commit_check[CP::VOLE_COMMIT_CHECK_SIZE];

    if (!vole_reconstruct<P>(iv, q, delta_bytes.data(), proof, veccom_open_start,
                             vole_commit_check))
    {
        free(q);
        return false;
    }

    // std::cout << "vole_verify vole_commit_check 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)vole_commit_check[0] << "\n";
    // std::cout << "vole_verify proof 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)proof[0] << "\n";

    // Getting the additional r
    hasher.init(S);
    hasher.update(r_additional, 32);
    std::array<uint8_t, 32> r_additional_hash_out;
    hasher.finalize(r_additional_hash_out.data(), 32);

    // chall_1 <- H_2^1(mu || com || c_1 || ... || c_\tau-1 || iv)
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> chal1;
    hasher.init(S);
    hasher.update(r_additional_hash_out.data(), 32);
    // hasher.update(&mu, sizeof(mu));
    hasher.update(vole_commit_check, CP::VOLE_COMMIT_CHECK_SIZE);
    hasher.update(proof, CP::VOLE_COMMIT_SIZE);
    hasher.update(&iv, sizeof(iv));
    hasher.update_byte(8 + 1);
    hasher.finalize(chal1.data(), sizeof(chal1));

    // std::cout << "vole_verify chal1 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal1[0] << std::endl;;

    // chall_2 <- H_2^2(chall_1 || \tilde{u} || h_V || d)
    std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
    hasher.init(S);
    hasher.update(r_additional, 32);
    hasher.update(chal1.data(), sizeof(chal1));
    hasher.update(vole_check_proof, CP::VOLE_CHECK::PROOF_BYTES);

    // vole_check_receiver hashes D
    vole_check_receiver<P>(q, delta_bytes.data(), chal1.data(), vole_check_proof, hasher);

    // continue with H_2^2
    hasher.update(correction, OC::WITNESS_BITS / 8);
    hasher.update_byte(8 + 2);
    hasher.finalize(chal2.data(), sizeof(chal2));

    // for (size_t i = 0; i < 1; i++) {
    //     std::cout << "vole_verify chal2 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal2[i] << std::endl;
    // }

    std::array<faest::vole_block, CP::WITNESS_BLOCKS> correction_blocks;

    memcpy(&correction_blocks, correction, (OC::WITNESS_BITS + 7) / 8);

    // for (size_t i = 0; i < 16; i++) {
    //     std::cout << static_cast<int>(correction[i]) << " ";
    // }
    // std::cout << "\n\n";

    memset(reinterpret_cast<uint8_t*>(correction_blocks.data()) + (OC::WITNESS_BITS + 7) / 8, 0,
           sizeof(correction_blocks) - (OC::WITNESS_BITS + 7) / 8);

    vole_receiver_apply_correction<P>(CP::WITNESS_BLOCKS, P::delta_bits_v, correction_blocks.data(), q,
                                      delta_bytes.data());

    faest::block_secpar<S>* macs = reinterpret_cast<faest::block_secpar<S>*>(
        aligned_alloc(alignof(faest::block_secpar<S>), CP::VOLE_ROWS_PADDED * sizeof(faest::block_secpar<S>)));
    transpose_secpar<S>(q, macs, CP::VOLE_COL_STRIDE, CP::QUICKSILVER_ROWS_PADDED);
    free(q);

    faest::block_secpar<S> delta_block;
    memcpy(&delta_block, delta, sizeof(delta_block));

    faest::public_key<P> pk;
    faest_unpack_public_key(&pk, packed_pk);

    faest::quicksilver_state<S, true, OC::QS_DEGREE> qs(macs, OC::OWF_NUM_CONSTRAINTS, delta_block, chal2.data());
    
    faest::owf_constraints<P, true>(&qs, &pk, chal2.data());

    std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
    qs.verify(OC::WITNESS_BITS, qs_proof, qs_check.data());
    free(macs);

    // chall_3' <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2 [|| ctr])
    faest::block_secpar<S> delta_check;
    hasher.init(S);
    hasher.update(chal2.data(), sizeof(chal2));
    hasher.update(qs_check.data(), CP::QS::CHECK_BYTES);
    hasher.update(qs_proof, CP::QS::PROOF_BYTES);
    if constexpr (P::use_grinding)
    {
        hasher.update(counter, P::grinding_counter_size);
    }
    hasher.update_byte(8 + 3);
    hasher.finalize(&delta_check, sizeof(delta_check));

    return memcmp(delta, &delta_check, sizeof(delta_check)) == 0;
}


// NOTE: Use these functions to serialize the pk and sk, after Sign2 algorithm
template <typename P> 
void serialize_pk(uint8_t* pk, const uint8_t* seed, const uint8_t* p1, const uint8_t* p2, const uint8_t* p3, const uint8_t* h) {

    size_t pk_offset = 0;

    memcpy(pk, seed, VOLEMAYO_PK_SEED_BYTES<P::secpar_v>);
    pk_offset += VOLEMAYO_PK_SEED_BYTES<P::secpar_v>;

    memcpy(pk + pk_offset, p1, VOLEMAYO_P1_SIZE_BYTES<P::secpar_v>);
    pk_offset += VOLEMAYO_P1_SIZE_BYTES<P::secpar_v>;

    memcpy(pk + pk_offset, p2, VOLEMAYO_P2_SIZE_BYTES<P::secpar_v>);
    pk_offset += VOLEMAYO_P2_SIZE_BYTES<P::secpar_v>;

    memcpy(pk + pk_offset, p3, VOLEMAYO_P3_SIZE_BYTES<P::secpar_v>);
    pk_offset += VOLEMAYO_P3_SIZE_BYTES<P::secpar_v>;

    memcpy(pk + pk_offset, h, VOLEMAYO_PROVE_1_H_SIZE_BYTES<P::secpar_v>);

}

// Ignore the r input, this was for debugging stuff
template <typename P> 
void serialize_sk(uint8_t* sk,  const uint8_t* pk, const uint8_t* s, const uint8_t* r) {

    size_t sk_offset = 0;

    memcpy(sk, pk, VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
    sk_offset += VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

    // memcpy(sk + sk_offset, r, VOLEMAYO_R_BYTES<P::secpar_v>);
    // NOTE: The witness r doesn't not exists, just putting ZEROs here to keep consistent with the witness size used in the entire vole code-base
    // TODO: changing this witness size in the const to only S bytes can be done later
    memset(sk + sk_offset, 0x00, VOLEMAYO_R_BYTES<P::secpar_v>);
    sk_offset += VOLEMAYO_R_BYTES<P::secpar_v>;

    memcpy(sk + sk_offset, s, VOLEMAYO_S_BYTES<P::secpar_v>);

}


} // namespace faest

#endif
