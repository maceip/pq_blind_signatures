#ifndef FAEST_HPP
#define FAEST_HPP

#include <cstdint>

#include "constants.hpp"
#include "parameters.hpp"
#include "prgs.hpp"
#include "vector_com.hpp"

namespace faest
{

// THE VOLE STUFF

template <typename P>
constexpr std::size_t VOLE_PROOF_BYTES =
    P::CONSTS::VOLE_COMMIT_SIZE 
    + P::CONSTS::VOLE_CHECK::PROOF_BYTES 
    + (P::OWF_CONSTS::WITNESS_BITS + 7) / 8 
    + P::CONSTS::QS::PROOF_BYTES 
    + P::bavc_t::OPEN_SIZE 
    + P::secpar_bytes + 16 
    + P::grinding_counter_size;

template <typename P>
bool vole_prove_1(uint8_t* chal1, uint8_t* r, faest::vole_block* u, faest::vole_block* v, faest::block_secpar<P::secpar_v>* forest, 
                    faest::block128* iv_pre, unsigned char* hashed_leaves, uint8_t* proof, 
                    const uint8_t* random_seed, size_t random_seed_len, uint8_t* r_additional);

template <typename P>
bool vole_prove_2(uint8_t* proof, uint8_t* chal1, faest::vole_block* u, faest::vole_block* v, 
                        faest::block128* iv_pre, size_t iv_pre_size, faest::block_secpar<P::secpar_v>* forest, 
                        unsigned char* hashed_leaves, uint8_t* packed_pk, const uint8_t* packed_sk, uint8_t* r_additional);

template <typename P>
bool vole_verify(const uint8_t* proof, size_t proof_size, const uint8_t* packed_pk, size_t packed_pk_size, uint8_t* r_additional);


} // namespace faest

#endif
