#ifndef FAEST_KEYS_HPP
#define FAEST_KEYS_HPP

#include "aes.hpp"
#include "block.hpp"
#include "constants.hpp"
#include "parameters.hpp"


namespace faest
{

// The size of the FAEST secret key is the size of the secret key and the input to the OWF.
template <typename P>
constexpr std::size_t FAEST_SECRET_KEY_BYTES = VOLEMAYO_SECRET_KEY_SIZE_BYTES<P::secpar_v>;

// The size of the public key is the size of the input and the output of the OWF.
template <typename P>
constexpr std::size_t FAEST_PUBLIC_KEY_BYTES = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

template <typename P> struct public_key
{
    P::OWF_CONSTS::block_t h[((VOLEMAYO_PROVE_1_H_ELEM_SIZE<P::secpar_v> * VOLEMAYO_BIN_FIELD_SIZE) + 127) / 128];
    uint64_t mayo_expanded_pk[VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>];
};

template <typename P> struct secret_key
{
    public_key<P> pk;
    vole_block sk[((((VOLEMAYO_K<P::secpar_v>*VOLEMAYO_N<P::secpar_v>) + VOLEMAYO_M<P::secpar_v>) * VOLEMAYO_BIN_FIELD_SIZE) + 127) / 128];     // this contains s and r (4 bits per element), fitting them in n vole_blocks of 128bits
    vole_block witness[((((VOLEMAYO_K<P::secpar_v>*VOLEMAYO_N<P::secpar_v>) + VOLEMAYO_M<P::secpar_v>) * VOLEMAYO_BIN_FIELD_SIZE) + 127) / 128];       // this is just a copy of the sk, (don't ask why I did this)
};

template <typename P> bool faest_unpack_secret_key(secret_key<P>* unpacked, const uint8_t* packed);
template <typename P> void faest_pack_public_key(uint8_t* packed, const public_key<P>* unpacked);
template <typename P> void faest_unpack_public_key(public_key<P>* unpacked, const uint8_t* packed);
template <typename P> bool faest_compute_witness(secret_key<P>* sk);
template <typename P>
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed,
                                    secret_key<P>* sk);

// Check if a byte string is a valid secret key. sk_packed must be FAEST_SECRET_KEY_BYTES long.
template <typename P> bool faest_seckey(const uint8_t* sk_packed);

// Find the public key corresponding to a given secret key. Returns true if sk_packed is a valid
// secret key, and false otherwise. For key generation, this function is intended to be called
// repeatedly on random values of sk_packed until a valid key is found. pk_packed must be
// FAEST_PUBLIC_KEY_BYTES long, while sk_packed must be FAEST_SECRET_KEY_BYTES long.
template <typename P> bool faest_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed);

} // namespace faest

#endif // FAEST_KEYS_H
