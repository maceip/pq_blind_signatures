#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

// Constants that are used in the implementation

#include "avx2/constants_impl.hpp"
#include "parameters.hpp"

namespace faest
{

template <std::size_t bits> struct block;
template <secpar S> using block_secpar = block<secpar_to_bits(S)>;
using block128 = block<128>;


// Number of AES rounds depending on the security parameter
template <secpar S>
constexpr std::size_t AES_ROUNDS = []
{
    if constexpr (S == secpar::s128)
    {
        return 10;
    }
    else if constexpr (S == secpar::s192)
    {
        return 12;
    }
    else if constexpr (S == secpar::s256)
    {
        return 14;
    }
    else
    {
        static_assert(false, "unsupported security parameter for AES");
    }
}();


// Number of Rijndael rounds depending on the security parameter
template <secpar S> constexpr std::size_t RIJNDAEL_ROUNDS = AES_ROUNDS<S>;

// Number of AES blocks to run in parallel, for maximum performance.
constexpr std::size_t AES_PREFERRED_WIDTH = (1 << AES_PREFERRED_WIDTH_SHIFT);

// Number of Rijndael256 blocks to run in parallel, for maximum performance.
constexpr std::size_t RIJNDAEL256_PREFERRED_WIDTH = (1 << RIJNDAEL256_PREFERRED_WIDTH_SHIFT);

// TODO: documentation, what about 192 bits?
template <secpar S>
constexpr std::size_t FIXED_KEY_PREFERRED_WIDTH_SHIFT = []
{
    if constexpr (S == secpar::s128)
    {
        return AES_PREFERRED_WIDTH_SHIFT;
    }
    else if constexpr (S == secpar::s256)
    {
        return RIJNDAEL256_PREFERRED_WIDTH_SHIFT;
    }
    else
    {
        static_assert(false, "unsupported security parameter for fixed-key AES");
    }
}();
template <secpar S>
constexpr std::size_t FIXED_KEY_PREFERRED_WIDTH = (1 << FIXED_KEY_PREFERRED_WIDTH_SHIFT<S>);

// Transpose-related constants
constexpr std::size_t TRANSPOSE_BITS_ROWS = 1 << TRANSPOSE_BITS_ROWS_SHIFT;

// Template containing constants that depend only on the security parameter and the one-way function
template <secpar S, owf O> struct OWF_CONSTANTS;

namespace detail
{


// Compute the number of encryption constraints for an OWF.
template <secpar S, owf O> constexpr std::size_t compute_owf_num_enc_constraints()
{
    //return VOLEMAYO_secpar_polys_per_m_vec<S>;
    return 1;
}

// Compute the total number of constraints for an OWF.
template <secpar S, owf O> constexpr std::size_t compute_owf_num_constraints()
{
    return compute_owf_num_enc_constraints<S, O>();
}

} // namespace detail


// Specialization: Constants for the MAYO one-way function
template <secpar S, owf O>
struct OWF_CONSTANTS
{
    constexpr static std::size_t OWF_KEY_SCHEDULE_SBOXES = 0;
    constexpr static std::size_t OWF_KEY_SCHEDULE_CONSTRAINTS = 0;
    constexpr static std::size_t OWF_KEY_WITNESS_BITS = VOLEMAYO_WITNESS_SIZE_BITS<S>;//get_witness_bit_size_mayo(S);
    constexpr static std::size_t OWF_BLOCK_SIZE = 1;
    constexpr static std::size_t OWF_BLOCKS = 1;
    constexpr static std::size_t OWF_ROUNDS = 1;

    constexpr static std::size_t OWF_ENC_SBOXES = VOLEMAYO_M<S>;
    constexpr static std::size_t OWF_ENC_CONSTRAINTS =
        detail::compute_owf_num_enc_constraints<S, O>();

    constexpr static std::size_t OWF_NUM_CONSTRAINTS = detail::compute_owf_num_constraints<S, O>();
    constexpr static std::size_t WITNESS_BITS = VOLEMAYO_WITNESS_SIZE_BITS<S>;
    constexpr static std::size_t QS_DEGREE = 2;             

    using block_t = block_secpar<S>;
};


// Constants for the QuickSilver implementation
template <secpar S, size_t max_deg> struct QS_CONSTANTS
{
    constexpr static size_t CHALLENGE_BYTES = ((3 * secpar_to_bits(S) + 64) / 8);
    constexpr static size_t PROOF_BYTES = (max_deg - 1) * secpar_to_bytes(S);
    constexpr static size_t CHECK_BYTES = secpar_to_bytes(S);
};

// Constants for the VOLE check
template <secpar S> struct VOLE_CHECK_CONSTANTS
{
    constexpr static std::size_t HASH_BYTES = secpar_to_bytes(S) + 2;
    constexpr static std::size_t CHALLENGE_BYTES = (5 * secpar_to_bits(S) + 64) / 8;
    constexpr static std::size_t PROOF_BYTES = HASH_BYTES;
    constexpr static std::size_t CHECK_BYTES = 2 * secpar_to_bytes(S);
};

// Constants related to the vector commitments
template <size_t TAU, size_t DELTA_BITS> struct VECTOR_COMMITMENT_CONSTANTS
{
    constexpr static size_t tau_v = TAU;
    constexpr static size_t delta_bits_v = DELTA_BITS;

    // The homomorphic commitments use small field VOLE with a mix of two values of k: MIN_K and
    // MAX_K. k is the number of bits of Delta input to a single VOLE.
    constexpr static std::size_t MIN_K = DELTA_BITS / TAU;
    constexpr static std::size_t MAX_K = (DELTA_BITS + TAU - 1) / TAU;

    // Number of VOLEs that use MIN_K and MAX_K.
    constexpr static std::size_t NUM_MAX_K = DELTA_BITS % TAU;
    constexpr static std::size_t NUM_MIN_K = TAU - NUM_MAX_K;
};

// Implementation constants that depend on the parameter set
template <typename P> struct CONSTANTS
{

    using QS = QS_CONSTANTS<P::secpar_v, P::OWF_CONSTS::QS_DEGREE>;
    using VOLE_CHECK = VOLE_CHECK_CONSTANTS<P::secpar_v>;
    using VEC_COM = VECTOR_COMMITMENT_CONSTANTS<P::tau_v, P::delta_bits_v>;

    // VOLE-related constants
    constexpr static std::size_t VOLE_BLOCK = 1 << VOLE_BLOCK_SHIFT;
    constexpr static std::size_t WITNESS_BLOCKS =
        (P::OWF_CONSTS::WITNESS_BITS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK);

    constexpr static std::size_t QUICKSILVER_ROW_PAD_TO =
        (128 * VOLE_BLOCK > TRANSPOSE_BITS_ROWS) ? (128 * VOLE_BLOCK) : TRANSPOSE_BITS_ROWS;
    constexpr static std::size_t QUICKSILVER_ROWS =
        P::OWF_CONSTS::WITNESS_BITS + (P::OWF_CONSTS::QS_DEGREE - 1) * P::secpar_bits;
    constexpr static std::size_t QUICKSILVER_ROWS_PADDED =
        ((QUICKSILVER_ROWS + QUICKSILVER_ROW_PAD_TO - 1) / QUICKSILVER_ROW_PAD_TO) *
        QUICKSILVER_ROW_PAD_TO;

    constexpr static std::size_t VOLE_ROWS = QUICKSILVER_ROWS + VOLE_CHECK::HASH_BYTES * 8;

    constexpr static std::size_t VOLE_COL_BLOCKS =
        (VOLE_ROWS + 128 * VOLE_BLOCK - 1) / (128 * VOLE_BLOCK);
    constexpr static std::size_t VOLE_COL_STRIDE = VOLE_COL_BLOCKS * 16 * VOLE_BLOCK;
    constexpr static std::size_t VOLE_ROWS_PADDED = VOLE_COL_BLOCKS * 128 * VOLE_BLOCK;

    // vole-commit-related constants
    constexpr static std::size_t VOLE_COMMIT_SIZE = (VOLE_ROWS / 8) * (P::tau_v - 1);
    constexpr static std::size_t VOLE_COMMIT_CHECK_SIZE = 2 * P::secpar_bytes;

    constexpr static std::size_t PRG_VOLE_BLOCK_SIZE_SHIFT = []
    {
        if constexpr (P::vole_prg_v == prg::rijndael_fixed_key_ctr && P::secpar_v == secpar::s256)
            return 1;
        else
            return 0;
    }();
    // Number of block128s in a prg_vole_block.
    constexpr static std::size_t PRG_VOLE_BLOCK_SIZE = 1 << PRG_VOLE_BLOCK_SIZE_SHIFT;

    // Number of prg_vole_block in a vole_block.
    constexpr static std::size_t PRG_VOLE_BLOCKS_SHIFT =
        VOLE_BLOCK_SHIFT - PRG_VOLE_BLOCK_SIZE_SHIFT;
    constexpr static std::size_t PRG_VOLE_BLOCKS = 1 << PRG_VOLE_BLOCKS_SHIFT;

    // VOLE is performed in chunks of VOLE_WIDTH keys, with each column consisting of 1
    // vole_block.
    constexpr static std::size_t VOLE_WIDTH_SHIFT =
        AES_PREFERRED_WIDTH_SHIFT - PRG_VOLE_BLOCKS_SHIFT;
    constexpr static std::size_t VOLE_WIDTH = 1 << VOLE_WIDTH_SHIFT;

    // Compile-time consistency checks
    // TODO: uncomment this line if required somehow 
    // using check_witness_bits_ = std::enable_if_t<P::OWF_CONSTS::WITNESS_BITS % 8 == 0>;
    // static_assert(PRG_VOLE_BLOCK_SIZE * 16 == sizeof(typename P::vole_prg_t::block_t), "a 'P::vole_prg_t::block_t` must be 16 * PRG_VOLE_BLOCK_SIZE");
};

} // namespace faest

#endif
