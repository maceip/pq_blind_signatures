#include "owf_proof.inc"

namespace faest
{

// clang-format off

template void owf_constraints(quicksilver_state<v1::mayo_128_s::secpar_v, false, v1::mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_128_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_128_f::secpar_v, false, v1::mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_128_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_192_s::secpar_v, false, v1::mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_192_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_192_f::secpar_v, false, v1::mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_192_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_256_s::secpar_v, false, v1::mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_256_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_256_f::secpar_v, false, v1::mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_256_f>*, unsigned char *);

template void owf_constraints(quicksilver_state<v2::mayo_128_s::secpar_v, false, v2::mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_128_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_128_f::secpar_v, false, v2::mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_128_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_192_s::secpar_v, false, v2::mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_192_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_192_f::secpar_v, false, v2::mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_192_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_256_s::secpar_v, false, v2::mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_256_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_256_f::secpar_v, false, v2::mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_256_f>*, unsigned char *);

template void owf_constraints(quicksilver_state<v1::mayo_128_s::secpar_v, true, v1::mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_128_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_128_f::secpar_v, true, v1::mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_128_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_192_s::secpar_v, true, v1::mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_192_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_192_f::secpar_v, true, v1::mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_192_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_256_s::secpar_v, true, v1::mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_256_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v1::mayo_256_f::secpar_v, true, v1::mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::mayo_256_f>*, unsigned char *);

template void owf_constraints(quicksilver_state<v2::mayo_128_s::secpar_v, true, v2::mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_128_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_128_f::secpar_v, true, v2::mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_128_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_192_s::secpar_v, true, v2::mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_192_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_192_f::secpar_v, true, v2::mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_192_f>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_256_s::secpar_v, true, v2::mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_256_s>*, unsigned char *);
template void owf_constraints(quicksilver_state<v2::mayo_256_f::secpar_v, true, v2::mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::mayo_256_f>*, unsigned char *);


// clang-format on

} // namespace faest
