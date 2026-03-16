use crate::zk::{
    ZKType,
    vole_mayo::{
        parameters::VOLEMAYOParameters,
        proof_state::{VOLEMAYOProof, VOLEMAYOProofState},
    },
};

pub mod parameters;
pub mod proof_state;

/// This struct acts as the object callable to utilize the functionalities of [`VOLEMAYO`].
/// With it, you can generate proofs (prove_1, prove_2) and validate proofs using
/// different parametersets.
/// It is used within the optimized blind signature [`BlindSignatureOptimized`](crate::blind_sig_optimized::BlindSignatureOptimized).
pub struct VOLEMAYO {
    pub vole_mayo_params: VOLEMAYOParameters,
}

impl VOLEMAYO {
    /// Given one of the parameter options (defined by [`ZKType`]), fix all functions and
    /// parameters for that specific parameter set.
    pub fn setup(params: ZKType) -> Self {
        VOLEMAYO {
            vole_mayo_params: VOLEMAYOParameters::setup(params),
        }
    }

    /// Computes a [`VOLEMAYOProofState`] that consists of the initial proof p1,
    /// auxilary information and also randomness `r` that can be used to blind messages.
    /// The proof state is also required to continue with `prove_2`.
    pub fn prove_1(&self, additional_r: &mut [u8]) -> VOLEMAYOProofState {
        
        let mut state = VOLEMAYOProofState::init(&self.vole_mayo_params);

        let random_seed_ptr = if state.random_seed.is_empty() {
            std::ptr::null()
        } else {
            state.random_seed.as_ptr()
        };

        assert!(unsafe {
            (self.vole_mayo_params.prove_1_fn)(
                state.chal1.as_mut_ptr(),
                self.vole_mayo_params.chal1_size,
                state.r.as_mut_ptr(),
                self.vole_mayo_params.r_size,
                state.u.as_mut_ptr(),
                self.vole_mayo_params.u_size,
                state.v.as_mut_ptr(),
                self.vole_mayo_params.v_size,
                state.forest.as_mut_ptr(),
                self.vole_mayo_params.forest_size,
                state.iv_pre.as_mut_ptr(),
                self.vole_mayo_params.iv_pre_size,
                state.hashed_leaves.as_mut_ptr(),
                self.vole_mayo_params.hashed_leaves_size,
                state.proof.as_mut_ptr(),
                self.vole_mayo_params.proof_size,
                random_seed_ptr,
                self.vole_mayo_params.random_seed_size,
                additional_r.as_mut_ptr(),
            )
        });

        state
    }

    /// Continuation of `prove_1`.
    /// However, in this step the witness, i.e., the signature and the randomness `r`
    /// is additionally required.
    /// Furthermore, the algorithm requires packed_pk and packed_pk defined by the ZK proof.
    pub fn prove_2(
        &self,
        mut state: VOLEMAYOProofState,
        packed_pk: &mut Vec<u8>, // todo: fix this to not be mutable
        packed_sk: &[u8],
        additional_r: &mut [u8],
    ) -> VOLEMAYOProof {
        assert!(unsafe {
            (self.vole_mayo_params.prove_2_fn)(
                state.chal1.as_mut_ptr(),
                self.vole_mayo_params.chal1_size,
                state.u.as_mut_ptr(),
                self.vole_mayo_params.u_size,
                state.v.as_mut_ptr(),
                self.vole_mayo_params.v_size,
                state.forest.as_mut_ptr(),
                self.vole_mayo_params.forest_size,
                state.iv_pre.as_mut_ptr(),
                self.vole_mayo_params.iv_pre_size,
                state.hashed_leaves.as_mut_ptr(),
                self.vole_mayo_params.hashed_leaves_size,
                state.proof.as_mut_ptr(),
                self.vole_mayo_params.proof_size,
                packed_pk.as_mut_ptr(),
                self.vole_mayo_params.packed_pk_size,
                packed_sk.as_ptr(),
                self.vole_mayo_params.packed_sk_size,
                additional_r.as_mut_ptr(),
            )
        });

        VOLEMAYOProof::from(state)
    }

    /// Publicly verifies a VOLEMAYOProof using the expanded public key of MAYO.
    pub fn verify(&self, proof: &VOLEMAYOProof, packed_pk: &[u8], additional_r: &mut [u8]) -> bool {
        unsafe {
            (self.vole_mayo_params.verify_fn)(
                proof.proof.as_ptr(),
                proof.proof.len(),
                packed_pk.as_ptr(),
                packed_pk.len(),
                additional_r.as_mut_ptr(),
            )
        }
    }
}
