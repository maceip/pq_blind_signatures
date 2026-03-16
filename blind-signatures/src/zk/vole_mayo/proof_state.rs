use crate::zk::vole_mayo::parameters::VOLEMAYOParameters;

use std::alloc::{alloc_zeroed, Layout};

fn aligned_vec(size: usize, align: usize) -> Vec<u8> {
    unsafe {
        let layout = Layout::from_size_align(size, align).unwrap();
        let ptr = alloc_zeroed(layout);
        Vec::from_raw_parts(ptr, size, size)
    }
}

/// Defines the intermediate proof state, that is described by the output of
/// `prove_1` with additional space for the target, the hash and the message that
/// are part of `sign_1` and needed for `sign_3`
#[derive(Clone)]
#[repr(align(32))]
pub struct VOLEMAYOProofState {
    pub chal1: Vec<u8>,
    pub r: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
    pub forest: Vec<u8>,
    pub iv_pre: Vec<u8>,
    pub hashed_leaves: Vec<u8>,
    pub proof: Vec<u8>,
    pub random_seed: Vec<u8>,
    pub mu: Vec<u8>,
    pub h: Vec<u8>,
    pub t: Vec<u8>,
}

/// Just a capture for the [`VOLEMAYOProof`] type.
pub struct VOLEMAYOProof {
    pub proof: Vec<u8>,
}

impl From<VOLEMAYOProofState> for VOLEMAYOProof {
    /// Extracts the proof from a [`VOLEMAYOProofState`] after `prove_2` was called.
    fn from(value: VOLEMAYOProofState) -> Self {
        VOLEMAYOProof { proof: value.proof }
    }
}

impl VOLEMAYOProofState {
    /// Initiates a state and allocates sufficient space in memory based on the provided
    /// [`VOLEMAYOParameters`].
    pub fn init(p: &VOLEMAYOParameters) -> Self {
        let chal1 = vec![0u8; p.chal1_size];
        let r = vec![0u8; p.r_size];
        let u = aligned_vec(p.u_size, 32);
        let v = aligned_vec(p.v_size, 32);
        let forest = aligned_vec(p.forest_size, 32);
        let hashed_leaves = aligned_vec(p.hashed_leaves_size, 32);
        let iv_pre = vec![0u8; p.iv_pre_size];
        let proof = vec![0u8; p.proof_size];
        let random_seed = vec![0u8; p.random_seed_size];

        VOLEMAYOProofState {
            chal1,
            r,
            u,
            v,
            forest,
            iv_pre,
            hashed_leaves,
            proof,
            random_seed,
            mu: Vec::new(),
            h: Vec::new(),
            t: Vec::new(),
        }
    }
}
