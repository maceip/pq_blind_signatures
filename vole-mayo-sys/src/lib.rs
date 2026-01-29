#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod vole_proof_test_mayo {
    use crate::{
        get_mayo128fv1_parameters, get_mayo128fv2_parameters, get_mayo128sv1_parameters,
        get_mayo128sv2_parameters, get_mayo192fv1_parameters, get_mayo192fv2_parameters,
        get_mayo192sv1_parameters, get_mayo192sv2_parameters, get_mayo256fv1_parameters,
        get_mayo256fv2_parameters, get_mayo256sv1_parameters, get_mayo256sv2_parameters,
        mayo128fv1_prove_1, mayo128fv2_prove_1, mayo128sv1_prove_1, mayo128sv2_prove_1,
        mayo192fv1_prove_1, mayo192fv2_prove_1, mayo192sv1_prove_1, mayo192sv2_prove_1,
        mayo256fv1_prove_1, mayo256fv2_prove_1, mayo256sv1_prove_1, mayo256sv2_prove_1,
    };

    type GetParamsFn = unsafe extern "C" fn(
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
    );

    type ProveFn = unsafe extern "C" fn(
        *mut u8,
        usize,
        *mut u8,
        usize,
        *mut u8,
        usize,
        *mut u8,
        usize,
        *mut u8,
        usize,
        *mut u8,
        usize,
        *mut u8,
        usize,
        *mut u8,
        usize,
        *const u8,
        usize,
        *mut u8,
    ) -> bool;

    #[test]
    fn test_binding() {
        let param_getters: [GetParamsFn; 12] = [
            get_mayo128sv1_parameters,
            get_mayo128fv1_parameters,
            get_mayo192sv1_parameters,
            get_mayo192fv1_parameters,
            get_mayo256sv1_parameters,
            get_mayo256fv1_parameters,
            get_mayo128sv2_parameters,
            get_mayo128fv2_parameters,
            get_mayo192sv2_parameters,
            get_mayo192fv2_parameters,
            get_mayo256sv2_parameters,
            get_mayo256fv2_parameters,
        ];
        let prove_functions: [ProveFn; 12] = [
            mayo128sv1_prove_1,
            mayo128fv1_prove_1,
            mayo192sv1_prove_1,
            mayo192fv1_prove_1,
            mayo256sv1_prove_1,
            mayo256fv1_prove_1,
            mayo128sv2_prove_1,
            mayo128fv2_prove_1,
            mayo192sv2_prove_1,
            mayo192fv2_prove_1,
            mayo256sv2_prove_1,
            mayo256fv2_prove_1,
        ];
        for (get_params, prove_fn) in param_getters.iter().zip(prove_functions.iter()) {
            println!("start next round");
            // Initialize all size variables
            let mut chal1_size = 0usize;
            let mut r_size = 0usize;
            let mut u_size = 0usize;
            let mut v_size = 0usize;
            let mut forest_size = 0usize;
            let mut iv_pre_size = 0usize;
            let mut hashed_leaves_size = 0usize;
            let mut proof_size = 0usize;
            let mut proof1_size = 0usize;
            let mut packed_pk_size = 0usize;
            let mut packed_sk_size = 0usize;
            let mut random_seed_size = 0usize;
            let mut pk_seed_size = 0usize;
            let mut p1_size = 0usize;
            let mut p2_size = 0usize;
            let mut p3_size = 0usize;
            let mut h_size = 0usize;
            let mut s_size = 0usize;

            unsafe {
                // Call parameter getter to fill the sizes
                get_params(
                    &mut chal1_size,
                    &mut r_size,
                    &mut u_size,
                    &mut v_size,
                    &mut forest_size,
                    &mut iv_pre_size,
                    &mut hashed_leaves_size,
                    &mut proof_size,
                    &mut proof1_size,
                    &mut packed_pk_size,
                    &mut packed_sk_size,
                    &mut random_seed_size,
                    &mut pk_seed_size,
                    &mut p1_size,
                    &mut p2_size,
                    &mut p3_size,
                    &mut h_size,
                    &mut s_size,
                );

                // Allocate buffers using the sizes
                let mut chal1 = vec![0u8; chal1_size];
                let mut r = vec![0u8; r_size];
                let mut u = vec![0u8; u_size];
                let mut v = vec![0u8; v_size];
                let mut forest = vec![0u8; forest_size];
                let mut iv_pre = vec![0u8; iv_pre_size];
                let mut hashed_leaves = vec![0u8; hashed_leaves_size];
                let mut proof = vec![0u8; proof_size];
                let random_seed = vec![0u8; random_seed_size];
                let mut additional_r = vec![0u8, 32];

                // Call the prove function with the buffers and sizes
                let success = prove_fn(
                    chal1.as_mut_ptr(),
                    chal1_size,
                    r.as_mut_ptr(),
                    r_size,
                    u.as_mut_ptr(),
                    u_size,
                    v.as_mut_ptr(),
                    v_size,
                    forest.as_mut_ptr(),
                    forest_size,
                    iv_pre.as_mut_ptr(),
                    iv_pre_size,
                    hashed_leaves.as_mut_ptr(),
                    hashed_leaves_size,
                    proof.as_mut_ptr(),
                    proof_size,
                    random_seed.as_ptr(),
                    random_seed_size,
                    additional_r.as_mut_ptr(),
                );

                assert!(success, "Prove function failed!");
                println!("Prove function succeeded for this parameter set.");
            }
        }
    }
}
