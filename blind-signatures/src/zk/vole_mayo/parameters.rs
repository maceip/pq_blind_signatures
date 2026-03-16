use crate::zk::ZKType;
use vole_mayo_sys::{
    get_mayo128fv1_parameters, 
    get_mayo128sv1_parameters, 
    get_mayo192fv1_parameters, 
    get_mayo192sv1_parameters,  
    get_mayo256fv1_parameters, 
    get_mayo256sv1_parameters, 
    mayo_128_f_v1_serialize_pk,
    mayo_128_f_v1_serialize_sk,  
    mayo_128_s_v1_serialize_pk, 
    mayo_128_s_v1_serialize_sk, 
    mayo_192_f_v1_serialize_pk,
    mayo_192_f_v1_serialize_sk, 
    mayo_192_s_v1_serialize_pk, 
    mayo_192_s_v1_serialize_sk,  
    mayo_256_f_v1_serialize_pk, 
    mayo_256_f_v1_serialize_sk, 
    mayo_256_s_v1_serialize_pk,
    mayo_256_s_v1_serialize_sk, 
    mayo128fv1_prove_1, 
    mayo128fv1_prove_2,
    mayo128fv1_verify, 
    mayo128sv1_prove_1, 
    mayo128sv1_prove_2,
    mayo128sv1_verify, 
    mayo192fv1_prove_1, 
    mayo192fv1_prove_2, 
    mayo192fv1_verify,  
    mayo192sv1_prove_1, 
    mayo192sv1_prove_2,
    mayo192sv1_verify, 
    mayo256fv1_prove_1, 
    mayo256fv1_prove_2, 
    mayo256fv1_verify,  
    mayo256sv1_prove_1, 
    mayo256sv1_prove_2,
    mayo256sv1_verify, 
};

/// Just a capture for all the parameters needed in our code that we need to access in
/// respect to the vole-mayo interface.
/// They are defined by the respective [`ZKType`].
pub struct VOLEMAYOParameters {
    pub chal1_size: usize,
    pub r_size: usize,
    pub u_size: usize,
    pub v_size: usize,
    pub forest_size: usize,
    pub iv_pre_size: usize,
    pub hashed_leaves_size: usize,
    pub proof_size: usize,
    pub proof1_size: usize,
    pub packed_pk_size: usize,
    pub packed_sk_size: usize,
    pub random_seed_size: usize,
    pub pk_seed_size: usize,
    pub p1_size: usize,
    pub p2_size: usize,
    pub p3_size: usize,
    pub h_size: usize,
    pub s_size: usize,
    pub prove_1_fn: Prove1Fn,
    pub prove_2_fn: Prove2Fn,
    pub verify_fn: VerifyFn,
    pub serialize_pk_fn: SerializePKFn,
    pub serialize_sk_fn: SerializeSKFn,
}

impl VOLEMAYOParameters {
    /// Sets all the VOLEMAYO parameters according to their definition in vole-mayo
    pub fn setup(params: ZKType) -> Self {
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

        let get_params_fun: GetParamsFn = VOLEMAYOParameters::get_get_params_function(params);

        unsafe {
            get_params_fun(
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
            )
        };

        Self {
            chal1_size,
            r_size,
            u_size,
            v_size,
            forest_size,
            iv_pre_size,
            hashed_leaves_size,
            proof_size,
            proof1_size,
            packed_pk_size,
            packed_sk_size,
            random_seed_size,
            pk_seed_size,
            p1_size,
            p2_size,
            p3_size,
            h_size,
            s_size,
            prove_1_fn: VOLEMAYOParameters::get_prove_1_function(params),
            prove_2_fn: VOLEMAYOParameters::get_prove_2_function(params),
            verify_fn: VOLEMAYOParameters::get_verify_function(params),
            serialize_pk_fn: VOLEMAYOParameters::get_serialize_pk_function(params),
            serialize_sk_fn: VOLEMAYOParameters::get_serialize_sk_function(params),
        }
    }

    fn get_get_params_function(params: ZKType) -> GetParamsFn {
        match params {
            ZKType::FV1_128 => get_mayo128fv1_parameters,
            ZKType::FV1_192 => get_mayo192fv1_parameters,
            ZKType::FV1_256 => get_mayo256fv1_parameters,
            ZKType::SV1_128 => get_mayo128sv1_parameters,
            ZKType::SV1_192 => get_mayo192sv1_parameters,
            ZKType::SV1_256 => get_mayo256sv1_parameters,
        }
    }

    fn get_prove_1_function(params: ZKType) -> Prove1Fn {
        match params {
            ZKType::FV1_128 => mayo128fv1_prove_1,
            ZKType::FV1_192 => mayo192fv1_prove_1,
            ZKType::FV1_256 => mayo256fv1_prove_1,
            ZKType::SV1_128 => mayo128sv1_prove_1,
            ZKType::SV1_192 => mayo192sv1_prove_1,
            ZKType::SV1_256 => mayo256sv1_prove_1,
        }
    }

    fn get_prove_2_function(params: ZKType) -> Prove2Fn {
        match params {
            ZKType::FV1_128 => mayo128fv1_prove_2,
            ZKType::FV1_192 => mayo192fv1_prove_2,
            ZKType::FV1_256 => mayo256fv1_prove_2,
            ZKType::SV1_128 => mayo128sv1_prove_2,
            ZKType::SV1_192 => mayo192sv1_prove_2,
            ZKType::SV1_256 => mayo256sv1_prove_2,
        }
    }

    fn get_verify_function(params: ZKType) -> VerifyFn {
        match params {
            ZKType::FV1_128 => mayo128fv1_verify,
            ZKType::FV1_192 => mayo192fv1_verify,
            ZKType::FV1_256 => mayo256fv1_verify,
            ZKType::SV1_128 => mayo128sv1_verify,
            ZKType::SV1_192 => mayo192sv1_verify,
            ZKType::SV1_256 => mayo256sv1_verify,
        }
    }

    fn get_serialize_sk_function(params: ZKType) -> SerializeSKFn {
        match params {
            ZKType::FV1_128 => mayo_128_f_v1_serialize_sk,
            ZKType::FV1_192 => mayo_192_f_v1_serialize_sk,
            ZKType::FV1_256 => mayo_256_f_v1_serialize_sk,
            ZKType::SV1_128 => mayo_128_s_v1_serialize_sk,
            ZKType::SV1_192 => mayo_192_s_v1_serialize_sk,
            ZKType::SV1_256 => mayo_256_s_v1_serialize_sk,
        }
    }

    fn get_serialize_pk_function(params: ZKType) -> SerializePKFn {
        match params {
            ZKType::FV1_128 => mayo_128_f_v1_serialize_pk,
            ZKType::FV1_192 => mayo_192_f_v1_serialize_pk,
            ZKType::FV1_256 => mayo_256_f_v1_serialize_pk,
            ZKType::SV1_128 => mayo_128_s_v1_serialize_pk,
            ZKType::SV1_192 => mayo_192_s_v1_serialize_pk,
            ZKType::SV1_256 => mayo_256_s_v1_serialize_pk,
        }
    }
}

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

type Prove1Fn = unsafe extern "C" fn(
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

type Prove2Fn = unsafe extern "C" fn(
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

type VerifyFn = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> bool;

type SerializeSKFn =
    unsafe extern "C" fn(*mut u8, usize, *const u8, usize, *const u8, usize, *const u8, usize);

type SerializePKFn = unsafe extern "C" fn(
    *mut u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
);
