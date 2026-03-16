use super::BlindSignatureOptimized;
use crate::zk::{ZKType, vole_mayo::VOLEMAYO};
use mayo_c_sys::mayo::{MAYO, MAYOParameterSet};

impl BlindSignatureOptimized {
    /// Initializes the blind signature and determines all the parameters for the
    /// construction. There are three different security levels (128, 192, 256).
    /// According to them, the respective versions for the zero-knwoledge proof and MAYO
    /// (MAYO1, MAYO3, MAYO5) are selected. Furthermore, there are different versions of
    /// the zero-knowledge proof to choose from for each of the security levels
    /// (fast, slow and additionally, version 1 and 2 for each).
    /// All of these options are captured by the enum ZKType that is provided as input to
    /// this function.
    ///
    /// # Parameters
    /// - `security_level`: Selects the bit-level security and the version of the
    ///   zero-knowledge proof that is intended to be used.
    ///
    /// # Example
    /// ```
    /// use blind_signatures::zk::ZKType;
    /// use blind_signatures::blind_sig_optimized::BlindSignatureOptimized;
    ///
    /// let bs = BlindSignatureOptimized::setup(ZKType::FV1_128);
    /// ```
    pub fn setup(security_level: ZKType) -> Self {
        let mayo_param = match security_level {
            ZKType::FV1_128 => MAYOParameterSet::MAYO1,
            ZKType::FV1_192 => MAYOParameterSet::MAYO3,
            ZKType::FV1_256 => MAYOParameterSet::MAYO5,
            ZKType::SV1_128 => MAYOParameterSet::MAYO1,
            ZKType::SV1_192 => MAYOParameterSet::MAYO3,
            ZKType::SV1_256 => MAYOParameterSet::MAYO5,
        };
        Self {
            mayo: MAYO::setup(mayo_param),
            vole_mayo: VOLEMAYO::setup(security_level),
        }
    }
}
