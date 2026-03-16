pub mod vole_mayo;

/// Defines the different security levels that can be chosen.
///
/// There are generally 3 levels: 128, 192, and 256.
/// Additionally, one can choose between fast and small, and implementations
/// of version 1 and 2 of the underlying framework of the QS circuit used for the zk proof.
#[derive(Clone, Copy, Debug)]
pub enum ZKType {
    FV1_128,
    FV1_192,
    FV1_256,
    SV1_128,
    SV1_192,
    SV1_256,
}
