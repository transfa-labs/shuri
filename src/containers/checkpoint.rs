use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

/// Represents a checkpoint in the chain's history.
#[derive(SszDecode, SszEncode, HashTreeRoot, Clone, Default, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The root hash of the checkpoint's block.
    pub root: [u8; 32],
    /// The slot number of the checkpoint's block.
    pub slot: u64,
}
