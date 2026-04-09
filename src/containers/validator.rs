use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

pub type Pubkey = [u8; 52];

#[derive(SszEncode, SszDecode, HashTreeRoot, Debug, Clone)]
pub struct Validator {
    /// XMSS one-time signature public key
    pub pubkey: Pubkey,

    /// Validator index in the registry
    pub index: u64,
}
