use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

#[derive(SszEncode, SszDecode, HashTreeRoot)]
pub struct Validator {
    /// XMSS one-time signature public key
    pub pubkey: [u8; 52],

    /// Validator index in the registry
    pub index: u64,
}
