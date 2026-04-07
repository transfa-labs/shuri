use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

#[derive(SszEncode, SszDecode, HashTreeRoot, Debug)]
pub struct Config {
    /// The timestamp of the genesis block.
    pub genesis_time: u64,
}
