use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;

use crate::containers::{Pubkey as PkContainer, Signature as SigContainer};

pub type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

pub type PublicKey = <LeanSigScheme as SignatureScheme>::PublicKey;
pub type Signature = <LeanSigScheme as SignatureScheme>::Signature;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("decode error: {0}")]
    DecodeError(String),
    #[error("signature verification error")]
    VerificationError,
}

pub fn verify_signature(
    pubkey: &PkContainer,
    epoch: u64,
    message: &[u8; 32],
    signature: &SigContainer,
) -> Result<(), Error> {
    let pk = PublicKey::from_bytes(pubkey).map_err(|e| Error::DecodeError(format!("{:?}", e)))?;
    let sig =
        Signature::from_bytes(signature).map_err(|e| Error::DecodeError(format!("{:?}", e)))?;
    if !LeanSigScheme::verify(
        &pk,
        epoch.try_into().expect("slot exceeds u32"),
        message,
        &sig,
    ) {
        return Err(Error::VerificationError);
    }
    Ok(())
}
