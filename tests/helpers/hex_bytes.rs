use std::ops::Deref;

use hex::{FromHex, FromHexError, ToHex};
use serde::{Deserialize, Serialize, de};

pub struct HexBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for HexBytes<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<const N: usize> FromHex for HexBytes<N> {
    type Error = FromHexError;
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = hex
            .as_ref()
            .try_into()
            .map_err(|_| FromHexError::InvalidStringLength)?;
        Ok(HexBytes(bytes))
    }
}

impl<const N: usize> ToHex for HexBytes<N> {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        <[u8; N]>::encode_hex(&self)
    }
    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        <[u8; N]>::encode_hex_upper(&self)
    }
}

impl<'de, const N: usize> Deserialize<'de> for HexBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: &str = Deserialize::deserialize(deserializer)?;
        let hex = value.strip_prefix("0x").unwrap_or(value);
        Self::from_hex(hex).map_err(de::Error::custom)
    }
}

impl<const N: usize> Serialize for HexBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = Self::encode_hex::<String>(&self);
        let encoded = format!("0x{}", encoded);
        serializer.serialize_str(&encoded)
    }
}
